import base64
import csv
import hashlib
import json
import os
import pwd
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

import requests
import typer
import urllib3
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt
from rich.table import Table

from k_vpn import config, probes, profiles

app = typer.Typer(help="k-vpn: Automated VPN Gate Connector")
console = Console()


class OpenVPNProcess(subprocess.Popen[str]):
    """Owned subprocess with a UID-restricted local shutdown channel."""

    _vpn_management_socket: str | None = None


class AuthenticationRequired(RuntimeError):
    """Local sudo permission expired; never a relay/network failure."""


VPN_GATE_DIRECT_IPS = [
    "http://130.158.6.82/api/iphone/",
    "https://130.158.6.82/api/iphone/",
    "http://130.158.6.101/api/iphone/",
]

VPN_GATE_URLS = (
    ["https://www.vpngate.net/api/iphone/"]
    + VPN_GATE_DIRECT_IPS
    + [
        "http://78.142.193.125/api/iphone/",
        "http://p6e430ddc.chibnt01.ap.so-net.ne.jp:18708/api/iphone/",
        "http://www.vpngate.net/api/iphone/",
    ]
)

# ---------------------------------------------------------------------------
# k-vpn BOOST: verified measurements, protocol-aware tuning, bounded failover
# ---------------------------------------------------------------------------
SPEEDTEST_URL = "https://speed.cloudflare.com/__down?bytes=40000000"
BENCH_TTL = 600  # a labelled recent observation, never a throughput guarantee


def _bench_cache_path() -> str:
    return str(config.cache_file())


def _measurement_key(server: dict[str, Any]) -> str:
    """Scope observations to endpoint, profile, tuning, and the current uplink."""
    routes = subprocess.run(
        ["ip", "-j", "-4", "route", "show", "default"],
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )
    network = [
        (r.get("dev"), r.get("gateway"), r.get("prefsrc"))
        for r in json.loads(routes.stdout or "[]")
    ]
    return hashlib.sha256(
        json.dumps(
            [
                network,
                server.get("OpenVPN_ConfigData_Base64"),
                server.get("_tuning", "balanced"),
            ]
        ).encode()
    ).hexdigest()


def load_bench_cache() -> dict[str, Any]:
    try:
        with open(_bench_cache_path()) as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_bench_cache(cache: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(_bench_cache_path()), mode=0o700, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", dir=os.path.dirname(_bench_cache_path()), delete=False
    ) as f:
        json.dump(cache, f)
        temporary = f.name
    os.replace(temporary, _bench_cache_path())


def cached_speed(ip: str, cache: dict[str, Any]) -> float:
    entry = cache.get(ip)
    if entry and time.time() - entry.get("ts", 0) < BENCH_TTL:
        return float(entry.get("speed", 0))
    return 0.0


def measure_speed(seconds: int = 6) -> float:
    """Compatibility helper; only a bound, verified tunnel can yield a speed."""
    result = probes.measure(seconds)
    return result.mbps or 0.0


def config_is_udp(ovpn_data: bytes) -> bool:
    endpoints = profiles.remotes(ovpn_data.decode("utf-8", "replace"))
    return bool(endpoints) and endpoints[0][2] == "udp"


def lift_socket_buffers() -> None:
    """Raise net.core.{w,r}mem_max to 16MB so --sndbuf/--rcvbuf actually apply
    (default 208KB would silently clamp them and cap throughput)."""
    target = 16_777_216
    updates = []
    for name in ("wmem_max", "rmem_max"):
        current = int(Path(f"/proc/sys/net/core/{name}").read_text().strip())
        if current < target:
            updates.append(f"net.core.{name}={target}")
    if updates:
        # Never reduce an operator's already larger buffers; surface failures.
        subprocess.run(["sudo", "sysctl", "-w", *updates], check=True)


def build_ovpn_cmd(
    config_path: str, creds_path: str, is_udp: bool, tuning: str = "balanced"
) -> list:
    """Native preserves profile MTU/buffers; balanced optionally tunes UDP.

    Earlier proposals predicted a 16-Mbps TCP cap and a 3-5x UDP speedup.
    These were not established by measurements and are NOT guarantees.
    AEAD is preferred; explicit legacy profile ciphers remain interoperable.
    """
    # Do not invent password authentication for a certificate-only profile.
    # VPN Gate's embedded client certificate/key must remain authoritative.
    with open(config_path) as profile:
        directives = [line.split("#", 1)[0].strip().split() for line in profile]
    requests_password = any(
        parts and parts[0] == "auth-user-pass" for parts in directives
    )
    common = [
        "--config",
        config_path,
        "--tls-timeout",
        "15",
        "--hand-window",
        "60",
        "--connect-retry",
        "1",
        "--connect-retry-max",
        "1",
        "--connect-timeout",
        "10",
        "--verb",
        "3",
        "--auth-nocache",
        "--remote-cert-tls",
        "server",
        "--data-ciphers",
        "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
    ]
    if requests_password:
        common.extend(["--auth-user-pass", creds_path])
    if any(parts == ["cipher", "AES-128-CBC"] for parts in directives):
        console.print(
            "[yellow]Profile requests legacy AES-128-CBC: enabling compatibility; AEAD remains preferred.[/yellow]"
        )
        common[common.index("--data-ciphers") + 1] += ":AES-128-CBC"
        common.extend(["--data-ciphers-fallback", "AES-128-CBC"])
    if tuning == "native":
        return ["sudo", "openvpn", *common]
    if is_udp:
        lift_socket_buffers()
        return [
            "sudo",
            "openvpn",
            *common,
            "--tun-mtu",
            "1400",
            "--sndbuf",
            "16777216",
            "--rcvbuf",
            "16777216",
            "--pull-filter",
            "ignore",
            "mssfix",
            "--pull-filter",
            "ignore",
            "fragment",
        ]
    # Let the TCP stack autotune its window and keep the profile's MTU.
    return ["sudo", "openvpn", *common, "--tcp-nodelay"]


def get_config_priority(b64_config: str) -> int:
    """Ranks configuration based on protocol and port for eduroam bypass."""
    try:
        config = base64.b64decode(b64_config).decode("utf-8", errors="ignore")
        endpoints = profiles.remotes(config)
        is_udp = bool(endpoints) and endpoints[0][2] == "udp"
        is_tcp = bool(endpoints) and endpoints[0][2] == "tcp"
        is_port_443 = bool(endpoints) and endpoints[0][1] == 443

        # Priority mapping for eduroam (Lower is better)
        # UDP 443 is a candidate preference, not proof that OpenVPN UDP passes.
        # QUIC reachability cannot establish reachability of another protocol.
        # TCP 443 is a fallback candidate, not DPI-proof or universally allowed.
        if is_udp and is_port_443:
            return 1
        if is_tcp and is_port_443:
            return 2
        if is_udp:
            return 3
        if is_tcp:
            return 4
        return 5
    except (ValueError, TypeError, IndexError):
        return 10


def _get_bounded(url: str, headers: dict[str, str], verify: bool):
    """Bound discovery including DNS, not just requests' socket read timeout."""
    result = queue.Queue(maxsize=1)

    def worker():
        try:
            with requests.Session() as client:
                client.trust_env = False
                response = client.get(
                    url,
                    timeout=(3, 5),
                    verify=verify,
                    headers=headers,
                    allow_redirects=False,
                )
            result.put(response)
        except requests.RequestException as exc:
            result.put(exc)

    threading.Thread(target=worker, daemon=True).start()
    try:
        response = result.get(timeout=9)
    except queue.Empty as exc:
        raise requests.Timeout(
            "Relay discovery deadline, including DNS, exceeded"
        ) from exc
    if isinstance(response, requests.RequestException):
        raise response
    return response


def fetch_vpn_servers(
    verify: bool = True, allow_http: bool = True
) -> list[dict[str, Any]]:
    """Fetches and parses VPN servers from VPN Gate API."""
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Host": "www.vpngate.net",
    }

    csv_content = None
    for url in VPN_GATE_URLS:
        if not allow_http and not url.startswith("https://"):
            continue
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn(f"[bold green]Trying {url.split('/')[2]}..."),
                transient=True,
            ) as progress:
                progress.add_task("fetch", total=None)
                response = _get_bounded(url, headers, verify)
                if (
                    response.status_code == 200
                    and "vpn_servers" in response.text.lower()
                ):
                    csv_content = response.text
                    if not url.startswith("https://"):
                        console.print(
                            "[yellow]Warning: relay list fetched over unauthenticated HTTP (legacy compatibility). Use --strict-discovery to forbid this. Destination HTTPS is separately verified.[/yellow]"
                        )
                    break
                elif response.status_code in [301, 302]:
                    location = response.headers.get("Location", "")
                    if not allow_http and not location.startswith("https://"):
                        continue
                    response = _get_bounded(location, headers, verify)
                    if (
                        response.status_code == 200
                        and "vpn_servers" in response.text.lower()
                    ):
                        csv_content = response.text
                        if not location.startswith("https://"):
                            console.print(
                                "[yellow]Warning: relay discovery redirected to unauthenticated HTTP.[/yellow]"
                            )
                        break
        except requests.RequestException as exc:
            console.print(f"[dim]Mirror unavailable: {url}: {type(exc).__name__}[/dim]")

    if not csv_content:
        console.print(
            "[bold red]Discovery failed:[/bold red] No usable relay list. VPN reachability has not been tested."
        )
        sys.exit(1)

    lines = csv_content.splitlines()
    csv_lines = [line for line in lines if not line.startswith("*")]
    csv_lines[0] = csv_lines[0].removeprefix("#")

    reader = csv.DictReader(csv_lines)
    servers = []
    for row in reader:
        if row.get("OpenVPN_ConfigData_Base64"):
            row["priority"] = get_config_priority(row["OpenVPN_ConfigData_Base64"])
            servers.append(row)
    return servers


def group_by_country(servers: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped = {}
    for server in servers:
        country = server.get("CountryLong", "Unknown")
        if country not in grouped:
            grouped[country] = []
        grouped[country].append(server)
    return grouped


@app.command()
def main(
    insecure: bool = typer.Option(
        False,
        "--insecure",
        "-k",
        help="Disable API TLS verification (unsafe; does not disable DNS)",
    ),
    bench: int | None = typer.Option(
        None,
        "--bench",
        min=0,
        help="Real-benchmark N servers after country choice (0 = skip, pure VPN Gate ranking)",
    ),
    min_speed: float | None = typer.Option(
        None,
        "--min-speed",
        help="Failover monitor: switch server if real speed < X Mbps (0 = off)",
    ),
    country: str = typer.Option(
        "", "--country", "-c", help="Country name or ISO code, no changing menu numbers"
    ),
    test_only: bool = typer.Option(
        False,
        "--test-only",
        help="Benchmark then disconnect; never leave a VPN running",
    ),
    tuning: str | None = typer.Option(
        None,
        "--tuning",
        help="native (preserve profile) or balanced (experimental UDP tuning)",
    ),
    server_ip: str = typer.Option(
        "", "--server", help="Pin a currently listed relay IP"
    ),
    strict_discovery: bool | None = typer.Option(
        None,
        "--strict-discovery/--no-strict-discovery",
        help="Forbid unauthenticated HTTP relay-list mirrors",
    ),
):
    try:
        settings = config.load()
    except (OSError, ValueError, TypeError) as exc:
        raise typer.BadParameter(f"Invalid configuration: {exc}") from exc
    bench = settings.bench if bench is None else bench
    min_speed = settings.min_speed if min_speed is None else min_speed
    tuning = settings.tuning if tuning is None else tuning
    strict_discovery = (
        settings.strict_discovery if strict_discovery is None else strict_discovery
    )
    if strict_discovery and insecure:
        raise typer.BadParameter(
            "--strict-discovery cannot be combined with --insecure"
        )
    if tuning not in ("balanced", "native"):
        raise typer.BadParameter("--tuning must be balanced or native")
    if test_only and bench == 0:
        raise typer.BadParameter("--test-only requires --bench > 0")
    config.initialize()
    console.print(
        Panel.fit(
            "[bold cyan]k-vpn[/bold cyan] - Secure World Connector", border_style="cyan"
        )
    )
    servers = fetch_vpn_servers(verify=not insecure, allow_http=not strict_discovery)
    if not servers:
        return
    for server in servers:
        server["_tuning"] = tuning
    if server_ip:
        servers = [server for server in servers if server.get("IP") == server_ip]
        if not servers:
            raise typer.BadParameter(
                "The requested relay is not in the current listing"
            )
    if country:
        matched = [
            s
            for s in servers
            if country.casefold()
            in (
                s.get("CountryLong", "").casefold(),
                s.get("CountryShort", "").casefold(),
            )
        ]
        if not matched:
            raise typer.BadParameter(f"No current relay listed for {country}")
        connect_to_country(
            matched[0]["CountryLong"], matched, bench, min_speed, test_only
        )
        return

    grouped_servers = group_by_country(servers)
    sorted_countries = sorted(grouped_servers.keys())

    table = Table(
        title="Available Countries", show_header=True, header_style="bold magenta"
    )
    table.add_column("#", style="dim", justify="right")
    table.add_column("Country", style="cyan")
    table.add_column("Servers", justify="right")
    table.add_column("Advertised", justify="right")
    table.add_column("Recent verified Mbps", justify="right")
    cache = load_bench_cache()

    for idx, country_label in enumerate(sorted_countries, 1):
        country_servers = grouped_servers[country_label]
        max_speed = max([int(s.get("Speed", 0)) for s in country_servers]) / 1000000
        measured = [cached_speed(_measurement_key(s), cache) for s in country_servers]
        real = max(measured, default=0)
        table.add_row(
            str(idx),
            country_label,
            str(len(country_servers)),
            f"{max_speed:.2f} Mbps",
            f"{real:.1f} (cached)" if real > 0 else "not measured",
        )
    console.print(table)
    console.print(
        "[dim]Advertised = VPN Gate's reported field, NOT a measurement on your line. "
        f"A REAL speed test (--bench {bench}) runs right after you pick a country.[/dim]"
    )

    choice = Prompt.ask("\nSelect a country number (or 'q' to quit)", default="q")
    if choice.lower() == "q":
        raise typer.Exit()

    try:
        index = int(choice) - 1
        if 0 <= index < len(sorted_countries):
            selected_country = sorted_countries[index]
            connect_to_country(
                selected_country,
                grouped_servers[selected_country],
                bench=bench,
                min_speed=min_speed,
                test_only=test_only,
            )
    except ValueError:
        console.print("[bold red]Invalid input.[/bold red]")


def config_proto_label(b64_config: str) -> str:
    """Human-readable protocol/port label for tables."""
    try:
        endpoints = profiles.remotes(
            base64.b64decode(b64_config).decode("utf-8", "replace")
        )
        if not endpoints:
            return "?"
        return ", ".join(f"{proto.upper()}/{port}" for _, port, proto in endpoints)
    except (ValueError, TypeError, IndexError):
        return "?"


def _drain_stdout(process):
    """Daemon thread: keep consuming stdout so openvpn never deadlocks on a full pipe."""
    if getattr(process, "_vpn_output_reader", False):
        return

    def _loop():
        try:
            for _ in process.stdout:
                pass
        except (OSError, ValueError):
            pass

    threading.Thread(target=_loop, daemon=True).start()


def _cleanup_session(process, config_path, creds_path):
    try:
        if process is not None and process.poll() is None:
            stopped = False
            control = getattr(process, "_vpn_management_socket", None)
            if control:
                try:
                    with socket.socket(
                        socket.AF_UNIX, socket.SOCK_STREAM
                    ) as connection:
                        connection.settimeout(8)
                        connection.connect(control)
                        # Wait for OpenVPN's greeting and keep the connection
                        # alive until it processes the command. Closing
                        # immediately can discard buffered management input.
                        connection.recv(4096)
                        connection.sendall(b"signal SIGTERM\n")
                        connection.recv(4096)
                    stopped = True
                except OSError as exc:
                    console.print(f"[dim]Management stop unavailable: {exc}[/dim]")
            if not stopped:
                subprocess.run(
                    ["sudo", "kill", "-TERM", "--", str(process.pid)], check=False
                )
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                subprocess.run(
                    ["sudo", "kill", "-KILL", "--", str(process.pid)], check=False
                )
    finally:
        control = getattr(process, "_vpn_management_socket", None) if process else None
        for p in (config_path, creds_path, control):
            if p and os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass


def _openvpn_start(server: dict[str, Any], config_dir: str):
    """Launch openvpn for one server entry. Returns (process, config_path, creds_path) or (None, None, None)."""
    try:
        ovpn_data = base64.b64decode(server["OpenVPN_ConfigData_Base64"])
        profiles.validate(ovpn_data.decode("utf-8", "replace"))
    except (ValueError, KeyError, TypeError) as exc:
        server["_last_result"] = {"status": "PROFILE_REJECTED", "error": str(exc)}
        console.print(f"[red]Profile rejected:[/red] {exc}")
        return None, None, None
    creds_path = os.path.join(config_dir, "vpn_creds.txt")
    os.makedirs(config_dir, mode=0o700, exist_ok=True)
    os.chmod(config_dir, 0o700)
    with open(creds_path, "w") as f:
        f.write("vpn\nvpn\n")
    os.chmod(creds_path, 0o600)
    with tempfile.NamedTemporaryFile(
        mode="wb", dir=config_dir, suffix=".ovpn", delete=False
    ) as tf:
        tf.write(ovpn_data)
        config_path = tf.name
    os.chmod(config_path, 0o600)
    cmd = build_ovpn_cmd(
        config_path,
        creds_path,
        config_is_udp(ovpn_data),
        server.get("_tuning", "balanced"),
    )
    # User-requested UX: ask interactively when needed, before the connection
    # deadline starts; never require a separate manual sudo -v command.
    auth = subprocess.run(["sudo", "-v"], check=False)
    if auth.returncode:
        _cleanup_session(None, config_path, creds_path)
        return None, None, None
    control = config_path + ".sock"
    cmd.extend(
        [
            "--management",
            control,
            "unix",
            "--management-client-user",
            pwd.getpwuid(os.getuid()).pw_name,
        ]
    )
    try:
        process = OpenVPNProcess(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
        process._vpn_management_socket = control
    except OSError as e:
        console.print(f"[bold red]Launch failed:[/bold red] {e}")
        _cleanup_session(None, config_path, creds_path)
        return None, None, None
    return process, config_path, creds_path


def _wait_connected(process, timeout: float = 30, echo: bool = False) -> bool:
    """A reader thread drains buffered stdout; a queue enforces the deadline.

    select() on TextIOWrapper's fd can miss lines already in Python's buffer.
    Never combine it with readline() for readiness/initialization detection.
    """
    lines = queue.Queue(maxsize=256)
    process._vpn_output_reader = True
    process._vpn_recent = []

    def reader():
        try:
            for text in process.stdout:
                process._vpn_recent.append(text.rstrip())
                del process._vpn_recent[:-50]
                if lines.full():
                    try:
                        lines.get_nowait()
                    except queue.Empty:
                        pass
                try:
                    lines.put_nowait(text)
                except queue.Full:
                    pass
        finally:
            try:
                lines.put_nowait(None)
            except queue.Full:
                pass

    threading.Thread(target=reader, daemon=True).start()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            line = lines.get(timeout=max(0.001, deadline - time.monotonic()))
        except queue.Empty:
            return False
        if line is None:
            return False
        if echo:
            console.print(line.strip())
        if "Initialization Sequence Completed" in line:
            return True
    return False


def _bench_one(server: dict[str, Any], config_dir: str, seconds: int = 6) -> float:
    """Connect + measure REAL download speed through the tunnel + disconnect."""
    process, cfg, creds = _openvpn_start(server, config_dir)
    if process is None:
        return 0.0
    try:
        if not _wait_connected(process, timeout=30, echo=False):
            recent = "\n".join(getattr(process, "_vpn_recent", []))
            status = "AUTH_FAILED" if "AUTH_FAILED" in recent else "CONNECT_FAILED"
            server["_last_result"] = {"status": status, "error": recent[-1200:]}
            return 0.0
        result = probes.measure(seconds, server.get("_baseline_ip"))
        server["_last_result"] = asdict(result)
        return result.mbps or 0.0
    finally:
        _cleanup_session(process, cfg, creds)


def _run_session(
    server: dict[str, Any], config_dir: str, country_name: str, min_speed: float
) -> bool:
    """Final connection with optional failover monitor.
    Returns True = session finished cleanly (stop), False = failover to next server."""
    process, cfg, creds = _openvpn_start(server, config_dir)
    if process is None:
        return False
    try:
        if not _wait_connected(process, timeout=30, echo=True):
            console.print(
                "[yellow]Connection initialization failed; trying another relay.[/yellow]"
            )
            return False
        ip = server.get("IP", "Unknown")
        verified = probes.measure(4, server.get("_baseline_ip"))
        if verified.status not in ("VERIFIED", "EGRESS_VERIFIED"):
            console.print(
                f"[yellow]Tunnel initialized but egress is unverified: {verified.status} {verified.error}[/yellow]"
            )
            return False
        speed_note = (
            f"{verified.mbps:.1f} Mbps measured"
            if verified.mbps is not None
            else "speed unmeasured"
        )
        console.print(
            Panel(
                f"[bold green]HTTPS EGRESS VERIFIED[/bold green]\n{country_name} | {ip} | {speed_note}\n"
                f"[dim]Exit {verified.exit_ip} · IPv4 only · no kill switch / no IPv6 protection[/dim]",
                expand=False,
            )
        )
        if min_speed <= 0:
            process.wait()
            return False  # remote death should try another relay, not claim success
        fail_streak = 0
        while process.poll() is None:
            time.sleep(45)
            if process.poll() is not None:
                return False
            measurement = probes.measure(3, server.get("_baseline_ip"))
            if measurement.status == "EGRESS_VERIFIED":
                console.print(
                    "[dim]HTTPS works; benchmark destinations unavailable (no speed decision).[/dim]"
                )
                fail_streak = 0
                continue
            spd = measurement.mbps or 0
            if spd < min_speed:
                fail_streak += 1
                console.print(
                    f"[yellow]monitor: {measurement.status}, below {min_speed} Mbps ({fail_streak}/2)[/yellow]"
                )
                if fail_streak >= 2:
                    return False
            else:
                fail_streak = 0
                console.print(f"[dim]monitor: {spd:.1f} Mbps OK[/dim]")
    except KeyboardInterrupt:
        console.print("\n[dim]Disconnected by user.[/dim]")
        return True
    finally:
        _cleanup_session(process, cfg, creds)
    return False


def _port_and_proto(b64_config: str) -> tuple:
    """Extract (port, 'udp'|'tcp') from an OpenVPN config."""
    try:
        txt = base64.b64decode(b64_config).decode("utf-8", "replace")
    except (ValueError, TypeError):
        return (0, "tcp")
    endpoints = profiles.remotes(txt)
    return (endpoints[0][1], endpoints[0][2]) if endpoints else (0, "tcp")


def _port_allowed(b64_config: str) -> bool:
    """Legacy name: a web-port preference, NOT an allow-list or reachability test.

    Earlier RST/QUIC observations were overgeneralised into a campus-wide policy.
    Live UDP/55688 subsequently worked. Other ports therefore remain candidates.
    """
    try:
        txt = base64.b64decode(b64_config).decode("utf-8", "replace")
    except (ValueError, TypeError):
        return False
    return any(port in {443, 8443} for _, port, _ in profiles.remotes(txt))


def connect_to_country(
    country_name: str,
    servers: list[dict[str, Any]],
    bench: int = 10,
    min_speed: float = 3.0,
    test_only: bool = False,
):
    with config.session_directory() as directory:
        return _connect_to_country(
            country_name, servers, bench, min_speed, test_only, directory
        )


def _connect_to_country(
    country_name: str,
    servers: list[dict[str, Any]],
    bench: int,
    min_speed: float,
    test_only: bool,
    config_dir: str,
):
    """Rank servers, REAL-benchmark the top candidates, connect to the best
    measured one, and fail over automatically if it degrades."""
    # Prefer web-port profiles first; no static list can prove reachability.
    allowed = [
        s for s in servers if _port_allowed(s.get("OpenVPN_ConfigData_Base64", ""))
    ]
    if allowed and len(allowed) < len(servers):
        console.print(
            f"[dim]Transport preference: {len(allowed)}/{len(servers)} profiles advertise "
            "443/8443. Other ports remain candidates; only live tests decide.[/dim]"
        )
    # Port 443 is a preference, NOT proof of reachability and NOT a reason to
    # discard every other relay. UDP/Web policies vary with the actual network.
    pool = allowed + [s for s in servers if s not in allowed]
    # Sort by protocol priority (UDP 443 first) then advertised speed
    ranked_servers = sorted(
        pool,
        key=lambda s: (
            not _port_allowed(s.get("OpenVPN_ConfigData_Base64", "")),
            s.get("priority", 10),
            -int(s.get("Speed", 0)),
        ),
    )
    os.makedirs(config_dir, exist_ok=True)
    try:
        baseline_ip = probes.public_ip()
    except ConnectionError:
        baseline_ip = None
    for server in ranked_servers:
        server["_baseline_ip"] = baseline_ip

    candidates = ranked_servers
    if bench > 0 and ranked_servers:
        candidates = ranked_servers[:bench]
        console.print(
            Panel(
                f"[bold cyan]REAL SPEED BENCH[/bold cyan] — {len(candidates)} candidates · "
                "measured on YOUR line (eduroam), not the CSV figure",
                border_style="cyan",
            )
        )
        cache = load_bench_cache()
        results = []
        with Progress(
            SpinnerColumn(), TextColumn("{task.description}"), transient=False
        ) as progress:
            task = progress.add_task(
                f"[green]Benchmarking {country_name}...[/green]", total=len(candidates)
            )
            for srv in candidates:
                ip = srv.get("IP", "?")
                # Selection/benchmark always uses fresh observations; cache
                # only annotates the country menu, never decides a live winner.
                try:
                    speed = _bench_one(srv, config_dir)
                except AuthenticationRequired as exc:
                    console.print(f"[red]{exc}[/red]")
                    raise typer.Exit(2) from exc
                note = srv.get("_last_result", {}).get("status", "UNMEASURED")
                if speed > 0:
                    cache[_measurement_key(srv)] = {
                        "speed": speed,
                        "ts": time.time(),
                        "ip": ip,
                        "result": srv.get("_last_result"),
                    }
                    save_bench_cache(cache)
                results.append((speed, srv, note))
                progress.advance(task)

        ordered = sorted(results, key=lambda x: -x[0])
        t = Table(
            title=f"REAL speed test — {country_name} (through the tunnel, your line)",
            header_style="bold magenta",
        )
        t.add_column("#", style="dim", justify="right")
        t.add_column("Server IP")
        t.add_column("Proto", justify="center")
        t.add_column("Advertised", justify="right", style="dim")
        t.add_column("REAL Mbps", justify="right", style="bold green")
        t.add_column("Note", style="dim")
        for i, (speed, srv, note) in enumerate(ordered, 1):
            adv = int(srv.get("Speed", 0)) / 1000000
            t.add_row(
                str(i),
                srv.get("IP", "?"),
                config_proto_label(srv.get("OpenVPN_ConfigData_Base64", "")),
                f"{adv:.0f}",
                f"{speed:.1f}" if speed > 0 else "unmeasured",
                note,
            )
        console.print(t)
        console.print(
            "[dim]Advertised = provider-reported field, not verified client throughput · "
            "REAL = measured through YOUR connection just now[/dim]"
        )
        alive = [
            srv
            for sp, srv, _note in ordered
            if srv.get("_last_result", {}).get("status")
            in ("VERIFIED", "EGRESS_VERIFIED")
        ]
        if test_only:
            console.print(
                "[dim]Benchmark finished; all test tunnels have been closed.[/dim]"
            )
            if not alive:
                raise typer.Exit(1)
            return
        if alive:
            candidates = alive
        else:
            console.print(
                "[yellow]No verified data path among tested relays. No unverified connection will be advertised as working.[/yellow]"
            )
            raise typer.Exit(1)

    # Connect chain: try up to 5 (best measured first), failover on failure/degradation
    n_try = min(5, len(candidates))
    for i, best_server in enumerate(candidates[:n_try], 1):
        ip = best_server.get("IP", "Unknown")
        adv = int(best_server.get("Speed", 0)) / 1000000
        console.print(
            f"\n[bold yellow][{i}/{n_try}][/bold yellow] Attempting connection to "
            f"[cyan]{ip}[/cyan] (advertised {adv:.0f} Mbps)..."
        )
        try:
            if _run_session(best_server, config_dir, country_name, min_speed):
                return
        except AuthenticationRequired as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(2) from exc
    console.print("[bold red]All server candidates failed.[/bold red]")


if __name__ == "__main__":
    app()
