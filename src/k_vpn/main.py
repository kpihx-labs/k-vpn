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

app = typer.Typer(
    help="k-vpn: Automated VPN Gate Connector", invoke_without_command=True
)
console = Console()


class OpenVPNProcess(subprocess.Popen[str]):
    """Owned subprocess with a UID-restricted local shutdown channel."""

    _vpn_management_socket: str | None = None


class AuthenticationRequired(RuntimeError):
    """Local sudo permission expired; never a relay/network failure."""


VPN_GATE_DIRECT_IPS = [
    "http://130.158.6.82/api/iphone/",
    "http://130.158.6.101/api/iphone/",
]

VPN_GATE_URLS = VPN_GATE_DIRECT_IPS + [
    "http://78.142.193.125/api/iphone/",
    "http://p6e430ddc.chibnt01.ap.so-net.ne.jp:18708/api/iphone/",
    "http://www.vpngate.net/api/iphone/",
    "https://www.vpngate.net/api/iphone/",
    "https://130.158.6.82/api/iphone/",
]

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
    # Restore the working VPN Gate authentication from f6093d8. An omitted
    # auth-user-pass directive does not establish that a relay rejects or does
    # not require VPN Gate's public vpn/vpn credentials.
    with open(config_path) as profile:
        directives = [line.split("#", 1)[0].strip().split() for line in profile]
    common = [
        "--config",
        config_path,
        "--auth-user-pass",
        creds_path,
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
    if any(parts == ["cipher", "AES-128-CBC"] for parts in directives):
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
    source_url = ""
    errors = []
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
                    source_url = url
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
                        source_url = location
                        break
                errors.append(
                    f"{url}: HTTP {response.status_code}, no usable relay list"
                )
        except requests.RequestException as exc:
            errors.append(f"{url}: {type(exc).__name__}")

    if not csv_content:
        for error in errors:
            console.print(f"[dim]Mirror unavailable: {error}[/dim]")
        console.print(
            "[bold red]Discovery failed:[/bold red] No usable relay list. VPN reachability has not been tested."
        )
        sys.exit(1)

    if source_url.startswith("http://"):
        console.print("[dim]Relay list loaded via HTTP (not authenticated).[/dim]")

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


@app.callback()
def main(
    ctx: typer.Context,
    insecure: bool = typer.Option(
        False,
        "--insecure",
        "-k",
        help="Disable API TLS verification (unsafe; does not disable DNS)",
    ),
    bench: int = typer.Option(
        0,
        "--bench",
        "-b",
        min=0,
        help="Explicitly benchmark N candidates (default: off)",
    ),
    min_speed: float = typer.Option(
        0.0,
        "--min-speed",
        "-m",
        min=0,
        help="Explicit speed monitoring threshold in Mbps (default: off)",
    ),
    country: str = typer.Option(
        "", "--country", "-c", help="Country name or ISO code, no changing menu numbers"
    ),
    test_only: bool = typer.Option(
        False,
        "--test-only",
        "-t",
        help="Benchmark then disconnect; never leave a VPN running",
    ),
    tuning: str | None = typer.Option(
        None,
        "--tuning",
        "-T",
        help="native (preserve profile) or balanced (experimental UDP tuning)",
    ),
    server_ip: str = typer.Option(
        "", "--server", "-s", help="Pin a currently listed relay IP"
    ),
    strict_discovery: bool | None = typer.Option(
        None,
        "--strict-discovery/--no-strict-discovery",
        "-d/-D",
        help="Forbid unauthenticated HTTP relay-list mirrors",
    ),
    attempts: int | None = typer.Option(
        None,
        "--attempts",
        "-a",
        min=1,
        help="Maximum relay connection attempts (config default: 5)",
    ),
):
    if ctx.invoked_subcommand is not None:
        return
    try:
        settings = config.load()
    except (OSError, ValueError, TypeError) as exc:
        raise typer.BadParameter(f"Invalid configuration: {exc}") from exc
    tuning = settings.tuning if tuning is None else tuning
    attempts = settings.attempts if attempts is None else attempts
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
            matched[0]["CountryLong"],
            matched,
            bench,
            min_speed,
            test_only,
            attempts=attempts,
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
        measured = (
            [cached_speed(_measurement_key(s), cache) for s in country_servers]
            if cache
            else []
        )
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
        "[dim]Advertised = provider-reported speed, not a measurement on your line. "
        + (
            f"Explicit benchmark: {bench} candidates after country choice.[/dim]"
            if bench
            else "Choose a country to connect directly; no benchmark.[/dim]"
        )
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
                attempts=attempts,
            )
    except ValueError:
        console.print("[bold red]Invalid input.[/bold red]")


@app.command()
def status(
    speed: bool = typer.Option(
        False,
        "--speed",
        "-s",
        help="Explicitly run short download and upload measurements on the active route",
    ),
    seconds: int = typer.Option(
        6,
        "--seconds",
        "-n",
        min=1,
        max=60,
        help="Maximum seconds for each optional transfer measurement",
    ),
):
    """Show current network path, public IP and best-effort location."""
    try:
        route = probes.active_route()
        exit_ip = probes.public_ip(route.device)
        try:
            location = probes.geolocate(exit_ip, route.device)
        except ConnectionError as exc:
            location = {
                "country": "unavailable",
                "country_code": "",
                "city": "",
                "isp": str(exc),
            }
    except (ConnectionError, OSError, ValueError, subprocess.SubprocessError) as exc:
        console.print(
            f"[bold red]Unable to inspect the active IPv4 route:[/bold red] {exc}"
        )
        raise typer.Exit(1) from exc

    table = Table(title="Current IPv4 Network Status", show_header=False)
    table.add_column("Property", style="cyan")
    table.add_column("Value")
    table.add_row("Active interface", route.device)
    table.add_row("Local IPv4", route.source_ip or "not reported")
    table.add_row("Gateway", route.gateway or "point-to-point or not reported")
    table.add_row("Public IPv4", exit_ip)
    country = " ".join(
        value
        for value in (location.get("country", ""), location.get("country_code", ""))
        if value
    )
    table.add_row(
        "Location (indicative)",
        ", ".join(value for value in (country, location.get("city", "")) if value)
        or "unavailable",
    )
    table.add_row("Network", location.get("isp", "") or "unavailable")
    console.print(table)

    if not speed:
        console.print(
            "[dim]No transfer measurement. Add --speed to measure download and upload.[/dim]"
        )
        return

    measurement = probes.measure_active_route(seconds)
    upload = probes.measure_upload_active_route(seconds)
    if measurement.status == "VERIFIED":
        console.print(
            Panel.fit(
                f"[bold green]{measurement.mbps:.2f} Mbps[/bold green] download\n"
                f"{measurement.bytes_received / 1_000_000:.1f} MB in {measurement.elapsed_s:.1f}s\n"
                f"{measurement.endpoint}",
                title="Active-route HTTP measurement",
                border_style="green",
            )
        )
    else:
        console.print(
            f"[yellow]Download unmeasured:[/yellow] {measurement.status} {measurement.error}"
        )
    if upload.status == "VERIFIED":
        console.print(
            Panel.fit(
                f"[bold green]{upload.mbps:.2f} Mbps[/bold green] upload\n"
                f"{upload.bytes_received / 1_000_000:.1f} MB in {upload.elapsed_s:.1f}s\n"
                f"{upload.endpoint}",
                title="Active-route HTTPS measurement",
                border_style="green",
            )
        )
    else:
        console.print(
            f"[yellow]Upload unmeasured:[/yellow] {upload.status} {upload.error}"
        )


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
        console.print(
            Panel(
                f"[bold green]OPENVPN TUNNEL ESTABLISHED[/bold green]\n{country_name} | {ip}\n"
                "[dim]No egress/speed test performed for this connection. Ctrl-C to disconnect.[/dim]",
                expand=False,
            )
        )
        if min_speed <= 0:
            process.wait()
            return False  # remote death should try another relay, not claim success
        console.print(
            f"[dim]Explicit speed monitoring enabled: threshold {min_speed} Mbps, interval 45 s.[/dim]"
        )
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
    bench: int = 0,
    min_speed: float = 0.0,
    test_only: bool = False,
    attempts: int = 5,
):
    with config.session_directory() as directory:
        return _connect_to_country(
            country_name,
            servers,
            bench,
            min_speed,
            test_only,
            directory,
            attempts=attempts,
        )


def _connect_to_country(
    country_name: str,
    servers: list[dict[str, Any]],
    bench: int,
    min_speed: float,
    test_only: bool,
    config_dir: str,
    attempts: int = 5,
):
    """Rank servers, REAL-benchmark the top candidates, connect to the best
    measured one, and fail over automatically if it degrades."""
    # Restore f6093d8 selection: provider Score, not transport or advertised
    # speed. Port reachability cannot be inferred from a fixed web-port list.
    ranked_servers = sorted(servers, key=lambda s: -int(s.get("Score", 0)))
    os.makedirs(config_dir, exist_ok=True)
    baseline_ip = None
    if bench > 0 or min_speed > 0:
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
                "measured on your current connection, not the provider figure",
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

    # The budget counts relay attempts, not speed tests or every listed relay.
    n_try = min(attempts, len(candidates))
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
    console.print(
        f"[bold red]All {n_try} connection attempts failed; {len(ranked_servers)} relays were listed for {country_name}.[/bold red]"
    )


if __name__ == "__main__":
    app()
