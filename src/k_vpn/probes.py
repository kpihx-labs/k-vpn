"""Bounded IPv4 egress verification and transfer measurements, never guessed speeds."""

import ipaddress
import json
import os
import subprocess
import time
from dataclasses import dataclass

IP_ENDPOINTS = ("https://api.ipify.org", "https://ifconfig.me/ip")
SPEED_ENDPOINT = "https://speed.cloudflare.com/__down?bytes=100000000"
SPEED_ENDPOINTS = (
    SPEED_ENDPOINT,
    "https://lil1-rbx.speedtest.network.ovh.net/files/100Mb.dat",
)
UPLOAD_ENDPOINT = "https://speed.cloudflare.com/__up"
UPLOAD_BYTES = 1_000_000


@dataclass(frozen=True)
class Measurement:
    status: str
    mbps: float | None = None
    bytes_received: int = 0
    elapsed_s: float = 0.0
    exit_ip: str | None = None
    error: str = ""
    endpoint: str = ""


@dataclass(frozen=True)
class Route:
    device: str
    source_ip: str = ""
    gateway: str = ""


def _curl(
    arguments: list[str], seconds: int, input_text: str | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "curl",
            "-q",
            "--noproxy",
            "*",
            "-4",
            "-sS",
            "--connect-timeout",
            "4",
            "--max-time",
            str(seconds),
            *arguments,
        ],
        capture_output=True,
        text=True,
        input=input_text,
        timeout=seconds + 3,
        check=False,
    )


def public_ip(interface: str | None = None) -> str:
    extra = ["--interface", interface] if interface else []
    errors = []
    for endpoint in IP_ENDPOINTS:
        result = _curl([*extra, "--fail", endpoint], 6)
        if result.returncode == 0:
            try:
                return str(ipaddress.IPv4Address(result.stdout.strip()))
            except ipaddress.AddressValueError:
                errors.append("IP endpoint returned a non-IP response")
        else:
            errors.append(result.stderr.strip())
    raise ConnectionError("; ".join(errors))


def active_route() -> Route:
    """Return the IPv4 route currently used for public Internet traffic."""
    result = subprocess.run(
        ["ip", "-j", "-4", "route", "get", "1.1.1.1"],
        capture_output=True,
        text=True,
        timeout=3,
        check=True,
    )
    route = json.loads(result.stdout)[0]
    device = str(route.get("dev", ""))
    if not device:
        raise ConnectionError("No active IPv4 route device")
    return Route(
        device=device,
        source_ip=str(route.get("prefsrc", route.get("src", ""))),
        gateway=str(route.get("gateway", "")),
    )


def geolocate(ip: str, interface: str | None = None) -> dict[str, str]:
    """Return best-effort public geolocation without influencing routing."""
    extra = ["--interface", interface] if interface else []
    result = _curl([*extra, "--fail", f"https://ipwho.is/{ip}"], 6)
    if result.returncode:
        raise ConnectionError(result.stderr.strip())
    data = json.loads(result.stdout)
    if not data.get("success"):
        raise ConnectionError("Geolocation service rejected the public IP")
    return {
        "country": str(data.get("country", "")),
        "country_code": str(data.get("country_code", "")),
        "city": str(data.get("city", "")),
        "isp": str(data.get("connection", {}).get("isp", "")),
    }


def tunnel_interface() -> str:
    device = active_route().device
    if not device.startswith("tun"):
        raise ConnectionError(
            f"Default IPv4 test route is not a TUN interface: {device}"
        )
    return device


def measure(seconds: int = 6, baseline_ip: str | None = None) -> Measurement:
    started = time.monotonic()
    try:
        interface = tunnel_interface()
        exit_ip = public_ip(interface)
        if baseline_ip and exit_ip == baseline_ip:
            return Measurement("EGRESS_UNCHANGED", exit_ip=exit_ip)
        errors = []
        for endpoint in SPEED_ENDPOINTS:
            result = _curl(
                [
                    "--interface",
                    interface,
                    "--location",
                    "--header",
                    "Accept-Encoding: identity",
                    "--header",
                    "Cache-Control: no-cache",
                    "--output",
                    os.devnull,
                    "--write-out",
                    "%{json}",
                    endpoint,
                ],
                seconds,
            )
            data = json.loads(result.stdout)
            received = int(data.get("size_download", 0))
            elapsed = float(data.get("time_total", 0))
            if (
                result.returncode in (0, 28)
                and 200 <= int(data.get("http_code", 0)) < 300
                and received > 0
            ):
                return Measurement(
                    "VERIFIED",
                    received * 8 / max(elapsed, 0.001) / 1_000_000,
                    received,
                    elapsed,
                    exit_ip,
                    endpoint=endpoint,
                )
            errors.append(
                f"{endpoint}: HTTP {data.get('http_code')} {result.stderr.strip()}"
            )
        return Measurement("EGRESS_VERIFIED", exit_ip=exit_ip, error="; ".join(errors))
    except (ConnectionError, OSError, ValueError, subprocess.SubprocessError) as exc:
        return Measurement(
            "EGRESS_UNVERIFIED", elapsed_s=time.monotonic() - started, error=str(exc)
        )


def measure_active_route(seconds: int = 6) -> Measurement:
    """Measure the system's current IPv4 path, regardless of VPN implementation."""
    started = time.monotonic()
    try:
        route = active_route()
        exit_ip = public_ip(route.device)
        errors = []
        for endpoint in SPEED_ENDPOINTS:
            result = _curl(
                [
                    "--interface",
                    route.device,
                    "--location",
                    "--header",
                    "Accept-Encoding: identity",
                    "--header",
                    "Cache-Control: no-cache",
                    "--output",
                    os.devnull,
                    "--write-out",
                    "%{json}",
                    endpoint,
                ],
                seconds,
            )
            data = json.loads(result.stdout)
            received = int(data.get("size_download", 0))
            elapsed = float(data.get("time_total", 0))
            if (
                result.returncode in (0, 28)
                and 200 <= int(data.get("http_code", 0)) < 300
                and received > 0
            ):
                return Measurement(
                    "VERIFIED",
                    received * 8 / max(elapsed, 0.001) / 1_000_000,
                    received,
                    elapsed,
                    exit_ip,
                    endpoint=endpoint,
                )
            errors.append(
                f"{endpoint}: HTTP {data.get('http_code')} {result.stderr.strip()}"
            )
        return Measurement("EGRESS_VERIFIED", exit_ip=exit_ip, error="; ".join(errors))
    except (ConnectionError, OSError, ValueError, subprocess.SubprocessError) as exc:
        return Measurement(
            "EGRESS_UNVERIFIED", elapsed_s=time.monotonic() - started, error=str(exc)
        )


def measure_upload_active_route(seconds: int = 6) -> Measurement:
    """Measure upload through the current IPv4 route with a bounded in-memory POST."""
    started = time.monotonic()
    try:
        route = active_route()
        result = _curl(
            [
                "--interface",
                route.device,
                "--request",
                "POST",
                "--header",
                "Content-Type: application/octet-stream",
                "--data-binary",
                "@-",
                "--output",
                os.devnull,
                "--write-out",
                "%{json}",
                UPLOAD_ENDPOINT,
            ],
            seconds,
            "x" * UPLOAD_BYTES,
        )
        data = json.loads(result.stdout)
        sent = int(data.get("size_upload", 0))
        elapsed = float(data.get("time_total", 0))
        if (
            result.returncode in (0, 28)
            and 200 <= int(data.get("http_code", 0)) < 300
            and sent > 0
        ):
            return Measurement(
                "VERIFIED",
                sent * 8 / max(elapsed, 0.001) / 1_000_000,
                sent,
                elapsed,
                endpoint=UPLOAD_ENDPOINT,
            )
        return Measurement(
            "UNMEASURED",
            elapsed_s=elapsed,
            error=f"HTTP {data.get('http_code')} {result.stderr.strip()}",
            endpoint=UPLOAD_ENDPOINT,
        )
    except (ConnectionError, OSError, ValueError, subprocess.SubprocessError) as exc:
        return Measurement(
            "UNMEASURED", elapsed_s=time.monotonic() - started, error=str(exc)
        )
