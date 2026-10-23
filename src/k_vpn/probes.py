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


@dataclass(frozen=True)
class Measurement:
    status: str
    mbps: float | None = None
    bytes_received: int = 0
    elapsed_s: float = 0.0
    exit_ip: str | None = None
    error: str = ""
    endpoint: str = ""


def _curl(arguments: list[str], seconds: int) -> subprocess.CompletedProcess[str]:
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


def tunnel_interface() -> str:
    routes = subprocess.run(
        ["ip", "-j", "-4", "route", "get", "1.1.1.1"],
        capture_output=True,
        text=True,
        timeout=3,
        check=True,
    )
    device = json.loads(routes.stdout)[0].get("dev", "")
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
