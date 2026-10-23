"""Constrain public relay profiles before passing them to a privileged process."""

import shlex

ALLOWED = frozenset(
    {
        "client",
        "dev",
        "dev-type",
        "proto",
        "remote",
        "remote-random",
        "resolv-retry",
        "nobind",
        "persist-key",
        "persist-tun",
        "cipher",
        "data-ciphers",
        "data-ciphers-fallback",
        "auth",
        "comp-lzo",
        "compress",
        "allow-compression",
        "verb",
        "mute",
        "mute-replay-warnings",
        "remote-cert-tls",
        "verify-x509-name",
        "tls-version-min",
        "tls-cipher",
        "tls-ciphersuites",
        "key-direction",
        "tun-mtu",
        "mssfix",
        "fragment",
        "sndbuf",
        "rcvbuf",
        "tcp-nodelay",
        "redirect-gateway",
        "dhcp-option",
        "route",
        "route-delay",
        "route-method",
        "route-nopull",
        "pull",
        "pull-filter",
        "auth-nocache",
        "auth-retry",
        "auth-user-pass",
        "connect-timeout",
        "connect-retry",
        "connect-retry-max",
        "ping",
        "ping-restart",
        "ping-timer-rem",
        "explicit-exit-notify",
        "reneg-sec",
        "hand-window",
        "tls-timeout",
        "tls-client",
    }
)
INLINE = frozenset({"ca", "cert", "key", "tls-auth", "tls-crypt"})


def validate(text: str) -> None:
    """Reject hooks, plugins, external files and unsupported options; never strip silently."""
    block = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if block:
            if line == f"</{block}>":
                block = None
            continue
        if line.startswith("<") and line.endswith(">"):
            block = line[1:-1]
            if block not in INLINE:
                raise ValueError(f"Unsupported inline profile block: {block}")
            continue
        parts = shlex.split(line, comments=True)
        if not parts:
            continue
        directive = parts[0]
        if directive in INLINE and parts[1:] == ["[inline]"]:
            continue
        if directive not in ALLOWED:
            raise ValueError(
                f"Unsafe or unsupported public profile option: {directive}"
            )
        if directive == "auth-user-pass" and len(parts) > 1:
            raise ValueError(
                "Public relay profile cannot reference an external credential file"
            )
        if directive == "dev" and parts[1:] not in (["tun"], ["tun0"]):
            raise ValueError("Only TUN profiles are supported")
    if block:
        raise ValueError(f"Unclosed inline profile block: {block}")


def remotes(text: str) -> list[tuple[str, int, str]]:
    """Parse protocol/port without substring matches or assuming port 443 is open."""
    protocol = "udp"
    lines = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith(("#", ";")):
            continue
        parts = shlex.split(raw, comments=True)
        if parts and parts[0] == "proto":
            protocol = "udp" if parts[1].startswith("udp") else "tcp"
        if parts and parts[0] == "remote":
            lines.append(parts)
    result = []
    for parts in lines:
        port = int(parts[2]) if len(parts) > 2 else 1194
        proto = (
            ("udp" if parts[3].startswith("udp") else "tcp")
            if len(parts) > 3
            else protocol
        )
        result.append((parts[1], port, proto))
    return result
