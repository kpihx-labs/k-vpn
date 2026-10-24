# k-vpn

Linux CLI for connecting to public VPN Gate relays with OpenVPN. Benchmarking
and speed monitoring are optional and require explicit command-line options.

The client is locally controlled; the exit fleet is not self-hosted. Country
availability and bandwidth change with volunteer relays. No anonymity, universal
network bypass or throughput guarantee is implied.

## Install

Requirements: Linux, Python 3.12+, uv, OpenVPN, curl, iproute2 and sudo.

```bash
uv tool install k-vpn

# Development checkout, the installation used on this workstation:
git clone git@github.com:kpihx-labs/k-vpn.git
cd k-vpn
make uv-link
```

The workstation checkout is `$HOME/Labs/KpihX-Labs/VPNs/k-vpn`. The command is
exposed through uv's normal user tool directory, usually `$HOME/.local/bin`.
Editable installation uses this checkout directly; moving it requires relinking.

## Use

```bash
k-vpn                                      # choose a country and connect directly
k-vpn status                               # current route, public IP and indicative location
k-vpn status --speed                       # explicit short download and upload measurement
k-vpn --country JP                         # direct connection; no speed/IP probes
k-vpn -c JP -a 15                           # try up to 15 relays, stopping on success
k-vpn -c JP -b 6 -t                         # benchmark, then close all test tunnels
k-vpn -c Japan -b 6 -m 0.5
k-vpn -c JP -s 122.133.152.245 -b 1 -t
k-vpn -c JP -b 4 -t -T balanced
```

Sudo asks for a password automatically when needed. A separate manual
authentication command is not required. Ctrl-C closes the owned session.

| Option | Behavior |
|---|---|
| `--country`, `-c` | Match a country name or ISO code, not a changing menu index |
| `--attempts N`, `-a N` | Maximum relay connection attempts, clipped to those listed; config default 5 |
| `--bench N`, `-b N` | Explicitly test up to N candidate profiles; default zero/off |
| `--test-only`, `-t` | Benchmark without retaining a connection; requires N greater than zero |
| `--server IP`, `-s IP` | Pin a relay only if it is still present in the current listing |
| `--tuning MODE`, `-T MODE` | `native` preserves profile MTU/buffers; `balanced` is experimental UDP tuning |
| `--min-speed X`, `-m X` | Explicitly enable repeated speed probes/failover; default zero/off |
| `--strict-discovery`, `-d` | Forbid unauthenticated HTTP relay-list fallback |
| `--no-strict-discovery`, `-D` | Explicitly allow the warned legacy HTTP fallback |
| `--insecure`, `-k` | Disable API TLS verification only; unsafe, does not disable DNS |

`k-vpn status` is independent of VPN Gate and OpenVPN: it observes the active
IPv4 route of the system. It therefore works with direct Wi-Fi, Tailscale,
OpenVPN, or another VPN implementation. `--speed` is explicit: it downloads from
Cloudflare/OVH and uploads a bounded 1 MB in-memory HTTPS payload to Cloudflare.
No test file is created. Use the installed `speedtest` CLI when you want a longer
third-party download/upload benchmark with its selected server.

For `status`, use `--speed` / `-s` and `--seconds N` / `-n N`.

Discovery uses the historical working mirror order rather than forcing an HTTPS
probe first. A successful HTTP retrieval produces one concise unauthenticated-list
notice; failed attempts are detailed only when no mirror works. Strict discovery
still permits HTTPS only and never disables certificate verification automatically.
Root profile validation does not authenticate a relay list's origin.

## Configuration and files

There is no legacy home-root directory, migration, snapshot recovery or automatic
benchmark report generation. Imports and `--help` create no application files.

| Purpose | Default path | Lifetime |
|---|---|---|
| Preferences | `$HOME/.config/k-vpn/config.json` | Created once on a real CLI invocation; never overwritten automatically |
| Derived measurement cache | `$HOME/.cache/k-vpn/measurements.json` | Persistent, labelled observations; ten-minute display validity |
| OpenVPN profiles, public VPN Gate credentials, control socket | `$XDG_RUNTIME_DIR/k-vpn-<random>/`, otherwise `/tmp/k-vpn-<random>/` | Private temporary directory, removed at session end |

`XDG_CONFIG_HOME` and `XDG_CACHE_HOME` override the standard bases when absolute.
`XDG_RUNTIME_DIR` is used only when it is a usable absolute directory; otherwise
Linux `/tmp` is used. No sudo password is stored. Configuration and temporary
credential files are private; the cache is derived data, not browsing history.

The initial configuration is:

```json
{
  "attempts": 5,
  "tuning": "native",
  "strict_discovery": false
}
```

Explicit attempts/tuning/strict-discovery flags override these preferences. Old `bench`
and `min_speed` keys are accepted but ignored: a previously generated config cannot
silently enable downloads. Supply `--bench N` or `--min-speed X` on the invocation
that should measure traffic. Plain connection makes no IP-service or speed-test
request and reports only that OpenVPN initialized, not verified Internet egress.

## How selection works

1. Fetch the current VPN Gate CSV; countries, relay IPs, reported speed and public
   OpenVPN profiles are live data, not a hardcoded country/server catalogue.
2. Parse active profile directives, ignoring comments. Restore historical provider
   Score order; advertised speed and transport preferences do not override it.
3. Reject hooks, plugins, external key files and unsupported profile directives
   before privileged execution. Restore the historical VPN Gate public vpn/vpn
   authentication even if the supplied profile omits auth-user-pass. These are
   relay credentials, not the user's sudo password.
4. When benchmarking is explicitly requested, require a TUN route, interface-bound HTTPS, a valid public exit and received
   payload before reporting a speed. Distinguish authentication, connection,
   egress verification and download-host refusals. Try OVH after a failed
   Cloudflare measurement. Failures remain unmeasured, not zero Mbps.
5. Without benchmarking, try candidates using profile/provider ranking and retain
   the initialized connection; no transfer is required to accept it. With an
   explicit benchmark, use the freshly measured candidates. Keep failover within
   the chosen country. Use the private UID-restricted control socket for shutdown.

`Advertised` is the provider's field, not a measurement from your device. Recent
cached observations are scoped to uplink/profile/tuning and labelled; they do not
trigger fresh measurements. There is no guaranteed advertised-to-real ratio.

## Evidence and limitations

[`BENCHMARKS.md`](https://github.com/kpihx-labs/k-vpn/blob/master/BENCHMARKS.md) is the single benchmark record: controlled runs,
the complete 95-profile survey, rechecks, failures and limitations. It establishes
no universal tuning multiplier or sustained speed guarantee.

This client handles IPv4. It has no kill switch or verified IPv6 protection.
HTTPS content stays encrypted to the destination; plain HTTP and traffic metadata
can be visible at the exit. A QUIC handshake or one open port does not prove every
VPN protocol will cross every restrictive network.

## License transition (2.0.0)

Starting with 2.0.0, this distribution is licensed under GNU AGPL version 3 only
(`AGPL-3.0-only`); see `LICENSE` for the complete text. The previously published
1.2.0 and earlier MIT releases retain their MIT permissions. This transition
does not revoke those grants or change third-party dependency licenses.

AGPL permits commercial use when its obligations are met. It does not require
every commercial user to negotiate a paid license. Its network-source provision
is mainly relevant when a modified covered application is offered over a network;
it does not automatically relicense a separate OpenVPN server or other programs.
Each distribution includes the complete applicable license text.

## Development commands

```bash
make check       # global ruff/pyright, compilation and offline regressions
make build       # validate; build sdist and wheel in dist/
make uv-link     # refresh the editable installation
make push        # xargs pushes the current branch to all remotes in parallel
make publish     # PyPI; run with-env make publish in the authenticated ops pane
```

Tests use isolated temporary directories, never live tunnels or sudo. `make push`
fails on detached HEAD, missing remotes or a failed remote push. No secrets belong
in the repository. Current license: `AGPL-3.0-only`; see `LICENSE`.
