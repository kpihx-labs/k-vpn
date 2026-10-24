# k-vpn

Linux CLI for selecting public VPN Gate relays, verifying the HTTPS exit and
measuring real download throughput before connecting with OpenVPN.

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
k-vpn                                      # interactive country table
k-vpn --country JP --bench 6 --test-only    # benchmark, then close all test tunnels
k-vpn --country Japan --bench 6 --min-speed 0.5
k-vpn --country JP --server 122.133.152.245 --bench 1 --test-only
k-vpn --country JP --bench 4 --test-only --tuning balanced
```

Sudo asks for a password automatically when needed. A separate manual
authentication command is not required. Ctrl-C closes the owned session.

| Option | Behavior |
|---|---|
| `--country`, `-c` | Match a country name or ISO code, not a changing menu index |
| `--bench N` | Test up to N candidate profiles; zero skips benchmarking |
| `--test-only` | Benchmark without retaining a connection; requires N greater than zero |
| `--server IP` | Pin a relay only if it is still present in the current listing |
| `--tuning native` | Preserve profile MTU/buffers; default, with authentication/cipher fixes |
| `--tuning balanced` | Experimental UDP MTU/buffer tuning; no proven universal gain |
| `--min-speed X` | Fail over after repeated unusable/slow probes; zero disables monitoring |
| `--strict-discovery` | Forbid unauthenticated HTTP discovery fallback |
| `--no-strict-discovery` | Explicitly allow the warned legacy HTTP fallback |
| `--insecure`, `-k` | Disable API TLS verification only; unsafe, does not disable DNS |

Discovery first tries HTTPS. When a legacy HTTP mirror is used, the CLI warns
that the relay list is unauthenticated. Root profile validation does not establish
the list's origin. HTTPS destinations are verified independently.

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
  "bench": 10,
  "min_speed": 3.0,
  "tuning": "native",
  "strict_discovery": false
}
```

Explicit CLI flags override these preferences, including zero and false.
For low-bandwidth relays, choose an appropriate monitoring threshold rather than
assuming the default 3 Mbps is attainable.

## How selection works

1. Fetch the current VPN Gate CSV; countries, relay IPs, reported speed and public
   OpenVPN profiles are live data, not a hardcoded country/server catalogue.
2. Parse active profile directives, ignoring comments. Prefer useful transports
   without discarding every non-web port; policy varies with the actual network.
3. Reject hooks, plugins, external key files and unsupported profile directives
   before privileged execution. Keep native certificate authentication; do not
   inject vpn/vpn into a profile that does not request password authentication.
4. Require a TUN route, interface-bound HTTPS, a valid public exit and received
   payload before reporting a speed. Distinguish authentication, connection,
   egress verification and download-host refusals. Try OVH after a failed
   Cloudflare measurement. Failures remain unmeasured, not zero Mbps.
5. Keep the best freshly verified candidate in the selected country. Use a
   private UID-restricted Unix control socket for shutdown, never killall.

`Advertised` is the provider's field, not a measurement from your device. Recent
cached observations are scoped to uplink/profile/tuning and labelled; live
selection always remeasures. There is no guaranteed advertised-to-real ratio.

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
