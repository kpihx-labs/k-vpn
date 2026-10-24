# Changelog

## 3.0.1 - 2026-10-24

- Add `make purge` for the installed uv tool and k-vpn live XDG state while retaining the source checkout.

## 3.0.0 - 2026-10-24

- Require the explicit `connect` subcommand; bare invocation displays help.
- Add read-only `doctor` and actionable missing-dependency errors before relay discovery.
- Document system-package installation. Preserve historical Score selection and vpn/vpn authentication.

## 2.0.2 - Unreleased

- Add `k-vpn status`, an active-route observer independent of VPN Gate and
  OpenVPN. It reports the active IPv4 interface, local route, public IP and
  best-effort public location.
- Add explicit `k-vpn status --speed [--seconds N]` for a bounded HTTP download
  and HTTPS upload measurement on the active route. It works with direct
  networking, OpenVPN, Tailscale or another VPN and never starts a tunnel.
- Add short forms for every application option, including `-a` attempts, `-b`
  benchmark, `-m` monitor threshold, `-t` test-only, `-T` tuning, `-s` server
  or status speed, `-d/-D` strict-discovery control and status `-n` seconds.

## 2.0.1 - Unreleased

- Restore f6093d8's Score-first relay selection and explicit public VPN Gate
  authentication; omission of auth-user-pass in a profile is no longer interpreted
  as a reason to remove the previously working credentials.
- Add --attempts N and the persistent attempts preference (default 5); failures
  report the number actually attempted instead of implying all listed relays failed.

- Restore direct connection as the normal path. No automatic benchmark, startup
  IP/speed check or periodic download is enabled without an explicit CLI option.
- Retire persisted bench/min_speed preferences; old generated values cannot
  activate measurements. Keep --bench and --min-speed as invocation-only opt-ins.
- Restore working historical discovery priority and show failed mirror details
  only if every attempt fails. Keep a concise honest HTTP-origin notice.
- Remove duplicate cipher chatter and the benchmark-only network name assumption.
- Add regressions preventing implicit probes and preserving explicit measurement,
  connection cleanup, strict HTTPS and full error diagnostics.

## 2.0.0 - 2026-10-24

- On the rights holder's explicit request, change this development distribution
  to AGPL-3.0-only using the canonical k-project asset and complete GNU text.
- Update package metadata, explicit license inclusion and README consistently.
- Published 1.2.0 and earlier MIT releases remain MIT; no retroactive revocation.
- Release the licensing transition as a new major version without changing
  previously granted MIT permissions.

## 1.2.0 - 2026-10-24

- Move the checkout to `VPNs/k-vpn` and publish under kpihx-labs on GitHub/GitLab.
- Use XDG configuration and cache directories; no home-root state directory,
  implicit migration or raw benchmark history is created.
- Create user preferences once in config.json; explicit flags override settings.
- Keep profiles, credentials and control sockets in private session directories
  under XDG_RUNTIME_DIR or Linux /tmp, cleaned even on errors.
- Consolidate benchmark records into BENCHMARKS.md; remove the redundant JSON.
- Remove the redundant legacy test script; the bounded public CLI is the only
  benchmark entry point. Refresh README and Linux-path regression coverage.
- Add make build, publish and parallel xargs push-to-all-remotes targets.

## 1.1.0 - 2026-10-23

- Parse active protocol directives, not comments; preserve native authentication.
- Prefer AEAD but retain explicitly requested CBC with a compatibility warning.
- Add country/code, pinned relay, native/balanced and benchmark-only CLI options.
- Verify TUN routing, HTTPS exit IP and payload before reporting a speed; bind
  probes to the tunnel, ignore ambient proxies and try OVH after speed-host refusal.
- Scope labelled cached observations to the network, profile and tuning; always
  use fresh observations for selection. Separate auth, connection and egress errors.
- Validate public profiles before privileged execution; reject hooks/plugins/files.
- Prefer verified HTTPS discovery, bound DNS/request waits and warn on legacy
  HTTP fallback. `--strict-discovery` forbids unauthenticated list retrieval.
- Bound initialization and output buffering; clean sessions on interruption.
- Use a private, UID-restricted management socket for shutdown without renewed
  sudo permission. Eliminate broad process termination.
- Add offline regression suite and project Makefile. No throughput multiplier is
  promised; controlled measurements and failures are preserved in BENCHMARKS.md.
