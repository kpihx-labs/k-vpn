# Changelog

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
