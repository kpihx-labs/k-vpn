# Benchmark synthesis

This is the single benchmark record, consolidating the former Markdown and JSON
reports. Tests were performed on KpihX-Ubuntu over eduroam on 2026-10-23/24.
They are historical observations, not a current relay catalogue or speed promise.
No new live benchmark was run for the v1.2 filesystem/release migration.

## Measurement rules

- Throughput is received payload bits divided by actual elapsed wall time,
  including HTTP/TLS setup. Short transfers do not establish sustained throughput.
- The comparative download was
  `https://lil1-rbx.speedtest.network.ovh.net/files/100Mb.dat`.
- IPv4 routing and HTTPS exit IP were checked before accepting a speed.
- Providers/relays were tested serially, not stacked. Country labels came from
  the listing or client notices, not an independent geolocation audit.
- Connection failures, authentication refusals, HTTPS success without a usable
  download and measured throughput are different outcomes. Failures are not zero.
- Cloudflare HTTP 403 or OVH disconnects were not called proof of a dead VPN.

## Controlled comparison

Approximately 23:10-23:12 local time on 2026-10-23: three nominal five-second
samples on the same OVH endpoint for each successful case.

| Provider / mode | Region | Mbps samples | Median Mbps | Outcome |
|---|---|---|---|---|
| Direct campus line | FR | 158.100, 167.622, 174.618 | 167.622 | baseline |
| k-vpn, native profile with auth/compatibility fixes | JP | 1.154, 2.019, 1.861 | 1.861 | exit 138.64.81.88, UDP/55688 |
| k-vpn, balanced | JP | unmeasured | unmeasured | same relay returned AUTH_FAILED before transfer |
| Psiphon, comparison only | JP | 0.156, 0.267, 0.171 | 0.171 | exit 172.104.120.138 |
| Psiphon, comparison only | DE | three transfer errors | unmeasured | exit 57.129.25.79 verified; OVH closed downloads |
| Psiphon, comparison only | FR | 58.659, 61.041, 60.815 | 60.815 | exit 57.128.117.194 |

For these particular Japanese exits, k-vpn's median was approximately 10.9 times
Psiphon's. This is not a general provider ranking. The native case includes bug
fixes, so it is not an unmodified-v1.0 throughput baseline. The balanced refusal
cannot establish a positive or negative tuning effect. The pinned Japanese relay
subsequently disappeared from a live listing; the CLI correctly refused reuse.

## Exhaustive OpenVPN snapshot survey

From 22:09 to 22:29 UTC on 2026-10-23 (00:09-00:29 local on 2026-10-24), every
one of 95 provided profiles was attempted across 13 countries. Exact profile-ID
set equality verified coverage. Three initial leaders were rechecked at the end.

The survey preserved native crypto/transport parameters. Only benchmark /32
destination routes were installed; default host routing and pushed DNS were not
replaced. Each usable relay received two nominal five-second OVH transfers;
Cloudflare fallback measurements remained separate. Thus it tests relay transfer
behavior, not all aspects of full-device routing, DNS or privacy.

First pass: **86 connection failures, 3 authentication refusals, 1 HTTPS-verified
exit without measurable download, 5 measured relays**. All three rechecks returned
payload measurements. No country or transport port was excluded from the snapshot.

| Relay | Country | Transport | Provider Mbps | Initial OVH median Mbps | Recheck Mbps |
|---|---|---|---|---|---|
| 122.133.152.245 | Japan | UDP/1783 | 90.00 | 1.363 | 0.799 |
| 49.163.136.34 | Korea Republic of | TCP/995 | 75.07 | 0.590 | 0.616 |
| 121.189.253.189 | Korea Republic of | TCP/995 | 185.74 | 0.367 | not rechecked |
| 153.225.227.12 | Japan | TCP/1246 | 63.55 | 0.432 | 0.223 |
| 141.223.143.39 | Korea Republic of | TCP/995 | 331.31 | 0.026 | not rechecked |

| Country | Profiles attempted | Measured relays |
|---|---|---|
| Canada | 2 | 0 |
| China | 1 | 0 |
| Germany | 1 | 0; authentication refused |
| Japan | 35 | 2; one additional HTTPS exit had no measurable download |
| Korea Republic of | 40 | 3 |
| Mexico | 1 | 0 |
| Morocco | 1 | 0 |
| Myanmar | 1 | 0 |
| Peru | 1 | 0 |
| Russian Federation | 6 | 0 |
| Thailand | 4 | 0 |
| United Kingdom | 1 | 0 |
| United States | 1 | 0 |

France, Belgium and the Netherlands were absent, not filtered out. The fastest
rechecked median was 0.799 Mbps, but its two samples were 1.468 and 0.131 Mbps.
This is substantial variability, not stable high speed. The full snapshot was
exhausted, not every relay that could appear afterward or every unadvertised
alternative protocol/port on those hosts. No high-throughput result was established.

## Other diagnostic and smoke runs

- Japanese TCP/443 relay 59.190.112.50 established TLS. Removing injected vpn/vpn
  allowed initialization; native and tuned sessions later lacked usable HTTPS
  forwarding to the tested destinations. It was not classified as a DNS-only issue.
- German TCP/443 relay 149.102.146.143 verified its exit and Google HTTPS (204).
  One Cloudflare transfer received 11,507 bytes in eight seconds. This isolated
  weak sample is not a stable country/provider throughput estimate.
- A Japanese UDP/1195 relay timed out while UDP/55688 worked on the same network.
  Later UDP/1783 and TCP/995 succeeded. QUIC reachability and isolated refusals do
  not establish a campus-wide OpenVPN port policy.
- A separate Psiphon FR/Cloudflare smoke test measured 66.3 Mbps. It is not part
  of the OVH comparison. Psiphon HTTP/SOCKS and service crash-recovery checks were
  operational tests, not further k-vpn throughput samples.
- A real OpenVPN process was stopped through its private UID-restricted Unix
  management socket while a test forbade a fresh privileged command. Cleanup
  left no test TUN/process; normal Wi-Fi routing was restored.
- Discovery HTTPS failed from this connection; a legacy HTTP mirror returned
  95 profiles with an explicit unauthenticated-list warning. Strict HTTPS-only
  discovery remains available. This does not establish TLS interception.

## Retractions and retained scope

Earlier claims of a universal 16-Mbps buffer ceiling, a guaranteed 3-5x UDP gain,
DPI-proof transports, a general Psiphon victory or dead Russian relays inferred
from password-blocked trials were unsupported and are withdrawn. CBC is not
synonymous with no AES hardware acceleration; no 10-20 percent cipher speedup
was demonstrated. Wrong-country menu selections were not valid Japan tests.

Raw runtime snapshots/logs were removed at the operator's request. This synthesis
retains the relevant observations; the application does not restore those files
or automatically generate new benchmark documents. Cached observations retain
their actual timestamps and normal ten-minute expiry.

One real Wi-Fi network and short samples do not prove global reachability,
anonymity, leak prevention or geographic availability. No tuning multiplier or
universal best country is established. Native settings remain the conservative
default; the fleet's capacity cannot be manufactured by changing client buffers.
