# Project memory and pending work

Updated: 2026-11-01 (Asia/Calcutta).

## User preferences

- Preserve current sidebar/dashboard layout and orange-neutral branding.
- Git author/committer: Junaid Ahmed <jahmed.cloud@outlook.com>, no coauthor trailers.
- Deploy authorized changes to the existing stack over the saved SSH key, preserving credentials, PKI, configuration, database volumes and action trust.

## Current release

One-second live flow is deployed (2026-11-01): agent 1.5.0, device counters, corrected final PF state parsing, shared RAM-only last frame, bounded authenticated SSE fan-out, one-second JSON fallback and in-place device branch updates. Local validation: 108 Python tests, JavaScript syntax and both DOM/stream behavior harnesses pass. See LIVE_STREAM.md; older release measurements below remain historical.

Final health verification caught a new settings default probing for a writable temp directory at import time, which prevented the read-only edge WAF log shipper from starting. Settings now select the live path without filesystem I/O. A regression test and an actual `docker run --read-only --network none` settings-import smoke test passed before redeploying the shipper. Caddy remained running throughout; only WAF log reporting was interrupted during that correction.

Verified on the services Pi: portal and ingest both mount tmpfs; 12 successive fast frames arrived 0.991–1.015 seconds apart, covering 11 devices, with zero historical rows added during that observation. Current-frame JSON was 1,892 bytes and snapshot generation measured 1.558 ms median over 20 reads. Resource samples: portal 2.34% CPU / 59 MiB; ingest 2.86% CPU / 39.74 MiB. These are short normal-use observations, not load-test guarantees. The state-read/parser diagnostic on the firewall measured 27.13 ms median across five reads at approximately 205 states before the upgrade.

Verified through the signed-in production browser: “Live stream · 1 s,” fresh per-device values, active device branches, paused animations, manual Refresh while paused, resumed streaming and WiFi expansion/collapse without losing the existing LAN/MGMT expansion state. Clients also displayed live streaming rates in 20 rate cells. Public unauthenticated stream returned 401; login returned 200. Both portal/ingest and matching edge shipper are deployed; current assets are CSS 35 / JavaScript 22. A few Chrome message-channel errors were captured; no corresponding server application exception was observed.

Streaming rollback: source archives `/opt/gateway/releases/streaming-before.tgz` on both Pis, Docker image tags ending `streaming-rollback`, and firewall agent source ending `.streaming-backup`. Temporary upload archives are removed after verification. Native firewall policy/configuration and agent credentials were preserved.

Network-flow follow-up is also live (2026-11-01): two-second WAN/network map rates, live Traffic bandwidth bars, separate 30-second map/device fragments, count-only collapsed segments, bounded stable device ordering, cancelled superseded expansion requests and reduced/paused animation. Validation: 94 Python tests plus JavaScript syntax/DOM/series/tooltip checks passed.

Portal rebuilt/restarted on Pi 4 and matching WAF shipper rebuilt/restarted on Pi 5. Ingest and firewall agent continue unchanged. Production browser verified CSS 34 / JS 20, fresh rates, WiFi collapse/expand and manual Refresh preserving expansion; no captured browser errors. Public unauthenticated `/api/flow` returns 401. A read-only map rendering diagnostic with all networks expanded measured 3.988 ms median over 20 renders (cold 148.308 ms; HTML 23,482 bytes). This excludes authentication middleware and public network latency. Portal resource sample: 1.71% CPU / 58.34 MiB, not a load-test guarantee.

Flow rollback copies: `/opt/gateway/releases/flow-before.tgz` on both Pis, `gw-services-portal:flow-rollback` and `gw-edge-waf-shipper:flow-rollback`. Temporary upload archives removed after verification; rollback archives retained.

All five performance changes are implemented. Local validation: 91 Python tests and the JavaScript DOM/series harness pass. Deployed to the existing stack and verified on 2026-11-01. All five requested changes are live.

## Deployment checklist

- Verified: portal and ingest rebuilt/restarted on Pi 4 (10.10.0.22).
- Verified: matching WAF shipper rebuilt/restarted on Pi 5 (10.10.0.21).
- Verified: agent 1.4.0 installed on OPNsense management address 10.99.99.1; agent.json, state and operator trust preserved.
- Verified: six observed snapshot timestamps advanced exactly 2 s apart, with 0 extra historical rows during the 12 s diagnostic.
- Verified: current snapshot reads measured 0.361 ms median across 20 reads; representative JSON size 822 bytes; unchanged revision returned 204 in the deployed handler diagnostic. Public unauthenticated request returned 401, login 200.
- Verified: cold diagnostic Threats rendering 160.84 ms and warm 30.35 ms with its CrowdSec refresh running separately; no synchronous CrowdSec wait in rendering.
- Verified in the signed-in production browser: fresh rate age, rolling real observations, graph retained through manual Refresh, and no browser error logs. Mounted SVG/path identity also covered by DOM regression harness.
- Resource sample: portal 1.72% CPU / 57.16 MiB, ingest 0.26% CPU / 39.16 MiB; these are point-in-time samples, not load-test guarantees.
- Rollback: source archives under /opt/gateway/releases/performance-before.tgz, Docker tags ending performance-rollback, and fw_agent.py.performance-backup on the firewall. Retain these until a full normal-use observation cycle passes.

## Remaining work outside this release

- Observe performance during an actual user-run speed test and sustained multi-viewer use; no speed test is run automatically.
- Audit log rotation/retention and action delivery/DHCP reassignment limitations described in SECURITY.md remain tracked.
- Nominal one-second collection plus stream/network/scheduling delay is approximate; subsecond delivery is not promised.
