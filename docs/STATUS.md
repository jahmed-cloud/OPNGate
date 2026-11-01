# Project memory and pending work

Updated: 2026-11-01 (Asia/Calcutta).

## User preferences

- Preserve current sidebar/dashboard layout and orange-neutral branding.
- Git author/committer: Junaid Ahmed <jahmed.cloud@outlook.com>, no coauthor trailers.
- Deploy authorized changes to the existing stack over the saved SSH key, preserving credentials, PKI, configuration, database volumes and action trust.

## Current release

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
- End-to-end counter/poll timing is approximate; subsecond streaming is not promised.
