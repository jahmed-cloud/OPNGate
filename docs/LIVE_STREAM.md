# One-second network and device flow

Agent 1.5.0 samples interface counters and routed PF state counters on a dedicated one-second worker. It caches IP/MAC neighbor bindings for five seconds. It does not collect leases, DNS, IDS data or control policies on this worker. Full inventory/security reports remain 30 seconds, with approved-action checks every 15 seconds.

The current frame travels over the existing mTLS `/v1/live` listener. Ingest validates at most 64 interfaces and 2048 devices, normalizes rates and atomically replaces one bounded `current.json` file. Both services mount the same 16 MiB tmpfs volume at `/run/portal-live`. Live frames do not update SQLite snapshots, client rows or historical samples and disappear when the RAM volume is unmounted or the host reboots. No Redis service or extra exposed port is needed. Normal 30-second historical collection remains enabled.

## Browser delivery

The portal runs one async fan-out task per process. It checks the current frame five times per second and publishes changed revisions over authenticated `/api/live/stream` server-sent events. Each subscriber has a single pending-frame slot; a slow browser receives the latest state without building an unbounded backlog. There are at most four streams per session and 64 per portal process.

Overview, Traffic and Clients consume the stream while visible and unpaused. A failed/unavailable stream falls back to revision-based JSON requests every second and periodically reconnects. Healthy streams do not also poll every second. Manual Refresh still works while paused. Hidden/paused tabs close their streams. Streams rotate after five minutes, and revoked/disabled/expired sessions are checked at least every five seconds. Streaming and fallback requests do not extend session idle expiry.

Responses use `text/event-stream`, `Cache-Control: no-store, no-transform` and `X-Accel-Buffering: no`. Caddy flushes event-stream responses immediately according to its [reverse proxy documentation](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#streaming). Verify this through the actual Cloudflare/WAF path after deployment; an unbuffered local handler alone does not prove end-to-end delivery.

## Flow-map behavior

- WAN/network labels and activity levels and per-device labels/branch activity use the new observations without replacing the SVG or control menus.
- Device rates are matched by MAC, current IP and segment. A binding mismatch displays unknown rather than attaching another address's rate to an old device card.
- Fast data becomes stale at five seconds. Stale, paused, hidden and off-screen animations stop; reduced-motion preferences remain respected.
- Names, status, policy controls and device membership refresh independently every 30 seconds through `/api/flow`. Expand/collapse requests only the map fragment. History refreshes every 60 seconds and preserves the owned map.
- Stable device ordering and the eight-device cap per expanded network remain. Clients lists also receive one-second rates.
- The rolling WAN graph retains at most 180 real observations from three minutes. Missing values and gaps over ten seconds break the line; no historical points are invented.

Device counters measure traffic seen in inside-interface PF states, including routed traffic and connections to the firewall itself. Same-subnet traffic switched by an access point or switch is not visible to PF. Very short connections that open and close between samples can be missed; IPv6-only neighbors are not discovered by the IPv4 ARP collector. These rates are operational estimates, not packet-capture or billing totals. One second is the nominal collection cadence, with command, network and browser scheduling time added.

The state parser now flushes its final record and ignores unknown-interface/duplicate state copies. Previously the last record could disappear, while device labels updated only on the slow inventory cadence.

## Upgrade and rollback

Back up current application/Compose sources and tag previous images. Deploy the new services Compose file, rebuild `portal` and `portal-ingest`, and recreate both so they share the RAM volume and `PORTAL_LIVE_DIR`. Rebuild/recreate the matching edge `waf-shipper`, then deploy the new agent code while preserving its configuration, state, credentials and operator trust. The example uses `live_interval: 1`; an existing explicit larger value must be reviewed if one-second sampling is desired. No firewall access/routing/shaping change is part of this upgrade.

Verify the tmpfs mount, advancing device frames, actual SSE arrival cadence, pause/resume, JSON fallback, authentication/idle expiry and history-row rate. Roll back the services source/images and agent source together if live ingestion or signed-in rendering fails. Retain the normal database and secrets; do not prune volumes. The old bounded database snapshot row may remain unused after upgrading.

The WAF shipper also imports the shared settings module but has a read-only root and no `/tmp` mount. Settings must only choose paths, with no writable-directory probing during import. Before recreating that service, verify its image can import `app.config` under `docker run --rm --read-only --network none --cap-drop ALL --security-opt no-new-privileges <shipper-image> python -c 'from app.config import settings'`.

Validation:

```sh
python -m pytest -q portal/tests
node --check portal/app/static/portal.js
node portal/tests/test_refresh_dom.cjs
node portal/tests/test_live_stream.cjs
```
