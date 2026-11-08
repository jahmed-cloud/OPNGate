# OPNGate project status

Updated: 2026-11-08 (Asia/Calcutta).

## User preferences

- Product and repository name: OPNGate. GitHub: https://github.com/jahmed-cloud/OPNGate.
- Author and committer: Junaid Ahmed <jahmed.cloud@outlook.com>; no coauthor trailers.
- Preserve the sidebar layout, orange branding, low-resource operation and existing controls.
- Deploy authorized updates with saved SSH access while retaining private configuration, PKI, database volumes and signed-action trust.

## Current release

OPNGate 2.0 rebuild retains existing console capabilities and routes while separating backend workspaces in `app.console` and browser workspaces in `static/console`. It adds a current-only Networks view, authenticated `/api/console` inventory, and Help & guides with contextual blocking, approval/status and undo instructions. Authentication, mTLS collection, signed controls, background CrowdSec, historical aggregation and one-second streaming remain in place. See ARCHITECTURE.md for feature parity and the deliberately retained security components.

The GitHub repository has been renamed. The live console moved to `opngate.jahmed.cloud`. The initial Cloudflare 525 was resolved by adding the new hostname to Caddy and obtaining its matching certificate. The user chose to retire the former hostname and enrolled a new operator passkey at the new address. The new public key was manually transferred over admin SSH; the firewall action RP ID/origin was updated. The old DNS/legacy-origin migration path is retired. TOTP remains available.

WAF enforcement is enabled in the private edge environment (`WAF_MODE=On`). A narrow Vaultwarden `/api/` method policy permits its REST updates while preserving method restrictions elsewhere and all payload inspection. The controlled XSS probe changed from HTTP 200 in DetectionOnly to HTTP 403 with Coraza engine On and is_interrupted true. Normal portal login and Vaultwarden config returned 200; an unauthenticated Vaultwarden PUT reached its application authentication check (401); protected application roots retained their login redirects. The portal received the On audit evidence and a confirmed block. These checks do not replace a real authenticated vault-edit/upload/sync exercise.

The existing community topic was rewritten as “OPNGate: a self-hosted OPNsense gateway console” and includes two earlier-release reference screenshots with sample data and an explicit historical caption. No private telemetry or configuration was published. See COMMUNITY_POST.md.

## UI cleanup and freshness fix (2.0.2)

The existing sidebar/orange layout is retained. The cleanup shortens repeated status/help text, aligns controls, fixes network rate colors, bounds long device names/rate columns, groups device controls, and improves the sign-in presentation. Mobile Refresh stays available; Sign out is reachable in the navigation drawer. Keyboard navigation includes a real open/close button, inert background/hidden drawer, Tab containment and Escape focus return. Hidden fixed menu panels and uncontained screen-reader labels no longer make the whole device page scroll sideways; the table scrolls inside its card. Expanded menu sections reposition within the viewport.

Live DOM updates are coalesced per animation frame; mounted-node lookups are cached and invalidated after page/map fragment changes. All observed chart points are retained within the existing 180-point bound. Manual refresh has a busy state and updates charts while automatic refresh remains paused. Hidden nested menu groups do not block later refreshes. Collection/SSE/history intervals are unchanged.

The Networks view now uses the live snapshot’s fractional-time freshness decision. Its previous second comparison used integer time, which could mark a newly received same-second sample as stale. Two regression cases cover fresh and genuinely stale reports.

Validation: 180 Python tests pass; JavaScript syntax and DOM/stream harnesses pass, including frame batching, node-cache invalidation, paused manual refresh and visible/hidden menu guards. Sample-data browser checks cover desktop light/dark themes, 390/320-pixel layouts, contained table scrolling, menu bounds and keyboard dismissal. CSS is 39; bootstrap JavaScript 26; live/UI workspace scripts 2; other workspace scripts 1. Production deployment and final browser confirmation are pending. No sustained frame-rate or production-load benchmark is claimed.

## Single-command deployment follow-up

`Deploy.ps1`/`Deploy.cmd` now default to Deploy; the shell equivalent is `sh deploy/deploy.sh deploy`. Both detect a fresh or compatible existing stack and stop on failed/mixed/partial probes. Existing updates use source checksums, exclusive host/operation locks, source/image/SQLite backups, both-host builds before cutover, read-only image/source validation, running-image checks, telemetry/shipper readiness and public GET auth checks. Failure recovery restores application source/images without replacing the current database. Rollback accepts the retained release ID and protects newer deployments. See [INSTALL.md](INSTALL.md).

Local deployment tests: 31 pass, including archive validation, configuration preservation, rollback, stale-image readiness, remote listing failures and failed-build/public-check orchestration. Full regression passes: 178 Python tests; DOM/stream harnesses and shell/PowerShell syntax checks pass. One pre-existing Starlette/httpx deprecation warning remains.

Production: the default Windows launcher selected Update and completed twice; the final `Deploy.cmd -NonInteractive -NoPause` run deployed the controller/launcher from `7a6f111` as `opngate-20261107T200732Z-39ba4f45` (release IDs use UTC). Both host checkpoints completed; read-only image imports, source hashes, active image IDs, restart checks and public login/health/auth guards passed. The final readiness sample was 0.89 seconds old; shipper contact was 5.77 seconds old. The private SQLite snapshot passed quick_check with mode 0600. Eleven private-file fingerprints across services, edge and firewall were unchanged, including live environment/Compose files, Caddy routes, services certificates, agent source/configuration and operator trust. WAF and native firewall policy were retained. Source/image/SQLite backups and recovery controllers remain available; no backup/image pruning ran. Fresh hardware installation and interrupted-host recovery remain bounded by the verification notes in INSTALL.md.

## Security follow-up (2.0.1)

The November 8 source review adds bounded browser request parsing, typed WebAuthn envelopes, bounded limiter state, conditional passkey-counter updates and atomic replacement of the presented login session. The pentest plan now reflects the actual Python/FastAPI architecture and separates local evidence from untested external exposure. See [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md). Local validation passes: 153 Python tests, JavaScript syntax and the DOM/stream harnesses. Source commit `fd905cc` is deployed to portal/ingest and the matching edge shipper. Deployed security-file hashes match; read-only image imports passed. Normal login/health returned 200, protected live endpoints returned 401 without a session, five live revisions advanced with 0.55–0.95-second sample ages, and shipper contact was 22.47 seconds old. Updated containers had zero restarts and portal/ingest had no recent error lines at the smoke check. WAF remains On; the agent and private native settings were not changed. Rollback source/images are retained under `/opt/gateway/releases/opngate-security-20261108`, with a private SQLite backup in the services volume. Physical-key login/control confirmation and sustained-load checks remain open. The earlier release evidence below remains dated November 5.

## Deployment and validation (November 5 release)

- Portal and ingest on the services Pi, matching edge WAF shipper, and the hostname/action-identity agent update are deployed with the existing database, credentials and native firewall policy preserved.
- Current browser assets: CSS 38; bootstrap JavaScript 25; browser workspace scripts version 1.
- Local validation: 125 Python tests across portal and installer suites pass; shell/PowerShell syntax and JavaScript syntax/DOM/stream harnesses pass. One existing Starlette/httpx deprecation warning remains.
- Production verification: the Windows launcher Check and Status actions passed against the real stack; public login returned 200, six network cards and the blocking guide rendered for the signed-in operator, one-second SSE resumed, and Threats displayed the On-mode audit. A final telemetry sample was 0.74 seconds old and the shipper heartbeat 24 seconds old.
- Installer tests simulate SSH hosts and verify connection failures, archive failures, SSH-key paths with spaces, retained PKI and a scoped existing-stack update. They do not establish a tested clean bare-metal installation.
- Windows deployment starts with Deploy.cmd / Deploy.ps1. Configure, Check, Install, Update and Status use the same shell deployment implementation. Update preserves live routes, certificates, agent configuration/code, trust and host firewall policy. Fresh installation remains a three-host deployment with external prerequisites.
- Rollback: private/source backups are under `/opt/gateway/releases/opngate-20261105` on the Pis; a SQLite backup is retained in the services data volume. Firewall source, configuration and public-key trust backups end in `.opngate-before`. Keep earlier performance/streaming rollback archives and image tags until a normal use cycle passes.

## Remaining verification and operations

- User-run authenticated Vaultwarden edit, attachment upload and sync; continue monitoring legitimate traffic under WAF enforcement and tune narrowly if needed.
- Real hardware confirmation of a new-hostname signed control action; new key enrollment and trust/identity installation are verified, and signature behavior is covered by software-authenticator tests.
- A clean hardware install using the guided launcher; automated installer checks use simulated hosts.
- Performance during sustained multi-viewer use and an actual speed test. Prior one-second production measurements remain documented in LIVE_STREAM.md/PERFORMANCE.md; no new speed test is run automatically.
- Coraza serial audit-log rotation/retention and reliable offset handling across rename/replace rotation.
- External origin/IPv6/services-listener verification and controlled authentication-load measurements in the revised pentesting plan.
- Existing action-delivery interruption and DHCP address-reassignment limitations documented in SECURITY.md.
- Collection runs at a nominal one-second interval; subsecond end-to-end delivery is not promised.
