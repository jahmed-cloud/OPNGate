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

## Security follow-up (2.0.1)

The November 8 source review adds bounded browser request parsing, typed WebAuthn envelopes, bounded limiter state, conditional passkey-counter updates and atomic replacement of the presented login session. The pentest plan now reflects the actual Python/FastAPI architecture and separates local evidence from untested external exposure. See [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md). Local validation passes: 153 Python tests, JavaScript syntax and the DOM/stream harnesses. Deployment is pending; the earlier release evidence below remains dated November 5.

## Deployment and validation

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
