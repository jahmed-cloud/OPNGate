# OPNGate console rebuild

ADR 001 · Accepted · 2026-11-05

## Purpose and constraints

Rebuild the application around gateway management while preserving the existing layout, one-second telemetry, device controls, authentication and signed-action trust boundary. The two Pi hosts and OPNsense remain the deployment targets. Preserve the current database and application URLs. Keep browser assets local and the existing strict Content Security Policy.

## Decision

Use focused FastAPI workspace routers in `app.console` with shared inventory and policy presentation helpers. The application bootstrap owns middleware and background services. `app.views` remains a compatibility facade for existing integrations.

Separate browser code into credentials, DOM reconciliation, live transport, UI controls, charts and flow workspaces. Deferred scripts load in dependency order, followed by the small application bootstrap. This retains the established browser behavior without a Node service, frontend framework or build-time package download on the Pis.

Retain the reviewed sessions, MFA libraries, signed-action verification and mTLS protocols. Reimplementing those primitives is unnecessary for the product rebuild and would expand its verification scope. Keep current telemetry separate from historical queries. `/api/console` supplies bounded current network inventory; `/api/live/stream` remains the rate transport.

Credentials now record their WebAuthn RP ID. An optional, explicit legacy origin supports a staged hostname transition; request headers can select only that configured origin. New credentials and action signatures bind to their own RP ID/origin pair. Retiring the old address removes the legacy setting. No wildcard origin acceptance is introduced.

## Feature parity

| Capability | Implementation |
| --- | --- |
| Overview and history | `console/overview.py`, `metrics.py` |
| Current networks and counters | `console/inventory.py`, `console/network.py`, `live.py` |
| Device search, labels and controls | `console/clients.py`, `console/controls.py`, `actions.py` |
| Expandable device flow | `console/flow.py`, server SVG helpers, browser flow workspace |
| Live transport and fallback | `console/api.py`, `live.py`, browser live workspace |
| Historical traffic and CSV | `console/traffic.py`, `console/api.py` |
| DNS and VPN | `console/network.py` |
| WAF, IDS, CrowdSec, alerts and audit | `console/protection.py`, background CrowdSec/WAF collectors |
| Passkeys, TOTP, recovery, roles | `auth.py`, `security.py`, `wa.py`, `identity.py` |
| Independently verified actions | `actions.py`, `agent/fw_agent.py` |

## Alternatives and consequences

A new SPA and a replacement backend would add a build pipeline, duplicate mature control/authentication paths and require substantially more migration work. A branding-only edit would leave the existing application structure unchanged. The chosen rebuild preserves behavior while moving the console into maintainable workspaces and adding a dedicated network inventory view.

SQLite, legacy Python imports and existing URLs remain compatibility constraints. Browser scripts still share a documented global scope; moving to an ES-module build can be reconsidered if frontend complexity warrants it. Fresh installation still needs DNS, SSH, Docker and real interface configuration; the launcher guides deployment rather than provisioning an ISP or Cloudflare account.

## Validation

Run all portal and installer tests, JavaScript syntax and DOM/stream harnesses. Test the actual ARM images, public TLS, both user roles, streaming freshness and operator-key identity during deployment. Installer tests use fake SSH hosts and exercise failure handling; they do not establish that a fresh bare-metal deployment has been tested.
