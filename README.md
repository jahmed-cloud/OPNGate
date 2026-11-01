# OPNsense Gateway Portal + WAF

A self-hosted gateway dashboard and web application security stack for a home lab. Monitor OPNsense connectivity, devices, traffic, DNS, VPNs and security events, with security-key-approved control actions.

The **WAF runs at the edge in Caddy with Coraza and OWASP Core Rule Set**. The FastAPI portal monitors it; installing the portal alone does not protect a website. The supplied edge configuration starts in **DetectionOnly**, which records matches without blocking them. The dashboard does not verify the live engine mode.

## Dashboard

- Latency, packet loss, bandwidth and availability graphs with visible UTC time axes and timestamp tooltips; 1-hour, 24-hour, 7-day and 30-day windows.
- Average latency/loss, peak throughput, observed availability and telemetry coverage. Missing observations leave gaps rather than suggesting healthy service.
- Timestamped network flow snapshot, current clients, recent alerts and outage history.
- Device search by name, IP, MAC or maker; segment/status filters. Alerts filter by search, source and severity.
- Seven UTC days of confirmed Coraza events, daily chart and per-site totals. Ordinary HTTP 403 responses are not counted as WAF blocks.
- Authenticated JSON metrics and CSV downloads, bounded to 240 aggregate points per window.
- Live content updates, pause/resume, manual refresh, timeout/error feedback, responsive layout and system light/dark themes. No CDN chart dependencies.

## Security and scope

Passkeys/FIDO2 or password plus TOTP, recovery codes, CSRF protection, trusted-proxy IP handling and viewer/operator roles protect the portal. The OPNsense agent pushes telemetry over mutual TLS and independently checks operator signatures before allowlisted actions. Start read-only, then provision trusted operator keys manually.

This is a home-lab project, not a security certification. WAF inspection covers HTTP traffic routed through the edge. OPNsense firewall rules, segmentation, CrowdSec and Suricata have separate jobs. See [security and limitations](docs/SECURITY.md).

## Local development

Use Python 3.12+, OpenSSL on PATH, and Node.js for the JavaScript syntax check. Development mode is for localhost only.

PowerShell, from this repository:

```powershell
py -3.12 -m venv portal/.venv
./portal/.venv/Scripts/python.exe -m pip install -r portal/requirements.txt pytest httpx
cd portal
$env:PORTAL_DEV = '1'
./.venv/Scripts/python.exe -m app.cli gen-key
./.venv/Scripts/python.exe -m app.cli create-user admin --role operator
./.venv/Scripts/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Linux/macOS:

```bash
python3 -m venv portal/.venv
portal/.venv/bin/python -m pip install -r portal/requirements.txt pytest httpx
cd portal
export PORTAL_DEV=1
.venv/bin/python -m app.cli gen-key
.venv/bin/python -m app.cli create-user admin --role operator
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Open http://localhost:8000 and sign in with the TOTP setup printed by create-user. Empty graphs are expected until the agent reports; this project does not substitute demo data for live telemetry.

## Deployment and configuration

Follow [the runbook](docs/RUNBOOK.md) for the two-host deployment. Copy each Compose directory's `.env.example` to `.env`, replace addresses/domains and generate independent secrets. Keep `.env`, certificates, private keys and databases out of Git.

| Component | Location | Purpose |
| --- | --- | --- |
| FastAPI portal | `portal/` | Dashboards, authentication, signed actions |
| OPNsense agent | `agent/` | Telemetry collection and verified actions |
| Caddy, Coraza/CRS, CrowdSec | `deploy/edge/` | Edge HTTP inspection and bans |
| Portal, mTLS ingest, CrowdSec LAPI | `deploy/services/` | Services host |
| PKI and host firewall | `deploy/pki/`, `deploy/hostfw/` | Private TLS and interim network isolation |

Current defaults use Cloudflare-proxied DNS, WAN IPv4 port forwarding to Caddy on 80/443, portal HTTPS on **9443**, agent mTLS on **9444**, and CrowdSec LAPI on **9080**. Cloudflare Tunnel is not deployed by these Compose files.

Important settings include PORTAL_ORIGIN, PORTAL_RP_ID, PORTAL_COOKIE_DOMAIN, PORTAL_TRUSTED_PROXIES, PORTAL_RETENTION_DAYS (90 by default), PORTAL_WAF_SHIP_TOKEN and optional Telegram credentials. Compose supplies the production origin/proxy settings. Agent interface names and gateway names must match your firewall.

## Validation and contributing

From the repository root on Windows:

```powershell
./portal/.venv/Scripts/python.exe -m pytest -q portal/tests
node --check portal/app/static/portal.js
```

On Linux use `portal/.venv/bin/python` instead. OpenSSL must be available for the real ES256/Ed25519 agent signature tests. Tests use temporary databases and software authenticators, without changing a firewall. See [the review](REVIEW.md) for validation boundaries and remaining work. For contributions, include a clear problem statement and focused tests; never include personal telemetry or credentials.

[Metrics reference](docs/METRICS.md) · [Community post draft](docs/COMMUNITY_POST.md) · [Historical design plan](Firewall%20Gateway%20Portal%20and%20WAF%20%E2%80%93%20Plan.md)
