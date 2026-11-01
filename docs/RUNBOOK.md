# Deployment runbook

Deploy read-only first and pass each gate before proceeding. Back up existing configurations. Commands below run on the named host; replace all example addresses/domains.

## Layout and prerequisites

Current examples use OPNsense `10.10.0.1`, Pi 5 edge `10.10.0.21`, Pi 4 services `10.10.0.22`. Install 64-bit Linux and Docker Compose on both Pis; use an SSD for services data. Use a separate admin workstation and preferably routed VLANs. Configure DNS and time synchronization.

```text
Internet -> Cloudflare proxy -> OPNsense IPv4 forward 80/443 -> Pi 5 Caddy
                                                              [CrowdSec + Coraza/CRS]
                                                              -> Pi 4 portal HTTPS :9443
                                                              -> configured app upstreams
OPNsense agent -------- mutual TLS --------> Pi 4 ingest :9444
Pi 5 / OPNsense CrowdSec clients ----------> Pi 4 LAPI :9080
```

The supplied Compose files do not start cloudflared. The portal hostname is `waf.<DOMAIN>`. Caddy only trusts Cloudflare client-IP headers from listed Cloudflare ranges. Maintain those ranges against [Cloudflare's list](https://www.cloudflare.com/ips/). Local private-range peers are also allowed by the supplied edge matcher; restrict that exception if it is unnecessary.

## 1. PKI and service configuration

On your trusted admin workstation with OpenSSL:

```sh
sh deploy/pki/make-pki.sh 10.10.0.22
```

Keep `ingest-ca.key` offline. Copy only `ingest-ca.pem` to the edge; copy `ingest-ca.pem`, `services.crt` and `services.key` into the services host's `deploy/pki/out/`. The script regenerates leaf keys/certificates when rerun: distribute replacements together and restart consumers. Protect the directory from other host users. Never commit this output.

On the services host:

```sh
cd deploy/services
cp .env.example .env
# Edit .env with your DOMAIN, SERVICES_HOST_IP and EDGE_HOST_IP.
# Generate separate random values (openssl rand -hex 32) for each CrowdSec key
# and PORTAL_WAF_SHIP_TOKEN; share only the required matching values with the edge.
docker compose build
docker compose run --rm portal python -m app.cli gen-key
docker compose run --rm portal python -m app.cli create-user admin --role operator
docker compose up -d
```

Save TOTP/recovery material privately. Never regenerate the portal encryption key over existing data: stored TOTP secrets depend on it. Telegram notifications are optional; fill the two Telegram settings only if wanted.

**Gate:** containers start without errors; portal/ingest serve TLS on 9443/9444. The ingest TLS handshake refuses clients without an agent certificate and refuses the services certificate as a client certificate. Do not publish 9443, 9444 or 9080 on WAN.

## 2. Install the OPNsense agent

From the admin workstation:

```sh
scp -r agent root@10.10.0.1:/tmp/
ssh root@10.10.0.1 'sh /tmp/agent/install.sh'
scp deploy/pki/out/agent.crt deploy/pki/out/agent.key deploy/pki/out/ingest-ca.pem root@10.10.0.1:/usr/local/etc/fw-agent/
```

Edit `/usr/local/etc/fw-agent/agent.json` on the firewall. Set portal_url to `https://10.10.0.22:9444`; set interfaces, gateway name, segment labels and optional telemetry sources to match your OPNsense version. Set action RP ID/origin to `waf.<DOMAIN>` / `https://waf.<DOMAIN>`. Keep `actions.enabled=false`.

```sh
python3 /usr/local/opnsense/scripts/fw-agent/fw_agent.py -c /usr/local/etc/fw-agent/agent.json --once
service fw_agent start
```

**Gate:** services ingest logs show telemetry every configured interval (default 30 seconds); check real device addresses, WAN rate directions and gateway latency. The portal should show unknown/stale telemetry when the agent is stopped, rather than claiming connectivity is confirmed.

## 3. Edge WAF and CrowdSec

On services, register the edge CrowdSec machine using the password you will put in the edge environment:

```sh
docker compose exec crowdsec cscli machines add edge-pi5 --password '<EDGE_PASSWORD>'
```

On the edge host:

```sh
cd deploy/edge
cp .env.example .env
# Edit DOMAIN and SERVICES_HOST_IP, matching CrowdSec/shipper secrets and edge password.
# Leave WAF_MODE=DetectionOnly initially.
```

Edit the Caddyfile with your own hosts and upstreams. Supplied Guacamole, Wake-on-LAN and Vaultwarden entries are deployment examples; remove or replace any you do not operate. Admin apps import `admin_app` for portal forward-auth; public application APIs may need their own authentication and cannot necessarily use browser forward-auth. Avoid insecure upstream TLS templates; trust a proper internal certificate.

```sh
docker compose up -d --build
docker compose exec caddy caddy validate --config /etc/caddy/Caddyfile
docker compose logs --tail=50 waf-shipper
```

On OPNsense configure its CrowdSec bouncer to use services LAPI `http://10.10.0.22:9080` with the dedicated OPNsense key.

**Gate:** Caddy validates with the custom modules, portal TLS trust succeeds, CrowdSec logs parse, and shipper contact appears on Threats. An ordinary login 401/403 must not increase confirmed WAF block counts. Run a harmless test rule/request on a host you own and confirm a Coraza audit match appears. A shipper heartbeat alone does not prove protection.

## 4. Network isolation and public routing

Use VLAN firewall rules to permit only edge -> services 9443/9080, firewall -> services 9444/9080, and edge -> explicitly listed application upstreams. Block other access to management and LAN segments. Restrict SSH to your admin workstation.

For interim flat-LAN isolation, install `deploy/hostfw/gw-hostfw.sh` and `gw-hostfw@.service` in `/usr/local/sbin/` and `/etc/systemd/system/`, copy hostfw.env.example to `/etc/gw-hostfw.env`, and fill ADMIN_IP, interface, addresses and upstreams. After Docker creates its chains, enable `gw-hostfw@edge` on the edge or `gw-hostfw@services` on services. Keep console access available before testing rules. This script changes iptables chains; inspect existing Docker/firewall policy first. It is not a replacement for VLANs and does not establish IPv6 isolation.

Configure Cloudflare DNS proxying and Full (strict) TLS. Point the required DNS records at your WAN address. Forward WAN IPv4 TCP 80/443 to edge Caddy, and avoid publishing the services ports. Remove competing Nginx Proxy Manager listeners/forwards after migrating each site. Cloudflare Access can be an additional outer gate for browser admin apps; validate it with your passkey/login flow.

**Gate, from an external network:** the portal and admin apps require login; direct-origin connections are refused; `/internal/*` is refused; services ports are unreachable. Stop the portal briefly and verify admin forward-auth fails closed. Test allowed/denied east-west traffic and IPv6 independently. Protect HTTP-01 certificate issuance and verify renewals with your network policy.

## 5. Enable WAF enforcement carefully

Review detection events and application behavior for at least a normal operating cycle. Tune narrowly for legitimate requests. Set WAF_MODE=On and recreate Caddy, or copy the WAF snippet with explicit On for one site at a time.

**Gate:** a benign request succeeds, a controlled known rule test is interrupted, confirmed blocks appear in Threats, and normal application login/uploads/API clients continue to work. Never use WAF counters alone to establish coverage. Consult [Coraza configuration](https://www.coraza.io/docs/seclang/directives/) when tuning.

## 6. Optional signed controls

Create the OPNsense external aliases/tables `portal_block` and `portal_paused` and matching quick block rules before enabling controls. Exempt management hosts above those rules. Register two operator security keys in the portal.

On services, export the public trust store, then transfer it from your admin workstation to the firewall:

```sh
docker compose run --rm portal python -m app.cli export-keys > operator_keys.json
scp operator_keys.json root@10.10.0.1:/usr/local/etc/fw-agent/operator_keys.json
```

Set protected_cidrs and protected_macs for your admin devices and infrastructure. Enable actions explicitly in agent.json and restart the service. Re-export the trust store whenever operator keys change; never automate trust-store installation from the portal.

**Gate:** approve a short test block on an address you own/control, confirm the agent verifies/runs it, then confirm expiry and undo remove it. Inspect actual tables when a request/response is interrupted. Device pause uses IP mappings; understand DHCP reassignment limitations in [SECURITY.md](SECURITY.md).

## Operations, upgrades and recovery

Back up the portal SQLite database using SQLite's backup interface or stop portal and ingest before copying its files. Back up the encryption key, agent configuration and state, operator public trust store and encrypted backup passphrase separately. Docker named volumes contain live state; repository files are not a data backup. Test restoration privately.

Upgrade services before the WAF shipper because the new protocol uses receipt IDs and new counter kinds. Build/recreate the two stacks from their respective Compose directories. Database initialization adds missing tables/indexes; back up first. Do not downgrade across an incompatible schema without restoring a matching backup. Keep the shipper state volume: it contains offsets and pending retry batches. Old ambiguous counts are preserved but excluded from confirmed charts.

Configure Coraza audit-log rotation/retention on the edge; access-log rotation is already configured. Audit messages may contain private request fragments. Monitor disk space, certificate expiry, stale telemetry, container health and shipper errors. Byte-offset rotation caveats are documented in SECURITY.md. Retention defaults to 90 days for samples/events; pruning runs hourly, while audit rows retain a year. WAF count-history cleanup is not currently automatic.

| Problem | Recovery |
| --- | --- |
| Lost TOTP device | Use a passkey or password plus one unused recovery code; replace TOTP in Security |
| Lost all factors | On services: `docker compose run --rm portal python -m app.cli reset-user <name> --drop-keys` |
| Disable account | `docker compose run --rm portal python -m app.cli disable-user <name>`; remove/re-export its operator keys |
| Wrong host firewall policy | Use local console, disable the matching gw-hostfw instance and repair addresses/rules |
| Suspected compromise | Stop stacks and agent; inspect firewall state, restore trusted configuration and rotate credentials |
| Stale graphs | Inspect agent service, ingest TLS/ports, time synchronization and services logs; do not assume zero traffic |

Per-client bandwidth is not collected by this portal; add a separately secured NetFlow collector if needed. Whole-WAN/interface rates are supported. See [METRICS.md](METRICS.md) for endpoint and measurement definitions and [REVIEW.md](../REVIEW.md) for verification limits.
