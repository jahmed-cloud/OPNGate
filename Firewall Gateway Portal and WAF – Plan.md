> Historical design document. Deployment choices and ports have changed. Use [README.md](README.md), [the current runbook](docs/RUNBOOK.md) and [the implementation review](REVIEW.md) for the supported implementation.

# Firewall Gateway Portal and WAF – Plan

Nov 1, 2026 · @Junaid

## Reality check

Build it, but with two changes: the portal is reachable from anywhere yet usable only by people you name, and the "WAF" is a chain of layers in which each protects only the traffic that passes through it.

- **"Accessed by everyone" must mean "reachable by everyone, usable by you".** A firewall console on the open internet is a top target. It gets its own login, FIDO2 security keys or passkeys first and TOTP as fallback, and nothing loads before it passes. A custom login is the part most likely to have a flaw, so it uses vetted libraries, never home-made crypto.
- **The portal must never hold firewall admin rights.** If the portal is compromised, the firewall must survive. The firewall pushes data out; the portal never logs in to the firewall. Changes go through a short allowlist of actions the firewall pulls, verifies and logs.
- **A WAF protects websites, not devices.** It inspects HTTP(S) requests to your published apps (behind Nginx Proxy Manager). Phones, the TV and the NAS are protected by segmentation, blocklists and IDS on the firewall, not by a WAF.
- **The J4125 can't run everything.** Blocklists, CrowdSec and Suricata IDS fit. TLS inspection, inline WAF and full IPS at gigabit do not. The WAF runs on the proxy host or at Cloudflare, not on the firewall.
- **"UniFi Cloud Gateway"** in this plan means its Site Manager experience: one remote view of health, clients, threats and alerts, plus a few safe controls.

## Target architecture

Traffic from the internet enters through Cloudflare and an outbound tunnel into a new DMZ; the firewall itself accepts no connection for the portal.

&#91;embedded content: target architecture · edge, firewall, DMZ, portal\]

- **Trust boundaries:** the internet ends at Cloudflare Access. The DMZ cannot open connections to LAN or MGMT. The firewall trusts the portal only for allowlisted actions it verifies itself.
- **Data flow:** the firewall agent pushes metrics every 30 s and events as they happen over mutual TLS. The portal stores them; browsers never touch the firewall.
- **What changes from today:** NPM leaves the LAN for the DMZ, WAN ports 80/443 close once the tunnel works, and the existing Telegram plugin becomes the agent's first data source.

## Portal

The first release is read-only; controls come later, one allowlisted action at a time, each needing a fresh MFA prompt and posting to Telegram.

| Area | Shows | Source on the firewall |
| --- | --- | --- |
| Overview | Online/offline, WAN IP, latency, loss, uptime, outage timeline (24 h / 7 d / 30 d) | gw-stats, net-watch outage log |
| Clients | Every device: name, IP, MAC, maker, segment, online now, first seen, traffic | ARP, Dnsmasq leases, NetFlow |
| Traffic | Top clients, top destinations, per-segment throughput | NetFlow / Insight |
| Threats | Blocked attackers by country, IDS alerts, WAF hits per site, CrowdSec bans | pf tables, Suricata eve.json, CrowdSec |
| DNS | Queries, blocked domains, top blocked per client | Unbound statistics |
| VPN | WireGuard peers, last handshake, endpoint | wg |
| Alerts | Same events as Telegram, searchable, with acknowledge | Telegram plugin event stream |
| Audit | Every login and action: who, when, from where | portal + firewall audit log |

**Access model**

- **Own login, no external identity provider.** Two ways in: a passkey or FIDO2 security key on its own (user verification required), or password + TOTP. There is no password-only path.
- **FIDO2 / WebAuthn (primary):** hardware keys such as YubiKey and platform passkeys (Windows Hello, iPhone, Android). Register at least two authenticators, one kept offline as a spare. Phishing-resistant because the key is bound to the portal's domain.
- **TOTP (fallback):** RFC 6238, 30 s, 6 digits, any authenticator app. Secret encrypted at rest; each code accepted once.
- **Passwords:** Argon2id hashes, 14+ characters, checked against breached-password lists.
- **Recovery:** 10 single-use recovery codes, stored hashed. Last resort is a reset command run on the portal host from MGMT, never through the web.
- **Sessions:** Secure, HttpOnly, SameSite=Strict cookie; 30 min idle and 12 h absolute; new session ID at every login; CSRF token on every change.
- **Brute-force defence:** 5 attempts per minute per IP and per account with growing delays; 10 failures make CrowdSec ban the IP at the firewall; every success and failure goes to the audit log, and a new device or a failure burst goes to Telegram.
- **Roles:** Viewer (all read) and Operator (actions). Every action re-asks for the FIDO2 key or a TOTP code if the last check was more than 5 minutes ago.
- **Libraries:** py\_webauthn + pyotp with Python/FastAPI, or SimpleWebAuthn + otplib with Node. Both are widely used and maintained.
- **Same login guards your other admin apps:** the proxy asks the portal before forwarding any admin page (forward-auth), so one FIDO2/TOTP login covers them all.

**Control actions (phase 4, allowlist)**

1. Block or unblock an IP or CIDR for a set time (adds to a dedicated pf table).
2. Disconnect a WireGuard peer.
3. Pause or resume a client (moves its MAC to a block alias).
4. Enable or disable the BREAKGLASS interface.
5. Trigger the encrypted config backup.

Each action is a signed, expiring request the firewall agent fetches, checks against its own allowlist, runs, and reports back. Rule edits, NAT, user management and firmware updates stay in the OPNsense GUI on MGMT, never in the portal.

## Defence layers

The protection comes from five layers, and the one link that makes them act as one is CrowdSec: a bad actor caught at any layer is banned at the firewall for every service and device.

| Layer | Runs on | Stops | Status today |
| --- | --- | --- | --- |
| 1. Edge | Cloudflare (proxied DNS, Access, Tunnel) | Unauthenticated access to the portal and admin apps, volumetric floods, known bad bots, origin-IP scanning | Not set up |
| 2. Firewall | OPNsense | Known attacker IPs (FireHOL, CrowdSec community list), port scans, lateral movement between segments | FireHOL, Suricata IDS, segmentation done; CrowdSec to add |
| 3. Proxy WAF | DMZ proxy host | SQL injection, XSS, path traversal, scanner fingerprints, exploit attempts against your published apps (OWASP Core Rule Set, CrowdSec AppSec virtual patches) | Not set up; NPM has no WAF |
| 4. Application | Each published app | Unauthorised use: the portal's FIDO2/TOTP login as a forward-auth gate in front of anything that has an admin page | Not set up |
| 5. Devices | Firewall segments + DNS | Malware callbacks, ads/trackers, a compromised IoT device reaching the PC or NAS | DNS blocklists done; IoT VLAN and DMZ to add |

**How the layers feed each other**

- CrowdSec agents read the proxy and WAF logs (and OPNsense SSH/GUI logs). A detection becomes a ban decision in the CrowdSec Local API.
- The OPNsense CrowdSec bouncer pulls those decisions into a pf table every 10 s, so a scanner caught on one website is blocked from WireGuard and every other site too.
- Suricata alerts and WAF blocks are shown in the portal and sent to Telegram.

**Rollout rule for any blocking layer:** detection-only for 7 days, tune false positives from the portal, then switch to blocking one site at a time.

## Phased delivery

About 9 to 10 weeks of evenings in total; the order matters more than the dates, because the portal is published only after the defences behind it are proven.

&#91;embedded content: delivery plan · 5 phases, a gate between each\]

Durations are estimates for one person working part-time; each gate is a test you run, not a date.

## Capacity, risks and decisions

The biggest risk is the portal becoming the easiest way into the network, so its design keeps it unable to change the firewall except through a short, verified list.

**Where each load runs**

| Component | Host | Expected load |
| --- | --- | --- |
| pf, blocklists, CrowdSec bouncer | OPNsense J4125 | Low; pf tables of tens of thousands of entries are cheap |
| Suricata | OPNsense J4125 | IDS on WAN is fine; IPS at full gigabit is not |
| CrowdSec agent + AppSec / Coraza WAF | DMZ proxy host | Moderate; needs about 1 to 2 GB RAM |
| Portal + VictoriaMetrics + database | DMZ host (NAS container or a Raspberry Pi 5) | Low for one site; a few GB of disk for 90 days |

**Risks**

| Risk | Mitigation |
| --- | --- |
| Portal compromised | Holds no firewall credentials; DMZ cannot reach LAN/MGMT; actions signed, expiring, allowlisted on the firewall |
| Custom login bypassed or brute-forced | Vetted WebAuthn and TOTP libraries; no password-only path; rate limits and CrowdSec bans; an auth test from a logged-out browser and an external scanner at every gate |
| WAF false positives break your sites | 7 days in detection mode; per-site exclusions; block one site at a time |
| Lockout from your own portal or firewall | MGMT cable and BREAKGLASS stay independent of the portal and of Cloudflare |
| Cloudflare outage | Sites and portal unreachable from outside; WireGuard still reaches home directly |
| Telemetry reveals your network | Portal data stays at home; Cloudflare sees only encrypted traffic metadata |
| Scope creep | Each phase ends at its gate; actions beyond the allowlist stay in the OPNsense GUI |

**Decisions needed before phase 0**

- [ ] Cloudflare Tunnel (recommended: no open ports) or keep port forwarding with Cloudflare IP restriction
- [ ] Outer lock in front of the custom login: none, or Cloudflare Access with an emailed one-time PIN as a second door (recommended for the first months, while the login is new)
- [ ] Proxy: keep NPM with the CrowdSec OpenResty bouncer, or move to Caddy or Traefik with Coraza + OWASP CRS
- [ ] Portal: build it custom (UniFi-style, this plan) or start with Grafana dashboards and build only the pages Grafana does poorly (clients, actions)
- [ ] DMZ host: NAS container or a dedicated Raspberry Pi 5
- [ ] Which websites and apps sit behind the proxy today (list each, so the WAF exclusions and Access policies can be written per site)
