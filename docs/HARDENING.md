# Host and network hardening

Steps applied around OPNGate on the reference deployment (2026-11-16). None are done by the installer; apply and verify each one from a session you can afford to lose, and keep console access to every host.

## Checklist

| Area | Setting | Verify |
|---|---|---|
| Linux hosts | SSH keys only, no root password login | `sshd -T \| grep -E 'passwordauth\|permitrootlogin'` |
| Linux hosts | Automatic Debian security updates | `systemctl is-active unattended-upgrades apt-daily-upgrade.timer` |
| Services host | Portal TLS key readable only by the container user | `ls -l deploy/pki/out/services.key` shows `-rw-------` and uid 10001 |
| Edge host | Host firewall (`edge` or `edge-shared`) | `systemctl is-active gw-hostfw@edge-shared`; direct app ports time out from another LAN host |
| Edge host | WAF audit log rotation | `systemctl is-active waf-log-rotate.timer` |
| Edge | HSTS on every proxied site | `curl -sI https://<site>/ \| grep -i strict-transport` |
| Edge | Admin consoles (NAS, remote desktop, Wake-on-LAN) behind the portal sign-in | a signed-out request is redirected to `/login` |
| OPNsense | SSH keys only | `sshd -T` on the firewall; a password attempt is refused |
| OPNsense | WAN 80/443 only from Cloudflare | `pfctl -sr \| grep 'port = https'` shows `from <CLOUDFLARE_V4>` |
| OPNsense | CrowdSec bans enforced by pf | `pfctl -t crowdsec_blocklists -T show \| wc -l`; `cscli bouncers list` shows a recent pull |

## Linux hosts (edge and services)

Key-only SSH. The drop-in name sorts before distribution defaults, and sshd keeps the first value it reads:

```sh
printf 'PasswordAuthentication no\nPermitRootLogin prohibit-password\n' > /etc/ssh/sshd_config.d/00-gateway-hardening.conf
sshd -t && systemctl reload ssh
```

Open a second session with your key before closing the first. Undo by deleting the file and reloading.

Automatic security updates (no automatic reboot). DietPi masks the apt timers, so unmask them:

```sh
apt-get install -y unattended-upgrades
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades
systemctl unmask apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service
systemctl enable --now unattended-upgrades apt-daily.timer apt-daily-upgrade.timer
```

Docker packages come from Docker's own repository and are not upgraded by this; plan those yourself.

On the services host, restrict the portal's private key to the container user (uid 10001):

```sh
chown 10001:10001 deploy/pki/out/services.key && chmod 600 deploy/pki/out/services.key
```

## Edge host firewall

`deploy/hostfw/gw-hostfw.sh` has two edge roles:

- `edge`: for a dedicated edge host. Drops all LAN input except SSH from `ADMIN_IP`.
- `edge-shared`: for an edge host that also serves the LAN (DNS, file shares, other apps). The host stays reachable; only `PROTECTED_PORTS` are closed to the LAN (except `ADMIN_IP`).

Both fence the gateway containers: they may reach the services host (9443, 9080), DNS on the firewall, the `UPSTREAMS` list and the internet, and nothing else on private networks. A compromised Caddy cannot explore the LAN.

`PROTECTED_PORTS` are the direct ports of apps that sit behind the portal sign-in and WAF. Without the rule, anyone on the LAN can open `http://<edge>:<port>` and skip both. Set them in `/etc/gw-hostfw.env` (see `hostfw.env.example`), then:

```sh
install -m 0755 deploy/hostfw/gw-hostfw.sh /usr/local/sbin/
install -m 0644 deploy/hostfw/gw-hostfw@.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now gw-hostfw@edge-shared
```

Test from the Caddy container that every upstream still answers, and from another LAN host that the protected ports time out. Emergency undo:

```sh
systemctl disable --now gw-hostfw@edge-shared
iptables -F DOCKER-USER; iptables -A DOCKER-USER -j RETURN; iptables -F GW-INPUT
```

Limits: IPv4 only (add ip6tables rules if the LAN carries IPv6), root on the host can remove the rules, and VLANs remain the stronger answer.

## WAF audit log rotation

Coraza appends to `coraza-audit.log` and never rotates it. `deploy/edge/logrotate/` holds a script and timer that compress it to `.1.gz` past 50 MiB (four copies kept) and empty it in place; the WAF shipper restarts from the top when the file shrinks.

```sh
install -m 0755 deploy/edge/logrotate/waf-log-rotate.sh /usr/local/sbin/
install -m 0644 deploy/edge/logrotate/waf-log-rotate.service deploy/edge/logrotate/waf-log-rotate.timer /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now waf-log-rotate.timer
```

`WAF_LOG_MAX_BYTES`, `WAF_LOG_KEEP` and `WAF_LOG_VOLUME` override the defaults. Entries written in the seconds between the last shipper read and the truncation are not shipped.

## OPNsense

**CrowdSec bouncer.** Install `os-crowdsec` (System > Firmware > Plugins). Under Services > CrowdSec > Settings: disable the agent and the local API, enable the firewall bouncer, the rules and "manual LAPI configuration". Then point the bouncer at the services host in `/usr/local/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml`:

```yaml
api_url: http://<services-host>:9080/
api_key: <CROWDSEC_OPNSENSE_KEY from deploy/services/.env>
```

Run `service crowdsec_firewall restart` and make sure the local `crowdsec` service is stopped. Add a short test decision on the services host with `cscli decisions add --ip 203.0.113.77 --duration 5m`; it should appear in `pfctl -t crowdsec_blocklists -T show` within about ten seconds. Delete it afterwards.

**Cloudflare-only web ports.** Create a network alias `CLOUDFLARE_V4` with the ranges from https://www.cloudflare.com/ips-v4 and set it as the source of the WAN rule that passes 80/443 to the edge. Caddy already drops other sources (`cf_only`); this stops them one hop earlier. Keep the alias and the Caddyfile list in sync. HTTP-01 certificate renewal keeps working because it also arrives through Cloudflare.

**SSH.** System > Settings > Administration: leave root login on with an authorized key, turn password login off, and listen only on management interfaces.

## Return URLs after sign-in

Forward-auth signs the return URL it hands to the login page (HMAC over the URL and a timestamp, 30 minutes). A cross-site `next=` without a fresh signature, for example from browser history or a crafted link, lands on the console. Local paths need no signature.

## Open items

- Published sites rely on each app's own patch level once a user is signed in; keep the NAS and other consoles updated.
- OPNsense package advisories (`pkg audit`) clear only with upstream firmware updates.
- The services and edge hosts share one LAN; VLAN separation is still the intended end state.
