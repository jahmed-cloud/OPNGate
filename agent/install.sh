#!/bin/sh
# Install the agent on OPNsense. Run as root from a shell on MGMT, in this directory:
#   scp -r agent root@<firewall-mgmt-ip>:/tmp/ && ssh root@<firewall-mgmt-ip> 'sh /tmp/agent/install.sh'
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ETC=/usr/local/etc/fw-agent

install -d -m 0755 /usr/local/opnsense/scripts/fw-agent
install -m 0755 "$HERE/fw_agent.py" /usr/local/opnsense/scripts/fw-agent/fw_agent.py
install -m 0644 "$HERE/shaper.php" /usr/local/opnsense/scripts/fw-agent/shaper.php
install -m 0644 "$HERE/portal_rules.php" /usr/local/opnsense/scripts/fw-agent/portal_rules.php
install -m 0755 "$HERE/rc.d/fw_agent" /usr/local/etc/rc.d/fw_agent
install -d -m 0700 "$ETC" /var/db/fw-agent

if [ ! -f "$ETC/agent.json" ]; then
    install -m 0600 "$HERE/agent.example.json" "$ETC/agent.json"
    echo "Edit $ETC/agent.json (interfaces, portal_url, rp_id/origin) before starting."
fi
if [ ! -f "$ETC/backup.pass" ]; then
    (umask 077 && openssl rand -base64 32 > "$ETC/backup.pass")
    echo "Generated $ETC/backup.pass - copy it to your password manager; backups are useless without it."
fi
touch /var/log/portal-events.jsonl

for f in ingest-ca.pem agent.crt agent.key operator_keys.json; do
    [ -f "$ETC/$f" ] || echo "Still needed: $ETC/$f"
done

# OPNsense regenerates rc.conf; use rc.conf.d so the setting survives.
echo 'fw_agent_enable="YES"' > /etc/rc.conf.d/fw_agent

echo "Test collection:   python3 /usr/local/opnsense/scripts/fw-agent/fw_agent.py -c $ETC/agent.json --once"
echo "Start the service: service fw_agent start   (logs: /var/log/messages, tag fw-agent)"
