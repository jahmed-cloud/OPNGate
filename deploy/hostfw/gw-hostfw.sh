#!/bin/sh
# Host firewall for the Pis while there are no VLANs. Without VLANs the OPNsense firewall never
# sees Pi-to-LAN traffic, so each Pi has to fence itself in:
#   - Pi 5 (edge): its containers may reach Cloudflare, the Pi 4 (9443, 9080), the listed app
#     upstreams and DNS on the firewall. Nothing else on the LAN.
#   - Pi 4 (services): 9443 only from the Pi 5, 9444 only from the firewall, 9080 only from the
#     Pi 5 and the firewall. Its containers may not open connections into the LAN.
# Both: SSH only from ADMIN_IP.
#   - edge-shared: for an edge host that also serves the LAN (DNS, file shares, other apps). Same container
#     fence as edge, but the host stays reachable; only PROTECTED_PORTS (the direct ports of apps that sit
#     behind the portal sign-in and WAF) are closed to the LAN, so nobody can walk around Caddy.
#
# Usage: gw-hostfw.sh edge|edge-shared|services   (run by gw-hostfw.service after Docker starts)
# This is weaker than VLANs: root on a Pi can remove these rules. Move to VLANs when the switch arrives.
set -eu
ROLE=${1:?edge or services}
. /etc/gw-hostfw.env
IPT="iptables -w"
PRIVATE="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16"

case "$ROLE" in edge|edge-shared|services) ;; *) echo "role must be edge, edge-shared or services" >&2; exit 2 ;; esac

# ---- host INPUT
$IPT -N GW-INPUT 2>/dev/null || $IPT -F GW-INPUT
$IPT -A GW-INPUT -i lo -j RETURN
$IPT -A GW-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
if [ "$ROLE" = edge-shared ]; then
    # Host-network apps behind the portal: direct access only from the admin PC.
    for port in ${PROTECTED_PORTS:-}; do
        $IPT -A GW-INPUT -i "$LAN_IF" -p tcp --dport "$port" -s "$ADMIN_IP" -j RETURN
        $IPT -A GW-INPUT -i "$LAN_IF" -p tcp --dport "$port" -j DROP
    done
else
    # SSH from the admin PC only; everything else that isn't a reply is dropped.
    $IPT -A GW-INPUT -p icmp -s "$LAN_NET" -j RETURN
    $IPT -A GW-INPUT -p tcp -s "$ADMIN_IP" --dport 22 -j RETURN
    $IPT -A GW-INPUT -i "$LAN_IF" -j DROP
fi
$IPT -C INPUT -j GW-INPUT 2>/dev/null || $IPT -I INPUT 1 -j GW-INPUT

# ---- containers (Docker's DOCKER-USER chain sees forwarded and published-port traffic)
# At boot this can run before Docker creates the chain; Docker keeps an existing DOCKER-USER chain.
$IPT -N DOCKER-USER 2>/dev/null || $IPT -F DOCKER-USER
$IPT -A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

if [ "$ROLE" = edge ] || [ "$ROLE" = edge-shared ]; then
    NET=172.30.0.0/24
    $IPT -A DOCKER-USER -s $NET -d $NET -j RETURN
    $IPT -A DOCKER-USER -s $NET -d "$SERVICES_IP" -p tcp -m multiport --dports 9443,9080 -j RETURN
    $IPT -A DOCKER-USER -s $NET -d "$FIREWALL_IP" -p udp --dport 53 -j RETURN
    $IPT -A DOCKER-USER -s $NET -d "$FIREWALL_IP" -p tcp --dport 53 -j RETURN
    # Match the address Caddy dialled: an upstream published by another container on this host has
    # already been rewritten to that container's address by the time it reaches this chain.
    for up in $UPSTREAMS; do
        $IPT -A DOCKER-USER -s $NET -p tcp -m conntrack --ctorigdst "${up%:*}" --ctorigdstport "${up#*:}" -j RETURN
    done
    for p in $PRIVATE; do $IPT -A DOCKER-USER -s $NET -d "$p" -j DROP; done
    if [ "$ROLE" = edge-shared ]; then
        # Container-published apps behind the portal: direct access only from the admin PC.
        for port in ${PROTECTED_PORTS:-}; do
            $IPT -A DOCKER-USER -i "$LAN_IF" -p tcp -m conntrack --ctorigdstport "$port" -s "$ADMIN_IP" -j RETURN
            $IPT -A DOCKER-USER -i "$LAN_IF" -p tcp -m conntrack --ctorigdstport "$port" -j DROP
        done
    fi
    # Anything public is allowed (cloudflared needs Cloudflare on 443 and 7844).
elif [ "$ROLE" = services ]; then
    NET=172.31.0.0/24
    $IPT -A DOCKER-USER -s $NET -d $NET -j RETURN
    # Inbound to published ports, by original destination port.
    $IPT -A DOCKER-USER -i "$LAN_IF" -p tcp -m conntrack --ctorigdstport 9443 -s "$EDGE_IP" -j RETURN
    $IPT -A DOCKER-USER -i "$LAN_IF" -p tcp -m conntrack --ctorigdstport 9444 -s "$FIREWALL_IP" -j RETURN
    $IPT -A DOCKER-USER -i "$LAN_IF" -p tcp -m conntrack --ctorigdstport 9080 -s "$EDGE_IP" -j RETURN
    $IPT -A DOCKER-USER -i "$LAN_IF" -p tcp -m conntrack --ctorigdstport 9080 -s "$FIREWALL_IP" -j RETURN
    $IPT -A DOCKER-USER -i "$LAN_IF" -p tcp -m conntrack --ctorigdstport 9443:9444 -j DROP
    $IPT -A DOCKER-USER -i "$LAN_IF" -p tcp -m conntrack --ctorigdstport 9080 -j DROP
    # Outbound from containers: DNS to the firewall, internet (Telegram, HIBP, CrowdSec hub), no LAN.
    $IPT -A DOCKER-USER -s $NET -d "$FIREWALL_IP" -p udp --dport 53 -j RETURN
    $IPT -A DOCKER-USER -s $NET -d "$FIREWALL_IP" -p tcp --dport 53 -j RETURN
    for p in $PRIVATE; do $IPT -A DOCKER-USER -s $NET -d "$p" -j DROP; done
fi
$IPT -A DOCKER-USER -j RETURN
# Normally Docker adds this jump itself; make sure of it in case we ran first.
$IPT -C FORWARD -j DOCKER-USER 2>/dev/null || $IPT -I FORWARD 1 -j DOCKER-USER
echo "gw-hostfw: $ROLE rules loaded"
