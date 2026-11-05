#!/bin/sh
# One-command setup for the whole gateway, run from your admin PC (Linux, macOS or Git Bash).
#
#   cp deploy/deploy.conf.example deploy/deploy.conf    # edit it once
#   sh deploy/deploy.sh all                              # everything, in order
#
# Steps (each is safe to run again; secrets, agent.json and the portal database are never overwritten):
#   check     SSH to every box, Docker on the Pis, required local tools
#   pki       private CA + certificates (deploy/pki/out), only if missing
#   secrets   deploy/services/.env and deploy/edge/.env with random keys, only the empty ones
#   services  Pi 4: portal, ingest, CrowdSec API (copies code, builds, starts)
#   edge      Pi 5: Caddy + Coraza WAF, CrowdSec agent, WAF shipper
#   firewall  OPNsense: telemetry/action agent, pf tables and block rules for pause/block
#   hostfw    host firewall on both Pis (only from ADMIN_IP, so you cannot lock yourself out)
#   user      create the first portal user (you type the password)
#   keys      copy registered passkeys to the firewall so it accepts signed actions
#   update    existing stack: portal, ingest and shipper only; preserves agent/routes/PKI
#   status    quick health check of all three boxes
#   all       check pki secrets services edge firewall [hostfw] user status
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CONF=${DEPLOY_CONF:-$ROOT/deploy/deploy.conf}
[ -f "$CONF" ] || { echo "Missing $CONF - copy deploy/deploy.conf.example and edit it."; exit 1; }
# shellcheck disable=SC1090
. "$CONF"
: "${DOMAIN:?}" "${FIREWALL:?}" "${EDGE:?}" "${EDGE_IP:?}" "${SERVICES:?}" "${SERVICES_IP:?}" "${ADMIN_IP:?}"
REMOTE_DIR=${REMOTE_DIR:-/opt/gateway}
PORTAL_SUBDOMAIN=${PORTAL_SUBDOMAIN:-waf}
PORTAL_HOST=$PORTAL_SUBDOMAIN.$DOMAIN
SSH_KEY=${SSH_KEY:-$HOME/.ssh/id_ed25519}
case "$SSH_KEY" in '~/'*) SSH_KEY=$HOME/${SSH_KEY#\~/} ;; esac
ssh_cmd() { command ssh -i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 "$@"; }
case "$REMOTE_DIR" in /*) ;; *) echo 'REMOTE_DIR must be an absolute POSIX path'; exit 1 ;; esac
case "$REMOTE_DIR" in *[!a-zA-Z0-9_./-]*|*..*) echo 'Unsafe REMOTE_DIR'; exit 1 ;; esac
for target in "$FIREWALL" "$EDGE" "$SERVICES"; do
  case "$target" in root@*[!a-zA-Z0-9@.:-]*|*[!a-zA-Z0-9@.:-]*|-*|'') echo 'Invalid SSH target'; exit 1 ;; esac
  case "$target" in root@*) ;; *) echo 'SSH targets must use root@host'; exit 1 ;; esac
done
case "$PORTAL_SUBDOMAIN" in ''|*[!a-zA-Z0-9-]*) echo 'Invalid PORTAL_SUBDOMAIN'; exit 1 ;; esac
PKI=$ROOT/deploy/pki/out

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok() { printf '   ok  %s\n' "$*"; }
die() { printf '   !!  %s\n' "$*" >&2; exit 1; }
rand() { openssl rand -hex "$1"; }

# Set KEY=VALUE in an env file; with "keep", only when the key is empty or missing.
setenv() { # file key value [keep]
  cur=$(sed -n "s/^$2=//p" "$1" | head -1)
  [ "${4:-}" = keep ] && [ -n "$cur" ] && return 0
  if grep -q "^$2=" "$1"; then
    awk -v k="$2" -v v="$3" 'BEGIN{FS=OFS="="} $1==k{print k"="v; next} {print}' "$1" > "$1.tmp" && mv "$1.tmp" "$1"
  else
    printf '%s=%s\n' "$2" "$3" >> "$1"
  fi
}
getenv() { sed -n "s/^$2=//p" "$1" | head -1; }

# Copy paths (relative to the repo) to a host's REMOTE_DIR, leaving local junk behind.
push() { # host path...
  host=$1; shift
  archive=$(mktemp)
  if ! tar -C "$ROOT" -cf "$archive" --exclude=.venv --exclude=data --exclude=__pycache__ --exclude=.pytest_cache --exclude=tests "$@"; then
    rm -f "$archive"; die "could not create the upload archive; nothing sent"
  fi
  if ! ssh_cmd "$host" "mkdir -p $REMOTE_DIR && tar -xf - -C $REMOTE_DIR" < "$archive"; then
    rm -f "$archive"; die "upload to $host failed"
  fi
  rm -f "$archive"
}

# Refuse to replace a box's certificate with a different one: a fresh local PKI would cut the firewall
# and Pi 5 off from the portal. FORCE_PKI=yes when you really are rotating the CA.
same_cert() { # host remote-file local-file
  [ "${FORCE_PKI:-no}" = yes ] && return 0
  remote=$(ssh_cmd "$1" "cat $2 2>/dev/null" || true)
  [ -z "$remote" ] && return 0
  [ "$remote" = "$(cat "$3")" ] || die "$1:$2 differs from $3. Copy the live certificates into deploy/pki/out, or run with FORCE_PKI=yes to replace them everywhere."
}

compose() { # host dir args...
  host=$1; dir=$2; shift 2
  ssh_cmd "$host" "cd $REMOTE_DIR/deploy/$dir && docker compose $*"
}

step_check() {
  say "Checking tools and SSH"
  for t in ssh tar openssl awk sed grep curl mktemp; do command -v "$t" >/dev/null || die "missing local tool: $t"; done
  ok "local tools"
  [ -f "$SSH_KEY" ] || die "SSH key not found: $SSH_KEY"
  for h in "$SERVICES" "$EDGE"; do
    ssh_cmd "$h" true 2>/dev/null || die "cannot SSH to $h (key login as root needed)"
    if ! ssh_cmd "$h" "docker compose version" >/dev/null 2>&1; then
      if [ "${INSTALL_DOCKER:-no}" = yes ]; then
        echo "   installing Docker on $h"
        ssh_cmd "$h" "curl -fsSL https://get.docker.com | sh"
      else
        die "Docker with compose missing on $h (install it, or set INSTALL_DOCKER=yes)"
      fi
    fi
    ok "$h (SSH, Docker)"
  done
  ssh_cmd "$FIREWALL" "/bin/sh -c 'test -x /usr/local/sbin/configctl'" 2>/dev/null || die "cannot reach OPNsense at $FIREWALL"
  ok "$FIREWALL (OPNsense)"
}

step_pki() {
  say "Certificates"
  complete=yes; found=no
  for file in services.crt services.key agent.crt agent.key ingest-ca.pem; do
    [ -f "$PKI/$file" ] || complete=no
    [ ! -e "$PKI/$file" ] || found=yes
  done
  [ ! -e "$PKI/ingest-ca.key" ] || found=yes
  if [ "$complete" = yes ]; then
    ok "existing certificate set retained"
  elif [ "$found" = yes ]; then
    die "incomplete PKI set; restore the matching files from backup before deploying"
  else
    sh "$ROOT/deploy/pki/make-pki.sh" "$SERVICES_IP"
    ok "created; move deploy/pki/out/ingest-ca.key somewhere offline when you are done"
  fi
}

step_secrets() {
  say "Secrets and settings"
  s=$ROOT/deploy/services/.env; e=$ROOT/deploy/edge/.env
  # An existing install keeps its keys: fetch its files instead of generating new ones.
  for f in "$SERVICES services/.env" "$EDGE edge/.env" "$SERVICES services/crowdsec/parsers/home-whitelist.yaml" \
           "$EDGE edge/crowdsec/parsers/home-whitelist.yaml"; do
    set -- $f
    [ -f "$ROOT/deploy/$2" ] && continue
    if ssh_cmd "$1" "cat $REMOTE_DIR/deploy/$2" > "$ROOT/deploy/$2.tmp" 2>/dev/null && [ -s "$ROOT/deploy/$2.tmp" ]; then
      mv "$ROOT/deploy/$2.tmp" "$ROOT/deploy/$2"; ok "kept existing deploy/$2 from $1"
    else
      rm -f "$ROOT/deploy/$2.tmp"
    fi
  done
  [ -f "$s" ] || cp "$ROOT/deploy/services/.env.example" "$s"
  [ -f "$e" ] || cp "$ROOT/deploy/edge/.env.example" "$e"
  setenv "$s" DOMAIN "$DOMAIN"; setenv "$s" SERVICES_HOST_IP "$SERVICES_IP"; setenv "$s" EDGE_HOST_IP "$EDGE_IP"
  setenv "$s" PORTAL_SUBDOMAIN "$PORTAL_SUBDOMAIN"; setenv "$s" PORTAL_LEGACY_ORIGIN "${LEGACY_PORTAL_ORIGIN:-}"; setenv "$s" PORTAL_RP_NAME "${PORTAL_TITLE:-OPNGate}"; setenv "$s" PORTAL_TZ "${TZ:-UTC}"
  for k in CROWDSEC_CADDY_KEY CROWDSEC_OPNSENSE_KEY PORTAL_WAF_SHIP_TOKEN; do setenv "$s" $k "$(rand 32)" keep; done
  setenv "$s" CROWDSEC_PORTAL_KEY "$(rand 24)" keep
  setenv "$e" DOMAIN "$DOMAIN"; setenv "$e" PORTAL_HOSTS "${PORTAL_HOSTS:-$PORTAL_HOST}"; setenv "$e" SERVICES_HOST_IP "$SERVICES_IP"; setenv "$e" WAF_MODE "${WAF_MODE:-DetectionOnly}"
  # Shared between the boxes: always copied from the services file.
  setenv "$e" CROWDSEC_CADDY_KEY "$(getenv "$s" CROWDSEC_CADDY_KEY)"
  setenv "$e" PORTAL_WAF_SHIP_TOKEN "$(getenv "$s" PORTAL_WAF_SHIP_TOKEN)"
  setenv "$e" CROWDSEC_EDGE_PASSWORD "$(rand 24)" keep
  chmod 600 "$s" "$e" 2>/dev/null || true
  for d in services edge; do
    w=$ROOT/deploy/$d/crowdsec/parsers/home-whitelist.yaml
    if [ ! -f "$w" ]; then
      if [ -n "${HOME_IP:-}" ]; then
        sed "s/203\.0\.113\.10/$HOME_IP/" "$w.example" > "$w"
      else
        cp "$w.example" "$w"
      fi
    fi
  done
  ok "deploy/services/.env, deploy/edge/.env, home whitelists (git-ignored, keep a copy in your password manager)"
}

step_services() {
  say "Pi 4 services ($SERVICES)"
  [ -f "$ROOT/deploy/services/.env" ] || die "run: deploy.sh secrets"
  same_cert "$SERVICES" "$REMOTE_DIR/deploy/pki/out/services.crt" "$PKI/services.crt"
  same_cert "$SERVICES" "$REMOTE_DIR/deploy/pki/out/ingest-ca.pem" "$PKI/ingest-ca.pem"
  push "$SERVICES" portal deploy/services deploy/pki/out/ingest-ca.pem deploy/pki/out/services.crt deploy/pki/out/services.key
  ok "code and certificates copied"
  compose "$SERVICES" services build -q portal portal-ingest
  ssh_cmd "$SERVICES" "cd $REMOTE_DIR/deploy/services && docker compose run --rm -T portal sh -c 'test -f \"\$PORTAL_SECRET_KEY_FILE\" || python -m app.cli gen-key'"
  compose "$SERVICES" services up -d --remove-orphans
  ok "containers up"
  # The edge CrowdSec agent logs in to this API with its own password.
  pw=$(getenv "$ROOT/deploy/edge/.env" CROWDSEC_EDGE_PASSWORD)
  for i in 1 2 3 4 5 6; do
    compose "$SERVICES" services exec -T crowdsec cscli machines add edge-pi5 --password "$pw" --force >/dev/null 2>&1 && break
    sleep 5
  done
  ok "CrowdSec machine edge-pi5 registered"
}

step_edge() {
  say "Pi 5 edge ($EDGE)"
  [ -f "$ROOT/deploy/edge/.env" ] || die "run: deploy.sh secrets"
  same_cert "$EDGE" "$REMOTE_DIR/deploy/pki/out/ingest-ca.pem" "$PKI/ingest-ca.pem"
  push "$EDGE" portal deploy/edge deploy/pki/out/ingest-ca.pem
  compose "$EDGE" edge up -d --build --remove-orphans
  ok "Caddy, Coraza, CrowdSec agent and WAF shipper up (WAF mode ${WAF_MODE:-DetectionOnly})"
}

step_firewall() {
  say "OPNsense agent ($FIREWALL)"
  same_cert "$FIREWALL" /usr/local/etc/fw-agent/agent.crt "$PKI/agent.crt"
  same_cert "$FIREWALL" /usr/local/etc/fw-agent/ingest-ca.pem "$PKI/ingest-ca.pem"
  tar -C "$ROOT" -cf - --exclude=__pycache__ agent deploy/pki/out/agent.crt deploy/pki/out/agent.key deploy/pki/out/ingest-ca.pem \
    | ssh_cmd "$FIREWALL" "/bin/sh -c 'rm -rf /tmp/fw-deploy && mkdir -p /tmp/fw-deploy && tar -xf - -C /tmp/fw-deploy'"
  ssh_cmd "$FIREWALL" /bin/sh -s -- "$SERVICES_IP" "$PORTAL_HOST" "${PAUSE_INTERFACES:-lan}" "${WAN_INTERFACE:-wan}" <<'EOF'
set -eu
SERVICES_IP=$1; PORTAL_HOST=$2; INSIDE=$3; WAN=$4
ETC=/usr/local/etc/fw-agent
FRESH=no; [ -f $ETC/agent.json ] || FRESH=yes
sh /tmp/fw-deploy/agent/install.sh >/dev/null
for f in agent.crt agent.key ingest-ca.pem; do install -m 0600 /tmp/fw-deploy/deploy/pki/out/$f $ETC/$f; done
if [ $FRESH = yes ]; then
  python3 - "$ETC/agent.json" "$SERVICES_IP" "$PORTAL_HOST" <<'PY'
import json, sys
path, ip, host = sys.argv[1:]
c = json.load(open(path))
c["portal_url"] = f"https://{ip}:9444"
c["actions"]["rp_id"], c["actions"]["origin"] = host, f"https://{host}"
json.dump(c, open(path, "w"), indent=2)
PY
  echo "   new $ETC/agent.json: check wan_interface and segments (interface names) before relying on it"
fi
cd /usr/local/opnsense/mvc && php /usr/local/opnsense/scripts/fw-agent/portal_rules.php "$INSIDE" "$WAN"
configctl filter reload >/dev/null
service fw_agent restart >/dev/null 2>&1 || service fw_agent start
rm -rf /tmp/fw-deploy
echo "   agent $(sed -n 's/^VERSION = "\(.*\)"/\1/p' /usr/local/opnsense/scripts/fw-agent/fw_agent.py) running"
EOF
  ok "agent installed; signed actions stay off until you run 'deploy.sh keys' and set actions.enabled"
}

step_hostfw() {
  [ "${INSTALL_HOSTFW:-yes}" = yes ] || { say "Host firewall skipped (INSTALL_HOSTFW=no)"; return 0; }
  say "Host firewall on the Pis"
  for pair in "$EDGE edge" "$SERVICES services"; do
    set -- $pair; host=$1; role=$2
    from=$(ssh_cmd "$host" 'echo ${SSH_CLIENT%% *}')
    [ "$from" = "$ADMIN_IP" ] || die "$host sees you as $from, not ADMIN_IP=$ADMIN_IP; fix deploy.conf first or you would lose SSH"
    push "$host" deploy/hostfw
    ssh_cmd "$host" /bin/sh -s <<EOF
set -eu
cat > /etc/gw-hostfw.env <<'ENV'
LAN_IF=${LAN_IF:-eth0}
LAN_NET=${LAN_NET:?}
FIREWALL_IP=${FIREWALL_LAN_IP:?}
EDGE_IP=$EDGE_IP
SERVICES_IP=$SERVICES_IP
ADMIN_IP=$ADMIN_IP
UPSTREAMS="${UPSTREAMS:-}"
ENV
install -m 0755 $REMOTE_DIR/deploy/hostfw/gw-hostfw.sh /usr/local/sbin/gw-hostfw.sh
install -m 0644 $REMOTE_DIR/deploy/hostfw/gw-hostfw@.service /etc/systemd/system/gw-hostfw@.service
systemctl daemon-reload
systemctl enable gw-hostfw@$role >/dev/null 2>&1
systemctl restart gw-hostfw@$role
EOF
    ssh_cmd "$host" true || die "lost SSH to $host after the host firewall: run 'systemctl stop gw-hostfw@$role' on its console"
    ok "$host ($role)"
  done
}

step_user() {
  say "Portal user"
  n=$(ssh_cmd "$SERVICES" "cd $REMOTE_DIR/deploy/services && docker compose exec -T portal python -m app.cli list-users" 2>/dev/null | grep -c . || true)
  if [ "${n:-0}" -gt 0 ]; then
    ok "users already exist (add more with: deploy.sh user NAME)"
    [ -z "${1:-}" ] && return 0
  fi
  name=${1:-${ADMIN_USER:-admin}}
  echo "   creating '$name' (operator). Type the password when asked; then sign in at https://$PORTAL_HOST"
  ssh -t -i "$SSH_KEY" -o StrictHostKeyChecking=yes -o ConnectTimeout=10 "$SERVICES" "cd $REMOTE_DIR/deploy/services && docker compose exec portal python -m app.cli create-user $name --role operator"
}

step_keys() {
  say "Passkeys to the firewall"
  ssh_cmd "$SERVICES" "cd $REMOTE_DIR/deploy/services && docker compose exec -T portal python -m app.cli export-keys" > "$ROOT/.tmp-operator_keys.json"
  grep -q '"' "$ROOT/.tmp-operator_keys.json" || { rm -f "$ROOT/.tmp-operator_keys.json"; die "no passkeys yet: register one under Account security first"; }
  ssh_cmd "$FIREWALL" "/bin/sh -c 'umask 077; cat > /usr/local/etc/fw-agent/operator_keys.json && service fw_agent restart >/dev/null'" < "$ROOT/.tmp-operator_keys.json"
  rm -f "$ROOT/.tmp-operator_keys.json"
  ok "operator_keys.json updated; set actions.enabled=true in agent.json once to allow signed actions"
}

# Existing-install application update. Keep live Compose files, routes, PKI,
# agent code/configuration, trust and host-firewall rules intact.
step_update() {
  step_check
  say "Updating OPNGate application on the existing stack"
  for pair in "$SERVICES services" "$EDGE edge"; do
    set -- $pair; host=$1; role=$2
    ssh_cmd "$host" "test -f $REMOTE_DIR/deploy/$role/.env && test -f $REMOTE_DIR/deploy/$role/docker-compose.yml" \
      || die "$host has no existing stack; use Install for a new deployment"
  done
  # Do not install the firewall agent here: local telemetry/control extensions
  # are operator-owned and need a separately reviewed firewall upgrade.
  for host in "$SERVICES" "$EDGE"; do
    ssh_cmd "$host" "mkdir -p $REMOTE_DIR/releases; tar -czf $REMOTE_DIR/releases/opngate-app-\$(date +%Y%m%d%H%M%S).tgz -C $REMOTE_DIR portal"
    push "$host" portal
  done
  compose "$SERVICES" services build portal portal-ingest
  compose "$SERVICES" services up -d --no-deps portal-ingest
  compose "$SERVICES" services up -d --no-deps portal
  compose "$EDGE" edge build waf-shipper
  compose "$EDGE" edge up -d --no-deps waf-shipper
  step_status
}

step_status() {
  say "Status"
  issues=0
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "https://$PORTAL_HOST/login") || code=000
  if [ "$code" = 200 ]; then ok "https://$PORTAL_HOST/login answers 200";
  else echo "   !!  https://$PORTAL_HOST/login answered $code (check DNS, TLS and Caddy)"; issues=1; fi
  for pair in "$SERVICES services" "$EDGE edge"; do
    set -- $pair
    if output=$(ssh_cmd "$1" "cd $REMOTE_DIR/deploy/$2 && docker compose ps -a --format '{{.Service}}: {{.Status}}'" 2>/dev/null); then
      printf '%s\n' "$output" | sed "s/^/   $2  /"
      running=$(ssh_cmd "$1" "cd $REMOTE_DIR/deploy/$2 && docker compose ps --status running -q | wc -l") || running=0
      if [ "$running" -lt 3 ]; then echo "   !!  $2 has fewer than three running core services"; issues=1; fi
    else echo "   !!  $1 unreachable"; issues=1; fi
  done
  if output=$(ssh_cmd "$FIREWALL" "/bin/sh -c 'service fw_agent status'" 2>/dev/null); then
    printf '%s\n' "$output" | sed 's/^/   firewall  /'
  else echo "   !!  agent not running"; issues=1; fi
  [ "$issues" -eq 0 ]
}

cmd=${1:-help}; [ $# -gt 0 ] && shift
case $cmd in
  check|pki|secrets|services|edge|firewall|hostfw|keys|status|update) step_$cmd ;;
  user) step_user "${1:-}" ;;
  all) step_check; step_pki; step_secrets; step_services; step_edge; step_firewall; step_hostfw; step_user; step_status
       say "Done. Next: sign in at https://$PORTAL_HOST, add a passkey under Account security, then run: sh deploy/deploy.sh keys" ;;
  *) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
