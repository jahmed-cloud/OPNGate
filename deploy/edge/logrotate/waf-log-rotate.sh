#!/bin/sh
# Coraza appends to one audit log and never rotates it, so it grows without limit. Caddy rotates its own
# access log; this keeps the WAF audit log bounded the same way: past MAX bytes it is compressed to .1.gz
# (older copies shift up, KEEP in total) and emptied in place. The WAF shipper restarts from the top when
# the file shrinks, so at most the last few seconds of entries are skipped.
#
# Install: cp waf-log-rotate.sh /usr/local/sbin/ && cp waf-log-rotate.service waf-log-rotate.timer /etc/systemd/system/
#          systemctl enable --now waf-log-rotate.timer
set -eu
VOLUME=${WAF_LOG_VOLUME:-gw-edge_caddy-logs}
LOG=${1:-$(docker volume inspect --format '{{.Mountpoint}}' "$VOLUME")/coraza-audit.log}
MAX=${WAF_LOG_MAX_BYTES:-52428800}
KEEP=${WAF_LOG_KEEP:-4}
[ -f "$LOG" ] || exit 0
[ "$(stat -c %s "$LOG")" -ge "$MAX" ] || exit 0
i=$KEEP
while [ "$i" -gt 1 ]; do
    [ -f "$LOG.$((i - 1)).gz" ] && mv -f "$LOG.$((i - 1)).gz" "$LOG.$i.gz"
    i=$((i - 1))
done
umask 027
gzip -c "$LOG" > "$LOG.1.gz"
: > "$LOG"
echo "waf-log-rotate: rotated $LOG"
