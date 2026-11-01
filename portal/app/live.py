"""Small current-state reads, independent of historical sample aggregation."""
import hashlib
import json

from . import db


def snapshot():
    rows = {r["kind"]: r for r in db.q(
        "SELECT kind,ts,data FROM snapshots WHERE kind IN ('live_interfaces','interfaces','gateway')"
    )}
    fast, full, gateway = (rows.get(k) for k in ("live_interfaces", "interfaces", "gateway"))
    current = fast if fast and (not full or fast["ts"] >= full["ts"]) else full
    source = "live" if current is fast and fast else "telemetry"
    stamp = current["ts"] if current else None
    interfaces = json.loads(current["data"]) if current else []
    interfaces = [{k: i.get(k) for k in ("name", "segment", "rx_bps", "tx_bps")}
                  for i in interfaces[:64] if isinstance(i, dict)]
    wan = next((i for i in interfaces if str(i.get("segment", "")).upper() == "WAN"), {})
    gw = json.loads(gateway["data"]) if gateway else {}
    now = db.now()
    payload = {
        "reported_at": stamp, "source": source,
        "stale": stamp is None or not 0 <= now - stamp < (20 if source == "live" else 120),
        "telemetry_reported_at": gateway["ts"] if gateway else None,
        "gateway_stale": not gateway or not 0 <= now - gateway["ts"] < 120,
        "interfaces": interfaces,
        "wan": {k: wan.get(k) for k in ("rx_bps", "tx_bps")},
        "gateway": {k: gw.get(k) for k in ("online", "latency_ms", "loss_pct", "wan_ip", "uptime_s")},
    }
    revision = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"revision": revision, **payload}
