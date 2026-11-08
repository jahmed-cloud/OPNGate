"""Current network inventory, independent of historical sample queries."""
from .. import db, live


def snapshot() -> dict:
    now = db.now()
    metadata_at, interfaces = db.get_snapshot("interfaces", [])
    gateway_at, gateway = db.get_snapshot("gateway", {})
    current = live.snapshot()
    rates = {(row.get("name"), row.get("segment")): row for row in current["interfaces"]}
    counts = {row["segment"]: dict(row) for row in db.q(
        "SELECT segment, COUNT(*) AS total, SUM(online) AS online FROM clients GROUP BY segment"
    )}
    networks = []
    for interface in interfaces[:64]:
        name = interface.get("segment") or interface.get("name") or "Unknown"
        wan = name.upper() == "WAN"
        rate = rates.get((interface.get("name"), interface.get("segment")))
        stamp = current["reported_at"] if rate else metadata_at
        # The live snapshot already checks fractional received_at against time.time().
        # Comparing it again with integer db.now() marks same-second reports as future/stale.
        stale = bool(rate and current["stale"]) or not stamp
        if not (rate and current.get("source") == "live"):
            stale = stale or not 0 <= now - stamp < 120
        value = rate if rate else interface
        rx, tx = (None, None) if stale else (value.get("rx_bps"), value.get("tx_bps"))
        count = counts.get(interface.get("segment"), {})
        networks.append({
            "name": name, "interface": interface.get("name") or "", "wan": wan,
            "down_bps": rx if wan else tx, "up_bps": tx if wan else rx,
            "online_clients": int(count.get("online") or 0), "total_clients": int(count.get("total") or 0),
            "reported_at": stamp, "stale": bool(stale), "blocks": interface.get("blocks"),
        })
    last_seen = int(db.kv_get("agent_last_seen", "0"))
    return {"version": "2.0.0", "reported_at": now, "agent_last_seen": last_seen,
            "agent_online": bool(last_seen and 0 <= now - last_seen < 120),
            "networks": networks, "gateway": {"online": gateway.get("online"), "reported_at": gateway_at},
            "rates_reported_at": current["reported_at"], "rates_stale": current["stale"]}
