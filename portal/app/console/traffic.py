"""Historical traffic and current interface rates."""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response, StreamingResponse
from .. import actions, crowdsec, db, devices, identity, live, metrics
from ..config import settings
from ..security import Session, audit, check_csrf, require_operator, require_user
from ..templating import flow_layout, render
from .common import _window, _json, RANGES
from .controls import NETWORK_ACTIONS

router = APIRouter()

@router.get("/traffic")
def traffic(request: Request, session: Session = Depends(require_user)):
    key, _ = _window(request)
    now = db.now()
    data = metrics.window(key, now)
    ts, interfaces = db.get_snapshot("interfaces", [])
    rx = [p["rx_bps"] for p in data["points"] if isinstance(p.get("rx_bps"), (int, float))]
    tx = [p["tx_bps"] for p in data["points"] if isinstance(p.get("tx_bps"), (int, float))]
    latest = db.one("SELECT ts, rx_bps, tx_bps FROM samples WHERE ts <= ? ORDER BY ts DESC LIMIT 1", now)
    stats = {"rx_now": latest["rx_bps"] if latest else None, "tx_now": latest["tx_bps"] if latest else None,
             "updated": latest["ts"] if latest else None,
             "stale": latest is None or now - latest["ts"] >= 120,
             "rx_avg": sum(rx) / len(rx) if rx else None, "tx_avg": sum(tx) / len(tx) if tx else None}
    current = live.snapshot()
    if current["reported_at"] is not None:
        stats.update(rx_now=current["wan"]["rx_bps"], tx_now=current["wan"]["tx_bps"],
                     updated=current["reported_at"], stale=current["stale"])
    # From the devices' side: on the WAN, in is download; on an inside interface, out is the devices' download.
    ifaces = []
    for i in interfaces:
        wan = (i.get("segment") or "").upper() == "WAN"
        ifaces.append({**i, "wan": wan, "down": i.get("rx_bps") if wan else i.get("tx_bps"),
                       "up": i.get("tx_bps") if wan else i.get("rx_bps")})
    peak_iface = max([max(i["down"] or 0, i["up"] or 0) for i in ifaces] or [0])
    net_pending = {}
    if session.is_operator:
        for row in db.q("SELECT id, type, params FROM actions WHERE status IN ('pending_approval','approved','fetched') "
                        "AND type IN (?, ?) AND expires_at >= ?", *NETWORK_ACTIONS, db.now()):
            net_pending.setdefault(_json(row["params"]).get("segment"), (row["id"], row["type"]))
    net_blocks = {key[1]: aid for aid, key in actions.active_effects().items() if key[0] == "network"}
    return render(
        request, "traffic.html", session=session, range_key=key, ranges=list(RANGES), interfaces=ifaces,
        peak_iface=peak_iface, updated=ts, metrics=data, stats=stats, refresh=60,
        net_pending=net_pending, net_blocks=net_blocks,
    )
