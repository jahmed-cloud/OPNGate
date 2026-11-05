"""Gateway overview and historical availability."""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response, StreamingResponse
from .. import actions, crowdsec, db, devices, identity, live, metrics
from ..config import settings
from ..security import Session, audit, check_csrf, require_operator, require_user
from ..templating import flow_layout, render
from .common import _window, RANGES
from .flow import _flow_data, _flow_open
from .controls import _device_controls

router = APIRouter()

@router.get("/")
def overview(request: Request, session: Session = Depends(require_user)):
    key, _ = _window(request)
    now = db.now()
    data = metrics.window(key, now)
    gw_ts, gw = db.get_snapshot("gateway", {})
    last_seen = int(db.kv_get("agent_last_seen", "0"))
    agent_online = bool(last_seen and 0 <= now - last_seen < 120)
    wan_state = "unknown" if gw.get("online") is None else "online" if gw["online"] else "offline"
    if last_seen and not agent_online:
        wan_state = "stale"
    segments = [((min(data["end"], p["ts"] + data["bucket_seconds"]) - max(data["start"], p["ts"])) / (data["end"] - data["start"]), "down" if p["wan_up"] == 0 else
                 "up" if p["wan_up"] == 1 else "nodata") for p in data["points"]]
    outages = db.q(
        "SELECT * FROM outages WHERE start_ts <= ? AND COALESCE(end_ts, ?) >= ? "
        "ORDER BY start_ts DESC LIMIT 50", now, now, data["start"],
    )
    latest = db.one("SELECT * FROM samples WHERE ts >= ? AND ts <= ? ORDER BY ts DESC LIMIT 1", data["start"], now)
    flow_gw, flow_wan, flow_segments = ({}, {}, []) if request.headers.get("X-Auto-Refresh") == "1" else _flow_data(gw, latest, _flow_open(request))
    flow_gw["state"] = wan_state
    flow_gw["last_seen"] = last_seen
    flow_height = flow_layout(flow_segments)
    return render(
        request, "overview.html", session=session, range_key=key, ranges=list(RANGES), gw=gw, latest=latest,
        metrics=data, flow_gw=flow_gw, flow_wan=flow_wan, flow_segments=flow_segments, flow_height=flow_height,
        refresh=60, **_device_controls(),
        wan_state=wan_state, agent_online=agent_online, last_seen=last_seen, segments=segments,
        availability=data["summary"]["availability_pct"], outages=outages,
        latency=[p["latency_ms"] for p in data["points"]], loss=[p["loss_pct"] for p in data["points"]],
        open_alerts=db.one("SELECT COUNT(*) AS n FROM events WHERE acked_at IS NULL AND severity != 'info'")["n"],
        recent_alerts=db.q("SELECT * FROM events WHERE acked_at IS NULL ORDER BY ts DESC LIMIT 5"),
        clients_online=db.one("SELECT COUNT(*) AS n FROM clients WHERE online=1")["n"], now=now,
    )
