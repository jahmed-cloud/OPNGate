"""Topology refresh stays independent of historical charts."""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response, StreamingResponse
from .. import actions, crowdsec, db, devices, identity, live, metrics
from ..config import settings
from ..security import Session, audit, check_csrf, require_operator, require_user
from ..templating import flow_layout, render
from urllib.parse import unquote
from .controls import _client, _device_controls, FLOW_TOP_DEVICES, FLOW_DEVICES_PER_SEGMENT, FLOW_IDLE_BPS, FLOW_ACTIVE, FLOW_TRAFFIC

router = APIRouter()

def _flow_open(request: Request) -> set:
    """Networks whose devices the flow map shows, from the flow_open cookie portal.js sets when a network is
    clicked ("*" = all). Collapsed networks only cost one row, which keeps the overview light."""
    raw = unquote(request.cookies.get("flow_open", ""))[:4096]
    return {"*"} if raw == "*" else {name for name in raw.split(",") if name}


def _flow_data(gw: dict, latest, open_segments=frozenset({"*"})) -> tuple:
    """On an inside interface the firewall's transmit is the devices' download. An open network shows its few busiest
    devices; "<network>~all" in flow_open shows every online device (busiest first, then idle ones by name). The
    order is re-read on each map refresh (30 s), not on every live rate, so rows do not jump while being read."""
    _, interfaces = db.get_snapshot("interfaces", [])
    wan, segments = {}, []
    counts = {r["segment"]: r["n"] for r in db.q("SELECT segment, COUNT(*) AS n FROM clients WHERE online=1 GROUP BY segment")}
    for interface in interfaces:
        if (interface.get("segment") or "").upper() == "WAN":
            wan = interface
            continue
        name = interface.get("segment") or interface.get("name")
        is_open = "*" in open_segments or name in open_segments
        all_open = f"{name}~all" in open_segments
        online = counts.get(interface.get("segment"), 0)
        shown = []
        if is_open:
            # The short view lists only devices with traffic or a policy; the full one adds the idle ones after them.
            only_active = "" if all_open else f" AND {FLOW_ACTIVE}"
            rows = db.q(f"{devices.CLIENTS} WHERE c.online=1 AND c.segment=?{only_active} "
                        f"ORDER BY {FLOW_ACTIVE} DESC, {FLOW_TRAFFIC} DESC, lower(COALESCE(l.name, c.hostname, c.ip, c.mac)), c.mac LIMIT ?",
                        interface.get("segment"), *([] if all_open else [FLOW_IDLE_BPS]), FLOW_IDLE_BPS,
                        FLOW_DEVICES_PER_SEGMENT if all_open else FLOW_TOP_DEVICES)
            for row in rows:
                c = _client(row)
                c["label"] = devices.label(c)
                shown.append(c)
        hidden = max(0, online - len(shown)) if is_open else 0
        segments.append({
            "name": name, "iface": interface.get("name"), "open": is_open,
            "down_bps": interface.get("tx_bps"), "up_bps": interface.get("rx_bps"),
            "online": online, "devices": shown, "all_open": all_open,
            # Short view: the rest sit behind "Show all". Full view: only what is past the cap (-> Clients page).
            "rest": 0 if all_open else hidden, "more": hidden if all_open else 0,
        })
    return {**gw, "latency_ms": latest["latency_ms"] if latest else gw.get("latency_ms")}, wan, segments


@router.get("/api/flow")
def flow_fragment(request: Request, session: Session = Depends(require_user)):
    """Map-only expansion/topology refresh: never reads historical samples."""
    ts, gw = db.get_snapshot("gateway", {})
    now = db.now()
    last_seen = int(db.kv_get("agent_last_seen", "0"))
    online = bool(last_seen and 0 <= now - last_seen < 120)
    state = "unknown" if gw.get("online") is None else "online" if gw["online"] else "offline"
    if last_seen and not online:
        state = "stale"
    flow_gw, wan, segments = _flow_data(gw, None, _flow_open(request))
    flow_gw.update(state=state, last_seen=last_seen)
    return render(request, "_flow.html", session=session, flow_gw=flow_gw,
                  flow_wan=wan, flow_segments=segments, flow_height=flow_layout(segments),
                  agent_online=online, last_seen=last_seen, refresh=30,
                  **(_device_controls() if session.is_operator else {}))
