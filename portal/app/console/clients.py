"""Device inventory, labels and filters."""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response, StreamingResponse
from .. import actions, crowdsec, db, devices, identity, live, metrics
from ..config import settings
from ..security import Session, audit, check_csrf, require_operator, require_user
from ..templating import flow_layout, render
from .common import _like
from .controls import _client, _device_controls, NAME_MAX

router = APIRouter()

@router.get("/clients")
def clients(request: Request, session: Session = Depends(require_user)):
    segment = request.query_params.get("segment", "")[:100]
    show = "all" if request.query_params.get("show") == "all" else "online"
    term = request.query_params.get("q", "").strip()[:200]
    sql, args = f"{devices.CLIENTS} WHERE 1=1", []
    if segment:
        sql += " AND c.segment=?"
        args.append(segment)
    if show == "online":
        sql += " AND c.online=1"
    if term:
        sql += (" AND (l.name LIKE ? ESCAPE '\\' OR c.hostname LIKE ? ESCAPE '\\' OR c.ip LIKE ? ESCAPE '\\'"
                " OR c.mac LIKE ? ESCAPE '\\' OR c.vendor LIKE ? ESCAPE '\\')")
        args += [_like(term)] * 5
    rows = db.q(sql + " ORDER BY c.online DESC, c.segment, COALESCE(l.name, c.hostname), c.ip LIMIT 501", *args)
    segments = [r["segment"] for r in db.q("SELECT DISTINCT segment FROM clients WHERE segment IS NOT NULL ORDER BY segment")]
    return render(request, "clients.html", session=session, rows=[_client(r) for r in rows[:500]], segments=segments,
                  segment=segment, show=show, q=term, limited=len(rows) > 500, now=db.now(), refresh=30,
                  **_device_controls())


@router.post("/clients/label")
async def label_device(request: Request, session: Session = Depends(require_operator)):
    """Give a device a name and icon. Display only, so it is not a signed firewall action; an empty
    name and the automatic icon put back what the network reports."""
    await check_csrf(request, session)
    form = await request.form()
    mac = str(form.get("mac", "")).strip().lower()
    if not actions.MAC_RE.match(mac):
        raise HTTPException(400, "bad device")
    name = " ".join("".join(ch for ch in str(form.get("name", "")) if ch.isprintable()).split())[:NAME_MAX]
    icon = str(form.get("icon", ""))
    icon = icon if icon in devices.ICONS else ""
    if name or icon:
        db.run("INSERT INTO device_labels(mac, name, icon, updated_by, updated_at) VALUES (?, ?, ?, ?, ?) "
               "ON CONFLICT(mac) DO UPDATE SET name=excluded.name, icon=excluded.icon, "
               "updated_by=excluded.updated_by, updated_at=excluded.updated_at",
               mac, name or None, icon or None, session.username, db.now())
    else:
        db.run("DELETE FROM device_labels WHERE mac=?", mac)
    audit("device_label", True, request, session.username, f"{mac} name={name!r} icon={icon or 'auto'}")
    back = str(form.get("next", "/"))
    return RedirectResponse(back if back in ("/", "/clients") else "/", 303)
