"""DNS and VPN views."""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response, StreamingResponse
from .. import actions, crowdsec, db, devices, identity, live, metrics
from ..config import settings
from ..security import Session, audit, check_csrf, require_operator, require_user
from ..templating import flow_layout, render
from . import inventory
from .controls import NETWORK_ACTIONS
from .common import _json


router = APIRouter()


@router.get("/help")
def help_page(request: Request, session: Session = Depends(require_user)):
    return render(request, "help.html", session=session)


@router.get("/networks")
def networks(request: Request, session: Session = Depends(require_user)):
    data = inventory.snapshot()
    pending = {}
    if session.is_operator:
        for row in db.q("SELECT id,type,params FROM actions WHERE type IN (?,?) "
                        "AND status IN ('pending_approval','approved','fetched') AND expires_at>=?",
                        *NETWORK_ACTIONS, db.now()):
            pending.setdefault(_json(row["params"]).get("segment"), (row["id"], row["type"]))
    active = {key[1]: aid for aid, key in actions.active_effects().items() if key[0] == "network"}
    return render(request, "networks.html", session=session, console=data,
                  net_pending=pending, net_blocks=active, refresh=30)

@router.get("/dns")
def dns(request: Request, session: Session = Depends(require_user)):
    ts, data = db.get_snapshot("dns", {})
    return render(request, "dns.html", session=session, data=data, updated=ts, refresh=60)


@router.get("/vpn")
def vpn(request: Request, session: Session = Depends(require_user)):
    ts, peers = db.get_snapshot("vpn", [])
    return render(request, "vpn.html", session=session, peers=peers, updated=ts, now=db.now(), refresh=30)
