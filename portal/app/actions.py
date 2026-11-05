"""Phase 4 control actions.

The portal never holds firewall credentials. An operator approves each action by
signing it with their security key: the WebAuthn challenge is the SHA-256 of the
exact action payload. The firewall agent fetches the payload plus the signed
assertion and verifies the signature itself against public keys that were copied
to the firewall from MGMT. A compromised portal can queue requests, but it cannot
produce an approval the firewall will accept.
"""
import hashlib
import ipaddress
import json
import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from . import db, notify, wa
from .devices import BLOCK_LISTS
from .config import settings
from . import identity
from .security import Session, audit, check_csrf, require_operator
from .templating import render

router = APIRouter()

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
WG_IF_RE = re.compile(r"^wg[0-9]{1,2}$")
# What Unbound's blocklist accepts: a domain with at least one dot (the agent checks the same rule).
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)((?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z][a-z0-9-]{0,62}$")
SEGMENT_RE = re.compile(r"^[A-Za-z0-9 _-]{1,20}$")

ACTION_LABELS = {
    "block_ip": "Block an IP or CIDR",
    "unblock_ip": "Unblock an IP or CIDR",
    "wg_disconnect": "Disconnect a WireGuard peer",
    "pause_client": "Pause a client",
    "resume_client": "Resume a client",
    "limit_client": "Limit a client's speed",
    "unlimit_client": "Remove a client's speed limit",
    "block_domains": "Block websites for a client",
    "unblock_domains": "Allow all websites for a client",
    "block_network": "Block websites on a network",
    "unblock_network": "Allow all websites on a network",
    "breakglass": "Enable / disable BREAKGLASS",
    "backup_config": "Run encrypted config backup",
}


class InvalidAction(ValueError):
    pass


def _cidr(value: str) -> str:
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError as exc:
        raise InvalidAction("not an IP or CIDR") from exc
    if net.prefixlen < (16 if net.version == 4 else 48):
        raise InvalidAction("network too large (max /16 IPv4, /48 IPv6)")
    if net.is_private or net.is_loopback or net.is_link_local or net.is_multicast:
        raise InvalidAction("refusing to block private/local addresses; use Pause client for LAN devices")
    return str(net)


def _minutes(value, allow_zero: bool = False) -> int:
    try:
        minutes = int(value)
    except (TypeError, ValueError) as exc:
        raise InvalidAction("minutes must be a number") from exc
    low = 0 if allow_zero else 1
    if not low <= minutes <= 10080:
        raise InvalidAction(f"minutes must be {low}-10080")
    return minutes


def _mac(value: str) -> str:
    mac = str(value).strip().lower().replace("-", ":")
    if not MAC_RE.match(mac):
        raise InvalidAction("not a MAC address")
    return mac


def _mbps(value, name: str) -> float:
    try:
        mbps = round(float(value), 1)
    except (TypeError, ValueError) as exc:
        raise InvalidAction(f"{name} must be a number of Mbit/s") from exc
    if not 0.1 <= mbps <= 1000:
        raise InvalidAction(f"{name} must be 0.1-1000 Mbit/s")
    return mbps


def _domains(value) -> list:
    """Domains from free text ("https://www.youtube.com/watch, tiktok.com"): scheme, path, port, a leading
    "*." or "www." are dropped, since a block always covers the domain and all its subdomains."""
    items = value if isinstance(value, list) else re.split(r"[\s,;]+", str(value or ""))
    found = set()
    for item in items:
        d = str(item).strip().lower()
        if not d:
            continue
        d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d).split("/")[0].split("?")[0].split(":")[0].rstrip(".")
        for prefix in ("*.", "www."):
            if d.startswith(prefix) and "." in d[len(prefix):]:
                d = d[len(prefix):]
        if not DOMAIN_RE.match(d):
            raise InvalidAction(f"not a domain name: {str(item).strip()[:60]}")
        found.add(d)
    if len(found) > 50:
        raise InvalidAction("enter at most 50 domain names")
    return sorted(found)


def _lists(value) -> list:
    items = value if isinstance(value, list) else [value] if value else []
    if any(i not in BLOCK_LISTS for i in items):
        raise InvalidAction("unknown blocklist")
    return sorted(set(items))


def _segment(value) -> str:
    segment = str(value or "").strip()
    if not SEGMENT_RE.match(segment):
        raise InvalidAction("not a network name")
    if segment.upper() == "WAN":
        raise InvalidAction("the WAN has no devices asking the firewall's DNS; pick an inside network")
    return segment


def validate(kind: str, raw: dict) -> dict:
    """Normalise parameters. The agent re-validates with its own copy of these rules."""
    if kind == "block_ip":
        return {"cidr": _cidr(raw.get("cidr", "")), "minutes": _minutes(raw.get("minutes", 60))}
    if kind == "unblock_ip":
        return {"cidr": _cidr(raw.get("cidr", ""))}
    if kind == "wg_disconnect":
        iface, key = str(raw.get("interface", "")).strip(), str(raw.get("public_key", "")).strip()
        if not WG_IF_RE.match(iface) or not WG_KEY_RE.match(key):
            raise InvalidAction("need a wgN interface and a peer public key")
        return {"interface": iface, "public_key": key}
    if kind == "pause_client":
        return {"mac": _mac(raw.get("mac", "")), "minutes": _minutes(raw.get("minutes", 0), allow_zero=True)}
    if kind == "resume_client":
        return {"mac": _mac(raw.get("mac", ""))}
    if kind == "limit_client":
        return {"mac": _mac(raw.get("mac", "")), "down_mbps": _mbps(raw.get("down_mbps"), "Download"),
                "up_mbps": _mbps(raw.get("up_mbps"), "Upload"),
                "minutes": _minutes(raw.get("minutes", 0), allow_zero=True)}
    if kind == "unlimit_client":
        return {"mac": _mac(raw.get("mac", ""))}
    if kind == "block_domains":
        domains, lists = _domains(raw.get("domains")), _lists(raw.get("lists"))
        if not domains and not lists:
            raise InvalidAction("pick a category or enter some domain names")
        return {"mac": _mac(raw.get("mac", "")), "domains": domains, "lists": lists,
                "minutes": _minutes(raw.get("minutes", 0), allow_zero=True)}
    if kind == "unblock_domains":
        return {"mac": _mac(raw.get("mac", ""))}
    if kind == "block_network":
        domains, lists = _domains(raw.get("domains")), _lists(raw.get("lists"))
        if not domains and not lists:
            raise InvalidAction("pick a category or enter some domain names")
        return {"segment": _segment(raw.get("segment")), "domains": domains, "lists": lists,
                "minutes": _minutes(raw.get("minutes", 0), allow_zero=True)}
    if kind == "unblock_network":
        return {"segment": _segment(raw.get("segment"))}
    if kind == "breakglass":
        return {"enable": str(raw.get("enable", "")).lower() in ("1", "true", "on", "yes")}
    if kind == "backup_config":
        return {}
    raise InvalidAction("unknown action")


def reverse_of(kind: str, params: dict):
    """The action that undoes a finished one, or None (a WireGuard disconnect undoes itself on the
    next WireGuard reload; a backup has nothing to undo)."""
    if kind == "pause_client":
        return "resume_client", {"mac": params["mac"]}
    if kind == "limit_client":
        return "unlimit_client", {"mac": params["mac"]}
    if kind == "block_domains":
        return "unblock_domains", {"mac": params["mac"]}
    if kind == "block_network":
        return "unblock_network", {"segment": params["segment"]}
    if kind == "block_ip":
        return "unblock_ip", {"cidr": params["cidr"]}
    if kind == "breakglass":
        return "breakglass", {"enable": not params.get("enable")}
    return None


EFFECT_ACTIONS = ("pause_client", "limit_client", "block_domains", "block_network", "block_ip")


def active_effects() -> dict:
    """Finished pause/limit/block actions still in force (not expired, not undone since), keyed by action id.
    Keys: ("mac", mac) for pauses, ("limit", mac) for speed limits, ("domains", mac) for blocked sites,
    ("network", segment) for a network's blocked sites, ("cidr", cidr) for blocks."""
    now = db.now()
    active, undone = {}, set()
    # rowid breaks ties: an undo created in the same second must still count as newer.
    for row in db.q("SELECT * FROM actions WHERE status='done' ORDER BY created_at DESC, rowid DESC LIMIT 500"):
        params = json.loads(row["params"])
        if row["type"] == "resume_client":
            undone.add(("mac", params.get("mac")))
        elif row["type"] == "unlimit_client":
            undone.add(("limit", params.get("mac")))
        elif row["type"] == "unblock_domains":
            undone.add(("domains", params.get("mac")))
        elif row["type"] == "unblock_network":
            undone.add(("network", params.get("segment")))
        elif row["type"] == "unblock_ip":
            undone.add(("cidr", params.get("cidr")))
        elif row["type"] in EFFECT_ACTIONS:
            key = {"pause_client": ("mac", params.get("mac")), "limit_client": ("limit", params.get("mac")),
                   "block_domains": ("domains", params.get("mac")), "block_network": ("network", params.get("segment")),
                   "block_ip": ("cidr", params.get("cidr"))}[row["type"]]
            minutes = params.get("minutes") or 0
            expired = minutes and (row["finished_at"] or row["created_at"]) + minutes * 60 < now
            if key not in undone and not expired:
                active[row["id"]] = key
            undone.add(key)  # older actions on the same target are superseded by this one
    return active


def canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(payload_str: str) -> bytes:
    return hashlib.sha256(payload_str.encode("utf-8")).digest()


def create(kind: str, params: dict, username: str) -> str:
    now = db.now()
    action_id = str(uuid.uuid4())
    payload = canonical({
        "v": 1,
        "id": action_id,
        "type": kind,
        "params": params,
        "created_by": username,
        "created_at": now,
        "expires_at": now + settings.action_ttl,
        "rp_id": identity.current().rp_id,
        "origin": identity.current().origin,
    })
    db.run(
        "INSERT INTO actions(id, type, params, payload, created_by, created_at, expires_at, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 'pending_approval')",
        action_id, kind, json.dumps(params), payload, username, now, now + settings.action_ttl,
    )
    return action_id


# ------------------------------------------------------------------ routes

@router.get("/actions")
def actions_page(request: Request, session: Session = Depends(require_operator)):
    rows = db.q("SELECT * FROM actions ORDER BY created_at DESC LIMIT 100")
    has_key = db.one("SELECT 1 FROM credentials WHERE user_id=? AND rp_id=?", session.user_id, identity.current().rp_id) is not None
    clients = db.q("SELECT c.mac, COALESCE(l.name, c.hostname) AS hostname, c.ip FROM clients c "
                   "LEFT JOIN device_labels l ON l.mac = c.mac ORDER BY 2")
    _, vpn = db.get_snapshot("vpn", [])
    return render(
        request, "actions.html", session=session, rows=rows, labels=ACTION_LABELS, has_key=has_key,
        clients=clients, vpn=vpn, prefill=dict(request.query_params), error=request.query_params.get("error"),
        active=active_effects(),
    )


@router.post("/actions/new")
async def new_action(request: Request, session: Session = Depends(require_operator)):
    await check_csrf(request, session)
    data = await request.form()
    form = dict(data)
    if "lists" in data:
        form["lists"] = data.getlist("lists")  # checkboxes: one entry per ticked box
    kind = form.pop("type", "")
    form.pop("csrf", None)
    try:
        params = validate(kind, form)
    except InvalidAction as exc:
        return RedirectResponse(f"/actions?error={exc}", 303)
    action_id = create(kind, params, session.username)
    audit("action_created", True, request, session.username, f"{kind} {json.dumps(params)}")
    return RedirectResponse(f"/actions/{action_id}", 303)


def _get(action_id: str):
    row = db.one("SELECT * FROM actions WHERE id=?", action_id)
    if not row:
        raise HTTPException(404)
    return row


def _check_identity(row):
    payload = json.loads(row["payload"])
    here = identity.current()
    if (payload.get("rp_id"), payload.get("origin")) != (here.rp_id, here.origin):
        raise HTTPException(409, "Approve this action at the portal address where it was created")


@router.get("/actions/{action_id}")
def action_detail(action_id: str, request: Request, session: Session = Depends(require_operator)):
    row = _get(action_id)
    undo = reverse_of(row["type"], json.loads(row["params"])) if row["status"] == "done" else None
    if undo and row["type"] in EFFECT_ACTIONS and action_id not in active_effects():
        undo = None  # already expired or undone
    return render(request, "action_detail.html", session=session, a=row, labels=ACTION_LABELS,
                  payload=json.dumps(json.loads(row["payload"]), indent=2), undo=undo,
                  refresh=5 if row["status"] in ("approved", "fetched") else None)


@router.post("/actions/{action_id}/undo")
async def undo(action_id: str, request: Request, session: Session = Depends(require_operator)):
    """Prepare the reverse of a finished action. It still has to be signed like any other action."""
    await check_csrf(request, session)
    row = _get(action_id)
    reverse = reverse_of(row["type"], json.loads(row["params"])) if row["status"] == "done" else None
    if not reverse:
        return RedirectResponse("/actions?error=That action can't be undone", 303)
    kind, params = reverse
    new_id = create(kind, validate(kind, {**params, "enable": "1" if params.get("enable") else "0"}), session.username)
    audit("action_created", True, request, session.username, f"undo {action_id}: {kind} {json.dumps(params)}")
    return RedirectResponse(f"/actions/{new_id}", 303)


@router.post("/actions/{action_id}/begin")
async def approve_begin(action_id: str, request: Request, session: Session = Depends(require_operator)):
    await check_csrf(request, session)
    row = _get(action_id)
    _check_identity(row)
    if row["status"] != "pending_approval" or row["expires_at"] < db.now():
        raise HTTPException(409, "Action is not awaiting approval")
    options, _ = wa.authentication_options(user_id=session.user_id, challenge=digest(row["payload"]))
    return JSONResponse(json.loads(options))


@router.post("/actions/{action_id}/approve")
async def approve_finish(action_id: str, request: Request, session: Session = Depends(require_operator)):
    await check_csrf(request, session)
    row = _get(action_id)
    _check_identity(row)
    if row["status"] != "pending_approval" or row["expires_at"] < db.now():
        raise HTTPException(409, "Action is not awaiting approval")
    body = await request.json()
    credential = body.get("credential", {})
    try:
        wa.finish_authentication(credential, digest(row["payload"]), user_id=session.user_id)
    except wa.WebAuthnError:
        audit("action_approve_failed", False, request, session.username, action_id)
        raise HTTPException(401, "Signature not accepted")
    cur = db.run(
        "UPDATE actions SET status='approved', assertion=?, approved_at=? WHERE id=? AND status='pending_approval'",
        json.dumps(credential), db.now(), action_id,
    )
    if cur.rowcount != 1:
        raise HTTPException(409, "Action changed while approving")
    audit("action_approved", True, request, session.username, f"{row['type']} {row['params']}")
    notify.send(f"{session.username} approved {ACTION_LABELS[row['type']]}: {row['params']}")
    return {"ok": True}


@router.post("/actions/{action_id}/cancel")
async def cancel(action_id: str, request: Request, session: Session = Depends(require_operator)):
    await check_csrf(request, session)
    cur = db.run(
        "UPDATE actions SET status='cancelled', finished_at=? WHERE id=? AND status IN ('pending_approval','approved')",
        db.now(), action_id,
    )
    if cur.rowcount:
        audit("action_cancelled", True, request, session.username, action_id)
    return RedirectResponse("/actions", 303)
