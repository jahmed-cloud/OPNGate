"""Current device policies and shared presentation state."""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response, StreamingResponse
from .. import actions, crowdsec, db, devices, identity, live, metrics
from ..config import settings
from ..security import Session, audit, check_csrf, require_operator, require_user
from ..templating import flow_layout, render
from .common import _json

RANGES = metrics.RANGES
DEVICE_ACTIONS = ("pause_client", "resume_client", "limit_client", "unlimit_client", "block_domains", "unblock_domains")
NETWORK_ACTIONS = ("block_network", "unblock_network")
FLOW_TOP_DEVICES = 8
FLOW_DEVICES_PER_SEGMENT = 150
NAME_MAX = 40
FLOW_IDLE_BPS = 2_000
FLOW_TRAFFIC = "(COALESCE(c.down_bps, 0) + COALESCE(c.up_bps, 0))"
FLOW_ACTIVE = f"({FLOW_TRAFFIC} >= ? OR c.paused = 1 OR c.speed_limit IS NOT NULL OR c.blocked_domains IS NOT NULL)"


def _client(row) -> dict:
    c = dict(row)
    c["limit"] = _json(c.get("speed_limit")) or None
    c["domains"] = _json(c.get("blocked_domains")) or None
    return c


def _device_controls() -> dict:
    """Waiting and in-force device actions, for the status badges and Manage menus (_device.html)."""
    effects = actions.active_effects()
    pending = {}
    marks = ",".join("?" * len(DEVICE_ACTIONS))
    for row in db.q(f"SELECT id, type, params FROM actions WHERE status IN ('pending_approval','approved','fetched') "
                    f"AND type IN ({marks}) AND expires_at >= ?", *DEVICE_ACTIONS, db.now()):
        pending.setdefault(_json(row["params"]).get("mac"), (row["id"], row["type"]))
    by_kind = lambda kind: {key[1]: aid for aid, key in effects.items() if key[0] == kind}  # noqa: E731
    return {
        "pending": pending, "paused": by_kind("mac"), "limits": by_kind("limit"), "domain_blocks": by_kind("domains"),
        "labels_short": {"pause_client": "Pause waiting", "resume_client": "Resume waiting", "limit_client": "Limit waiting",
                         "unlimit_client": "Unlimit waiting", "block_domains": "Site block waiting",
                         "unblock_domains": "Unblock waiting"},
    }
