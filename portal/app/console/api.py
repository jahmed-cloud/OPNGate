"""Authenticated current and historical telemetry APIs."""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response, StreamingResponse
from .. import actions, crowdsec, db, devices, identity, live, metrics
from ..config import settings
from ..security import Session, audit, check_csrf, require_operator, require_user
from ..templating import flow_layout, render
import csv
import io
from datetime import datetime, timezone
from .common import _window
from . import inventory

router = APIRouter()


@router.get("/api/console")
def console_snapshot(request: Request, session: Session = Depends(require_user)):
    return inventory.snapshot()

@router.get("/api/metrics")
def metrics_api(request: Request, session: Session = Depends(require_user)):
    return metrics.window(_window(request)[0])


@router.get("/api/live")
def live_api(request: Request, session: Session = Depends(require_user)):
    data = live.snapshot()
    if request.headers.get("x-live-revision") == data["revision"]:
        return Response(status_code=204)
    return data


@router.get("/api/live/stream")
async def live_stream(request: Request, session: Session = Depends(require_user)):
    hub = request.app.state.live_hub
    try:
        queue = hub.subscribe(session.id_hash)
    except ValueError:
        raise HTTPException(429, "Too many live streams; use the JSON fallback")
    return StreamingResponse(live.events(request, session, hub, queue), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store, no-transform", "X-Accel-Buffering": "no"})


@router.get("/exports/metrics.csv")
def metrics_csv(request: Request, session: Session = Depends(require_user)):
    data = metrics.window(_window(request)[0])
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["bucket_start_utc", "bucket_seconds", "sample_count", "wan_up", "latency_ms",
                     "loss_pct", "rx_bps", "tx_bps"])
    for point in data["points"]:
        writer.writerow([
            datetime.fromtimestamp(point["ts"], timezone.utc).isoformat(), data["bucket_seconds"],
            point["sample_count"], point["wan_up"], *(point[field] for field in metrics.FIELDS),
        ])
    return Response(output.getvalue(), media_type="text/csv", headers={
        "Content-Disposition": f'attachment; filename="gateway-metrics-{data["range_key"]}.csv"',
    })


@router.get("/healthz")
def healthz():
    db.one("SELECT 1")
    return {"ok": True}
