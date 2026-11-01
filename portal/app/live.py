"""One current RAM-backed frame and bounded SSE fan-out, independent of history."""
import asyncio
import hashlib
import json
import logging
import math
import os
import tempfile
import time

from . import db
from .config import settings

MAX_FRAME_BYTES = 512 * 1024
STREAM_LEASE = 300
SESSION_CHECK_INTERVAL = 5
log = logging.getLogger("portal.live")


def publish(interfaces, clients=None):
    """Atomic last-value replacement. Production mounts live_dir as shared tmpfs."""
    frame = {"received_at": time.time(), "interfaces": interfaces, "clients": clients}
    raw = json.dumps(frame, separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > MAX_FRAME_BYTES:
        raise ValueError("live frame too large")
    settings.live_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = None
    try:
        with tempfile.NamedTemporaryFile(dir=settings.live_dir, prefix=".frame-", delete=False) as fh:
            name = fh.name
            fh.write(raw)
        os.replace(name, settings.live_dir / "current.json")
    finally:
        if name and os.path.exists(name):
            os.unlink(name)


def read_frame():
    try:
        with (settings.live_dir / "current.json").open("rb") as fh:
            raw = fh.read(MAX_FRAME_BYTES + 1)
        if len(raw) > MAX_FRAME_BYTES:
            return None
        frame = json.loads(raw)
        if (not isinstance(frame, dict) or not isinstance(frame.get("received_at"), (int, float))
                or not math.isfinite(frame["received_at"]) or not isinstance(frame.get("interfaces"), list)):
            return None
        return frame
    except (OSError, ValueError):
        return None


def snapshot():
    rows = {r["kind"]: r for r in db.q(
        "SELECT kind,ts,data FROM snapshots WHERE kind IN ('interfaces','gateway')"
    )}
    full, gateway = (rows.get(k) for k in ("interfaces", "gateway"))
    frame = read_frame()
    now = time.time()
    fast = bool(frame and (0 <= now - frame["received_at"] < 5 or not full or frame["received_at"] >= full["ts"]))
    source = "live" if fast else "telemetry"
    stamp = frame["received_at"] if fast else full["ts"] if full else None
    interfaces = frame["interfaces"] if fast else json.loads(full["data"]) if full else []
    interfaces = [{k: i.get(k) for k in ("name", "segment", "rx_bps", "tx_bps")}
                  for i in interfaces[:64] if isinstance(i, dict)]
    wan = next((i for i in interfaces if str(i.get("segment", "")).upper() == "WAN"), {})
    gw = json.loads(gateway["data"]) if gateway else {}
    device_stamp = frame["received_at"] if frame and isinstance(frame.get("clients"), list) else None
    payload = {
        "reported_at": stamp, "source": source,
        "stale": stamp is None or not 0 <= now - stamp < (5 if fast else 120),
        "clients": frame["clients"] if device_stamp is not None else None,
        "clients_reported_at": device_stamp,
        "clients_stale": device_stamp is None or not 0 <= now - device_stamp < 5,
        "interval_seconds": 1,
        "telemetry_reported_at": gateway["ts"] if gateway else None,
        "gateway_stale": not gateway or not 0 <= now - gateway["ts"] < 120,
        "interfaces": interfaces,
        "wan": {k: wan.get(k) for k in ("rx_bps", "tx_bps")},
        "gateway": {k: gw.get(k) for k in ("online", "latency_ms", "loss_pct", "wan_ip", "uptime_s")},
    }
    revision = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"revision": revision, **payload}


class LiveHub:
    """One producer per portal process; slow consumers retain only the latest frame."""
    def __init__(self):
        self.latest = None
        self.listeners = {}

    def subscribe(self, session_id):
        if len(self.listeners) >= 64 or sum(s == session_id for s in self.listeners.values()) >= 4:
            raise ValueError("too many live streams")
        queue = asyncio.Queue(maxsize=1)
        self.listeners[queue] = session_id
        return queue

    def unsubscribe(self, queue):
        self.listeners.pop(queue, None)

    def broadcast(self, data):
        if self.latest and self.latest["revision"] == data["revision"]:
            return
        self.latest = data
        for queue in tuple(self.listeners):
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(data)

    async def run(self):
        while True:
            try:
                self.broadcast(await asyncio.to_thread(snapshot))
            except Exception:
                log.exception("live snapshot refresh failed")
            await asyncio.sleep(0.2)


async def events(request, session, hub, queue):
    from .security import load_session
    started = checked = heartbeat = time.monotonic()
    previous = None
    try:
        data = hub.latest or await asyncio.to_thread(snapshot)
        yield "retry: 1000\n\n"
        while time.monotonic() - started < STREAM_LEASE:
            now = time.monotonic()
            if now - checked >= SESSION_CHECK_INTERVAL:
                active = await asyncio.to_thread(load_session, request)
                if not active or active.id_hash != session.id_hash:
                    yield 'event: auth\ndata: {}\n\n'
                    return
                checked = now
            if data and data["revision"] != previous:
                previous = data["revision"]
                yield f'id: {previous}\nevent: telemetry\ndata: {json.dumps(data, separators=(",", ":"))}\n\n'
                heartbeat = now
            elif now - heartbeat >= 10:
                yield ": keepalive\n\n"
                heartbeat = now
            try:
                data = await asyncio.wait_for(queue.get(), timeout=1)
            except asyncio.TimeoutError:
                data = None
        yield 'event: reconnect\ndata: {}\n\n'
    finally:
        hub.unsubscribe(queue)
