"""Active CrowdSec decisions for the Threats page, read from the central API with a bouncer key.

A bouncer key can only read decisions, so the portal cannot change bans through it.
A background worker refreshes every 30 s. Rendering only reads the cache and never waits for the API.
"""
import json
import logging
import re
import threading
import time
import urllib.request

from .config import settings

log = logging.getLogger("portal")
_lock = threading.Lock()
_cache = {"at": 0.0, "data": None, "updated_at": None, "error": None}
_DURATION = re.compile(r"(-?[\d.]+)(h|ms|m|s)")
_UNIT = {"h": 3600, "m": 60, "s": 1, "ms": 0.001}


def _seconds(duration: str) -> int:
    """Go duration such as '3h59m12.5s' -> seconds left."""
    return int(sum(float(n) * _UNIT[u] for n, u in _DURATION.findall(str(duration or ""))))


def _fetch() -> list:
    req = urllib.request.Request(settings.crowdsec_lapi.rstrip("/") + "/v1/decisions",
                                 headers={"X-Api-Key": settings.crowdsec_key, "User-Agent": "portal"})
    with urllib.request.urlopen(req, timeout=3) as response:
        rows = json.loads(response.read() or b"null")
    return rows if isinstance(rows, list) else []


def refresh_once():
    """Run only from the background worker (or a controlled diagnostic/test)."""
    if not (settings.crowdsec_lapi and settings.crowdsec_key):
        return
    try:
        rows = [r for r in _fetch() if isinstance(r, dict)]
        data = _summarize(rows)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        log.warning("CrowdSec API unavailable: %s", exc)
        with _lock:
            _cache.update(error="CrowdSec API unavailable")
        return
    with _lock:
        _cache.update(at=time.monotonic(), data=data, updated_at=int(time.time()), error=None)


def _summarize(rows):
    by_origin, by_scenario, local = {}, {}, []
    for r in rows:
        origin = str(r.get("origin") or "?")
        by_origin[origin] = by_origin.get(origin, 0) + 1
        # Community blocklists add thousands of entries; list only bans raised by this network.
        if origin.lower() in ("crowdsec", "cscli", "console"):
            scenario = str(r.get("scenario") or "?")
            by_scenario[scenario] = by_scenario.get(scenario, 0) + 1
            local.append({"value": str(r.get("value") or "")[:64], "scope": str(r.get("scope") or ""),
                          "type": str(r.get("type") or ""), "scenario": scenario[:120], "origin": origin,
                          "left_s": _seconds(r.get("duration"))})
    local.sort(key=lambda r: -r["left_s"])
    data = {"total": len(rows), "local": len(local),
            "by_origin": sorted(by_origin.items(), key=lambda kv: -kv[1]),
            "by_scenario": sorted(by_scenario.items(), key=lambda kv: -kv[1])[:20],
            "recent": local[:50]}
    return data


def decisions() -> dict | None:
    """Read a last-known snapshot without performing network I/O or waiting on it."""
    if not (settings.crowdsec_lapi and settings.crowdsec_key):
        return None
    with _lock:
        data = _cache["data"]
        age = max(0, time.monotonic() - _cache["at"]) if data is not None else 0
        result = dict(data) if data is not None else {"total": 0, "local": 0, "by_origin": [], "by_scenario": [], "recent": []}
        result.update(loading=data is None and not _cache.get("error"), stale=data is None or age >= 60 or bool(_cache.get("error")),
                      updated_at=_cache.get("updated_at"), error=_cache.get("error"))
        result["recent"] = [{**row, "left_s": max(0, row["left_s"] - int(age))} for row in result["recent"]]
        return result


def start_background(stop):
    def loop():
        while not stop.is_set():
            refresh_once()
            if stop.wait(30):
                break
    worker = threading.Thread(target=loop, daemon=True, name="crowdsec-cache")
    worker.start()
    return worker
