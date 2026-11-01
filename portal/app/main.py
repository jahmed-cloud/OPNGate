"""Public (browser-facing) portal app. Sits behind Caddy, which sits behind Cloudflare."""
import hmac
import ipaddress
import json
import logging
import re
import threading
import time
from collections import Counter
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from . import actions, auth, crowdsec, db, views, waflog
from .config import settings
from .security import LoginRequired

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

# form-action also covers the redirect after a form post: signing in from gauc.<domain> ends with a
# redirect back there, which browsers block unless the sibling subdomains are listed.
_FORM_ACTION = "'self'" + (f" https://*.{settings.cookie_domain}" if settings.cookie_domain else "")
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    f"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action {_FORM_ACTION}; object-src 'none'"
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not settings.secret_key_file.exists():
        raise SystemExit(f"Missing {settings.secret_key_file}; run `python -m app.cli gen-key` first")
    db.init()
    stop = threading.Event()
    waflog.start_background(stop)
    crowdsec.start_background(stop)
    yield
    stop.set()


app = FastAPI(title="portal", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
app.include_router(auth.router)
app.include_router(views.router)
app.include_router(actions.router)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    started = time.perf_counter()
    response = await call_next(request)
    response.headers["Server-Timing"] = f"app;dur={(time.perf_counter() - started) * 1000:.1f}"
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    # "same-origin", not "no-referrer": with no-referrer browsers send Origin: null on form posts,
    # which the CSRF Origin check (rightly) refuses.
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    if not settings.dev:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if not request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/internal/waf-hits")
async def waf_hits(request: Request):
    """Counts from the WAF shipper. Token plus trusted-proxy source; Caddy refuses /internal/* from outside."""
    token = request.headers.get("authorization", "").removeprefix("Bearer ")
    try:
        peer = ipaddress.ip_address(request.client.host if request.client else "")
        peer_ok = any(peer in net for net in settings.trusted_proxies)
    except ValueError:
        peer_ok = False
    if not settings.waf_ship_token or not hmac.compare_digest(token, settings.waf_ship_token) or not peer_ok:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    raw = bytearray()
    async for chunk in request.stream():
        raw.extend(chunk)
        if len(raw) > 2 * 1024 * 1024:
            return JSONResponse({"error": "batch too large"}, status_code=413)
    try:
        body = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return JSONResponse({"error": "invalid JSON"}, status_code=400)
    if not isinstance(body, dict) or not isinstance(body.get("hits", []), list) or len(body.get("hits", [])) > 5000:
        return JSONResponse({"error": "expected at most 5000 hits"}, status_code=400)
    batch_id = body.get("batch_id")
    if batch_id is not None and (not isinstance(batch_id, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{16,80}", batch_id)):
        return JSONResponse({"error": "invalid batch_id"}, status_code=400)
    hits = Counter()
    for h in body.get("hits", []):
        try:
            if not isinstance(h, dict):
                raise ValueError()
            day = time.strftime("%Y-%m-%d", time.strptime(str(h["day"]), "%Y-%m-%d"))
            kind = h["kind"] if h["kind"] in ("waf_blocked", "waf_detected", "blocked", "detected") else None
            count = h["count"]
            if type(count) is not int or not kind or not 0 < count < 10_000_000:
                raise ValueError()
        except (KeyError, ValueError, TypeError):
            return JSONResponse({"error": "invalid hit"}, status_code=400)
        hits[(day, str(h.get("host") or "?")[:120], kind)] += count
    events = body.get("events") or []
    if not isinstance(events, list) or len(events) > 500:
        return JSONResponse({"error": "expected at most 500 events"}, status_code=400)
    stored = await run_in_threadpool(waflog.store, hits, batch_id, True)
    if stored:
        await run_in_threadpool(waflog.store_events, events)
    return {"ok": True, "stored": len(hits) if stored else 0, "duplicate": not stored}


@app.exception_handler(LoginRequired)
async def login_required(request: Request, exc: LoginRequired):
    if request.method != "GET" or request.headers.get("accept", "").startswith("application/json"):
        return JSONResponse({"error": "login required"}, status_code=401)
    target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    return RedirectResponse(f"/login?next={quote(target, safe='')}", 303)
