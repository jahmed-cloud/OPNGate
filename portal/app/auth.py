"""Login, logout, step-up, forward-auth, and authenticator management.

Two ways in, never a password on its own:
  1. a passkey / FIDO2 key with user verification, or
  2. password + TOTP code (or a single-use recovery code in place of the code).
"""
import json
import secrets
from urllib.parse import quote, urlparse

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from . import db, identity, notify, wa
from .config import settings
from .security import (
    Session,
    audit,
    check_csrf,
    check_origin_only,
    clear_cookie,
    client_ip,
    create_session,
    destroy_session,
    limiter,
    load_session,
    mark_mfa,
    new_recovery_codes,
    new_totp_secret,
    password_problems,
    hash_password,
    rate_keys,
    require_user,
    set_cookie,
    store_challenge,
    take_challenge,
    totp_uri,
    encrypt,
    use_recovery_code,
    verify_password,
    verify_totp,
)
from .templating import render

router = APIRouter()

GENERIC_FAIL = "Sign-in failed. Check your details and try again."


def _safe_next(target: str) -> str:
    """Allow redirects only to this portal or to subdomains covered by forward-auth."""
    # The passkey flow returns this string to location.assign(), whose URL parser
    # treats backslashes as slashes and strips ASCII controls. Reject those before
    # testing for a local path so /\\outside.example cannot become an external URL.
    if (not isinstance(target, str) or not target or target != target.strip()
            or "\\" in target or any(ord(ch) < 32 or ord(ch) == 127 for ch in target)):
        return "/"
    if target.startswith("/") and not target.startswith("//"):
        return target
    try:
        parsed = urlparse(target)
        host = parsed.hostname or ""
        # Reject malformed authorities, including invalid ports, without a 500.
        parsed.port
    except ValueError:
        return "/"
    if parsed.username is not None or parsed.password is not None:
        return "/"
    if parsed.scheme == "https" and settings.cookie_domain and (
        host == settings.cookie_domain or host.endswith("." + settings.cookie_domain)
    ):
        return target
    return "/"


def _login_response(request: Request, user, next_url: str, method: str, json_reply: bool = False):
    token = create_session(request, user)
    audit("login", True, request, user["username"], method)
    target = _safe_next(next_url)
    response = JSONResponse({"ok": True, "redirect": target}) if json_reply else RedirectResponse(target, 303)
    set_cookie(response, settings.session_cookie, token, settings.absolute_timeout)
    clear_cookie(response, settings.challenge_cookie)
    return response


def _fail(request: Request, username: str, keys: list, method: str) -> None:
    limiter.failure(*keys)
    audit("login_failed", False, request, username, method)
    recent = db.one(
        "SELECT COUNT(*) AS n FROM audit WHERE event='login_failed' AND ts > ? AND (ip=? OR username=?)",
        db.now() - 300, client_ip(request), username,
    )["n"]
    if recent == 5:
        notify.send(f"5 failed portal sign-ins in 5 minutes (user '{username}', see Audit)")


# ------------------------------------------------------------------ pages

@router.get("/login")
def login_page(request: Request, next: str = "/"):
    if load_session(request):
        return RedirectResponse(_safe_next(next), 303)
    return render(request, "login.html", next=next, error=request.query_params.get("error"))


@router.post("/login/password")
async def login_password(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    code: str = Form(...),
    next: str = Form("/"),
):
    await check_origin_only(request)
    username = username.strip()[:64]
    keys = rate_keys(request, username)
    wait = limiter.check(*keys)
    if wait:
        audit("login_throttled", False, request, username, "password")
        return render(request, "login.html", next=next, error=f"Too many attempts. Wait {wait} s.", status_code=429)

    user = db.one("SELECT * FROM users WHERE username=? AND disabled=0", username)
    password_ok = verify_password(user["password_hash"] if user else None, password)
    second_ok = False
    method = "password+totp"
    if user and password_ok:
        if "-" in code:
            second_ok = use_recovery_code(user["id"], code)
            method = "password+recovery"
            if second_ok:
                left = db.one("SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id=? AND used_at IS NULL", user["id"])["n"]
                notify.send(f"Recovery code used by {username}; {left} left")
        else:
            second_ok = verify_totp(user, code)
    if not (user and password_ok and second_ok):
        _fail(request, username, keys, method)
        return render(request, "login.html", next=next, error=GENERIC_FAIL, status_code=401)
    limiter.success(*keys)
    return _login_response(request, user, next, method)


@router.post("/auth/passkey/begin")
async def passkey_begin(request: Request):
    await check_origin_only(request)
    wait = limiter.check(*rate_keys(request))
    if wait:
        raise HTTPException(429, f"Too many attempts. Wait {wait} s.")
    options, challenge = wa.authentication_options()
    token = store_challenge("login", challenge)
    response = JSONResponse(json.loads(options))
    set_cookie(response, settings.challenge_cookie, token, 300)
    return response


@router.post("/auth/passkey/finish")
async def passkey_finish(request: Request):
    await check_origin_only(request)
    body = await request.json()
    keys = rate_keys(request)
    row = take_challenge(request, "login")
    if not row:
        raise HTTPException(400, "Challenge expired; try again")
    try:
        user, cred_id = wa.finish_authentication(body.get("credential", {}), row["challenge"])
    except wa.WebAuthnError:
        _fail(request, "", keys, "passkey")
        raise HTTPException(401, GENERIC_FAIL)
    limiter.success(*keys)
    return _login_response(request, user, body.get("next", "/"), f"passkey:{cred_id[:12]}", json_reply=True)


@router.post("/logout")
async def logout(request: Request, session: Session = Depends(require_user)):
    await check_csrf(request, session)
    destroy_session(session)
    audit("logout", True, request, session.username)
    response = RedirectResponse("/login", 303)
    clear_cookie(response, settings.session_cookie)
    return response


# ------------------------------------------------------------------ forward-auth

@router.get("/auth/verify")
def forward_auth(request: Request, role: str = "viewer"):
    """Called by Caddy `forward_auth` before it forwards a request to another admin app."""
    session = load_session(request)
    if session and (role != "operator" or session.is_operator):
        return JSONResponse({"ok": True}, headers={"X-Portal-User": session.username, "X-Portal-Role": session.role})
    proto = request.headers.get("x-forwarded-proto", "https")
    host = request.headers.get("x-forwarded-host", "")
    uri = request.headers.get("x-forwarded-uri", "/")
    original = f"{proto}://{host}{uri}" if host else "/"
    if session:
        return JSONResponse({"ok": False, "error": "forbidden"}, status_code=403)
    return RedirectResponse(f"{identity.current().origin}/login?next={quote(original, safe='')}", 302)


# ------------------------------------------------------------------ step-up

@router.post("/security/stepup/passkey/begin")
async def stepup_begin(request: Request, session: Session = Depends(require_user)):
    await check_csrf(request, session)
    options, challenge = wa.authentication_options(user_id=session.user_id)
    token = store_challenge("stepup", challenge, session.user_id)
    response = JSONResponse(json.loads(options))
    set_cookie(response, settings.challenge_cookie, token, 300)
    return response


@router.post("/security/stepup/passkey/finish")
async def stepup_finish(request: Request, session: Session = Depends(require_user)):
    await check_csrf(request, session)
    body = await request.json()
    row = take_challenge(request, "stepup")
    if not row or row["user_id"] != session.user_id:
        raise HTTPException(400, "Challenge expired; try again")
    try:
        wa.finish_authentication(body.get("credential", {}), row["challenge"], user_id=session.user_id)
    except wa.WebAuthnError:
        audit("stepup_failed", False, request, session.username, "passkey")
        raise HTTPException(401, "Verification failed")
    mark_mfa(session)
    audit("stepup", True, request, session.username, "passkey")
    return {"ok": True}


@router.post("/security/stepup/totp")
async def stepup_totp(request: Request, code: str = Form(...), session: Session = Depends(require_user)):
    await check_csrf(request, session)
    keys = rate_keys(request, session.username)
    wait = limiter.check(*keys)
    if wait:
        raise HTTPException(429, f"Too many attempts. Wait {wait} s.")
    user = db.one("SELECT * FROM users WHERE id=?", session.user_id)
    if not verify_totp(user, code):
        limiter.failure(*keys)
        audit("stepup_failed", False, request, session.username, "totp")
        return RedirectResponse("/security?error=Code+not+accepted", 303)
    limiter.success(*keys)
    mark_mfa(session)
    audit("stepup", True, request, session.username, "totp")
    return RedirectResponse("/security", 303)


# ------------------------------------------------------------------ authenticator management

def _require_fresh(session: Session) -> None:
    if not session.mfa_fresh:
        raise HTTPException(401, "Confirm with your security key or a TOTP code first")


@router.get("/security")
def security_page(request: Request, session: Session = Depends(require_user)):
    user = db.one("SELECT * FROM users WHERE id=?", session.user_id)
    creds = db.q("SELECT id, name, alg, created_at, last_used_at FROM credentials WHERE user_id=? ORDER BY created_at", session.user_id)
    codes_left = db.one("SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id=? AND used_at IS NULL", session.user_id)["n"]
    return render(
        request, "security.html", session=session, user=user, creds=creds, codes_left=codes_left,
        error=request.query_params.get("error"), flash=request.query_params.get("ok"),
    )


@router.post("/security/passkey/register/begin")
async def register_begin(request: Request, session: Session = Depends(require_user)):
    await check_csrf(request, session)
    _require_fresh(session)
    user = db.one("SELECT * FROM users WHERE id=?", session.user_id)
    options, challenge = wa.registration_options(user)
    token = store_challenge("register", challenge, session.user_id)
    response = JSONResponse(json.loads(options))
    set_cookie(response, settings.challenge_cookie, token, 300)
    return response


@router.post("/security/passkey/register/finish")
async def register_finish(request: Request, session: Session = Depends(require_user)):
    await check_csrf(request, session)
    _require_fresh(session)
    body = await request.json()
    row = take_challenge(request, "register")
    if not row or row["user_id"] != session.user_id:
        raise HTTPException(400, "Challenge expired; try again")
    user = db.one("SELECT * FROM users WHERE id=?", session.user_id)
    try:
        cred_id = wa.finish_registration(user, body.get("credential", {}), row["challenge"], body.get("name", ""))
    except wa.WebAuthnError as exc:
        audit("passkey_register_failed", False, request, session.username, str(exc)[:200])
        raise HTTPException(400, "Registration failed")
    audit("passkey_registered", True, request, session.username, cred_id[:12])
    notify.send(f"New security key '{body.get('name', '')[:40]}' registered for {session.username}")
    return {"ok": True}


@router.post("/security/passkey/{cred_id}/delete")
async def delete_passkey(cred_id: str, request: Request, session: Session = Depends(require_user)):
    await check_csrf(request, session)
    _require_fresh(session)
    user = db.one("SELECT * FROM users WHERE id=?", session.user_id)
    count = db.one("SELECT COUNT(*) AS n FROM credentials WHERE user_id=?", session.user_id)["n"]
    if count <= 1 and not user["totp_secret_enc"]:
        return RedirectResponse("/security?error=That+is+your+only+way+in", 303)
    db.run("DELETE FROM credentials WHERE id=? AND user_id=?", cred_id, session.user_id)
    audit("passkey_deleted", True, request, session.username, cred_id[:12])
    notify.send(f"Security key removed from {session.username}")
    return RedirectResponse("/security?ok=Key+removed", 303)


@router.post("/security/totp/begin")
async def totp_begin(request: Request, session: Session = Depends(require_user)):
    await check_csrf(request, session)
    _require_fresh(session)
    secret = new_totp_secret()
    token = store_challenge("totp_enroll", secrets.token_bytes(16), session.user_id, data=encrypt(secret))
    response = render(request, "totp_enroll.html", session=session, secret=secret, uri=totp_uri(secret, session.username))
    set_cookie(response, settings.challenge_cookie, token, 300)
    return response


@router.post("/security/totp/confirm")
async def totp_confirm(request: Request, code: str = Form(...), session: Session = Depends(require_user)):
    await check_csrf(request, session)
    _require_fresh(session)
    row = take_challenge(request, "totp_enroll")
    if not row or row["user_id"] != session.user_id:
        return RedirectResponse("/security?error=Enrolment+expired", 303)
    probe = {"id": session.user_id, "totp_secret_enc": row["data"]}
    db.run("UPDATE users SET totp_last_step=0 WHERE id=?", session.user_id)
    if not verify_totp(probe, code):
        return RedirectResponse("/security?error=Code+not+accepted;+TOTP+unchanged", 303)
    db.run("UPDATE users SET totp_secret_enc=? WHERE id=?", row["data"], session.user_id)
    audit("totp_changed", True, request, session.username)
    notify.send(f"TOTP authenticator changed for {session.username}")
    return RedirectResponse("/security?ok=TOTP+updated", 303)


@router.post("/security/recovery")
async def regenerate_recovery(request: Request, session: Session = Depends(require_user)):
    await check_csrf(request, session)
    _require_fresh(session)
    codes = new_recovery_codes(session.user_id)
    audit("recovery_regenerated", True, request, session.username)
    notify.send(f"Recovery codes regenerated for {session.username}")
    return render(request, "recovery_codes.html", session=session, codes=codes)


@router.post("/security/password")
async def change_password(
    request: Request,
    current: str = Form(...),
    new: str = Form(...),
    session: Session = Depends(require_user),
):
    await check_csrf(request, session)
    _require_fresh(session)
    user = db.one("SELECT * FROM users WHERE id=?", session.user_id)
    if not verify_password(user["password_hash"], current):
        audit("password_change_failed", False, request, session.username)
        return RedirectResponse("/security?error=Current+password+wrong", 303)
    problems = password_problems(new)
    if problems:
        return RedirectResponse("/security?error=New+password+" + quote("; ".join(problems)), 303)
    with db.tx() as conn:
        conn.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(new), session.user_id))
        # Sign out every other session.
        conn.execute("DELETE FROM sessions WHERE user_id=? AND id_hash != ?", (session.user_id, session.id_hash))
    audit("password_changed", True, request, session.username)
    notify.send(f"Password changed for {session.username}")
    return RedirectResponse("/security?ok=Password+changed", 303)
