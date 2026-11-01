"""Sessions, CSRF, rate limits, audit, password/TOTP primitives.

Nothing here invents crypto: Argon2id comes from argon2-cffi, TOTP from pyotp,
encryption at rest from cryptography's Fernet, randomness from `secrets`.
"""
import hashlib
import hmac
import ipaddress
import logging
import secrets
import threading
import time
import urllib.request
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Optional

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet
from fastapi import HTTPException, Request

from . import db, notify
from .config import settings

log = logging.getLogger("portal")
ph = PasswordHasher()  # argon2id, library defaults (RFC 9106 low-memory profile)
_DUMMY_HASH = ph.hash(secrets.token_hex(16))

MIN_PASSWORD_LEN = 14


# ---------------------------------------------------------------- client IP

def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else "0.0.0.0"
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if any(peer_ip in net for net in settings.trusted_proxies):
        forwarded = request.headers.get("x-real-ip", "").strip()
        if forwarded:
            try:
                return str(ipaddress.ip_address(forwarded))
            except ValueError:
                pass
    return peer


# ---------------------------------------------------------------- audit

_auth_log_lock = threading.Lock()


def audit(event: str, ok: bool, request: Optional[Request] = None, username: str = "", detail: str = "") -> None:
    ip = client_ip(request) if request else "-"
    db.run(
        "INSERT INTO audit(ts, username, ip, event, ok, detail) VALUES (?, ?, ?, ?, ?, ?)",
        db.now(), username, ip, event, int(ok), detail,
    )
    # One line per event in a fixed format that the CrowdSec parser in deploy/crowdsec reads.
    safe_user = username.replace('"', "").replace("\n", "")[:64]
    line = (
        f'{time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())} portal-auth '
        f'event={event} ok={int(ok)} ip={ip} user="{safe_user}"\n'
    )
    settings.auth_log.parent.mkdir(parents=True, exist_ok=True)
    with _auth_log_lock, open(settings.auth_log, "a", encoding="utf-8") as fh:
        fh.write(line)


# ---------------------------------------------------------------- rate limiting

class RateLimiter:
    """5 attempts per minute per key, plus a lockout that doubles after each failure past 5.

    In-memory on purpose: the portal runs as one process, and CrowdSec (reading the
    auth log) provides the durable, network-level ban after 10 failures.
    """

    def __init__(self, per_minute: int = 5, free_failures: int = 5, base_lock: int = 30, max_lock: int = 3600):
        self.per_minute = per_minute
        self.free_failures = free_failures
        self.base_lock = base_lock
        self.max_lock = max_lock
        self._attempts = defaultdict(deque)
        self._failures = defaultdict(int)
        self._locked_until = defaultdict(float)
        self._lock = threading.Lock()

    def check(self, *keys: str) -> int:
        """Return 0 if allowed (and record the attempt), else seconds to wait."""
        now = time.monotonic()
        with self._lock:
            wait = 0
            for key in keys:
                attempts = self._attempts[key]
                while attempts and now - attempts[0] > 60:
                    attempts.popleft()
                if len(attempts) >= self.per_minute:
                    wait = max(wait, int(60 - (now - attempts[0])) + 1)
                if self._locked_until[key] > now:
                    wait = max(wait, int(self._locked_until[key] - now) + 1)
            if wait:
                return wait
            for key in keys:
                self._attempts[key].append(now)
            return 0

    def failure(self, *keys: str) -> None:
        now = time.monotonic()
        with self._lock:
            for key in keys:
                self._failures[key] += 1
                extra = self._failures[key] - self.free_failures
                if extra >= 0:
                    self._locked_until[key] = now + min(self.base_lock * (2 ** extra), self.max_lock)

    def success(self, *keys: str) -> None:
        with self._lock:
            for key in keys:
                self._failures.pop(key, None)
                self._locked_until.pop(key, None)


limiter = RateLimiter()


def rate_keys(request: Request, username: str = "") -> list:
    keys = [f"ip:{client_ip(request)}"]
    if username:
        keys.append(f"user:{username.lower()}")
    return keys


# ---------------------------------------------------------------- passwords

def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(stored_hash: Optional[str], password: str) -> bool:
    """Constant-ish time: hashes against a dummy when the user does not exist."""
    try:
        return ph.verify(stored_hash or _DUMMY_HASH, password) and stored_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_problems(password: str) -> list:
    problems = []
    if len(password) < MIN_PASSWORD_LEN:
        problems.append(f"must be at least {MIN_PASSWORD_LEN} characters")
    count = pwned_count(password)
    if count is None:
        log.warning("breached-password check unavailable; password accepted on length only")
    elif count > 0:
        problems.append(f"appears in {count} known breaches")
    return problems


def pwned_count(password: str) -> Optional[int]:
    """Have I Been Pwned k-anonymity range query: only the first 5 hex chars of SHA-1 leave the host."""
    digest = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    try:
        req = urllib.request.Request(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true", "User-Agent": "home-gateway-portal"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode()
    except OSError:
        return None
    for line in body.splitlines():
        tail, _, count = line.partition(":")
        if tail.strip() == suffix:
            return int(count.strip() or 0)
    return 0


# ---------------------------------------------------------------- secrets at rest

def _fernet() -> Fernet:
    return Fernet(settings.secret_key_file.read_bytes().strip())


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt(token: str) -> str:
    return _fernet().decrypt(token.encode()).decode()


# ---------------------------------------------------------------- TOTP

def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=settings.rp_name)


def verify_totp(user_row, code: str) -> bool:
    """RFC 6238, 30 s steps, +/-1 step of drift, and each step accepted only once."""
    code = "".join(ch for ch in code if ch.isdigit())
    if len(code) != 6 or not user_row["totp_secret_enc"]:
        return False
    totp = pyotp.TOTP(decrypt(user_row["totp_secret_enc"]))
    current = int(time.time()) // 30
    for step in (current - 1, current, current + 1):
        if hmac.compare_digest(totp.at(step * 30), code):
            with db.tx() as conn:
                # Compare-and-set so two concurrent requests cannot both spend the same code.
                cur = conn.execute(
                    "UPDATE users SET totp_last_step=? WHERE id=? AND totp_last_step < ?",
                    (step, user_row["id"], step),
                )
                return cur.rowcount == 1
    return False


# ---------------------------------------------------------------- recovery codes

def new_recovery_codes(user_id: int) -> list:
    codes = ["-".join(secrets.token_hex(3) for _ in range(3)) for _ in range(10)]
    with db.tx() as conn:
        conn.execute("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
        for code in codes:
            conn.execute("INSERT INTO recovery_codes(user_id, code_hash) VALUES (?, ?)", (user_id, ph.hash(code)))
    return codes


def use_recovery_code(user_id: int, code: str) -> bool:
    code = code.strip().lower()
    for row in db.q("SELECT id, code_hash FROM recovery_codes WHERE user_id=? AND used_at IS NULL", user_id):
        if verify_password(row["code_hash"], code):
            cur = db.run("UPDATE recovery_codes SET used_at=? WHERE id=? AND used_at IS NULL", db.now(), row["id"])
            return cur.rowcount == 1
    return False


# ---------------------------------------------------------------- sessions

@dataclass
class Session:
    id_hash: str
    user_id: int
    username: str
    role: str
    csrf: str
    last_mfa: int

    @property
    def is_operator(self) -> bool:
        return self.role == "operator"

    @property
    def mfa_fresh(self) -> bool:
        return db.now() - self.last_mfa <= settings.stepup_window


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(request: Request, user_row) -> str:
    """New random session ID at every login; any session ID the browser had is discarded."""
    token = secrets.token_urlsafe(32)
    now = db.now()
    db.run(
        "INSERT INTO sessions(id_hash, user_id, csrf, created_at, last_seen, last_mfa, ip, user_agent) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        _hash_token(token), user_row["id"], secrets.token_urlsafe(32), now, now, now,
        client_ip(request), request.headers.get("user-agent", "")[:300],
    )
    _note_device(request, user_row)
    return token


def _note_device(request: Request, user_row) -> None:
    ua = request.headers.get("user-agent", "")
    fingerprint = hashlib.sha256(f"{client_ip(request)}|{ua}".encode()).hexdigest()
    cur = db.run(
        "INSERT OR IGNORE INTO known_devices(user_id, fingerprint, first_seen) VALUES (?, ?, ?)",
        user_row["id"], fingerprint, db.now(),
    )
    if cur.rowcount == 1:
        notify.send(f"New device signed in to the portal as {user_row['username']} from {client_ip(request)} ({ua[:80]})")


def load_session(request: Request) -> Optional[Session]:
    token = request.cookies.get(settings.session_cookie)
    if not token:
        return None
    row = db.one(
        "SELECT s.*, u.username, u.role, u.disabled FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash=?",
        _hash_token(token),
    )
    if not row:
        return None
    now = db.now()
    if row["disabled"] or now - row["last_seen"] > settings.idle_timeout or now - row["created_at"] > settings.absolute_timeout:
        db.run("DELETE FROM sessions WHERE id_hash=?", row["id_hash"])
        return None
    # Background refreshes of an open dashboard tab must not keep an unattended session alive.
    if request.headers.get("x-auto-refresh") != "1" and request.url.path != "/api/live/stream":
        db.run("UPDATE sessions SET last_seen=? WHERE id_hash=?", now, row["id_hash"])
    return Session(row["id_hash"], row["user_id"], row["username"], row["role"], row["csrf"], row["last_mfa"])


def mark_mfa(session: Session) -> None:
    db.run("UPDATE sessions SET last_mfa=? WHERE id_hash=?", db.now(), session.id_hash)


def destroy_session(session: Optional[Session]) -> None:
    if session:
        db.run("DELETE FROM sessions WHERE id_hash=?", session.id_hash)


def _samesite(name: str) -> str:
    # The session cookie is Lax so that opening gauc.<domain> from a link or bookmark still carries it
    # (Strict drops it on any navigation that starts elsewhere, which breaks forward-auth). CSRF is
    # covered separately by the token + Origin check on every POST.
    return "lax" if name == settings.session_cookie else "strict"


def set_cookie(response, name: str, value: str, max_age: int) -> None:
    response.set_cookie(
        name, value, max_age=max_age, httponly=True, secure=not settings.dev, samesite=_samesite(name), path="/",
        domain=(settings.cookie_domain or None) if name == settings.session_cookie else None,
    )


def clear_cookie(response, name: str) -> None:
    response.delete_cookie(
        name, path="/", secure=not settings.dev, httponly=True, samesite=_samesite(name),
        domain=(settings.cookie_domain or None) if name == settings.session_cookie else None,
    )


# ---------------------------------------------------------------- request guards

class LoginRequired(Exception):
    pass


def require_user(request: Request) -> Session:
    session = load_session(request)
    if not session:
        raise LoginRequired()
    request.state.session = session
    return session


def require_operator(request: Request) -> Session:
    session = require_user(request)
    if not session.is_operator:
        raise HTTPException(403, "Operator role required")
    return session


def same_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    if origin is None:
        # Browsers always send Origin on POST from a page; allow only if Referer matches.
        referer = request.headers.get("referer", "")
        return referer.startswith(settings.origin + "/")
    return origin == settings.origin


async def check_csrf(request: Request, session: Session) -> None:
    if not same_origin(request):
        raise HTTPException(403, "Cross-origin request refused")
    token = request.headers.get("x-csrf-token")
    if token is None:
        form = await request.form()
        token = form.get("csrf", "")
    if not hmac.compare_digest(str(token), session.csrf):
        raise HTTPException(403, "Bad CSRF token")


async def check_origin_only(request: Request) -> None:
    """For pre-login POSTs (no session yet): SameSite=Strict + Origin check."""
    if not same_origin(request):
        raise HTTPException(403, "Cross-origin request refused")


# ---------------------------------------------------------------- one-time challenge store

def store_challenge(purpose: str, challenge: bytes, user_id: Optional[int] = None, data: str = "") -> str:
    token = secrets.token_urlsafe(24)
    db.run(
        "INSERT INTO challenges(token_hash, purpose, user_id, challenge, data, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        _hash_token(token), purpose, user_id, challenge, data, db.now() + 300,
    )
    return token


def take_challenge(request: Request, purpose: str):
    """Fetch and delete in one step, so a challenge can be used once."""
    token = request.cookies.get(settings.challenge_cookie)
    if not token:
        return None
    with db.tx() as conn:
        row = conn.execute(
            "SELECT * FROM challenges WHERE token_hash=? AND purpose=?", (_hash_token(token), purpose)
        ).fetchone()
        if row:
            conn.execute("DELETE FROM challenges WHERE token_hash=?", (row["token_hash"],))
    if not row or row["expires_at"] < db.now():
        return None
    return row
