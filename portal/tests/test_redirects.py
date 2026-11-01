"""Login return URLs must be safe for both HTTP and browser-side redirects."""
import json
import secrets
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import auth, db, security, wa
from softkey import SoftKey


@pytest.mark.parametrize("target", [
    "/\\evil.example/", "//evil.example/", "/\t/evil.example/",
    "/\n/evil.example/", "/\r/evil.example/", "/\x00/evil.example/",
    " https://example.com/", "https://example.com/\x7f",
    "https://evil.example/", "https://example.com.evil.example/",
    "https://example.com@evil.example/", "https://evil.example@example.com/",
    "http://example.com/", "https://[broken/", "https://example.com:invalid/",
    "javascript:alert(1)", [], {"next": "/"}, None,
])
def test_unsafe_return_urls_use_home(monkeypatch, target):
    monkeypatch.setattr(auth, "settings", SimpleNamespace(cookie_domain="example.com"))
    assert auth._safe_next(target) == "/"


@pytest.mark.parametrize("target", [
    "/", "/clients?show=all", "/alerts?q=failed%20login#latest",
    "https://example.com/", "https://admin.example.com/settings?tab=users",
])
def test_local_and_configured_sibling_return_urls_work(monkeypatch, target):
    monkeypatch.setattr(auth, "settings", SimpleNamespace(cookie_domain="example.com"))
    assert auth._safe_next(target) == target


def test_sibling_redirect_needs_a_configured_cookie_domain(monkeypatch):
    monkeypatch.setattr(auth, "settings", SimpleNamespace(cookie_domain=""))
    assert auth._safe_next("https://admin.example.com/") == "/"


def test_passkey_login_does_not_return_browser_normalized_external_url(monkeypatch):
    """Exercise the real signed login and JSON redirect consumed by location.assign."""
    origin = "http://testserver"
    monkeypatch.setattr(auth, "limiter", security.RateLimiter())
    app = FastAPI()
    app.include_router(auth.router)
    db.init()
    with TestClient(app, base_url=origin) as client:
        username = "redirect-" + secrets.token_hex(8)
        db.run(
            "INSERT INTO users(username, password_hash, role, webauthn_user_id, created_at) "
            "VALUES (?, ?, 'viewer', ?, ?)",
            username, "unused-password", secrets.token_bytes(32), db.now(),
        )
        user = db.one("SELECT * FROM users WHERE username=?", username)
        key = SoftKey()
        options, challenge = wa.registration_options(user)
        wa.finish_registration(user, key.create(json.loads(options), origin), challenge, "test key")
        options = client.post("/auth/passkey/begin", headers={"Origin": origin}).json()
        response = client.post(
            "/auth/passkey/finish", headers={"Origin": origin},
            json={"credential": key.get(options["challenge"], "testserver", origin),
                  "next": "/\\evil.example/"},
        )
        assert response.status_code == 200
        assert response.json() == {"ok": True, "redirect": "/"}
        assert client.get("/auth/verify").status_code == 200
