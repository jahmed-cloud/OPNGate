"""Explicit portal identities during a hostname migration.

The request host may select only a configured identity. It never supplies an
arbitrary WebAuthn relying party or trusted origin.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from urllib.parse import urlsplit

from .config import settings


@dataclass(frozen=True)
class Identity:
    rp_id: str
    origin: str


_selected = ContextVar("portal_identity", default=None)


def primary() -> Identity:
    return Identity(settings.rp_id, settings.origin)


def legacy() -> Identity | None:
    origin = settings.legacy_origin.rstrip("/")
    if not origin:
        return None
    url = urlsplit(origin)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.path or url.query or url.fragment:
        raise ValueError("PORTAL_LEGACY_ORIGIN must be an HTTPS origin")
    return Identity(url.hostname, origin)


def current() -> Identity:
    return _selected.get() or primary()


def for_request(request) -> Identity:
    old = legacy()
    if old and request.url.netloc.lower() == urlsplit(old.origin).netloc.lower():
        return old
    return primary()


@contextmanager
def use(value: Identity):
    token = _selected.set(value)
    try:
        yield
    finally:
        _selected.reset(token)
