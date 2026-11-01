"""Telegram notifications. Best effort, on a background thread; never blocks a request."""
import json
import logging
import threading
import urllib.request

from .config import settings

log = logging.getLogger("portal")


def send(text: str) -> None:
    if not (settings.telegram_token and settings.telegram_chat):
        log.info("notify (telegram not configured): %s", text)
        return
    threading.Thread(target=_post, args=(text,), daemon=True).start()


def _post(text: str) -> None:
    body = json.dumps({"chat_id": settings.telegram_chat, "text": f"[portal] {text}", "disable_web_page_preview": True})
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{settings.telegram_token}/sendMessage",
        data=body.encode(), headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=10).read()
    except OSError as exc:
        log.warning("telegram send failed: %s", exc)
