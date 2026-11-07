"""Bound browser control requests before framework form/JSON parsing."""
import json

from fastapi import HTTPException, Request
from starlette.responses import JSONResponse

BROWSER_BODY_LIMIT = 128 * 1024


class BrowserBodyLimit:
    """Buffer at most 128 KiB, including bodies without Content-Length.

    Live SSE and WebSockets pass through. The authenticated WAF batch endpoint
    retains its own source/token checks and separate two-MiB streaming limit.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if (scope["type"] != "http" or scope["method"] not in ("POST", "PUT", "PATCH", "DELETE")
                or scope["path"] == "/internal/waf-hits"):
            return await self.app(scope, receive, send)
        length = next((v for k, v in scope.get("headers", []) if k.lower() == b"content-length"), None)
        if length is not None:
            try:
                declared = int(length)
                if declared < 0:
                    raise ValueError()
            except ValueError:
                return await JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)(scope, receive, send)
            if declared > BROWSER_BODY_LIMIT:
                return await JSONResponse({"detail": "Request body too large"}, status_code=413)(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > BROWSER_BODY_LIMIT:
                return await JSONResponse({"detail": "Request body too large"}, status_code=413)(scope, receive, send)
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


def _nonfinite(_):
    raise ValueError("non-finite JSON number")


async def credential_body(request: Request) -> dict:
    """Return a JSON object with typed WebAuthn envelope fields; no raw errors."""
    try:
        body = json.loads(await request.body(), parse_constant=_nonfinite)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise HTTPException(400, "Invalid JSON object")
    if not isinstance(body, dict):
        raise HTTPException(400, "Expected JSON object")
    if "credential" in body and not isinstance(body["credential"], dict):
        raise HTTPException(400, "Invalid credential object")
    for field in ("name", "next"):
        if field in body and not isinstance(body[field], str):
            raise HTTPException(400, f"Invalid {field}")
    return body
