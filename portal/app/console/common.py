"""Shared bounded view helpers; no request handlers."""
import json
from fastapi import Request
from .. import metrics

RANGES = metrics.RANGES

def _window(request: Request) -> tuple:
    key = request.query_params.get("range", "24h")
    key = key if key in RANGES else "24h"
    return key, RANGES[key]


def _like(term: str) -> str:
    """Treat user search text literally, including SQL LIKE wildcards."""
    return "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _json(value) -> dict:
    try:
        data = json.loads(value) if value else {}
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}
