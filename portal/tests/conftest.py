import os
import sys
import tempfile
from pathlib import Path

import pytest

_tmp = tempfile.mkdtemp(prefix="portal-test-")
os.environ.update({
    "PORTAL_DATA_DIR": _tmp,
    "PORTAL_LIVE_DIR": str(Path(_tmp) / "live"),
    "PORTAL_SECRET_KEY_FILE": str(Path(_tmp) / "secret.key"),
    "PORTAL_RP_ID": "testserver",
    "PORTAL_ORIGIN": "http://testserver",
    "PORTAL_DEV": "1",
    "PORTAL_WAF_SHIP_TOKEN": "shiptoken",
    "PORTAL_TRUSTED_PROXIES": "10.99.0.1/32",
    "PORTAL_CADDY_ACCESS_LOG": str(Path(_tmp) / "access.log"),
    "PORTAL_CORAZA_AUDIT_LOG": str(Path(_tmp) / "coraza.log"),
})
from cryptography.fernet import Fernet  # noqa: E402

Path(os.environ["PORTAL_SECRET_KEY_FILE"]).write_bytes(Fernet.generate_key())

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "portal"))
sys.path.insert(0, str(ROOT / "agent"))


@pytest.fixture(autouse=True)
def clear_live_frame():
    from app.config import settings
    path = settings.live_dir / "current.json"
    path.unlink(missing_ok=True)
    yield
    path.unlink(missing_ok=True)
