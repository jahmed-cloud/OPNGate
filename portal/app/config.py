"""Portal settings, read once from the environment."""
import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _networks(value: str) -> list:
    return [ipaddress.ip_network(v.strip(), strict=False) for v in value.split(",") if v.strip()]


def _live_directory() -> Path:
    # Settings are also imported by the read-only WAF shipper: choose a path
    # without tempfile.gettempdir(), which probes the filesystem by writing.
    return Path(_env("PORTAL_LIVE_DIR") or os.path.join(
        os.environ.get("TMPDIR") or os.environ.get("TEMP") or "/tmp", "waf-portal-live"))


@dataclass(frozen=True)
class Settings:
    rp_id: str = field(default_factory=lambda: _env("PORTAL_RP_ID", "localhost"))
    rp_name: str = field(default_factory=lambda: _env("PORTAL_RP_NAME", "OPNGate"))
    origin: str = field(default_factory=lambda: _env("PORTAL_ORIGIN", "http://localhost:8000"))
    legacy_origin: str = field(default_factory=lambda: _env("PORTAL_LEGACY_ORIGIN"))
    data_dir: Path = field(default_factory=lambda: Path(_env("PORTAL_DATA_DIR", "./data")))
    live_dir: Path = field(default_factory=_live_directory)
    # Fernet key used to encrypt TOTP secrets at rest. Generate with `python -m app.cli gen-key`.
    secret_key_file: Path = field(default_factory=lambda: Path(_env("PORTAL_SECRET_KEY_FILE", "./data/secret.key")))
    # Only these peers may set X-Real-IP (the reverse proxy). Everyone else is taken at face value.
    trusted_proxies: list = field(default_factory=lambda: _networks(_env("PORTAL_TRUSTED_PROXIES", "127.0.0.1/32,::1/128")))
    # Set to the parent domain (e.g. example.com) so forward-auth covers the other admin apps.
    cookie_domain: str = field(default_factory=lambda: _env("PORTAL_COOKIE_DOMAIN"))
    # Dev mode allows a non-Secure cookie over http://localhost. Never enable in production.
    dev: bool = field(default_factory=lambda: _env("PORTAL_DEV") == "1")
    telegram_token: str = field(default_factory=lambda: _env("TELEGRAM_BOT_TOKEN"))
    telegram_chat: str = field(default_factory=lambda: _env("TELEGRAM_CHAT_ID"))
    retention_days: int = field(default_factory=lambda: int(_env("PORTAL_RETENTION_DAYS", "90")))
    # Caddy / Coraza logs shared with the portal container, read for the "WAF hits per site" view.
    caddy_access_log: Path = field(default_factory=lambda: Path(_env("PORTAL_CADDY_ACCESS_LOG", "/logs/caddy/access.log")))
    coraza_audit_log: Path = field(default_factory=lambda: Path(_env("PORTAL_CORAZA_AUDIT_LOG", "/logs/caddy/coraza-audit.log")))
    # Shared secret for the WAF shipper on the proxy host (POST /internal/waf-hits).
    waf_ship_token: str = field(default_factory=lambda: _env("PORTAL_WAF_SHIP_TOKEN"))
    # Time zone for pages until the browser reports its own (the "tz" cookie set by portal.js).
    default_tz: str = field(default_factory=lambda: _env("PORTAL_TZ", "UTC"))
    # CrowdSec central API and a bouncer key, read-only, for the active bans on the Threats page.
    crowdsec_lapi: str = field(default_factory=lambda: _env("PORTAL_CROWDSEC_LAPI"))
    crowdsec_key: str = field(default_factory=lambda: _env("PORTAL_CROWDSEC_KEY"))
    oui_file: Path = field(default_factory=lambda: Path(_env("PORTAL_OUI_FILE", "./data/oui.txt")))

    idle_timeout: int = 30 * 60
    absolute_timeout: int = 12 * 60 * 60
    stepup_window: int = 5 * 60
    action_ttl: int = 10 * 60

    @property
    def db_path(self) -> Path:
        return self.data_dir / "portal.db"

    @property
    def auth_log(self) -> Path:
        return self.data_dir / "logs" / "auth.log"

    @property
    def session_cookie(self) -> str:
        return "portal_session" if self.dev else "__Secure-portal_session"

    @property
    def challenge_cookie(self) -> str:
        return "portal_wa" if self.dev else "__Secure-portal_wa"


settings = Settings()
