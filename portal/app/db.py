"""SQLite storage. One file, WAL mode; plenty for one home network and 90 days of samples."""
import json
import sqlite3
import threading
import time
from contextlib import contextmanager

from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('viewer', 'operator')),
    totp_secret_enc TEXT,
    totp_last_step INTEGER NOT NULL DEFAULT 0,
    webauthn_user_id BLOB NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key BLOB NOT NULL,
    alg INTEGER NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
);
CREATE TABLE IF NOT EXISTS recovery_codes (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
    id_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    last_mfa INTEGER NOT NULL,
    ip TEXT,
    user_agent TEXT
);
CREATE TABLE IF NOT EXISTS known_devices (
    user_id INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    PRIMARY KEY (user_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS challenges (
    token_hash TEXT PRIMARY KEY,
    purpose TEXT NOT NULL,
    user_id INTEGER,
    challenge BLOB NOT NULL,
    data TEXT,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    username TEXT,
    ip TEXT,
    event TEXT NOT NULL,
    ok INTEGER NOT NULL,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS samples (
    ts INTEGER PRIMARY KEY,
    wan_up INTEGER,
    latency_ms REAL,
    loss_pct REAL,
    clients_online INTEGER,
    rx_bps REAL,
    tx_bps REAL
);
CREATE TABLE IF NOT EXISTS snapshots (
    kind TEXT PRIMARY KEY,
    ts INTEGER NOT NULL,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS clients (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    hostname TEXT,
    vendor TEXT,
    segment TEXT,
    online INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    source TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT,
    acked_by TEXT,
    acked_at INTEGER
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_open_ts ON events(ts DESC) WHERE acked_at IS NULL;
CREATE INDEX IF NOT EXISTS events_source_ts ON events(source, ts DESC);
CREATE INDEX IF NOT EXISTS clients_online_segment ON clients(online, segment);
CREATE TABLE IF NOT EXISTS outages (
    id INTEGER PRIMARY KEY,
    start_ts INTEGER NOT NULL,
    end_ts INTEGER
);
CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    params TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    status TEXT NOT NULL,
    assertion TEXT,
    approved_at INTEGER,
    result TEXT,
    finished_at INTEGER
);
CREATE TABLE IF NOT EXISTS waf_hits (
    day TEXT NOT NULL,
    host TEXT NOT NULL,
    kind TEXT NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (day, host, kind)
);
-- Names and icons operators give devices; kept apart from clients, which the agent's reports rewrite.
CREATE TABLE IF NOT EXISTS device_labels (
    mac TEXT PRIMARY KEY,
    name TEXT,
    icon TEXT,
    updated_by TEXT,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS kv (
    k TEXT PRIMARY KEY,
    v TEXT
);
CREATE TABLE IF NOT EXISTS waf_batches (
    batch_id TEXT PRIMARY KEY,
    received_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS waf_batches_received ON waf_batches(received_at);
CREATE TABLE IF NOT EXISTS waf_events (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    host TEXT NOT NULL,
    client_ip TEXT,
    method TEXT,
    path TEXT,
    rules TEXT,
    blocked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS waf_events_ts ON waf_events(ts);
"""

_local = threading.local()


def connect() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    if conn is None:
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(settings.db_path, timeout=10, isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        _local.conn = conn
    return conn


# Columns added after the first release; CREATE TABLE IF NOT EXISTS does not add them to old databases.
MIGRATIONS = {"credentials": (("rp_id", "TEXT"),), "clients": (("down_bps", "REAL"), ("up_bps", "REAL"), ("paused", "INTEGER NOT NULL DEFAULT 0"),
                          ("speed_limit", "TEXT"), ("blocked_domains", "TEXT"))}


def init() -> None:
    conn = connect()
    conn.executescript(SCHEMA)
    for table, columns in MIGRATIONS.items():
        have = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        for name, decl in columns:
            if name not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
    from . import identity
    previous = identity.legacy() or identity.primary()
    conn.execute("UPDATE credentials SET rp_id=? WHERE rp_id IS NULL", (previous.rp_id,))


@contextmanager
def tx():
    conn = connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise


def q(sql: str, *args) -> list:
    return connect().execute(sql, args).fetchall()


def one(sql: str, *args):
    return connect().execute(sql, args).fetchone()


def run(sql: str, *args) -> sqlite3.Cursor:
    return connect().execute(sql, args)


def now() -> int:
    return int(time.time())


def put_snapshot(kind: str, data) -> None:
    run(
        "INSERT INTO snapshots(kind, ts, data) VALUES (?, ?, ?) "
        "ON CONFLICT(kind) DO UPDATE SET ts=excluded.ts, data=excluded.data",
        kind, now(), json.dumps(data),
    )


def get_snapshot(kind: str, default=None):
    row = one("SELECT ts, data FROM snapshots WHERE kind=?", kind)
    if not row:
        return None, default
    return row["ts"], json.loads(row["data"])


def kv_get(k: str, default=None):
    row = one("SELECT v FROM kv WHERE k=?", k)
    return row["v"] if row else default


def kv_set(k: str, v: str) -> None:
    run("INSERT INTO kv(k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", k, v)


def prune() -> None:
    cutoff = now() - settings.retention_days * 86400
    run("DELETE FROM samples WHERE ts < ?", cutoff)
    run("DELETE FROM events WHERE ts < ?", cutoff)
    run("DELETE FROM waf_batches WHERE received_at < ?", cutoff)
    run("DELETE FROM waf_events WHERE ts < ?", now() - 30 * 86400)
    run("DELETE FROM audit WHERE ts < ?", now() - 365 * 86400)
    run("DELETE FROM challenges WHERE expires_at < ?", now())
    run("DELETE FROM sessions WHERE created_at < ?", now() - settings.absolute_timeout)
    run("UPDATE actions SET status='expired' WHERE status IN ('pending_approval','approved') AND expires_at < ?", now())
