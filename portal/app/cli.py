"""Host-side admin commands. Run on the portal host (from MGMT), never through the web.

    python -m app.cli gen-key
    python -m app.cli create-user <name> --role operator
    python -m app.cli reset-user <name> [--drop-keys]
    python -m app.cli disable-user <name>
    python -m app.cli list-users
    python -m app.cli export-keys > operator_keys.json   # copy to the firewall agent
"""
import argparse
import getpass
import json
import secrets
import sys

from cryptography.fernet import Fernet

from . import db, wa
from .config import settings
from .security import (
    encrypt,
    hash_password,
    new_recovery_codes,
    new_totp_secret,
    password_problems,
    totp_uri,
)


def _ask_password() -> str:
    while True:
        pw = getpass.getpass("New password (14+ characters): ")
        if pw != getpass.getpass("Repeat: "):
            print("Passwords differ.")
            continue
        problems = password_problems(pw)
        if problems:
            print("Rejected: " + "; ".join(problems))
            continue
        return pw


def _print_second_factors(username: str, secret: str, codes: list) -> None:
    print("\nTOTP secret (add to your authenticator app, then keep this terminal private):")
    print(f"  {secret}\n  {totp_uri(secret, username)}")
    print("\nRecovery codes (each works once, store them offline):")
    for code in codes:
        print(f"  {code}")
    print("\nNext: sign in with password + TOTP, open Security, and register at least two security keys.")


def gen_key(args) -> None:
    path = settings.secret_key_file
    if path.exists() and not args.force:
        sys.exit(f"{path} exists; refusing to overwrite (it would make stored TOTP secrets unreadable)")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(Fernet.generate_key())
    try:
        path.chmod(0o600)
    except OSError:
        pass
    print(f"Wrote {path}")


def create_user(args) -> None:
    db.init()
    if db.one("SELECT 1 FROM users WHERE username=?", args.username):
        sys.exit("User exists")
    password = args.password or _ask_password()
    secret = new_totp_secret()
    db.run(
        "INSERT INTO users(username, password_hash, role, totp_secret_enc, webauthn_user_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        args.username, hash_password(password), args.role, encrypt(secret), secrets.token_bytes(32), db.now(),
    )
    user = db.one("SELECT id FROM users WHERE username=?", args.username)
    _print_second_factors(args.username, secret, new_recovery_codes(user["id"]))


def reset_user(args) -> None:
    db.init()
    user = db.one("SELECT * FROM users WHERE username=?", args.username)
    if not user:
        sys.exit("No such user")
    password = _ask_password()
    secret = new_totp_secret()
    with db.tx() as conn:
        conn.execute(
            "UPDATE users SET password_hash=?, totp_secret_enc=?, totp_last_step=0, disabled=0 WHERE id=?",
            (hash_password(password), encrypt(secret), user["id"]),
        )
        conn.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
        if args.drop_keys:
            conn.execute("DELETE FROM credentials WHERE user_id=?", (user["id"],))
    db.run("INSERT INTO audit(ts, username, ip, event, ok, detail) VALUES (?, ?, 'host-cli', 'user_reset', 1, ?)",
           db.now(), args.username, "drop_keys" if args.drop_keys else "")
    _print_second_factors(args.username, secret, new_recovery_codes(user["id"]))
    if args.drop_keys:
        print("\nSecurity keys removed. Re-export keys to the firewall after registering new ones.")


def disable_user(args) -> None:
    db.init()
    db.run("UPDATE users SET disabled=1 WHERE username=?", args.username)
    db.run("DELETE FROM sessions WHERE user_id=(SELECT id FROM users WHERE username=?)", args.username)
    print("Disabled and signed out.")


def list_users(args) -> None:
    db.init()
    for u in db.q("SELECT u.*, (SELECT COUNT(*) FROM credentials c WHERE c.user_id=u.id) AS keys FROM users u"):
        print(f"{u['username']:20} {u['role']:9} keys={u['keys']} totp={'yes' if u['totp_secret_enc'] else 'no'}"
              f"{' DISABLED' if u['disabled'] else ''}")


def export_keys(args) -> None:
    """Public keys of operators' security keys, for the firewall agent's trust store.

    This file is the trust anchor for control actions. Move it to the firewall over
    MGMT (scp from your admin PC); never let the portal push it.
    """
    db.init()
    json.dump(trusted_keys_doc(), sys.stdout, indent=2)
    print()


def trusted_keys_doc() -> dict:
    rows = db.q(
        "SELECT c.*, u.username FROM credentials c JOIN users u ON u.id=c.user_id "
        "WHERE u.role='operator' AND u.disabled=0 ORDER BY u.username, c.created_at"
    )
    return {
        "rp_id": settings.rp_id,
        "origin": settings.origin,
        "keys": [
            {"credential_id": r["id"], "user": r["username"], "name": r["name"], "alg": r["alg"],
             "public_key_pem": wa.public_key_pem(r["public_key"])}
            for r in rows
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(prog="app.cli")
    sub = parser.add_subparsers(required=True)
    p = sub.add_parser("gen-key"); p.add_argument("--force", action="store_true"); p.set_defaults(fn=gen_key)
    p = sub.add_parser("create-user"); p.add_argument("username"); p.add_argument("--role", choices=["viewer", "operator"], default="viewer")
    p.add_argument("--password", help=argparse.SUPPRESS); p.set_defaults(fn=create_user)
    p = sub.add_parser("reset-user"); p.add_argument("username"); p.add_argument("--drop-keys", action="store_true"); p.set_defaults(fn=reset_user)
    p = sub.add_parser("disable-user"); p.add_argument("username"); p.set_defaults(fn=disable_user)
    p = sub.add_parser("list-users"); p.set_defaults(fn=list_users)
    p = sub.add_parser("export-keys"); p.set_defaults(fn=export_keys)
    args = parser.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
