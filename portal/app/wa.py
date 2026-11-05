"""WebAuthn (FIDO2 / passkeys) via py_webauthn. User verification is always required."""
import json
from typing import Optional

from cryptography.hazmat.primitives import serialization
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    decode_credential_public_key,
    decoded_public_key_to_cryptography,
    parse_authentication_credential_json,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from . import db
from .config import settings
from . import identity

# Only algorithms the firewall agent can verify with the stock `openssl` binary.
ALGS = [
    COSEAlgorithmIdentifier.ECDSA_SHA_256,
    COSEAlgorithmIdentifier.EDDSA,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
]


class WebAuthnError(Exception):
    pass


def registration_options(user_row) -> tuple:
    existing = db.q("SELECT id FROM credentials WHERE user_id=? AND rp_id=?", user_row["id"], identity.current().rp_id)
    options = generate_registration_options(
        rp_id=identity.current().rp_id,
        rp_name=settings.rp_name,
        user_id=user_row["webauthn_user_id"],
        user_name=user_row["username"],
        user_display_name=user_row["username"],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["id"])) for r in existing],
        supported_pub_key_algs=ALGS,
    )
    return options_to_json(options), options.challenge


def finish_registration(user_row, credential: dict, challenge: bytes, name: str) -> str:
    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=identity.current().rp_id,
            expected_origin=identity.current().origin,
            require_user_verification=True,
            supported_pub_key_algs=ALGS,
        )
    except Exception as exc:  # py_webauthn raises several exception types
        raise WebAuthnError(str(exc)) from exc
    cred_id = bytes_to_base64url(verified.credential_id)
    alg = int(decode_credential_public_key(verified.credential_public_key).alg)
    db.run(
        "INSERT INTO credentials(id, user_id, public_key, alg, sign_count, name, created_at, rp_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        cred_id, user_row["id"], verified.credential_public_key, alg, verified.sign_count,
        (name or "Security key")[:60], db.now(), identity.current().rp_id,
    )
    return cred_id


def authentication_options(user_id: Optional[int] = None, challenge: Optional[bytes] = None) -> tuple:
    allow = None
    if user_id is not None:
        allow = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["id"]))
                 for r in db.q("SELECT id FROM credentials WHERE user_id=? AND rp_id=?", user_id, identity.current().rp_id)]
    options = generate_authentication_options(
        rp_id=identity.current().rp_id,
        challenge=challenge,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return options_to_json(options), options.challenge


def finish_authentication(credential: dict, challenge: bytes, user_id: Optional[int] = None):
    """Verify an assertion; return the user row. Raises WebAuthnError."""
    try:
        parsed = parse_authentication_credential_json(json.dumps(credential))
    except Exception as exc:
        raise WebAuthnError("malformed credential") from exc
    cred_id = bytes_to_base64url(parsed.raw_id)
    cred = db.one("SELECT * FROM credentials WHERE id=?", cred_id)
    if not cred or (cred["rp_id"] and cred["rp_id"] != identity.current().rp_id) or (user_id is not None and cred["user_id"] != user_id):
        raise WebAuthnError("unknown credential")
    user = db.one("SELECT * FROM users WHERE id=? AND disabled=0", cred["user_id"])
    if not user:
        raise WebAuthnError("unknown credential")
    if parsed.response.user_handle is not None and parsed.response.user_handle != user["webauthn_user_id"]:
        raise WebAuthnError("user handle mismatch")
    try:
        verified = verify_authentication_response(
            credential=parsed,
            expected_challenge=challenge,
            expected_rp_id=identity.current().rp_id,
            expected_origin=identity.current().origin,
            credential_public_key=cred["public_key"],
            credential_current_sign_count=cred["sign_count"],
            require_user_verification=True,
        )
    except Exception as exc:
        raise WebAuthnError(str(exc)) from exc
    db.run("UPDATE credentials SET sign_count=?, last_used_at=? WHERE id=?", verified.new_sign_count, db.now(), cred_id)
    return user, cred_id


def public_key_pem(cose_key: bytes) -> str:
    key = decoded_public_key_to_cryptography(decode_credential_public_key(cose_key))
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
