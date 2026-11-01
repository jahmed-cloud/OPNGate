"""A software FIDO2 authenticator for tests (ES256 or Ed25519, 'none' attestation)."""
import base64
import hashlib
import json
import os

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class SoftKey:
    def __init__(self, alg: int = -7, counter: bool = True):
        self.alg = alg
        self.key = ec.generate_private_key(ec.SECP256R1()) if alg == -7 else ed25519.Ed25519PrivateKey.generate()
        self.cred_id = os.urandom(16)
        self.count = 0
        self.counter = counter
        self.user_handle = None

    def _cose(self) -> bytes:
        pub = self.key.public_key()
        if self.alg == -7:
            nums = pub.public_numbers()
            return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return cbor2.dumps({1: 1, 3: -8, -1: 6, -2: raw})

    def _sign(self, data: bytes) -> bytes:
        if self.alg == -7:
            return self.key.sign(data, ec.ECDSA(hashes.SHA256()))
        return self.key.sign(data)

    def _count(self) -> bytes:
        if self.counter:
            self.count += 1
        return self.count.to_bytes(4, "big")

    def create(self, options: dict, origin: str) -> dict:
        rp_id = options["rp"]["id"]
        self.user_handle = unb64u(options["user"]["id"])
        client_data = json.dumps({"type": "webauthn.create", "challenge": options["challenge"], "origin": origin,
                                  "crossOrigin": False}).encode()
        cose = self._cose()
        auth_data = (hashlib.sha256(rp_id.encode()).digest() + bytes([0x45]) + self._count()
                     + bytes(16) + len(self.cred_id).to_bytes(2, "big") + self.cred_id + cose)
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(client_data), "attestationObject": b64u(att), "transports": ["usb"]},
                "clientExtensionResults": {}}

    def get(self, challenge_b64u: str, rp_id: str, origin: str, flags: int = 0x05, client_type: str = "webauthn.get") -> dict:
        client_data = json.dumps({"type": client_type, "challenge": challenge_b64u, "origin": origin,
                                  "crossOrigin": False}).encode()
        auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + self._count()
        sig = self._sign(auth_data + hashlib.sha256(client_data).digest())
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(client_data), "authenticatorData": b64u(auth_data),
                             "signature": b64u(sig), "userHandle": b64u(self.user_handle) if self.user_handle else None},
                "clientExtensionResults": {}}
