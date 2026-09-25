"""Passkey step-up: proves a person is present at the device.

A computer-use agent can move the mouse and type, but it cannot touch a
fingerprint sensor or look into a face camera. We create a passkey with
userVerification="required" and reject the credential unless the
authenticator reports the UV (user verified) flag.

Scope: registration ceremony only, attestation "none". UV is reported by the
authenticator, so a software authenticator could claim it; require attestation
from an allow-list of hardware authenticators (AAGUIDs) where that matters.
"""
import base64
import hashlib
import json
import secrets
import struct
import threading
import time

FLAG_UP, FLAG_UV, FLAG_AT = 0x01, 0x04, 0x40
SUPPORTED_ALGS = {-7: "ES256", -8: "EdDSA", -257: "RS256"}


class WebAuthnError(Exception):
    pass


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def cbor_decode(data: bytes, pos: int = 0):
    """Minimal CBOR decoder: everything WebAuthn attestation objects use."""
    if pos >= len(data):
        raise WebAuthnError("truncated CBOR")
    initial = data[pos]
    major, info = initial >> 5, initial & 0x1F
    pos += 1
    if info < 24:
        value = info
    elif info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        if pos + size > len(data):
            raise WebAuthnError("truncated CBOR")
        value = int.from_bytes(data[pos:pos + size], "big")
        pos += size
    else:
        raise WebAuthnError("unsupported CBOR encoding")
    if major == 0:
        return value, pos
    if major == 1:
        return -1 - value, pos
    if major in (2, 3):
        if pos + value > len(data):
            raise WebAuthnError("truncated CBOR")
        chunk = data[pos:pos + value]
        return (chunk if major == 2 else chunk.decode()), pos + value
    if major == 4:
        items = []
        for _ in range(value):
            item, pos = cbor_decode(data, pos)
            items.append(item)
        return items, pos
    if major == 5:
        result = {}
        for _ in range(value):
            k, pos = cbor_decode(data, pos)
            v, pos = cbor_decode(data, pos)
            result[k] = v
        return result, pos
    if major == 7 and info in (20, 21, 22):
        return {20: False, 21: True, 22: None}[info], pos
    raise WebAuthnError("unsupported CBOR type")


def parse_auth_data(auth_data: bytes) -> dict:
    if len(auth_data) < 37:
        raise WebAuthnError("authenticator data too short")
    rp_id_hash, flags = auth_data[:32], auth_data[32]
    sign_count = struct.unpack(">I", auth_data[33:37])[0]
    result = {"rp_id_hash": rp_id_hash, "flags": flags, "sign_count": sign_count}
    if flags & FLAG_AT:
        if len(auth_data) < 55:
            raise WebAuthnError("attested credential data truncated")
        cred_len = struct.unpack(">H", auth_data[53:55])[0]
        cred_id = auth_data[55:55 + cred_len]
        public_key, _ = cbor_decode(auth_data, 55 + cred_len)
        result.update(aaguid=auth_data[37:53].hex(), credential_id=cred_id, public_key=public_key)
    return result


class PasskeyStepUp:
    def __init__(self, rp_id: str, rp_name: str, origins: list[str], ttl: int = 300, clock=time.time):
        self.rp_id, self.rp_name, self.origins = rp_id, rp_name, set(origins)
        self._ttl, self._clock = ttl, clock
        self._pending: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    def options(self, account_id: str, user_name: str) -> dict:
        challenge = b64u_encode(secrets.token_bytes(32))
        with self._lock:
            self._pending[account_id] = (challenge, self._clock() + self._ttl)
        return {
            "challenge": challenge,
            "rp": {"id": self.rp_id, "name": self.rp_name},
            "user": {"id": b64u_encode(account_id.encode()), "name": user_name, "displayName": user_name},
            "pubKeyCredParams": [{"type": "public-key", "alg": a} for a in SUPPORTED_ALGS],
            "authenticatorSelection": {"userVerification": "required", "residentKey": "preferred"},
            "attestation": "none",
            "timeout": self._ttl * 1000,
        }

    def verify_registration(self, account_id: str, credential: dict) -> dict:
        with self._lock:
            challenge, expires = self._pending.pop(account_id, (None, 0))
        if challenge is None or self._clock() > expires:
            raise WebAuthnError("no pending passkey challenge")
        try:
            response = credential["response"]
            client_data = json.loads(b64u_decode(response["clientDataJSON"]))
            attestation, _ = cbor_decode(b64u_decode(response["attestationObject"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise WebAuthnError(f"malformed credential: {exc}")
        if client_data.get("type") != "webauthn.create":
            raise WebAuthnError("wrong ceremony type")
        if client_data.get("challenge") != challenge:
            raise WebAuthnError("challenge mismatch")
        if client_data.get("origin") not in self.origins:
            raise WebAuthnError("origin not allowed")
        if not isinstance(attestation, dict) or not isinstance(attestation.get("authData"), bytes):
            raise WebAuthnError("attestation object missing authData")

        auth = parse_auth_data(attestation["authData"])
        if auth["rp_id_hash"] != hashlib.sha256(self.rp_id.encode()).digest():
            raise WebAuthnError("credential created for a different site")
        if not auth["flags"] & FLAG_UP:
            raise WebAuthnError("user presence not confirmed")
        if not auth["flags"] & FLAG_UV:
            raise WebAuthnError("user verification (biometric/PIN) not performed")
        if "public_key" not in auth:
            raise WebAuthnError("no credential in attestation")
        alg = auth["public_key"].get(3)
        if alg not in SUPPORTED_ALGS:
            raise WebAuthnError("unsupported key algorithm")
        return {"credential_id": b64u_encode(auth["credential_id"]), "alg": SUPPORTED_ALGS[alg],
                "aaguid": auth["aaguid"], "attestation_format": attestation.get("fmt")}
