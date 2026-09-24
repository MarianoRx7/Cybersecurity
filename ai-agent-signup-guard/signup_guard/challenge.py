"""Stateless, signed, single-use signup challenges.

Each challenge carries:
  * a proof-of-work nonce and difficulty,
  * a randomised honeypot field name (invisible to humans, tempting to bots),
  * a canary phrase derived from the nonce. The page hides an instruction
    addressed to "AI assistants" telling them to type the phrase into the
    referral field. Humans never see it; LLM agents reading the DOM often obey.
  * the issue time, so the server (not the client) measures time-to-submit.
"""
import base64
import hashlib
import hmac
import json
import secrets
import threading
import time

HONEYPOT_NAMES = ["website", "company_url", "fax_number", "homepage", "middle_initial", "nickname_alt"]
CANARY_WORDS = [
    "amber", "basalt", "cobalt", "delta", "ember", "fjord", "garnet", "harbor",
    "indigo", "juniper", "kestrel", "lagoon", "meadow", "nimbus", "onyx", "prairie",
    "quartz", "raven", "sierra", "tundra", "umber", "violet", "willow", "zephyr",
]


class ChallengeError(Exception):
    pass


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class ChallengeIssuer:
    def __init__(self, secret: bytes, ttl: int = 600, clock=time.time):
        self._secret = secret
        self._ttl = ttl
        self._clock = clock
        self._used: dict[str, float] = {}
        self._lock = threading.Lock()

    def _sign(self, data: bytes) -> bytes:
        return hmac.new(self._secret, data, hashlib.sha256).digest()

    def canary_for(self, nonce: str) -> str:
        h = hmac.new(self._secret, b"canary:" + nonce.encode(), hashlib.sha256).digest()
        first = CANARY_WORDS[h[0] % len(CANARY_WORDS)]
        second = CANARY_WORDS[h[1] % len(CANARY_WORDS)]
        return f"{first}-{second}-{int.from_bytes(h[2:4], 'big') % 900 + 100}"

    def issue(self, pow_bits: int) -> dict:
        nonce = secrets.token_urlsafe(16)
        honeypot = f"{secrets.choice(HONEYPOT_NAMES)}_{secrets.token_hex(2)}"
        payload = {"n": nonce, "iat": self._clock(), "b": pow_bits, "hp": honeypot}
        body = json.dumps(payload, separators=(",", ":")).encode()
        token = f"{_b64e(body)}.{_b64e(self._sign(body))}"
        return {
            "token": token,
            "pow": {"nonce": nonce, "bits": pow_bits},
            "honeypot_field": honeypot,
            "canary_phrase": self.canary_for(nonce),
            "expires_in": self._ttl,
        }

    def verify(self, token: str, consume: bool = True) -> dict:
        try:
            body_b64, sig_b64 = token.split(".")
            body = _b64d(body_b64)
            sig = _b64d(sig_b64)
        except (ValueError, AttributeError):
            raise ChallengeError("malformed challenge token")
        if not hmac.compare_digest(sig, self._sign(body)):
            raise ChallengeError("invalid challenge signature")
        payload = json.loads(body)
        now = self._clock()
        if now - payload["iat"] > self._ttl:
            raise ChallengeError("challenge expired")
        if consume:
            with self._lock:
                self._used = {n: exp for n, exp in self._used.items() if exp > now}
                if payload["n"] in self._used:
                    raise ChallengeError("challenge already used")
                self._used[payload["n"]] = payload["iat"] + self._ttl
        return payload
