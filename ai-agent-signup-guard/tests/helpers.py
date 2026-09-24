import base64
import json
import os
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from signup_guard.config import Settings
from signup_guard.pow import solve_pow
from signup_guard.server import Headers, SignupApp
from signup_guard.store import Mailer

BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"
HUMAN_TELEMETRY = {"key_events": 42, "pointer_events": 180, "paste_events": 0,
                   "untrusted_events": 0, "webdriver": False, "headless_hints": []}


class Clock:
    def __init__(self, now=1_800_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


def make_agent_key(keyid="test-agent-key", operator="Example Agents Inc."):
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    registry = {"agents": {keyid: {"operator": operator, "public_key": base64.b64encode(raw).decode()}}}
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as fh:
        json.dump(registry, fh)
    return key, path


def make_app(clock=None, **overrides):
    clock = clock or Clock()
    settings = Settings(secret_key=b"k" * 32, pow_bits=8, pow_bits_elevated=10, **overrides)
    return SignupApp(settings, clock=clock, mailer=Mailer(echo=False)), clock


def browser_headers(**extra):
    h = {"User-Agent": BROWSER_UA, "Accept-Language": "en-US,en;q=0.9", "Host": "signup.example"}
    h.update(extra)
    return Headers(h)


def get_challenge(app, headers=None):
    status, _, body = app.handle("GET", "/api/signup/challenge", headers or browser_headers(), b"", "203.0.113.5")
    assert status == 200
    return json.loads(body)


def signup(app, challenge, fields=None, headers=None, ip="203.0.113.5", telemetry=HUMAN_TELEMETRY, pow_solution=None):
    payload = {
        "email": "alice@example.org", "password": "correct horse battery", "display_name": "Alice",
        "referral_code": "", challenge["honeypot_field"]: "",
        "challenge_token": challenge["token"],
        "pow_solution": pow_solution or solve_pow(challenge["pow"]["nonce"], challenge["pow"]["bits"]),
    }
    if telemetry is not None:
        payload["telemetry"] = telemetry
    payload.update(fields or {})
    status, _, body = app.handle("POST", "/api/signup", headers or browser_headers(),
                                 json.dumps(payload).encode(), ip)
    return status, json.loads(body)
