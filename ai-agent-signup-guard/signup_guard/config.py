import os
import secrets
from dataclasses import dataclass, field


def _secret_from_env() -> bytes:
    value = os.environ.get("SIGNUP_GUARD_SECRET")
    return value.encode() if value else secrets.token_bytes(32)


@dataclass
class Settings:
    secret_key: bytes = field(default_factory=_secret_from_env)
    challenge_ttl: int = 600            # seconds a signup challenge stays valid
    pow_bits: int = 14                  # proof-of-work difficulty (leading zero bits)
    pow_bits_elevated: int = 18         # difficulty for clients that already look risky
    min_fill_seconds: float = 3.0       # humans rarely finish the form faster
    velocity_window: int = 3600         # seconds
    velocity_max_per_ip: int = 5        # signup attempts per IP per window
    allow_below: int = 30               # score < allow_below        -> allow
    deny_at: int = 70                   # score >= deny_at           -> deny
    trust_proxy: bool = False           # honour X-Forwarded-For
    trusted_agents_file: str = os.path.join(os.path.dirname(__file__), "..", "trusted_agents.json")
    max_signature_age: int = 3600       # seconds a Web Bot Auth signature may live
