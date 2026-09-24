"""In-memory account store and mailer. Swap for a database and a real email
provider in production; the interfaces are deliberately small."""
import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass, field


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${digest.hex()}"


def check_password(password: str, stored: str) -> bool:
    _, salt, digest = stored.split("$")
    candidate = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1)
    return hmac.compare_digest(candidate.hex(), digest)


@dataclass
class Account:
    email: str
    kind: str                 # "human" | "agent"
    status: str               # pending_email_verification | pending_step_up | pending_owner_approval | active
    risk_score: int = 0
    password_hash: str = ""
    display_name: str = ""
    agent_operator: str = ""
    purpose: str = ""
    step_up_required: bool = False
    email_verified: bool = False
    passkey: dict | None = None
    id: str = field(default_factory=lambda: secrets.token_urlsafe(12))

    def refresh_status(self):
        if self.kind == "agent":
            self.status = "active" if self.email_verified else "pending_owner_approval"
        elif not self.email_verified:
            self.status = "pending_email_verification"
        elif self.step_up_required and not self.passkey:
            self.status = "pending_step_up"
        else:
            self.status = "active"


class AccountStore:
    def __init__(self):
        self._accounts: dict[str, Account] = {}
        self._tokens: dict[str, str] = {}
        self._lock = threading.Lock()

    def get(self, email: str) -> Account | None:
        return self._accounts.get(email.lower())

    def by_id(self, account_id: str) -> Account | None:
        return next((a for a in self._accounts.values() if a.id == account_id), None)

    def complete_step_up(self, account_id: str, passkey: dict) -> Account | None:
        with self._lock:
            account = self.by_id(account_id)
            if account:
                account.passkey = passkey
                account.refresh_status()
            return account

    def create(self, account: Account) -> str | None:
        """Store the account and return a verification token, or None if the
        email is already registered."""
        key = account.email.lower()
        with self._lock:
            if key in self._accounts:
                return None
            self._accounts[key] = account
            token = secrets.token_urlsafe(24)
            self._tokens[token] = key
            return token

    def redeem(self, token: str) -> Account | None:
        with self._lock:
            key = self._tokens.pop(token, None)
            account = self._accounts.get(key) if key else None
            if account is None:
                return None
            account.email_verified = True
            account.refresh_status()
            return account


class Mailer:
    def __init__(self, echo: bool = True):
        self.outbox: list[dict] = []
        self._echo = echo

    def send(self, to: str, subject: str, body: str):
        self.outbox.append({"to": to, "subject": subject, "body": body})
        if self._echo:
            print(f"[mail] to={to} subject={subject!r}\n{body}\n", flush=True)
