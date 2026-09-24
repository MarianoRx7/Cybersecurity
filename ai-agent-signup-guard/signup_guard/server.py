"""HTTP API for the protected signup flow (standard library only).

Routes
  GET  /                             demo signup page
  GET  /api/signup/challenge         issue a signed challenge (PoW, honeypot, canary)
  POST /api/signup                   human signup, risk-scored
  POST /api/agent/signup             signed AI agents register here, bound to a human owner
  GET  /api/verify?token=...         email verification / owner approval link
  GET  /.well-known/agent-signup     machine-readable policy for AI agents
"""
import json
import logging
import os
import re
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import agent_auth, signals
from .challenge import ChallengeError, ChallengeIssuer
from .config import Settings
from .pow import verify_pow
from .risk import Decision, assess
from .store import Account, AccountStore, Mailer, hash_password

log = logging.getLogger("signup_guard")
MAX_BODY = 16 * 1024
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[A-Za-z]{2,}$")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "static")
AGENT_POLICY = {
    "agent_signup_endpoint": "/api/agent/signup",
    "authentication": "Web Bot Auth (HTTP Message Signatures, RFC 9421) with tag=web-bot-auth",
    "requirements": [
        "Sign requests with a key published by your operator",
        "Provide owner_email: the human accountable for the agent",
        "The owner must approve the account before it becomes active",
    ],
    "human_signup_by_agents": "not permitted; undeclared automation is rejected",
}


class Headers:
    """Case-insensitive header view for both http.server and tests."""

    def __init__(self, items):
        self._h = {k.lower(): v for k, v in dict(items).items()}

    def get(self, name, default=None):
        return self._h.get(name.lower(), default)


class SignupApp:
    def __init__(self, settings: Settings | None = None, clock=time.time, mailer: Mailer | None = None):
        self.settings = settings or Settings()
        self.clock = clock
        self.challenges = ChallengeIssuer(self.settings.secret_key, self.settings.challenge_ttl, clock)
        self.velocity = signals.VelocityTracker(self.settings.velocity_window, clock)
        self.store = AccountStore()
        self.mailer = mailer or Mailer()
        self.agent_registry = agent_auth.load_registry(self.settings.trusted_agents_file)

    # -- helpers -------------------------------------------------------------
    def _verified_agent(self, headers: Headers, method: str, path: str):
        if not agent_auth.has_signature_headers(headers):
            return None
        try:
            return agent_auth.verify_request(headers, method, path, self.agent_registry,
                                             self.settings.max_signature_age, self.clock)
        except agent_auth.AgentAuthError as exc:
            log.info("agent signature rejected: %s", exc)
            return None

    # -- routes --------------------------------------------------------------
    def handle(self, method: str, target: str, headers: Headers, body: bytes, client_ip: str):
        url = urlsplit(target)
        route = (method, url.path)
        if route == ("GET", "/"):
            with open(os.path.join(STATIC_DIR, "signup.html"), "rb") as fh:
                return 200, "text/html; charset=utf-8", fh.read()
        if route == ("GET", "/.well-known/agent-signup"):
            return self._json(200, AGENT_POLICY)
        if route == ("GET", "/api/signup/challenge"):
            return self.issue_challenge(headers)
        if route == ("GET", "/api/verify"):
            return self.verify(parse_qs(url.query).get("token", [""])[0])
        if method == "POST" and url.path in ("/api/signup", "/api/agent/signup"):
            if len(body) > MAX_BODY:
                return self._json(413, {"error": "payload_too_large"})
            try:
                data = json.loads(body or b"{}")
                if not isinstance(data, dict):
                    raise ValueError
            except ValueError:
                return self._json(400, {"error": "invalid_json"})
            if url.path == "/api/signup":
                return self.signup(data, headers, client_ip, url.path)
            return self.agent_signup(data, headers, url.path)
        return self._json(404, {"error": "not_found"})

    def issue_challenge(self, headers: Headers):
        risky = signals.user_agent_signals(headers.get("User-Agent", ""))
        bits = self.settings.pow_bits_elevated if risky else self.settings.pow_bits
        return self._json(200, self.challenges.issue(bits))

    def signup(self, data: dict, headers: Headers, client_ip: str, path: str):
        s = self.settings
        agent = self._verified_agent(headers, "POST", path)
        if agent:
            # Honest, signed agents are welcome, just not through the human door.
            return self._json(403, {"error": "use_agent_registration",
                                    "agent_signup_url": AGENT_POLICY["agent_signup_endpoint"]})
        try:
            challenge = self.challenges.verify(str(data.get("challenge_token", "")))
        except ChallengeError as exc:
            return self._json(400, {"error": "invalid_challenge", "detail": str(exc)})
        if not verify_pow(challenge["n"], data.get("pow_solution"), challenge["b"]):
            return self._json(400, {"error": "invalid_proof_of_work"})

        email = str(data.get("email", "")).strip()
        password = str(data.get("password", ""))
        if not EMAIL_RE.match(email) or len(password) < 10:
            return self._json(422, {"error": "invalid_fields",
                                    "detail": "valid email and a password of 10+ characters required"})

        now = self.clock()
        text_fields = {k: v for k, v in data.items() if k not in ("challenge_token", "pow_solution", "telemetry")}
        found = []
        found += signals.user_agent_signals(headers.get("User-Agent", ""))
        found += signals.header_signals(headers)
        found += signals.form_signals(text_fields, challenge["hp"], challenge["iat"], s.min_fill_seconds, now)
        found += signals.telemetry_signals(data.get("telemetry"))
        for extra in (signals.canary_signal(text_fields, self.challenges.canary_for(challenge["n"])),
                      signals.velocity_signal(self.velocity.hit(client_ip), s.velocity_max_per_ip)):
            if extra:
                found.append(extra)

        result = assess(found, s.allow_below, s.deny_at)
        log.info("signup ip=%s email=%s score=%d decision=%s signals=%s", client_ip, email,
                 result.score, result.decision.value, [x.name for x in result.signals])

        if result.decision is Decision.DENY:
            # Don't tell the client which signal tripped; that just trains the bot.
            payload = {"error": "signup_rejected"}
            if result.agent_suspected:
                payload["agent_signup_url"] = AGENT_POLICY["agent_signup_endpoint"]
                payload["agent_policy"] = "/.well-known/agent-signup"
            return self._json(403, payload)

        step_up = result.decision is Decision.CHALLENGE
        token = self.store.create(Account(
            email=email, kind="human", status="pending_email_verification", risk_score=result.score,
            password_hash=hash_password(password), display_name=str(data.get("display_name", ""))[:80],
            step_up_required=step_up))
        if token:
            self.mailer.send(email, "Verify your email", f"/api/verify?token={token}")
        else:
            # Same response either way so the endpoint can't be used to enumerate accounts.
            self.mailer.send(email, "Signup attempt", "Someone tried to create an account with this email.")
        next_steps = ["verify_email"] + (["step_up_verification"] if step_up else [])
        return self._json(202, {"status": "check_your_email", "next_steps": next_steps})

    def agent_signup(self, data: dict, headers: Headers, path: str):
        agent = self._verified_agent(headers, "POST", path)
        if not agent:
            return self._json(401, {"error": "agent_signature_required",
                                    "agent_policy": "/.well-known/agent-signup"})
        owner = str(data.get("owner_email", "")).strip()
        if not EMAIL_RE.match(owner):
            return self._json(422, {"error": "owner_email_required"})
        agent_id = f"agent+{agent.keyid[:12]}+{owner}"
        token = self.store.create(Account(
            email=agent_id, kind="agent", status="pending_owner_approval",
            agent_operator=agent.operator, purpose=str(data.get("purpose", ""))[:200]))
        if token is None:
            return self._json(409, {"error": "agent_already_registered_for_owner"})
        self.mailer.send(owner, "Approve an AI agent account",
                         f"{agent.operator} wants an account acting on your behalf "
                         f"(purpose: {data.get('purpose', 'n/a')}). Approve: /api/verify?token={token}")
        return self._json(202, {"status": "pending_owner_approval", "agent_account": agent_id,
                                "operator": agent.operator})

    def verify(self, token: str):
        account = self.store.redeem(token)
        if not account:
            return self._json(404, {"error": "invalid_or_used_token"})
        return self._json(200, {"status": account.status, "kind": account.kind})

    @staticmethod
    def _json(status: int, payload: dict):
        return status, "application/json", json.dumps(payload).encode()


def make_handler(app: SignupApp):
    class Handler(BaseHTTPRequestHandler):
        server_version = "signup-guard"

        def _dispatch(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                status, ctype, body = SignupApp._json(413, {"error": "payload_too_large"})
            else:
                raw = self.rfile.read(length) if length else b""
                ip = self.client_address[0]
                if app.settings.trust_proxy and self.headers.get("X-Forwarded-For"):
                    ip = self.headers["X-Forwarded-For"].split(",")[0].strip()
                status, ctype, body = app.handle(self.command, self.path, Headers(self.headers.items()), raw, ip)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Link", '</.well-known/agent-signup>; rel="agent-policy"')
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = _dispatch

        def log_message(self, fmt, *args):
            log.debug(fmt, *args)

    return Handler


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(SignupApp()))
    print(f"signup-guard listening on http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
