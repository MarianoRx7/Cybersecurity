"""HTTP API for the protected signup flow (standard library only).

Routes
  GET  /                             demo signup page
  GET  /api/signup/challenge         issue a signed challenge (PoW, honeypot, canary)
  POST /api/signup                   human signup, risk-scored
  POST /api/agent/signup             signed AI agents register here, bound to a human owner
  POST /api/stepup/passkey/options   start passkey (biometric/PIN) step-up
  POST /api/stepup/passkey/verify    finish passkey step-up
  GET  /api/verify?token=...         email verification / owner approval link
  GET  /.well-known/agent-signup     machine-readable policy for AI agents
  GET  /admin                        attack dashboard (data needs the admin token)
  GET  /admin/api/summary?window=60  dashboard data
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import agent_auth, signals
from .challenge import ChallengeError, ChallengeIssuer
from .config import Settings
from .events import EventLog, mask_email
from .pow import verify_pow
from .risk import Decision, assess, classify
from .store import Account, AccountStore, Mailer, hash_password
from .webauthn import PasskeyStepUp, WebAuthnError

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
        self.events = EventLog(path=self.settings.event_log_path, clock=clock)
        rp_id = self.settings.rp_id or urlsplit(self.settings.origins[0]).hostname
        self.passkeys = PasskeyStepUp(rp_id, "Signup Guard", self.settings.origins, clock=clock)

    # Step-up tokens bind the passkey ceremony to the account that was just created.
    def _seal(self, payload: dict) -> str:
        body = json.dumps(payload, separators=(",", ":")).encode()
        mac = hmac.new(self.settings.secret_key, b"stepup:" + body, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(body).decode() + "." + base64.urlsafe_b64encode(mac).decode()

    def _unseal(self, token: str) -> dict | None:
        try:
            body_b64, mac_b64 = token.split(".")
            body = base64.urlsafe_b64decode(body_b64)
            mac = base64.urlsafe_b64decode(mac_b64)
        except (ValueError, AttributeError):
            return None
        expected = hmac.new(self.settings.secret_key, b"stepup:" + body, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected):
            return None
        try:
            payload = json.loads(body)
        except ValueError:
            return None
        return payload if isinstance(payload, dict) and payload.get("exp", 0) > self.clock() else None

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
        if route == ("GET", "/admin"):
            with open(os.path.join(STATIC_DIR, "dashboard.html"), "rb") as fh:
                return 200, "text/html; charset=utf-8", fh.read()
        if route == ("GET", "/admin/api/summary"):
            auth = headers.get("Authorization") or ""
            if not hmac.compare_digest(auth.encode(), f"Bearer {self.settings.admin_token}".encode()):
                return self._json(401, {"error": "admin_token_required"})
            try:
                window = max(5, min(int(parse_qs(url.query).get("window", ["60"])[0]), 7 * 24 * 60))
            except ValueError:
                window = 60
            return self._json(200, self.events.summary(window))
        if method == "POST" and url.path in ("/api/signup", "/api/agent/signup",
                                             "/api/stepup/passkey/options", "/api/stepup/passkey/verify"):
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
            if url.path == "/api/agent/signup":
                return self.agent_signup(data, headers, client_ip, url.path)
            return self.passkey_step_up(url.path.rsplit("/", 1)[1], data, client_ip)
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
        ua = headers.get("User-Agent", "")
        try:
            challenge = self.challenges.verify(str(data.get("challenge_token", "")))
        except ChallengeError as exc:
            self.events.record(type="invalid_request", ip=client_ip, ua=ua[:120], reason=str(exc))
            return self._json(400, {"error": "invalid_challenge", "detail": str(exc)})
        if not verify_pow(challenge["n"], data.get("pow_solution"), challenge["b"]):
            self.events.record(type="invalid_request", ip=client_ip, ua=ua[:120], reason="invalid proof of work")
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
        telemetry = data.get("telemetry")
        found += signals.telemetry_signals(telemetry)
        found += signals.behavior_signals(telemetry.get("behavior") if isinstance(telemetry, dict) else None)
        for extra in (signals.canary_signal(text_fields, self.challenges.canary_for(challenge["n"])),
                      signals.visible_trap_signal(text_fields),
                      signals.velocity_signal(self.velocity.hit(client_ip), s.velocity_max_per_ip)):
            if extra:
                found.append(extra)

        result = assess(found, s.allow_below, s.deny_at)
        label = classify(result.signals)
        log.info("signup ip=%s email=%s score=%d decision=%s class=%s signals=%s", client_ip, email,
                 result.score, result.decision.value, label, [x.name for x in result.signals])
        self.events.record(type="signup", ip=client_ip, email=mask_email(email), ua=ua[:120],
                           score=result.score, decision=result.decision.value, classification=label,
                           signals=[x.name for x in result.signals],
                           details={x.name: x.detail for x in result.signals if x.detail})

        if result.decision is Decision.DENY:
            # Don't tell the client which signal tripped; that just trains the bot.
            payload = {"error": "signup_rejected"}
            if result.agent_suspected:
                payload["agent_signup_url"] = AGENT_POLICY["agent_signup_endpoint"]
                payload["agent_policy"] = "/.well-known/agent-signup"
            return self._json(403, payload)

        step_up = result.decision is Decision.CHALLENGE
        account = Account(
            email=email, kind="human", status="pending_email_verification", risk_score=result.score,
            password_hash=hash_password(password), display_name=str(data.get("display_name", ""))[:80],
            step_up_required=step_up)
        token = self.store.create(account)
        if token:
            self.mailer.send(email, "Verify your email", f"/api/verify?token={token}")
        else:
            # Same response either way so the endpoint can't be used to enumerate accounts.
            self.mailer.send(email, "Signup attempt", "Someone tried to create an account with this email.")
        response = {"status": "check_your_email", "next_steps": ["verify_email"]}
        if step_up:
            response["next_steps"].append("passkey_verification")
            # A duplicate email gets a token for an account id that doesn't exist, so the
            # response looks identical and cannot attach a passkey to someone else's account.
            aid = account.id if token else secrets.token_urlsafe(12)
            response["step_up_token"] = self._seal({"aid": aid, "email": email, "exp": self.clock() + 1800})
        return self._json(202, response)

    def passkey_step_up(self, stage: str, data: dict, client_ip: str):
        sealed = self._unseal(str(data.get("step_up_token", "")))
        if not sealed:
            return self._json(401, {"error": "invalid_step_up_token"})
        if stage == "options":
            return self._json(200, self.passkeys.options(sealed["aid"], sealed["email"]))
        try:
            passkey = self.passkeys.verify_registration(sealed["aid"], data.get("credential") or {})
        except WebAuthnError as exc:
            self.events.record(type="step_up", ip=client_ip, email=mask_email(sealed["email"]),
                               ok=False, reason=str(exc))
            return self._json(400, {"error": "passkey_rejected", "detail": str(exc)})
        account = self.store.complete_step_up(sealed["aid"], passkey)
        self.events.record(type="step_up", ip=client_ip, email=mask_email(sealed["email"]), ok=True)
        return self._json(200, {"status": account.status if account else "pending_email_verification",
                                "passkey": "verified"})

    def agent_signup(self, data: dict, headers: Headers, client_ip: str, path: str):
        agent = self._verified_agent(headers, "POST", path)
        if not agent:
            self.events.record(type="invalid_request", ip=client_ip,
                               ua=(headers.get("User-Agent") or "")[:120], reason="unsigned agent registration")
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
        self.events.record(type="agent_signup", ip=client_ip, email=mask_email(owner),
                           ua=(headers.get("User-Agent") or "")[:120], operator=agent.operator)
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
    settings = Settings()
    if "SIGNUP_GUARD_ORIGINS" not in os.environ:
        settings.origins = [f"http://localhost:{port}", f"http://127.0.0.1:{port}"]
    demo = os.environ.get("SIGNUP_GUARD_DEMO_TRAFFIC") == "1"
    # Demo traffic fakes source IPs via X-Forwarded-For; never enable demo mode in production.
    settings.trust_proxy = demo or os.environ.get("SIGNUP_GUARD_TRUST_PROXY") == "1"
    app = SignupApp(settings)
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app))
    print(f"signup page:       http://localhost:{port}/")
    print(f"attack dashboard:  http://localhost:{port}/admin   (admin token: {settings.admin_token})")
    if demo:
        from .demo import start_demo_traffic
        start_demo_traffic(f"http://127.0.0.1:{port}", app)
        print("demo traffic: simulating humans, bots and AI agents in the background")
    server.serve_forever()


if __name__ == "__main__":
    main()
