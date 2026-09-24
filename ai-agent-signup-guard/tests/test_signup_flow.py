"""Scenario tests: humans get through, bots and undeclared AI agents don't,
declared (signed) AI agents are routed to an accountable path."""
import json
import os
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

from signup_guard.agent_auth import sign_request
from signup_guard.server import Headers, make_handler

from .helpers import BROWSER_UA, HUMAN_TELEMETRY, browser_headers, get_challenge, make_agent_key, make_app, signup


class HumanSignupTests(unittest.TestCase):
    def setUp(self):
        self.app, self.clock = make_app()

    def _fill_form(self, seconds=25):
        c = get_challenge(self.app)
        self.clock.now += seconds
        return c

    def test_human_is_allowed_and_verifies_email(self):
        status, body = signup(self.app, self._fill_form())
        self.assertEqual(status, 202)
        self.assertEqual(body["next_steps"], ["verify_email"])
        link = self.app.mailer.outbox[-1]["body"]
        status, _, raw = self.app.handle("GET", link, browser_headers(), b"", "203.0.113.5")
        self.assertEqual((status, json.loads(raw)["status"]), (200, "active"))

    def test_password_manager_user_still_allowed(self):
        telemetry = dict(HUMAN_TELEMETRY, key_events=0, paste_events=2)
        status, body = signup(self.app, self._fill_form(), telemetry=telemetry)
        self.assertEqual((status, body["next_steps"]), (202, ["verify_email"]))

    def test_duplicate_email_gives_same_response(self):
        signup(self.app, self._fill_form())
        status, body = signup(self.app, self._fill_form(), ip="198.51.100.9")
        self.assertEqual(status, 202)
        self.assertEqual(self.app.mailer.outbox[-1]["subject"], "Signup attempt")

    def test_disposable_email_requires_step_up(self):
        status, body = signup(self.app, self._fill_form(), fields={"email": "x@mailinator.com"})
        self.assertEqual(body["next_steps"], ["verify_email", "step_up_verification"])
        link = self.app.mailer.outbox[-1]["body"]
        _, _, raw = self.app.handle("GET", link, browser_headers(), b"", "203.0.113.5")
        self.assertEqual(json.loads(raw)["status"], "pending_step_up")

    def test_weak_input_rejected(self):
        status, body = signup(self.app, self._fill_form(), fields={"password": "short"})
        self.assertEqual((status, body["error"]), (422, "invalid_fields"))


class BotTests(unittest.TestCase):
    def setUp(self):
        self.app, self.clock = make_app()

    def test_naive_spam_script_denied(self):
        headers = Headers({"User-Agent": "python-requests/2.32", "Host": "signup.example"})
        c = get_challenge(self.app, headers)
        self.assertEqual(c["pow"]["bits"], 10, "risky clients get harder proof of work")
        status, body = signup(self.app, c, headers=headers, telemetry=None,
                              fields={c["honeypot_field"]: "http://cheap-pills.example"})
        self.assertEqual((status, body), (403, {"error": "signup_rejected"}))

    def test_invalid_proof_of_work(self):
        status, body = signup(self.app, get_challenge(self.app), pow_solution="not-a-solution-" * 3)
        self.assertEqual((status, body["error"]), (400, "invalid_proof_of_work"))

    def test_challenge_replay_rejected(self):
        c = get_challenge(self.app)
        self.clock.now += 20
        signup(self.app, c)
        status, body = signup(self.app, c, fields={"email": "bob@example.org"})
        self.assertEqual((status, body["detail"]), (400, "challenge already used"))

    def test_headless_automation_denied(self):
        headers = browser_headers(**{"User-Agent": "Mozilla/5.0 HeadlessChrome/140.0"})
        c = get_challenge(self.app, headers)
        self.clock.now += 1
        telemetry = dict(HUMAN_TELEMETRY, webdriver=True, key_events=0, pointer_events=0)
        status, _ = signup(self.app, c, headers=headers, telemetry=telemetry)
        self.assertEqual(status, 403)

    def test_ip_velocity(self):
        results = []
        for i in range(10):
            c = get_challenge(self.app)
            self.clock.now += 20
            results.append(signup(self.app, c, fields={"email": f"u{i}@example.org"}))
        self.assertTrue(all(body["next_steps"] == ["verify_email"] for _, body in results[:5]))
        self.assertEqual(results[5][1]["next_steps"], ["verify_email", "step_up_verification"])
        self.assertEqual(results[-1][0], 403)


class UndeclaredAIAgentTests(unittest.TestCase):
    """Agents driving a real browser look human at the network layer, so the
    canary (hidden instruction only an LLM would read) is the key signal."""

    def setUp(self):
        self.app, self.clock = make_app()

    def test_agent_that_obeys_hidden_instruction_is_denied(self):
        c = get_challenge(self.app)
        self.clock.now += 40   # LLM agents are not necessarily fast
        status, body = signup(self.app, c, fields={"referral_code": c["canary_phrase"]})
        self.assertEqual(status, 403)
        self.assertEqual(body["agent_signup_url"], "/api/agent/signup")

    def test_self_declared_agent_ua_needs_step_up(self):
        headers = browser_headers(**{"User-Agent": BROWSER_UA + " ChatGPT-User/1.0"})
        c = get_challenge(self.app, headers)
        self.clock.now += 30
        status, body = signup(self.app, c, headers=headers)
        self.assertEqual(body["next_steps"], ["verify_email", "step_up_verification"])

    def test_forged_signature_headers_are_not_trusted(self):
        headers = browser_headers(**{"Signature-Agent": '"https://agent.example"',
                                     "Signature-Input": 'sig1=("@authority");keyid="x";tag="web-bot-auth"',
                                     "Signature": "sig1=:AAAA:"})
        c = get_challenge(self.app, headers)
        self.clock.now += 30
        status, body = signup(self.app, c, headers=headers)
        self.assertEqual(body["next_steps"], ["verify_email", "step_up_verification"])


class SignedAgentTests(unittest.TestCase):
    def setUp(self):
        self.key, path = make_agent_key()
        self.addCleanup(os.remove, path)
        self.app, self.clock = make_app(trusted_agents_file=path)

    def _signed(self, **kwargs):
        sig = sign_request(self.key, "test-agent-key", "signup.example", "https://agent.example",
                           created=int(self.clock.now), **kwargs)
        return browser_headers(**sig)

    def _agent_signup(self, headers, owner="owner@example.org"):
        body = json.dumps({"owner_email": owner, "purpose": "book travel"}).encode()
        status, _, raw = self.app.handle("POST", "/api/agent/signup", headers, body, "192.0.2.1")
        return status, json.loads(raw)

    def test_signed_agent_redirected_away_from_human_signup(self):
        c = get_challenge(self.app)
        status, body = signup(self.app, c, headers=self._signed())
        self.assertEqual((status, body["error"]), (403, "use_agent_registration"))

    def test_agent_registration_requires_owner_approval(self):
        status, body = self._agent_signup(self._signed())
        self.assertEqual((status, body["status"]), (202, "pending_owner_approval"))
        self.assertEqual(body["operator"], "Example Agents Inc.")
        mail = self.app.mailer.outbox[-1]
        self.assertEqual(mail["to"], "owner@example.org")
        link = mail["body"].rsplit("Approve: ", 1)[1]
        status, _, raw = self.app.handle("GET", link, browser_headers(), b"", "192.0.2.1")
        self.assertEqual(json.loads(raw), {"status": "active", "kind": "agent"})

    def test_unsigned_or_tampered_agent_rejected(self):
        self.assertEqual(self._agent_signup(browser_headers())[0], 401)
        tampered = self._signed()
        tampered._h["host"] = "evil.example"      # signature covered @authority
        self.assertEqual(self._agent_signup(tampered)[0], 401)

    def test_expired_signature_rejected(self):
        headers = self._signed(ttl=60)
        self.clock.now += 120
        self.assertEqual(self._agent_signup(headers)[0], 401)

    def test_policy_document(self):
        status, _, raw = self.app.handle("GET", "/.well-known/agent-signup", browser_headers(), b"", "x")
        self.assertEqual(json.loads(raw)["agent_signup_endpoint"], "/api/agent/signup")


class HttpServerTests(unittest.TestCase):
    def test_real_http_roundtrip(self):
        app, _ = make_app()
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        with urllib.request.urlopen(base + "/") as resp:
            self.assertIn(b"Create account", resp.read())
        with urllib.request.urlopen(base + "/api/signup/challenge") as resp:
            self.assertIn("token", json.load(resp))
        req = urllib.request.Request(base + "/api/signup", data=b"[1]", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
