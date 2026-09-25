import hashlib
import json
import struct
import unittest

from signup_guard.webauthn import b64u_encode, cbor_decode

from .helpers import HUMAN_TELEMETRY, browser_headers, get_challenge, make_app, signup

ORIGIN = "http://localhost:8000"

HUMAN_BEHAVIOR = {"clicks": 5, "teleport_clicks": 1, "click_center_offset": 0.37, "path_samples": 4,
                  "path_straightness": 0.86, "keys": 40, "key_interval_cv": 0.55, "idle_gaps": 1, "idle_ratio": 0.2}
COMPUTER_USE_BEHAVIOR = {"clicks": 5, "teleport_clicks": 5, "click_center_offset": 0.02, "path_samples": 0,
                         "path_straightness": None, "keys": 38, "key_interval_cv": 0.06, "idle_gaps": 6, "idle_ratio": 0.85}


def telemetry(behavior, **extra):
    return dict(HUMAN_TELEMETRY, behavior=behavior, **extra)


# -- a minimal CBOR encoder and fake authenticator for passkey tests ----------
def cbor(value) -> bytes:
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, "big")
    if isinstance(value, bool):
        return bytes([0xF5 if value else 0xF4])
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        return head(3, len(value.encode())) + value.encode()
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(v) for v in value)
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    raise TypeError(value)


def fake_credential(options, origin=ORIGIN, flags=0x45, rp_id=None):
    cred_id = b"credential-id-123"
    cose_key = {1: 2, 3: -7, -1: 1, -2: b"x" * 32, -3: b"y" * 32}
    auth_data = (hashlib.sha256((rp_id or options["rp"]["id"]).encode()).digest() + bytes([flags])
                 + struct.pack(">I", 0) + b"\0" * 16 + struct.pack(">H", len(cred_id)) + cred_id + cbor(cose_key))
    client_data = {"type": "webauthn.create", "challenge": options["challenge"], "origin": origin}
    return {"id": b64u_encode(cred_id), "response": {
        "clientDataJSON": b64u_encode(json.dumps(client_data).encode()),
        "attestationObject": b64u_encode(cbor({"fmt": "none", "attStmt": {}, "authData": auth_data}))}}


class ComputerUseTests(unittest.TestCase):
    def setUp(self):
        self.app, self.clock = make_app()

    def _run(self, behavior, fields=None):
        c = get_challenge(self.app)
        self.clock.now += 35
        return signup(self.app, c, telemetry=telemetry(behavior), fields=fields)

    def test_human_behavior_allowed(self):
        status, body = self._run(HUMAN_BEHAVIOR)
        self.assertEqual((status, body["next_steps"]), (202, ["verify_email"]))

    def test_screenshot_driven_agent_must_pass_passkey(self):
        # Behaviour alone is capped below deny (accessibility tools can look robotic),
        # so it lands on the passkey step, which an agent can't complete.
        status, body = self._run(COMPUTER_USE_BEHAVIOR)
        self.assertEqual((status, body["next_steps"]), (202, ["verify_email", "passkey_verification"]))
        event = self.app.events.snapshot()[-1]
        self.assertEqual((event["classification"], event["score"]), ("computer_use_agent", 65))
        self.assertIn("cursor_teleports_to_targets", event["signals"])

    def test_screenshot_driven_agent_with_other_signals_denied(self):
        status, body = self._run(COMPUTER_USE_BEHAVIOR, fields={"email": "a@mailinator.com"})
        self.assertEqual(status, 403)
        self.assertIn("agent_signup_url", body)

    def test_single_odd_trait_only_steps_up(self):
        # A careful, precise human might click near centres; alone that must not block.
        behavior = dict(HUMAN_BEHAVIOR, teleport_clicks=4, click_center_offset=0.05)
        status, body = self._run(behavior)
        self.assertEqual((status, body["next_steps"]), (202, ["verify_email", "passkey_verification"]))

    def test_visible_agent_checkbox(self):
        status, body = self._run(HUMAN_BEHAVIOR, fields={"agent_ack": "1"})
        self.assertIn("passkey_verification", body["next_steps"])
        self.assertEqual(self.app.events.snapshot()[-1]["classification"], "llm_agent")
        status, _ = self._run(dict(HUMAN_BEHAVIOR, teleport_clicks=5, click_center_offset=0.02),
                              fields={"agent_ack": "on", "email": "b@example.org"})
        self.assertEqual(status, 403)


class PasskeyStepUpTests(unittest.TestCase):
    def setUp(self):
        self.app, self.clock = make_app(origins=[ORIGIN])
        c = get_challenge(self.app)
        self.clock.now += 30
        status, body = signup(self.app, c, fields={"email": "risky@mailinator.com"})
        self.assertIn("step_up_token", body)
        self.token = body["step_up_token"]

    def _post(self, stage, body):
        status, _, raw = self.app.handle("POST", f"/api/stepup/passkey/{stage}", browser_headers(),
                                         json.dumps(body).encode(), "203.0.113.5")
        return status, json.loads(raw)

    def _options(self):
        status, options = self._post("options", {"step_up_token": self.token})
        self.assertEqual(status, 200)
        self.assertEqual(options["authenticatorSelection"]["userVerification"], "required")
        return options

    def _verify_email(self):
        link = self.app.mailer.outbox[-1]["body"]
        _, _, raw = self.app.handle("GET", link, browser_headers(), b"", "x")
        return json.loads(raw)["status"]

    def test_full_flow_activates_account(self):
        self.assertEqual(self._verify_email(), "pending_step_up")
        status, body = self._post("verify", {"step_up_token": self.token, "credential": fake_credential(self._options())})
        self.assertEqual((status, body["status"]), (200, "active"))
        self.assertEqual(self.app.store.get("risky@mailinator.com").passkey["alg"], "ES256")

    def test_rejects_without_user_verification(self):
        cred = fake_credential(self._options(), flags=0x41)     # UP + AT, no UV
        status, body = self._post("verify", {"step_up_token": self.token, "credential": cred})
        self.assertEqual(status, 400)
        self.assertIn("user verification", body["detail"])

    def test_rejects_wrong_origin_and_wrong_site(self):
        status, _ = self._post("verify", {"step_up_token": self.token,
                                          "credential": fake_credential(self._options(), origin="https://evil.example")})
        self.assertEqual(status, 400)
        status, _ = self._post("verify", {"step_up_token": self.token,
                                          "credential": fake_credential(self._options(), rp_id="evil.example")})
        self.assertEqual(status, 400)

    def test_challenge_single_use_and_token_required(self):
        options = self._options()
        self._post("verify", {"step_up_token": self.token, "credential": fake_credential(options)})
        status, _ = self._post("verify", {"step_up_token": self.token, "credential": fake_credential(options)})
        self.assertEqual(status, 400)
        self.assertEqual(self._post("options", {"step_up_token": self.token[:-4] + "AAAA"})[0], 401)

    def test_expired_step_up_token(self):
        self.clock.now += 3600
        self.assertEqual(self._post("options", {"step_up_token": self.token})[0], 401)

    def test_cbor_decoder_rejects_truncation(self):
        from signup_guard.webauthn import WebAuthnError
        with self.assertRaises(WebAuthnError):
            cbor_decode(cbor({"authData": b"x" * 40})[:-5])


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.app, self.clock = make_app(admin_token="secret-admin")

    def _summary(self, token="secret-admin", window="15"):
        h = browser_headers(Authorization=f"Bearer {token}")
        status, _, raw = self.app.handle("GET", f"/admin/api/summary?window={window}", h, b"", "x")
        return status, json.loads(raw)

    def test_requires_admin_token(self):
        self.assertEqual(self._summary("wrong")[0], 401)
        status, _, raw = self.app.handle("GET", "/admin/api/summary", browser_headers(), b"", "x")
        self.assertEqual(status, 401)

    def test_aggregates_attempts(self):
        for fields, behavior in (({}, HUMAN_BEHAVIOR), ({"email": "x@example.org"}, COMPUTER_USE_BEHAVIOR)):
            c = get_challenge(self.app)
            self.clock.now += 30
            signup(self.app, c, fields=fields, telemetry=telemetry(behavior))
        bad = get_challenge(self.app)
        signup(self.app, bad, pow_solution="x" * 40)
        status, d = self._summary()
        self.assertEqual(status, 200)
        self.assertEqual(d["totals"]["attempts"], 2)
        self.assertEqual((d["totals"]["allow"], d["totals"]["challenge"]), (1, 1))
        self.assertEqual(d["totals"]["agents_detected"], 1)
        self.assertEqual(d["totals"]["invalid_requests"], 1)
        self.assertEqual(sum(b["allow"] + b["deny"] + b["challenge"] for b in d["series"]), 2)
        self.assertEqual(dict(d["classifications"]), {"human": 1, "computer_use_agent": 1})
        self.assertEqual(d["top_ips"][0]["ip"], "203.0.113.5")
        self.assertEqual(d["recent"][0]["type"], "invalid_request")
        self.assertNotIn("alice@example.org", json.dumps(d), "emails must be masked")

    def test_window_excludes_old_events(self):
        c = get_challenge(self.app)
        self.clock.now += 30
        signup(self.app, c)
        self.clock.now += 20 * 60
        self.assertEqual(self._summary(window="15")[1]["totals"]["attempts"], 0)
        self.assertEqual(self._summary(window="60")[1]["totals"]["attempts"], 1)
        self.assertEqual(self._summary(window="junk")[0], 200)


if __name__ == "__main__":
    unittest.main()
