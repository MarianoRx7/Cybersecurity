import unittest

from signup_guard.challenge import ChallengeError, ChallengeIssuer
from signup_guard.pow import leading_zero_bits, solve_pow, verify_pow
from signup_guard.risk import Decision, assess
from signup_guard.signals import Signal, canary_signal, user_agent_signals

from .helpers import Clock


class PowTests(unittest.TestCase):
    def test_leading_zero_bits(self):
        self.assertEqual(leading_zero_bits(b"\x00\x0f"), 12)
        self.assertEqual(leading_zero_bits(b"\x80"), 0)

    def test_solve_and_verify(self):
        solution = solve_pow("abc", 10)
        self.assertTrue(verify_pow("abc", solution, 10))
        self.assertFalse(verify_pow("other-nonce", solution, 20))
        self.assertFalse(verify_pow("abc", "x" * 100, 0))
        self.assertFalse(verify_pow("abc", None, 0))


class ChallengeTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.issuer = ChallengeIssuer(b"s" * 32, ttl=60, clock=self.clock)

    def test_roundtrip_and_single_use(self):
        c = self.issuer.issue(8)
        payload = self.issuer.verify(c["token"])
        self.assertEqual(payload["hp"], c["honeypot_field"])
        with self.assertRaisesRegex(ChallengeError, "already used"):
            self.issuer.verify(c["token"])

    def test_tampered_token_rejected(self):
        c = self.issuer.issue(8)
        body, sig = c["token"].split(".")
        with self.assertRaisesRegex(ChallengeError, "signature"):
            self.issuer.verify(body[:-2] + "AA." + sig)

    def test_expired(self):
        c = self.issuer.issue(8)
        self.clock.now += 61
        with self.assertRaisesRegex(ChallengeError, "expired"):
            self.issuer.verify(c["token"])

    def test_canary_is_deterministic_and_not_in_token(self):
        c = self.issuer.issue(8)
        self.assertEqual(self.issuer.canary_for(c["pow"]["nonce"]), c["canary_phrase"])
        self.assertNotIn(c["canary_phrase"].split("-")[0], c["token"])


class SignalTests(unittest.TestCase):
    def test_user_agents(self):
        names = lambda ua: {s.name for s in user_agent_signals(ua)}
        self.assertEqual(names("python-requests/2.32"), {"http_library_client"})
        self.assertIn("headless_browser_ua", names("Mozilla/5.0 HeadlessChrome/140.0"))
        self.assertIn("declared_ai_agent_ua", names("Mozilla/5.0 (compatible; ChatGPT-User/1.0)"))
        self.assertEqual(names("Mozilla/5.0 (Macintosh) Safari/605.1.15"), set())

    def test_canary_matches_loosely(self):
        self.assertIsNotNone(canary_signal({"referral_code": "Amber Delta 123"}, "amber-delta-123"))
        self.assertIsNone(canary_signal({"referral_code": "FRIEND10"}, "amber-delta-123"))

    def test_assess_thresholds(self):
        sig = lambda w: Signal("x", w, "bot")
        self.assertIs(assess([], 30, 70).decision, Decision.ALLOW)
        self.assertIs(assess([sig(10), sig(25)], 30, 70).decision, Decision.CHALLENGE)
        self.assertIs(assess([sig(50), sig(50)], 30, 70).decision, Decision.DENY)
        self.assertEqual(assess([sig(80), sig(80)], 30, 70).score, 100)


if __name__ == "__main__":
    unittest.main()
