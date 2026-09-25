"""Demo traffic: simulated people, spam bots and AI agents hitting the real
HTTP endpoints, so the attack dashboard has something to show.

Enabled with SIGNUP_GUARD_DEMO_TRAFFIC=1. It relies on X-Forwarded-For to fake
many source IPs, so demo mode turns on trust_proxy. Never run it in production.
All IPs are from the documentation ranges (RFC 5737); emails use example domains.
"""
import json
import random
import threading
import time
import urllib.error
import urllib.request

from .pow import solve_pow

BROWSER_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
]
NAMES = ["alice", "bruno", "chen", "dana", "emeka", "fatima", "giulia", "hiro", "ines", "jonas", "kavya", "liam",
         "maya", "noah", "olga", "priya", "quinn", "rosa", "sam", "tariq", "uma", "vera", "wen", "yusuf", "zoe"]
BOT_POOL = [f"192.0.2.{i}" for i in (11, 12, 13, 57, 58)]           # "datacenter" spam hosts
AGENT_POOL = [f"198.51.100.{i}" for i in range(200, 212)]


def _human_ip():
    return f"203.0.113.{random.randint(1, 254)}"


def _human_behavior():
    clicks = random.randint(4, 7)
    return {"clicks": clicks, "teleport_clicks": random.randint(0, 1), "click_center_offset": random.uniform(0.18, 0.6),
            "path_samples": clicks - 1, "path_straightness": random.uniform(0.7, 0.95),
            "keys": random.randint(25, 60), "key_interval_cv": random.uniform(0.35, 0.9),
            "idle_gaps": random.randint(0, 2), "idle_ratio": random.uniform(0.05, 0.4)}


def _human_telemetry(**overrides):
    t = {"key_events": random.randint(25, 60), "pointer_events": random.randint(80, 400), "paste_events": 0,
         "untrusted_events": 0, "webdriver": False, "headless_hints": [], "behavior": _human_behavior()}
    t.update(overrides)
    return t


def _computer_use_telemetry():
    clicks = random.randint(4, 6)
    return _human_telemetry(pointer_events=random.randint(4, 12), behavior={
        "clicks": clicks, "teleport_clicks": clicks - random.randint(0, 1), "click_center_offset": random.uniform(0.0, 0.05),
        "path_samples": 0, "path_straightness": None, "keys": random.randint(25, 45),
        "key_interval_cv": random.uniform(0.02, 0.12), "idle_gaps": random.randint(4, 8),
        "idle_ratio": random.uniform(0.75, 0.92)})


class DemoTraffic:
    def __init__(self, base_url: str, app=None):
        self.base = base_url.rstrip("/")
        self.app = app
        self._slots = threading.BoundedSemaphore(24)
        self._signed = self._setup_signed_agent()

    def _setup_signed_agent(self):
        if self.app is None:
            return None
        try:
            import base64
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        except ImportError:
            return None
        key = Ed25519PrivateKey.generate()
        raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.app.agent_registry["demo-agent-key"] = {"operator": "Demo Assistant Co.",
                                                      "public_key": base64.b64encode(raw).decode()}
        return key

    # -- HTTP -----------------------------------------------------------------
    def _request(self, method, path, ip, ua, body=None, extra_headers=None):
        headers = {"User-Agent": ua, "X-Forwarded-For": ip, "Content-Type": "application/json"}
        if ua.startswith("Mozilla"):
            headers["Accept-Language"] = "en-US,en;q=0.9"
        headers.update(extra_headers or {})
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)

    def _signup(self, ip, ua, fill_seconds, telemetry, email=None, mutate=None, reuse=None):
        status, challenge = reuse or self._request("GET", "/api/signup/challenge", ip, ua)
        time.sleep(fill_seconds)
        name = random.choice(NAMES)
        body = {"email": email or f"{name}.{random.randint(10, 9999)}@example.com",
                "password": "demo-password-" + str(random.randint(1000, 9999)), "display_name": name.title(),
                "referral_code": "", challenge["honeypot_field"]: "",
                "challenge_token": challenge["token"],
                "pow_solution": solve_pow(challenge["pow"]["nonce"], challenge["pow"]["bits"])}
        if telemetry is not None:
            body["telemetry"] = telemetry
        if mutate:
            mutate(body, challenge)
        self._request("POST", "/api/signup", ip, ua, body)
        return status, challenge

    # -- actors ---------------------------------------------------------------
    def human(self):
        self._signup(_human_ip(), random.choice(BROWSER_UA), random.uniform(6, 20), _human_telemetry())

    def password_manager_human(self):
        t = _human_telemetry(key_events=0, paste_events=2)
        t["behavior"].update(keys=0, key_interval_cv=None)
        self._signup(_human_ip(), random.choice(BROWSER_UA), random.uniform(4, 10), t)

    def spam_bot_burst(self):
        ip = random.choice(BOT_POOL)
        for _ in range(random.randint(4, 9)):
            self._signup(ip, "python-requests/2.32.3", random.uniform(0.1, 0.6), None,
                         email=f"promo{random.randint(1, 99999)}@mailinator.com",
                         mutate=lambda b, c: b.update({c["honeypot_field"]: "https://cheap-deals.example"}))

    def headless(self):
        ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/140.0 Safari/537.36"
        t = _human_telemetry(webdriver=True, key_events=0, pointer_events=0, headless_hints=["no_plugins", "headless_ua"])
        t["behavior"] = {}
        self._signup(random.choice(AGENT_POOL), ua, random.uniform(0.5, 2.5), t)

    def llm_agent(self):
        """Agent browser that reads the DOM and obeys the hidden instruction."""
        self._signup(random.choice(AGENT_POOL), random.choice(BROWSER_UA), random.uniform(8, 25), _human_telemetry(),
                     mutate=lambda b, c: b.update({"referral_code": c["canary_phrase"]}))

    def computer_use_agent(self):
        """Screenshot-driven agent on a real browser: only behaviour gives it away."""
        ticks = random.random() < 0.35
        self._signup(_human_ip(), random.choice(BROWSER_UA), random.uniform(15, 40), _computer_use_telemetry(),
                     mutate=(lambda b, c: b.update({"agent_ack": "1"})) if ticks else None)

    def declared_agent(self):
        self._signup(random.choice(AGENT_POOL), BROWSER_UA[0] + " ChatGPT-User/1.0", random.uniform(8, 20),
                     _human_telemetry())

    def disposable(self):
        self._signup(_human_ip(), random.choice(BROWSER_UA), random.uniform(6, 15), _human_telemetry(),
                     email=f"{random.choice(NAMES)}@yopmail.com")

    def replay(self):
        ip, ua = random.choice(BOT_POOL), "Go-http-client/2.0"
        first = self._signup(ip, ua, 0.2, None)
        self._signup(ip, ua, 0.1, None, reuse=first)

    def signed_agent(self):
        if self._signed is None:
            return self.human()
        from urllib.parse import urlsplit
        from .agent_auth import sign_request
        headers = sign_request(self._signed, "demo-agent-key", urlsplit(self.base).netloc, "https://assistant.example")
        self._request("POST", "/api/agent/signup", random.choice(AGENT_POOL), "DemoAssistant/1.0 (+https://assistant.example)",
                      {"owner_email": f"{random.choice(NAMES)}@example.com", "purpose": "manage bookings"}, headers)

    ACTORS = [("human", 38), ("password_manager_human", 8), ("spam_bot_burst", 7), ("headless", 9),
              ("llm_agent", 8), ("computer_use_agent", 12), ("declared_agent", 5), ("disposable", 5),
              ("replay", 3), ("signed_agent", 5)]

    def _run_actor(self, name):
        try:
            getattr(self, name)()
        except Exception as exc:          # keep the demo alive whatever happens
            print(f"[demo] {name} failed: {exc}")
        finally:
            self._slots.release()

    def loop(self, rate_per_minute: float = 40):
        names, weights = zip(*self.ACTORS)
        while True:
            self._slots.acquire()
            name = random.choices(names, weights)[0]
            threading.Thread(target=self._run_actor, args=(name,), daemon=True).start()
            time.sleep(random.expovariate(rate_per_minute / 60))


def start_demo_traffic(base_url: str, app=None, rate_per_minute: float = 40) -> DemoTraffic:
    demo = DemoTraffic(base_url, app)
    threading.Thread(target=demo.loop, args=(rate_per_minute,), daemon=True).start()
    return demo
