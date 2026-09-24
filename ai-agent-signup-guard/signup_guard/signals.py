"""Individual risk signals. Each is weak on its own; together they separate
humans from spam bots and from AI agents that do not identify themselves."""
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

# Categories drive the response: "ai_agent" signals point the client at the
# agent registration path, the rest are generic bot/abuse indicators.
AI_AGENT, AUTOMATION, BOT, ABUSE = "ai_agent", "automation", "bot", "abuse"


@dataclass(frozen=True)
class Signal:
    name: str
    weight: int
    category: str
    detail: str = ""


# Self-declared AI agent / assistant user agents. Spoofable, so they only
# raise the score; a verified Web Bot Auth signature is what earns trust.
AI_AGENT_UA = re.compile(
    r"GPTBot|ChatGPT-User|ChatGPT[- ]Agent|OAI-SearchBot|Claude-User|ClaudeBot|Claude-SearchBot|"
    r"anthropic-ai|Perplexity-User|PerplexityBot|Operator|Manus|browser-use|Google-Agent|"
    r"Amazonbot|Bytespider|MistralAI-User|DuckAssistBot|agent/\d", re.I)
HEADLESS_UA = re.compile(r"HeadlessChrome|PhantomJS|Puppeteer|Playwright|Selenium|SlimerJS", re.I)
HTTP_LIBRARY_UA = re.compile(
    r"^(curl|wget|python-requests|python-urllib|python-httpx|aiohttp|Go-http-client|"
    r"node-fetch|axios|undici|okhttp|Java/|libwww-perl|Scrapy|httpie)", re.I)

DISPOSABLE_DOMAINS = frozenset({
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "temp-mail.org",
    "yopmail.com", "trashmail.com", "sharklasers.com", "getnada.com", "dispostable.com",
    "throwawaymail.com", "maildrop.cc", "fakeinbox.com", "mintemail.com", "emailondeck.com",
})


def user_agent_signals(user_agent: str) -> list[Signal]:
    ua = user_agent or ""
    if not ua:
        return [Signal("missing_user_agent", 40, BOT)]
    if HTTP_LIBRARY_UA.search(ua):
        return [Signal("http_library_client", 50, BOT, ua[:60])]
    found = []
    if HEADLESS_UA.search(ua):
        found.append(Signal("headless_browser_ua", 45, AUTOMATION, ua[:60]))
    if AI_AGENT_UA.search(ua):
        found.append(Signal("declared_ai_agent_ua", 40, AI_AGENT, ua[:60]))
    return found


def header_signals(headers) -> list[Signal]:
    found = []
    if not headers.get("Accept-Language"):
        found.append(Signal("missing_accept_language", 10, BOT))
    if headers.get("Signature-Agent") or headers.get("Signature-Input"):
        found.append(Signal("unverified_signed_agent", 40, AI_AGENT,
                            "sent Web Bot Auth headers that did not verify"))
    return found


def canary_signal(fields: dict, canary: str) -> Signal | None:
    """The hidden 'note to AI assistants' asks for the canary phrase. A human
    never sees it, so the phrase appearing anywhere means an agent read and
    obeyed text that was not meant for people."""
    needle = re.sub(r"[\s_-]+", "", canary.lower())
    for value in fields.values():
        if isinstance(value, str) and needle in re.sub(r"[\s_-]+", "", value.lower()):
            return Signal("followed_hidden_agent_instruction", 90, AI_AGENT)
    return None


def form_signals(fields: dict, honeypot_field: str, issued_at: float,
                 min_fill_seconds: float, now: float) -> list[Signal]:
    found = []
    if str(fields.get(honeypot_field, "")).strip():
        found.append(Signal("honeypot_filled", 70, BOT, honeypot_field))
    elapsed = now - issued_at
    if elapsed < min_fill_seconds:
        found.append(Signal("submitted_too_fast", 35, BOT, f"{elapsed:.1f}s"))
    domain = str(fields.get("email", "")).rpartition("@")[2].lower()
    if domain in DISPOSABLE_DOMAINS:
        found.append(Signal("disposable_email", 30, ABUSE, domain))
    return found


def telemetry_signals(telemetry) -> list[Signal]:
    """Client-side observations. Attackers can forge these, so they are only
    ever used to add risk, never to vouch for a client."""
    if not isinstance(telemetry, dict):
        return [Signal("no_browser_telemetry", 25, BOT)]
    found = []
    if telemetry.get("webdriver") is True:
        found.append(Signal("webdriver_flag", 45, AUTOMATION))
    if telemetry.get("headless_hints"):
        found.append(Signal("headless_environment", 30, AUTOMATION,
                            ",".join(map(str, telemetry["headless_hints"]))[:60]))
    keys = int(telemetry.get("key_events") or 0)
    pointer = int(telemetry.get("pointer_events") or 0)
    if keys == 0 and pointer == 0:
        found.append(Signal("no_human_input_events", 30, AUTOMATION))
    elif keys == 0:
        # Password managers / autofill do this too, so keep it light.
        found.append(Signal("no_keystrokes", 10, AUTOMATION))
    if telemetry.get("untrusted_events"):
        found.append(Signal("synthetic_input_events", 35, AUTOMATION))
    return found


class VelocityTracker:
    """Sliding-window attempt counter per key (IP address, subnet, ...)."""

    def __init__(self, window: int, clock=time.time):
        self._window = window
        self._clock = clock
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str) -> int:
        now = self._clock()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - self._window:
                q.popleft()
            q.append(now)
            return len(q)


def velocity_signal(count: int, limit: int) -> Signal | None:
    """Escalates gradually: shared IPs (offices, campuses, CGNAT) first get a
    step-up challenge, sustained bursts get denied."""
    if count > limit:
        return Signal("ip_velocity", 35 + 10 * min(count - limit - 1, 6), ABUSE, f"{count} attempts")
    return None
