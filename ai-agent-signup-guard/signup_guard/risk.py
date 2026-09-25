from dataclasses import dataclass, field
from enum import Enum

from .signals import AGENT_CATEGORIES, COMPUTER_USE, Signal


class Decision(str, Enum):
    ALLOW = "allow"            # create account, still require email verification
    CHALLENGE = "challenge"    # create account in a restricted state, require step-up
    DENY = "deny"


@dataclass
class Assessment:
    score: int
    decision: Decision
    signals: list[Signal] = field(default_factory=list)

    @property
    def agent_suspected(self) -> bool:
        return any(s.category in AGENT_CATEGORIES for s in self.signals)


def assess(signals: list[Signal], allow_below: int, deny_at: int) -> Assessment:
    # Behaviour alone never blocks: switch access, eye-tracking and voice control
    # can move the pointer in machine-like ways. It caps just below deny and
    # leads to a passkey step-up; combined with any other signal it can deny.
    behaviour = sum(s.weight for s in signals if s.category == COMPUTER_USE)
    other = sum(s.weight for s in signals if s.category != COMPUTER_USE)
    score = min(100, other + min(behaviour, deny_at - 5))
    if score >= deny_at:
        decision = Decision.DENY
    elif score >= allow_below:
        decision = Decision.CHALLENGE
    else:
        decision = Decision.ALLOW
    return Assessment(score, decision, signals)


def classify(signals: list[Signal]) -> str:
    """Single label for dashboards: what most likely made this attempt."""
    names = {s.name for s in signals}
    cats = [s.category for s in signals]
    if names & {"followed_hidden_agent_instruction", "ticked_agent_checkbox"}:
        return "llm_agent"
    if cats.count("computer_use") >= 2:
        return "computer_use_agent"
    if "automation" in cats and ({"webdriver_flag", "headless_browser_ua", "headless_environment"} & names):
        return "headless_automation"
    if "bot" in cats and any(s.weight >= 25 for s in signals if s.category == "bot"):
        return "spam_bot"
    if "ai_agent" in cats:
        return "declared_agent"
    if "abuse" in cats:
        return "abuse"
    return "human"
