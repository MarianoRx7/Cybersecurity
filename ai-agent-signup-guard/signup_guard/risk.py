from dataclasses import dataclass, field
from enum import Enum

from .signals import AI_AGENT, Signal


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
        return any(s.category == AI_AGENT for s in self.signals)


def assess(signals: list[Signal], allow_below: int, deny_at: int) -> Assessment:
    score = min(100, sum(s.weight for s in signals))
    if score >= deny_at:
        decision = Decision.DENY
    elif score >= allow_below:
        decision = Decision.CHALLENGE
    else:
        decision = Decision.ALLOW
    return Assessment(score, decision, signals)
