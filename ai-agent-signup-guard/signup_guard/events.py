"""Signup attempt log and the aggregates the attack dashboard shows."""
import json
import threading
import time
from collections import Counter, deque


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    if not domain:
        return "?"
    return f"{local[:1]}***@{domain}"


class EventLog:
    def __init__(self, maxlen: int = 20000, path: str | None = None, clock=time.time):
        self._events: deque[dict] = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._path = path
        self._clock = clock
        self._seq = 0

    def record(self, **event) -> dict:
        with self._lock:
            self._seq += 1
            event = {"id": self._seq, "ts": self._clock(), **event}
            self._events.append(event)
            if self._path:
                with open(self._path, "a") as fh:
                    fh.write(json.dumps(event) + "\n")
        return event

    def snapshot(self) -> list[dict]:
        with self._lock:
            return list(self._events)

    def summary(self, window_minutes: int = 60, recent: int = 60) -> dict:
        now = self._clock()
        start = now - window_minutes * 60
        events = [e for e in self.snapshot() if e["ts"] >= start]
        signups = [e for e in events if e["type"] == "signup"]

        bucket = max(60, window_minutes * 60 // 60)       # at most 60 columns
        n_buckets = int(-(-window_minutes * 60 // bucket))
        first = now - n_buckets * bucket
        series = [{"t": first + i * bucket, "allow": 0, "challenge": 0, "deny": 0} for i in range(n_buckets)]
        for e in signups:
            i = min(n_buckets - 1, int((e["ts"] - first) // bucket))
            if i >= 0:
                series[i][e["decision"]] += 1

        decisions = Counter(e["decision"] for e in signups)
        classes = Counter(e["classification"] for e in signups)
        signal_counts = Counter(s for e in signups for s in e["signals"])

        per_ip: dict[str, dict] = {}
        for e in signups:
            row = per_ip.setdefault(e["ip"], {"ip": e["ip"], "attempts": 0, "denied": 0, "max_score": 0,
                                              "last_seen": 0, "classes": Counter()})
            row["attempts"] += 1
            row["denied"] += e["decision"] == "deny"
            row["max_score"] = max(row["max_score"], e["score"])
            row["last_seen"] = max(row["last_seen"], e["ts"])
            row["classes"][e["classification"]] += 1
        top_ips = sorted(per_ip.values(), key=lambda r: (r["denied"], r["attempts"]), reverse=True)[:10]
        for row in top_ips:
            row["top_class"] = row.pop("classes").most_common(1)[0][0]

        return {
            "now": now,
            "window_minutes": window_minutes,
            "bucket_seconds": bucket,
            "totals": {
                "attempts": len(signups),
                "allow": decisions["allow"],
                "challenge": decisions["challenge"],
                "deny": decisions["deny"],
                "agents_detected": sum(v for k, v in classes.items()
                                       if k in ("llm_agent", "computer_use_agent", "declared_agent")),
                "agent_registrations": sum(1 for e in events if e["type"] == "agent_signup"),
                "invalid_requests": sum(1 for e in events if e["type"] == "invalid_request"),
                "passkeys_completed": sum(1 for e in events if e["type"] == "step_up" and e.get("ok")),
            },
            "series": series,
            "classifications": classes.most_common(),
            "top_signals": signal_counts.most_common(12),
            "top_ips": top_ips,
            "recent": list(reversed(events))[:recent],
        }
