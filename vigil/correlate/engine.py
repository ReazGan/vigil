"""Alert correlation and noise control.

Detectors fire on every packet that still matches their condition, so a single
ongoing scan or flood can produce thousands of raw alerts. The correlator
collapses repeats of the same event (same detector, category, source and
destination) inside a cooldown into one, counts how many raw hits each event
absorbed, and keeps the category/severity tallies the dashboard reads.
"""

from __future__ import annotations

from collections import Counter

from ..config import DEFAULT, Thresholds
from ..models import Alert


class Correlator:
    def __init__(self, cfg: Thresholds = DEFAULT) -> None:
        self.cooldown = cfg.correlation_cooldown
        self._last_seen: dict[tuple, float] = {}
        self._hits: Counter = Counter()
        self.by_category: Counter = Counter()
        self.by_severity: Counter = Counter()
        self.total_events = 0
        self.total_raw = 0

    def process(self, alert: Alert) -> Alert | None:
        """Return the alert if it opens or renews an event, else ``None``."""
        self.total_raw += 1
        key = alert.dedup_key()
        last = self._last_seen.get(key)
        self._hits[key] += 1

        if last is not None and (alert.ts - last) < self.cooldown:
            # Within cooldown of the last *emitted* event for this key: suppress.
            # last_seen is deliberately not refreshed here, so an ongoing attack
            # re-alerts once per cooldown window instead of going silent forever.
            return None

        self._last_seen[key] = alert.ts
        self.total_events += 1
        self.by_category[alert.category] += 1
        self.by_severity[alert.severity.label] += 1
        return alert

    def snapshot(self) -> dict:
        return {
            "total_events": self.total_events,
            "total_raw_alerts": self.total_raw,
            "by_category": dict(self.by_category),
            "by_severity": dict(self.by_severity),
        }
