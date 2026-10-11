"""Distributed flood detection.

Where the SYN flood watches rate from any source, this watches *breadth*: a
large number of distinct sources all aiming at one host at once, past a volume
floor so a busy-but-legitimate host does not trip it. Distinct sources are kept
exact over the window with per-source reference counts.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Iterable

from ..config import DEFAULT, Thresholds
from ..models import Alert, Packet, Severity
from .base import Detector, register


@register
class DdosDetector(Detector):
    name = "ddos"
    category = "DDoS Attack"

    def __init__(self, cfg: Thresholds = DEFAULT) -> None:
        super().__init__(cfg)
        self._events: dict[str, deque] = defaultdict(deque)        # dst -> [(ts,src)]
        self._sources: dict[str, dict] = defaultdict(lambda: defaultdict(int))

    def inspect(self, pkt: Packet) -> Iterable[Alert]:
        dst = pkt.dst_ip
        events = self._events[dst]
        sources = self._sources[dst]

        events.append((pkt.ts, pkt.src_ip))
        sources[pkt.src_ip] += 1

        cutoff = pkt.ts - self.cfg.ddos_window
        while events and events[0][0] < cutoff:
            _, old = events.popleft()
            sources[old] -= 1
            if sources[old] <= 0:
                del sources[old]

        distinct = len(sources)
        total = len(events)
        if distinct >= self.cfg.ddos_unique_sources and total >= self.cfg.ddos_min_packets:
            yield Alert(
                ts=pkt.ts,
                detector=self.name,
                category=self.category,
                severity=Severity.CRITICAL,
                src_ip=pkt.src_ip,
                dst_ip=dst,
                summary=(
                    f"Distributed flood on {dst}: {total} packets from "
                    f"{distinct} sources in {self.cfg.ddos_window:.0f}s"
                ),
                evidence={
                    "unique_sources": distinct,
                    "packets": total,
                    "window_s": self.cfg.ddos_window,
                },
                event_key=(self.name, self.category, dst),
            )
