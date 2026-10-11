"""SYN flood detection.

A SYN flood is a one-sided burst of connection openers against a host that
never complete the handshake. We count half-open SYNs per destination over a
short window; a sustained rate above the threshold is the flood.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Iterable

from ..config import DEFAULT, Thresholds
from ..models import Alert, Packet, Severity
from .base import Detector, register


@register
class SynFloodDetector(Detector):
    name = "synflood"
    category = "SYN Flood"

    def __init__(self, cfg: Thresholds = DEFAULT) -> None:
        super().__init__(cfg)
        self._events: dict[str, deque] = defaultdict(deque)   # dst -> [ts]

    def inspect(self, pkt: Packet) -> Iterable[Alert]:
        if not pkt.is_syn:
            return
        events = self._events[pkt.dst_ip]
        events.append(pkt.ts)

        cutoff = pkt.ts - self.cfg.synflood_window
        while events and events[0] < cutoff:
            events.popleft()

        count = len(events)
        if count >= self.cfg.synflood_count:
            rate = count / self.cfg.synflood_window
            yield Alert(
                ts=pkt.ts,
                detector=self.name,
                category=self.category,
                severity=Severity.HIGH,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                summary=(
                    f"SYN flood on {pkt.dst_ip}: {count} half-open SYNs "
                    f"in {self.cfg.synflood_window:.0f}s (~{rate:.0f}/s)"
                ),
                evidence={
                    "syn_count": count,
                    "window_s": self.cfg.synflood_window,
                    "rate_per_s": round(rate, 1),
                },
                event_key=(self.name, self.category, pkt.dst_ip),
            )
