"""Credential brute-force detection.

At the packet layer we cannot see a failed login, but we can see the shape of
one: many short-lived connections from one source to an authentication service
(SSH, RDP, FTP, database ports) in a short time. We count connection openers
per (source, host, port) against the known auth ports.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Iterable

from ..config import DEFAULT, Thresholds
from ..models import Alert, Packet, Severity
from .base import Detector, register


@register
class BruteForceDetector(Detector):
    name = "bruteforce"
    category = "Brute Force"

    def __init__(self, cfg: Thresholds = DEFAULT) -> None:
        super().__init__(cfg)
        self._events: dict[tuple, deque] = defaultdict(deque)   # (src,dst,port)->[ts]

    def inspect(self, pkt: Packet) -> Iterable[Alert]:
        if not pkt.is_syn or pkt.dst_port not in self.cfg.bruteforce_ports:
            return
        key = (pkt.src_ip, pkt.dst_ip, pkt.dst_port)
        events = self._events[key]
        events.append(pkt.ts)

        cutoff = pkt.ts - self.cfg.bruteforce_window
        while events and events[0] < cutoff:
            events.popleft()

        count = len(events)
        if count >= self.cfg.bruteforce_attempts:
            yield Alert(
                ts=pkt.ts,
                detector=self.name,
                category=self.category,
                severity=Severity.HIGH,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                summary=(
                    f"{pkt.src_ip} opened {count} connections to "
                    f"{pkt.dst_ip}:{pkt.dst_port} in {self.cfg.bruteforce_window:.0f}s"
                ),
                evidence={
                    "attempts": count,
                    "port": pkt.dst_port,
                    "window_s": self.cfg.bruteforce_window,
                },
            )
