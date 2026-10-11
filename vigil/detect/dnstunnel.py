"""DNS tunneling detection.

Data smuggled over DNS shows up as query names that are long and look random:
base32/hex-encoded payloads stuffed into subdomains. We score each query by
length and Shannon entropy, and alert when one source sends many suspicious
queries in a window (a single odd lookup is not worth waking anyone for).
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict, deque
from typing import Iterable

from ..config import DEFAULT, Thresholds
from ..models import Alert, Packet, Severity
from .base import Detector, register


def shannon_entropy(text: str) -> float:
    """Bits of entropy per character; ~5 for random base32, ~3 for English."""
    if not text:
        return 0.0
    n = len(text)
    counts = Counter(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@register
class DnsTunnelDetector(Detector):
    name = "dnstunnel"
    category = "DNS Tunneling"

    def __init__(self, cfg: Thresholds = DEFAULT) -> None:
        super().__init__(cfg)
        self._events: dict[str, deque] = defaultdict(deque)   # src -> [ts]

    def _suspicious(self, qname: str) -> bool:
        return (
            len(qname) >= self.cfg.dnstunnel_min_qlen
            or shannon_entropy(qname) >= self.cfg.dnstunnel_min_entropy
        )

    def inspect(self, pkt: Packet) -> Iterable[Alert]:
        if pkt.protocol != "UDP" or pkt.dst_port != 53 or not pkt.dns_qname:
            return
        if not self._suspicious(pkt.dns_qname):
            return

        events = self._events[pkt.src_ip]
        events.append(pkt.ts)
        cutoff = pkt.ts - self.cfg.dnstunnel_window
        while events and events[0] < cutoff:
            events.popleft()

        count = len(events)
        if count >= self.cfg.dnstunnel_count:
            yield Alert(
                ts=pkt.ts,
                detector=self.name,
                category=self.category,
                severity=Severity.MEDIUM,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                summary=(
                    f"{pkt.src_ip} sent {count} long/high-entropy DNS queries "
                    f"in {self.cfg.dnstunnel_window:.0f}s"
                ),
                evidence={
                    "suspicious_queries": count,
                    "sample": pkt.dns_qname[:80],
                    "entropy": round(shannon_entropy(pkt.dns_qname), 2),
                },
            )
