"""Port scan detection.

A single source touching many different ports on one host in a short window is
the classic vertical scan signature. We only count connection-opening SYNs, so
an established, chatty connection reusing high ports does not look like a scan.

The distinct-port count is kept exact over the sliding window with a small
reference count per port, so the detector is O(1) per packet rather than
rescanning a buffer.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Iterable

from ..config import DEFAULT, Thresholds
from ..models import Alert, Packet, Severity
from .base import Detector, register


@register
class PortScanDetector(Detector):
    name = "portscan"
    category = "Port Scan"

    def __init__(self, cfg: Thresholds = DEFAULT) -> None:
        super().__init__(cfg)
        self._events: dict[tuple, deque] = defaultdict(deque)      # (src,dst)->[(ts,port)]
        self._ports: dict[tuple, dict] = defaultdict(lambda: defaultdict(int))

    def inspect(self, pkt: Packet) -> Iterable[Alert]:
        if not pkt.is_syn:
            return
        key = (pkt.src_ip, pkt.dst_ip)
        events = self._events[key]
        ports = self._ports[key]

        events.append((pkt.ts, pkt.dst_port))
        ports[pkt.dst_port] += 1

        cutoff = pkt.ts - self.cfg.portscan_window
        while events and events[0][0] < cutoff:
            _, old = events.popleft()
            ports[old] -= 1
            if ports[old] <= 0:
                del ports[old]

        distinct = len(ports)
        if distinct >= self.cfg.portscan_unique_ports:
            yield Alert(
                ts=pkt.ts,
                detector=self.name,
                category=self.category,
                severity=Severity.MEDIUM,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                summary=(
                    f"{pkt.src_ip} probed {distinct} ports on {pkt.dst_ip} "
                    f"within {self.cfg.portscan_window:.0f}s"
                ),
                evidence={
                    "unique_ports": distinct,
                    "window_s": self.cfg.portscan_window,
                    "last_port": pkt.dst_port,
                },
            )
