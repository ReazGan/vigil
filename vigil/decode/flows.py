"""Flow aggregation.

Detectors work packet by packet, but the dashboard and the operator think in
flows and totals. ``FlowTable`` folds packets into 5-tuple flows and keeps the
running counters the UI needs (packets, bytes, protocol mix, active flows)
without holding on to every packet forever.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ..models import Packet


@dataclass(slots=True)
class Flow:
    key: tuple
    first_ts: float
    last_ts: float
    packets: int = 0
    bytes: int = 0
    flags: int = 0

    @property
    def duration(self) -> float:
        return self.last_ts - self.first_ts


class FlowTable:
    """Running view of traffic. ``idle_timeout`` decides when a flow is 'done'
    for the active-flow count; it is not evicted so totals stay correct."""

    def __init__(self, idle_timeout: float = 60.0) -> None:
        self.idle_timeout = idle_timeout
        self._flows: dict[tuple, Flow] = {}
        self.total_packets = 0
        self.total_bytes = 0
        self.by_protocol: dict[str, int] = defaultdict(int)
        self._last_ts = 0.0

    def update(self, pkt: Packet) -> Flow:
        self.total_packets += 1
        self.total_bytes += pkt.length
        self.by_protocol[pkt.protocol] += 1
        self._last_ts = max(self._last_ts, pkt.ts)

        flow = self._flows.get(pkt.flow_key)
        if flow is None:
            flow = Flow(key=pkt.flow_key, first_ts=pkt.ts, last_ts=pkt.ts)
            self._flows[pkt.flow_key] = flow
        flow.packets += 1
        flow.bytes += pkt.length
        flow.last_ts = pkt.ts
        flow.flags |= pkt.tcp_flags
        return flow

    def active_flows(self, now: float | None = None) -> int:
        ref = self._last_ts if now is None else now
        cutoff = ref - self.idle_timeout
        return sum(1 for f in self._flows.values() if f.last_ts >= cutoff)

    def snapshot(self) -> dict:
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "flows": len(self._flows),
            "active_flows": self.active_flows(),
            "by_protocol": dict(self.by_protocol),
        }
