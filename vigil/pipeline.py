"""The processing pipeline.

One packet in, zero or more correlated alerts out. The pipeline owns the
detectors, the flow table and the correlator, and nothing else: it does not
know where packets come from or where alerts go. That keeps it the same code
path for a live capture, a pcap replay, or a unit test feeding hand-built
packets.
"""

from __future__ import annotations

from typing import Callable, Iterable, Optional

from .config import DEFAULT, Thresholds
from .correlate import Correlator
from .decode import FlowTable, StreamReassembler
from .detect import Detector, build_all
from .models import Alert, Packet


class Pipeline:
    def __init__(
        self,
        detectors: Optional[list[Detector]] = None,
        cfg: Thresholds = DEFAULT,
        correlator: Optional[Correlator] = None,
        on_alert: Optional[Callable[[Alert], None]] = None,
        keep_alerts: bool = True,
    ) -> None:
        self.cfg = cfg
        self.detectors = detectors if detectors is not None else build_all(cfg)
        self.correlator = correlator if correlator is not None else Correlator(cfg)
        self.flows = FlowTable()
        self.reassembler = StreamReassembler()
        self.on_alert = on_alert
        self.keep_alerts = keep_alerts
        self.alerts: list[Alert] = []

    def process(self, pkt: Packet) -> list[Alert]:
        self.flows.update(pkt)
        if pkt.protocol == "TCP" and pkt.payload:
            pkt.stream = self.reassembler.update(pkt)
        emitted: list[Alert] = []
        for detector in self.detectors:
            for raw in detector.inspect(pkt):
                alert = self.correlator.process(raw)
                if alert is None:
                    continue
                emitted.append(alert)
                if self.keep_alerts:
                    self.alerts.append(alert)
                if self.on_alert is not None:
                    self.on_alert(alert)
        return emitted

    def run(self, source: Iterable[Packet]) -> list[Alert]:
        for pkt in source:
            self.process(pkt)
        return self.alerts

    def stats(self) -> dict:
        return {
            "traffic": self.flows.snapshot(),
            "alerts": self.correlator.snapshot(),
            "detectors": [d.name for d in self.detectors],
        }
