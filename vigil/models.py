"""Core data types shared by every layer.

A single normalized ``Packet`` is the contract between capture sources and
detectors. Nothing downstream of capture is allowed to know whether a packet
came off the wire or out of a pcap file; it only sees this record.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

# TCP flag bits, so detectors do not carry magic numbers around.
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()


@dataclass(slots=True)
class Packet:
    """Normalized packet record.

    Ports default to 0 for protocols that do not have them (ICMP, other).
    ``payload`` and ``dns_qname`` are filled only when the capture layer could
    cheaply parse them; detectors must tolerate them being absent.
    """

    ts: float
    src_ip: str
    dst_ip: str
    protocol: str = "OTHER"          # TCP | UDP | ICMP | OTHER
    src_port: int = 0
    dst_port: int = 0
    length: int = 0
    tcp_flags: int = 0
    payload: Optional[bytes] = None
    dns_qname: Optional[str] = None
    # Reassembled flow bytes, filled by the pipeline for TCP payloads so a
    # signature split across segments can still be matched. None off the wire.
    stream: Optional[bytes] = None

    @property
    def is_syn(self) -> bool:
        """A connection-opening SYN: SYN set, ACK clear."""
        return (
            self.protocol == "TCP"
            and bool(self.tcp_flags & SYN)
            and not (self.tcp_flags & ACK)
        )

    @property
    def flow_key(self) -> tuple:
        return (self.protocol, self.src_ip, self.src_port, self.dst_ip, self.dst_port)


@dataclass(slots=True)
class Alert:
    """A detector's verdict about a packet or a window of packets."""

    ts: float
    detector: str
    category: str
    severity: Severity
    src_ip: str
    dst_ip: str
    summary: str
    evidence: dict = field(default_factory=dict)
    event_key: Optional[tuple] = None

    def dedup_key(self) -> tuple:
        """What makes two alerts 'the same ongoing event'.

        Most alerts are identified by their source and destination. Flood-type
        detectors override this with ``event_key``, because in a flood the
        source rotates and it is the victim that stays constant; keying on the
        source would explode one attack into thousands of events.
        """
        if self.event_key is not None:
            return self.event_key
        return (self.detector, self.category, self.src_ip, self.dst_ip)

    def as_dict(self) -> dict:
        return {
            "ts": self.ts,
            "detector": self.detector,
            "category": self.category,
            "severity": self.severity.label,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "summary": self.summary,
            "evidence": self.evidence,
        }
