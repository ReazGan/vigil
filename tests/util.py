"""Tiny builders for synthetic packets, so tests read like attack narratives."""

from __future__ import annotations

from typing import Iterable, Optional

from vigil.models import SYN, Packet


def pkt(
    ts: float = 0.0,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    proto: str = "TCP",
    sport: int = 12345,
    dport: int = 80,
    length: int = 60,
    flags: Optional[int] = None,
    syn: bool = False,
    payload: Optional[bytes] = None,
    dns_qname: Optional[str] = None,
) -> Packet:
    if flags is not None:
        tcp_flags = flags
    elif syn:
        tcp_flags = SYN
    else:
        tcp_flags = 0
    return Packet(
        ts=ts,
        src_ip=src,
        dst_ip=dst,
        protocol=proto,
        src_port=sport,
        dst_port=dport,
        length=length,
        tcp_flags=tcp_flags,
        payload=payload,
        dns_qname=dns_qname,
    )


def collect(detector, packets: Iterable[Packet]) -> list:
    out = []
    for p in packets:
        out.extend(detector.inspect(p))
    return out
