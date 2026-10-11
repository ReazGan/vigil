"""Scapy -> Packet conversion.

Kept in one place so both the pcap reader and the live sniffer normalize
exactly the same way. The capture layer cannot work without scapy, so the
layer imports live at module top: importing them also registers scapy's
link-layer and protocol bindings, so a reader can resolve Ethernet (and the
rest) before the first packet is decoded. The *core* of vigil deliberately
never imports this module, which is why the core stays scapy-free.
"""

from __future__ import annotations

from typing import Optional

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether  # noqa: F401  registers linktype 1 (Ethernet)
from scapy.packet import Raw

from ..models import Packet

try:
    from scapy.layers.inet6 import IPv6
except Exception:  # pragma: no cover - ipv6 ships with scapy
    IPv6 = None


def scapy_to_packet(pkt) -> Optional[Packet]:
    """Convert one scapy packet to a Packet, or None if it is not IP traffic."""
    if IP in pkt:
        ip = pkt[IP]
        src, dst = ip.src, ip.dst
    elif IPv6 is not None and IPv6 in pkt:
        ip6 = pkt[IPv6]
        src, dst = ip6.src, ip6.dst
    else:
        return None

    proto = "OTHER"
    sport = dport = 0
    flags = 0
    payload = None
    qname = None

    if TCP in pkt:
        proto = "TCP"
        t = pkt[TCP]
        sport, dport, flags = int(t.sport), int(t.dport), int(t.flags)
    elif UDP in pkt:
        proto = "UDP"
        u = pkt[UDP]
        sport, dport = int(u.sport), int(u.dport)
    elif ICMP in pkt:
        proto = "ICMP"

    if Raw in pkt:
        try:
            payload = bytes(pkt[Raw].load)
        except Exception:
            payload = None

    if DNS in pkt and pkt[DNS].qdcount and pkt[DNS].qd is not None:
        try:
            raw_name = pkt[DNS].qd.qname
            qname = raw_name.decode(errors="replace") if isinstance(raw_name, bytes) else str(raw_name)
            qname = qname.rstrip(".")
        except Exception:
            qname = None

    return Packet(
        ts=float(pkt.time),
        src_ip=src,
        dst_ip=dst,
        protocol=proto,
        src_port=sport,
        dst_port=dport,
        length=len(pkt),
        tcp_flags=flags,
        payload=payload,
        dns_qname=qname,
    )
