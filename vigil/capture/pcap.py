"""Replay packets from a pcap/pcapng file.

Streams with scapy's ``PcapReader`` instead of ``rdpcap`` so a multi-gigabyte
capture does not have to be loaded into memory at once. This is the source used
for reproducible tests and benchmarks.
"""

from __future__ import annotations

from typing import Iterator

from scapy.utils import PcapReader

from ..models import Packet
from ._scapy import scapy_to_packet
from .base import PacketSource


class PcapSource(PacketSource):
    def __init__(self, path: str) -> None:
        self.path = path

    def __iter__(self) -> Iterator[Packet]:
        with PcapReader(self.path) as reader:
            for pkt in reader:
                record = scapy_to_packet(pkt)
                if record is not None:
                    yield record
