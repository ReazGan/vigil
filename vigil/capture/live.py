"""Live capture off a network interface.

Sniffing runs on scapy's background thread and hands packets to this generator
through a bounded queue, so a capture burst cannot grow memory without bound: if
the pipeline falls behind, the newest packets are dropped rather than buffered
forever (and the drop is counted). Requires privileges and, on Windows, Npcap.
"""

from __future__ import annotations

import queue
from typing import Iterator, Optional

from ..models import Packet
from ._scapy import scapy_to_packet
from .base import PacketSource


class LiveSource(PacketSource):
    def __init__(
        self,
        iface: Optional[str] = None,
        bpf: Optional[str] = None,
        max_queue: int = 10000,
    ) -> None:
        self.iface = iface
        self.bpf = bpf
        self.max_queue = max_queue
        self.dropped = 0

    def __iter__(self) -> Iterator[Packet]:
        from scapy.sendrecv import AsyncSniffer

        q: "queue.Queue[Packet]" = queue.Queue(maxsize=self.max_queue)

        def _on_packet(pkt) -> None:
            record = scapy_to_packet(pkt)
            if record is None:
                return
            try:
                q.put_nowait(record)
            except queue.Full:
                self.dropped += 1

        sniffer = AsyncSniffer(iface=self.iface, filter=self.bpf, prn=_on_packet, store=False)
        sniffer.start()
        try:
            while True:
                try:
                    yield q.get(timeout=0.5)
                except queue.Empty:
                    if not sniffer.running:
                        break
        finally:
            try:
                sniffer.stop()
            except Exception:
                pass
