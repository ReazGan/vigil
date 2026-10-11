"""Lightweight TCP stream reassembly.

Signatures that match a single packet miss an attack split across TCP segments.
This keeps a bounded, per-flow buffer of payload bytes in arrival order so the
signature detector can scan the recent stream rather than one packet.

It concatenates in capture order; it does not reorder by sequence number, so it
assumes roughly in-order delivery (true for most captures). The buffer is capped
per flow, and the number of tracked flows is capped with LRU eviction, so memory
stays bounded under load. This is the documented trade-off, not an oversight.
"""

from __future__ import annotations

from collections import OrderedDict

from ..models import Packet


class StreamReassembler:
    def __init__(self, max_bytes: int = 8192, max_flows: int = 4096) -> None:
        self.max_bytes = max_bytes
        self.max_flows = max_flows
        self._buffers: "OrderedDict[tuple, bytearray]" = OrderedDict()

    def update(self, pkt: Packet) -> bytes:
        """Append this packet's payload to its flow buffer and return the
        current (bounded) buffer for that flow."""
        key = pkt.flow_key
        buf = self._buffers.get(key)
        if buf is None:
            buf = bytearray()
            self._buffers[key] = buf
            if len(self._buffers) > self.max_flows:
                self._buffers.popitem(last=False)  # evict least recently used
        else:
            self._buffers.move_to_end(key)

        buf.extend(pkt.payload or b"")
        if len(buf) > self.max_bytes:
            del buf[: -self.max_bytes]  # keep only the most recent bytes
        return bytes(buf)
