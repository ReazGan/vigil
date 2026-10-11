"""Capture sources.

``PacketSource`` is always importable. ``PcapSource`` and ``LiveSource`` import
scapy lazily when iterated, so this package can be imported without scapy
present.
"""

from .base import PacketSource
from .live import LiveSource
from .pcap import PcapSource

__all__ = ["PacketSource", "PcapSource", "LiveSource"]
