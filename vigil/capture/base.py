"""Capture source contract.

A packet source is anything that can be iterated to yield normalized
``Packet`` records. Live sniffing and pcap replay both implement this, so the
pipeline neither knows nor cares which it is being fed.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator

from ..models import Packet


class PacketSource(ABC):
    @abstractmethod
    def __iter__(self) -> Iterator[Packet]:
        raise NotImplementedError
