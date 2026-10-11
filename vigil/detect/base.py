"""Detector contract and registry.

Detectors are deliberately dumb about noise: each one emits an alert every time
its condition holds for the current packet. Collapsing a burst of identical
alerts into a single event is the correlator's job, not the detector's. That
split keeps detectors small, pure, and easy to test in isolation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from typing import Iterable

from ..config import DEFAULT, Thresholds
from ..models import Alert, Packet

_REGISTRY: dict[str, type["Detector"]] = {}


def register(cls: type["Detector"]) -> type["Detector"]:
    """Class decorator: add a detector to the registry under its ``name``."""
    if not getattr(cls, "name", None):
        raise ValueError(f"{cls.__name__} must define a non-empty name")
    _REGISTRY[cls.name] = cls
    return cls


def all_detectors() -> list[type["Detector"]]:
    return list(_REGISTRY.values())


def build_all(cfg: Thresholds = DEFAULT) -> list["Detector"]:
    """Instantiate every registered detector with one config."""
    return [cls(cfg) for cls in _REGISTRY.values()]


class Detector(ABC):
    name: str = ""
    category: str = "generic"

    def __init__(self, cfg: Thresholds = DEFAULT) -> None:
        self.cfg = cfg

    @abstractmethod
    def inspect(self, pkt: Packet) -> Iterable[Alert]:
        """Yield zero or more alerts for this packet."""
        raise NotImplementedError


def prune(events: deque, now: float, window: float) -> None:
    """Drop events older than ``window`` from the left of a (ts, ...) deque."""
    cutoff = now - window
    while events and events[0][0] < cutoff:
        events.popleft()
