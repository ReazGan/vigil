"""Detector registry.

Importing this package imports every detector module, which registers it via
the ``@register`` decorator. After that, ``build_all()`` returns a live
instance of each. Add a new detector by dropping a module here and importing
it below.
"""

from .base import Detector, all_detectors, build_all, prune, register

# Importing for side effect: each module registers its detector on import.
from . import portscan, synflood, ddos, bruteforce, dnstunnel, signature  # noqa: E402,F401

__all__ = ["Detector", "all_detectors", "build_all", "prune", "register"]
