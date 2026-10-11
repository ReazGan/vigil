"""Tunable thresholds for the behavioral detectors.

Every number here is a trade-off between catching real attacks and staying
quiet on normal traffic. They live in one place so they can be tuned against a
corpus without touching detector code, and overridden per run from the CLI.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Thresholds:
    # Port scan: distinct destination ports probed by one source on one host.
    portscan_window: float = 5.0
    portscan_unique_ports: int = 20

    # SYN flood: half-open SYNs aimed at a single host.
    synflood_window: float = 2.0
    synflood_count: int = 200

    # Distributed flood: distinct sources hammering one host.
    ddos_window: float = 5.0
    ddos_unique_sources: int = 100
    ddos_min_packets: int = 1000

    # Credential brute force: repeated connections to an auth service.
    bruteforce_window: float = 30.0
    bruteforce_attempts: int = 15
    bruteforce_ports: tuple = (21, 22, 23, 3389, 5900, 3306, 1433, 5432)

    # DNS tunneling: long, high-entropy query names from one source.
    dnstunnel_window: float = 10.0
    dnstunnel_count: int = 20
    dnstunnel_min_qlen: int = 50
    dnstunnel_min_entropy: float = 3.5

    # How long the correlator treats repeat alerts as the same event.
    correlation_cooldown: float = 60.0


DEFAULT = Thresholds()
