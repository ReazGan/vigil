"""Measure engine throughput.

Reports how many packets per second the detection pipeline sustains, separate
from pcap parsing, so the number reflects the detectors and correlator rather
than scapy's decoder. A synthetic workload is built in memory (rotating
sources and ports, so the sliding-window bookkeeping does real work) and fed
through Pipeline.process.

    python bench/benchmark.py [packet_count]
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vigil.models import SYN, Packet  # noqa: E402
from vigil.pipeline import Pipeline  # noqa: E402

VICTIM = "10.0.0.9"


def workload(n: int) -> list[Packet]:
    pkts = []
    t = 0.0
    for i in range(n):
        pkts.append(
            Packet(
                ts=t,
                src_ip=f"10.{i % 255}.{(i // 255) % 255}.{(i * 7) % 255}",
                dst_ip=VICTIM,
                protocol="TCP",
                src_port=1024 + (i % 40000),
                dst_port=1 + (i % 1024),
                length=74,
                tcp_flags=SYN,
            )
        )
        t += 0.0001
    return pkts


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 200_000
    packets = workload(n)

    pipe = Pipeline()
    start = time.perf_counter()
    for pkt in packets:
        pipe.process(pkt)
    elapsed = time.perf_counter() - start

    pps = n / elapsed if elapsed else 0.0
    print(f"packets      : {n:,}")
    print(f"elapsed      : {elapsed:.3f} s")
    print(f"throughput   : {pps:,.0f} packets/s")
    print(f"detectors    : {len(pipe.detectors)} active")
    print(f"events       : {pipe.correlator.total_events}")


if __name__ == "__main__":
    main()
