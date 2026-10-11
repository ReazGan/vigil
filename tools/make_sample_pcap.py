"""Generate a small synthetic pcap with a handful of attacks.

Used for the README demo and the benchmark. It is not a capture of real
traffic; it is just enough structure for every detector to light up next to
some benign background noise:

    normal TLS traffic, a vertical port scan, a SYN flood, an SSH brute force,
    and an HTTP request carrying a SQL injection payload.

    python tools/make_sample_pcap.py sample.pcap
"""

from __future__ import annotations

import sys

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

VICTIM = "10.0.0.9"


def build() -> list:
    pkts = []
    t = 1_000_000.0  # arbitrary epoch base

    def stamp(pkt, dt):
        nonlocal t
        pkt.time = t
        t += dt
        pkts.append(pkt)

    # Benign background: a client opening TLS connections.
    for i in range(20):
        stamp(Ether() / IP(src="10.0.0.50", dst=VICTIM) / TCP(sport=40000 + i, dport=443, flags="S"), 0.5)

    # Vertical port scan: one source, many ports, fast.
    for port in range(1, 61):
        stamp(Ether() / IP(src="203.0.113.7", dst=VICTIM) / TCP(sport=55000, dport=port, flags="S"), 0.01)

    # SYN flood: a burst of half-open SYNs from spoofed sources.
    for i in range(300):
        src = f"198.51.100.{i % 254 + 1}"
        stamp(Ether() / IP(src=src, dst=VICTIM) / TCP(sport=1024 + i % 2000, dport=80, flags="S"), 0.005)

    # SSH brute force: repeated openers to port 22 from one source.
    for i in range(25):
        stamp(Ether() / IP(src="203.0.113.66", dst=VICTIM) / TCP(sport=50000 + i, dport=22, flags="S"), 0.2)

    # SQL injection carried in an HTTP request.
    payload = (
        b"GET /product?id=1' UNION SELECT username,password FROM users-- "
        b"HTTP/1.1\r\nHost: shop.example\r\n\r\n"
    )
    stamp(Ether() / IP(src="203.0.113.90", dst=VICTIM) / TCP(sport=51000, dport=80, flags="PA") / Raw(load=payload), 0.1)

    return pkts


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else "sample.pcap"
    pkts = build()
    wrpcap(out, pkts)
    print(f"wrote {len(pkts)} packets to {out}")


if __name__ == "__main__":
    main()
