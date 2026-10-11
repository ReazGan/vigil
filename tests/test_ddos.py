from vigil.config import Thresholds
from vigil.detect.ddos import DdosDetector

from tests.util import collect, pkt

CFG = Thresholds(ddos_unique_sources=5, ddos_min_packets=10, ddos_window=5.0)


def test_fires_on_distributed_flood():
    det = DdosDetector(CFG)
    packets = []
    t = 0.0
    for _ in range(10):
        for s in range(5):
            packets.append(pkt(ts=t, src=f"203.0.113.{s}", dst="10.0.0.9", dport=80))
            t += 0.01
    alerts = collect(det, packets)
    assert alerts
    assert alerts[0].category == "DDoS Attack"
    assert alerts[0].severity.name == "CRITICAL"


def test_quiet_for_single_busy_source():
    det = DdosDetector(CFG)
    packets = [pkt(ts=i * 0.01, src="203.0.113.1", dst="10.0.0.9") for i in range(50)]
    assert collect(det, packets) == []
