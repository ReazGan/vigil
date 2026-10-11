from vigil.config import Thresholds
from vigil.detect.synflood import SynFloodDetector

from tests.util import collect, pkt

CFG = Thresholds(synflood_count=10, synflood_window=2.0)


def test_fires_on_syn_burst():
    det = SynFloodDetector(CFG)
    packets = [
        pkt(ts=i * 0.05, src=f"198.51.100.{i % 7}", dst="10.0.0.9", dport=80, syn=True)
        for i in range(10)
    ]
    alerts = collect(det, packets)
    assert alerts
    assert alerts[0].category == "SYN Flood"
    assert alerts[0].severity.name == "HIGH"


def test_quiet_when_spread_out():
    det = SynFloodDetector(CFG)
    # One SYN per second against a 2s window never stacks up to the threshold.
    packets = [pkt(ts=float(i), dst="10.0.0.9", dport=80, syn=True) for i in range(20)]
    assert collect(det, packets) == []
