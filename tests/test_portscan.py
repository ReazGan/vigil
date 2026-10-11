from vigil.config import Thresholds
from vigil.models import ACK, SYN
from vigil.detect.portscan import PortScanDetector

from tests.util import collect, pkt

CFG = Thresholds(portscan_unique_ports=10, portscan_window=5.0)


def test_fires_on_many_ports():
    det = PortScanDetector(CFG)
    packets = [pkt(ts=i * 0.1, dport=1000 + i, syn=True) for i in range(10)]
    alerts = collect(det, packets)
    assert alerts, "expected a port scan alert"
    assert alerts[0].category == "Port Scan"
    assert alerts[0].evidence["unique_ports"] >= 10


def test_quiet_below_threshold():
    det = PortScanDetector(CFG)
    packets = [pkt(ts=i * 0.1, dport=1000 + i, syn=True) for i in range(9)]
    assert collect(det, packets) == []


def test_window_expiry_resets_count():
    det = PortScanDetector(CFG)
    packets = [pkt(ts=i * 0.1, dport=1000 + i, syn=True) for i in range(9)]
    packets.append(pkt(ts=100.0, dport=2000, syn=True))  # long after the window
    assert collect(det, packets) == []


def test_non_syn_is_ignored():
    det = PortScanDetector(CFG)
    packets = [pkt(ts=i * 0.1, dport=1000 + i, flags=SYN | ACK) for i in range(12)]
    assert collect(det, packets) == []
