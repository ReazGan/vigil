from vigil.config import Thresholds
from vigil.detect.bruteforce import BruteForceDetector

from tests.util import collect, pkt

CFG = Thresholds(bruteforce_attempts=5, bruteforce_window=30.0)


def test_fires_on_ssh_hammering():
    det = BruteForceDetector(CFG)
    packets = [
        pkt(ts=float(i), src="10.0.0.5", dst="10.0.0.9", dport=22, sport=40000 + i, syn=True)
        for i in range(5)
    ]
    alerts = collect(det, packets)
    assert alerts
    assert alerts[0].category == "Brute Force"
    assert alerts[0].evidence["port"] == 22


def test_ignores_non_auth_ports():
    det = BruteForceDetector(CFG)
    packets = [pkt(ts=float(i), dst="10.0.0.9", dport=8081, syn=True) for i in range(10)]
    assert collect(det, packets) == []
