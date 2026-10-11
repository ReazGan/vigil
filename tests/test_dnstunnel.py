from vigil.config import Thresholds
from vigil.detect.dnstunnel import DnsTunnelDetector, shannon_entropy

from tests.util import collect, pkt


def test_entropy_rises_with_randomness():
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("abcdefgh")


def test_fires_on_many_long_queries():
    cfg = Thresholds(dnstunnel_count=5, dnstunnel_window=10.0, dnstunnel_min_qlen=20)
    det = DnsTunnelDetector(cfg)
    base = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4.tunnel.example.com"
    packets = [
        pkt(ts=i * 0.5, proto="UDP", dport=53, dns_qname=f"{i}{base}") for i in range(5)
    ]
    alerts = collect(det, packets)
    assert alerts
    assert alerts[0].category == "DNS Tunneling"


def test_ignores_normal_dns():
    cfg = Thresholds(dnstunnel_count=5, dnstunnel_min_qlen=50, dnstunnel_min_entropy=4.5)
    det = DnsTunnelDetector(cfg)
    packets = [
        pkt(ts=i * 0.5, proto="UDP", dport=53, dns_qname="www.google.com") for i in range(20)
    ]
    assert collect(det, packets) == []
