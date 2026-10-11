from vigil.config import Thresholds
from vigil.pipeline import Pipeline

from tests.util import pkt


def test_pipeline_detects_portscan_end_to_end():
    cfg = Thresholds(portscan_unique_ports=10, portscan_window=5.0)
    pipe = Pipeline(cfg=cfg)
    for i in range(10):
        pipe.process(pkt(ts=i * 0.1, src="10.0.0.5", dst="10.0.0.9", dport=1000 + i, syn=True))
    categories = {a.category for a in pipe.alerts}
    assert "Port Scan" in categories


def test_flood_collapses_to_one_event_despite_rotating_source():
    # A SYN flood rotates its source address every packet. The event identity
    # must be the victim, so the whole flood is one event, not hundreds.
    cfg = Thresholds(synflood_count=10, synflood_window=2.0, correlation_cooldown=60.0)
    pipe = Pipeline(cfg=cfg)
    for i in range(40):
        pipe.process(
            pkt(ts=i * 0.02, src=f"198.51.100.{i % 200}", dst="10.0.0.9", dport=80, syn=True)
        )
    flood = [a for a in pipe.alerts if a.category == "SYN Flood"]
    assert len(flood) == 1


def test_pipeline_runs_all_default_detectors():
    pipe = Pipeline()
    assert len(pipe.detectors) >= 6  # portscan, synflood, ddos, bruteforce, dnstunnel, signature


def test_stats_shape():
    pipe = Pipeline()
    pipe.process(pkt(ts=0.0, length=100, syn=True))
    stats = pipe.stats()
    assert set(stats) == {"traffic", "alerts", "detectors"}
    assert stats["traffic"]["total_packets"] == 1
