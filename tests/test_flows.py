from vigil.decode import FlowTable

from tests.util import pkt


def test_counts_bytes_and_flows():
    ft = FlowTable()
    ft.update(pkt(ts=0.0, src="a", dst="b", sport=1, dport=2, length=100))
    ft.update(pkt(ts=1.0, src="a", dst="b", sport=1, dport=2, length=50))
    ft.update(pkt(ts=2.0, src="c", dst="b", sport=3, dport=2, length=40, proto="UDP"))

    snap = ft.snapshot()
    assert snap["total_packets"] == 3
    assert snap["total_bytes"] == 190
    assert snap["flows"] == 2
    assert snap["by_protocol"]["TCP"] == 2
    assert snap["by_protocol"]["UDP"] == 1


def test_active_flows_respects_idle_timeout():
    ft = FlowTable(idle_timeout=10.0)
    ft.update(pkt(ts=0.0, src="a", dst="b", sport=1, dport=2))
    ft.update(pkt(ts=100.0, src="c", dst="b", sport=3, dport=2))
    # Only the recent flow is active relative to the latest timestamp.
    assert ft.active_flows() == 1
