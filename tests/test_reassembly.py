from vigil.decode import StreamReassembler
from vigil.pipeline import Pipeline

from tests.util import pkt


def _flow(**kw):
    base = dict(src="1.1.1.1", dst="2.2.2.2", sport=5555, dport=80, proto="TCP")
    base.update(kw)
    return base


def test_reassembler_concatenates_and_bounds():
    r = StreamReassembler(max_bytes=10)
    assert r.update(pkt(payload=b"abcde", **_flow())) == b"abcde"
    assert r.update(pkt(payload=b"fghij", **_flow())) == b"abcdefghij"
    assert r.update(pkt(payload=b"KL", **_flow())) == b"cdefghijKL"  # bounded to last 10


def test_signature_matches_across_segments():
    # Neither packet carries "UNION SELECT" alone; the reassembled stream does.
    pipe = Pipeline()
    pipe.process(pkt(ts=0.0, payload=b"GET /?q=UNI", **_flow()))
    pipe.process(pkt(ts=0.1, payload=b"ON SELECT pw FROM users", **_flow()))
    assert "SQL Injection" in {a.category for a in pipe.alerts}


def test_separate_flows_do_not_merge():
    pipe = Pipeline()
    pipe.process(pkt(ts=0.0, payload=b"GET /?q=UNI", **_flow(sport=1111)))
    pipe.process(pkt(ts=0.1, payload=b"ON SELECT pw FROM users", **_flow(sport=2222)))
    assert "SQL Injection" not in {a.category for a in pipe.alerts}
