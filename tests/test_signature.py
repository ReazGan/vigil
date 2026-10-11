from vigil.detect.signature import SignatureDetector

from tests.util import pkt


def test_detects_sql_injection():
    det = SignatureDetector()
    p = pkt(dport=80, payload=b"GET /item?id=1 UNION SELECT password FROM users")
    cats = [a.category for a in det.inspect(p)]
    assert "SQL Injection" in cats


def test_detects_xss():
    det = SignatureDetector()
    p = pkt(dport=8080, payload=b"GET /search?q=<script>alert(1)</script>")
    cats = [a.category for a in det.inspect(p)]
    assert "XSS Attack" in cats


def test_clean_payload_is_quiet():
    det = SignatureDetector()
    p = pkt(dport=80, payload=b"GET /index.html HTTP/1.1\r\nHost: example.com")
    assert list(det.inspect(p)) == []


def test_no_payload_is_quiet():
    det = SignatureDetector()
    assert list(det.inspect(pkt(dport=80))) == []
