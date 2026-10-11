from vigil.models import Alert, Severity
from vigil.store import EventStore


def _alert(category="Port Scan", src="1.1.1.1"):
    return Alert(
        ts=1000.0,
        detector="d",
        category=category,
        severity=Severity.HIGH,
        src_ip=src,
        dst_ip="2.2.2.2",
        summary="x",
        evidence={"k": 1},
    )


def test_record_and_recent(tmp_path):
    store = EventStore(str(tmp_path / "e.db"))
    store.record(_alert("Port Scan"), 1.0)
    store.record(_alert("SYN Flood"), 2.0)

    recent = store.recent(10)
    assert len(recent) == 2
    assert recent[0]["category"] == "SYN Flood"   # newest first
    assert recent[0]["evidence"] == {"k": 1}
    assert store.total() == 2
    store.close()


def test_persists_across_reopen(tmp_path):
    path = str(tmp_path / "e.db")
    s1 = EventStore(path)
    s1.record(_alert(), 1.0)
    s1.close()

    s2 = EventStore(path)
    assert s2.total() == 1
    s2.close()


def test_memory_store_works():
    store = EventStore(":memory:")
    store.record(_alert(), 1.0)
    assert store.total() == 1
    store.close()
