from vigil.config import Thresholds
from vigil.correlate import Correlator
from vigil.models import Alert, Severity


def _alert(ts: float) -> Alert:
    return Alert(
        ts=ts,
        detector="d",
        category="C",
        severity=Severity.HIGH,
        src_ip="a",
        dst_ip="b",
        summary="x",
    )


def test_collapses_repeats_within_cooldown():
    c = Correlator(Thresholds(correlation_cooldown=60.0))
    assert c.process(_alert(0.0)) is not None   # opens the event
    assert c.process(_alert(10.0)) is None       # same event, suppressed
    assert c.process(_alert(70.0)) is not None   # cooldown elapsed, new event

    assert c.total_events == 2
    assert c.total_raw == 3
    assert c.snapshot()["by_severity"]["High"] == 2


def test_distinct_keys_are_separate_events():
    c = Correlator(Thresholds(correlation_cooldown=60.0))
    a = _alert(0.0)
    b = Alert(ts=1.0, detector="d", category="C", severity=Severity.HIGH, src_ip="z", dst_ip="b", summary="y")
    assert c.process(a) is not None
    assert c.process(b) is not None
    assert c.total_events == 2
