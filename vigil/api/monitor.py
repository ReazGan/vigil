"""Live monitor: a pipeline fed by a background thread.

Wraps a Pipeline with the things a dashboard needs that the engine itself does
not care about: a bounded buffer of recent events, a per-second time series for
the traffic chart, and uptime. A single feed thread owns all writes under one
lock; the API threads only read.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable, Iterator, Optional

from ..config import DEFAULT, Thresholds
from ..models import Alert, Packet
from ..pipeline import Pipeline
from ..store import EventStore

SourceFactory = Callable[[], Iterator[Packet]]


class Monitor:
    def __init__(
        self,
        source_factory: SourceFactory,
        source_label: str = "",
        loop: bool = False,
        speed: float = 8.0,
        cfg: Thresholds = DEFAULT,
        store: Optional[EventStore] = None,
        buckets: int = 300,
    ) -> None:
        self._source_factory = source_factory
        self.source_label = source_label
        self.loop = loop
        self.speed = speed
        self.pipeline = Pipeline(cfg=cfg, keep_alerts=False, on_alert=self._on_alert)
        # Correlated events are persisted; an in-memory DB is used when no path
        # is given, so the store path is always exercised.
        self.store = store if store is not None else EventStore(":memory:")
        self._buckets: deque[dict] = deque(maxlen=buckets)
        self._cur: Optional[dict] = None
        self.started_at = time.time()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    # ---- lifecycle -----------------------------------------------------
    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="vigil-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        # Rewrite packet timestamps to advance monotonically. For a single live
        # capture this is a no-op in practice; for a looped pcap it stops time
        # from resetting each loop, so sliding windows and the correlator see
        # one continuous stream rather than the same 17 seconds over and over.
        prev_raw: Optional[float] = None
        adjusted = 0.0
        while not self._stop.is_set():
            try:
                for pkt in self._source_factory():
                    if self._stop.is_set():
                        break
                    raw = pkt.ts
                    if prev_raw is None:
                        delta = 0.0
                    else:
                        delta = raw - prev_raw
                        if delta < 0 or delta > 3600:
                            delta = 0.01  # loop boundary or a large gap
                    prev_raw = raw
                    if self.speed and delta > 0:
                        time.sleep(min(delta / self.speed, 0.2))
                    adjusted += delta
                    pkt.ts = adjusted
                    with self._lock:
                        emitted = self.pipeline.process(pkt)
                        self._tick(time.time(), 1, len(emitted))
            except Exception:
                # A failing source (e.g. no capture privileges) must not take
                # the server down; stop feeding and leave the API serving.
                break
            if not self.loop or self._stop.is_set():
                break

    # ---- writes (feed thread, under lock) ------------------------------
    def _on_alert(self, alert: Alert) -> None:
        # Called from inside pipeline.process (feed thread). Persist with a
        # wall-clock arrival time so the dashboard shows when an event was seen,
        # not the (possibly 1970-era) pcap timestamp.
        self.store.record(alert, time.time())

    def _tick(self, now: float, packets: int, detections: int) -> None:
        bucket = int(now)
        if self._cur is None or self._cur["t"] != bucket:
            self._cur = {"t": bucket, "packets": 0, "detections": 0}
            self._buckets.append(self._cur)
        self._cur["packets"] += packets
        self._cur["detections"] += detections

    # ---- reads (API threads) -------------------------------------------
    def snapshot(self) -> dict:
        with self._lock:
            traffic = self.pipeline.flows.snapshot()
            alerts = self.pipeline.correlator.snapshot()
            by_sev = alerts["by_severity"]
            if len(self._buckets) >= 2:
                pps = self._buckets[-2]["packets"]  # last completed second
            elif self._buckets:
                pps = self._buckets[-1]["packets"]
            else:
                pps = 0
            return {
                "uptime_s": round(time.time() - self.started_at, 1),
                "packets": traffic["total_packets"],
                "bytes": traffic["total_bytes"],
                "flows": traffic["flows"],
                "active_flows": traffic["active_flows"],
                "by_protocol": traffic["by_protocol"],
                "pps": pps,
                "events_total": alerts["total_events"],
                "events_stored": self.store.total(),
                "raw_detections": alerts["total_raw_alerts"],
                "high_critical": by_sev.get("High", 0) + by_sev.get("Critical", 0),
                "by_category": alerts["by_category"],
                "by_severity": by_sev,
                "detectors": len(self.pipeline.detectors),
                "source": self.source_label,
            }

    def events_list(self, limit: int = 50) -> list[dict]:
        return self.store.recent(limit)

    def timeseries(self) -> dict:
        with self._lock:
            return {"buckets": [dict(b) for b in self._buckets]}
