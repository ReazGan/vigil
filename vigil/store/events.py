"""Persistent event store backed by SQLite.

Correlated events are written here so the alert history survives a restart and
can be queried. SQLite (standard library) is enough for a single node and keeps
the dependency surface at zero; the distributed design in docs/DESIGN.md swaps
this for Postgres behind the same small interface.

All access goes through one connection guarded by a lock. Events are rare
compared to packets (the correlator collapses bursts), so a commit per event is
not a bottleneck.
"""

from __future__ import annotations

import json
import sqlite3
import threading

from ..models import Alert

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL,
    seen      REAL,
    detector  TEXT,
    category  TEXT,
    severity  TEXT,
    src_ip    TEXT,
    dst_ip    TEXT,
    summary   TEXT,
    evidence  TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_id ON events(id DESC);
"""


class EventStore:
    def __init__(self, path: str = ":memory:") -> None:
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            if path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def record(self, alert: Alert, seen: float) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO events "
                "(ts, seen, detector, category, severity, src_ip, dst_ip, summary, evidence) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    alert.ts,
                    seen,
                    alert.detector,
                    alert.category,
                    alert.severity.label,
                    alert.src_ip,
                    alert.dst_ip,
                    alert.summary,
                    json.dumps(alert.evidence),
                ),
            )
            self._conn.commit()

    def recent(self, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, seen, detector, category, severity, src_ip, dst_ip, summary, evidence "
                "FROM events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        out = []
        for row in rows:
            data = dict(row)
            data["evidence"] = json.loads(data["evidence"] or "{}")
            out.append(data)
        return out

    def total(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
