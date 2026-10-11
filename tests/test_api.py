"""API tests: authentication and the read endpoints.

Skipped unless the api extra and a test client are installed. The monitor is
created but not started, so these run against an empty-but-valid pipeline with
no capture thread.
"""

import importlib.util

import pytest

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("fastapi") is None or importlib.util.find_spec("httpx") is None,
    reason="api extra not installed",
)


def _client():
    from fastapi.testclient import TestClient

    from vigil.api import auth
    from vigil.api.monitor import Monitor
    from vigil.api.server import create_app

    auth._USER = "admin"
    auth._PASSWORD = "testpass"
    monitor = Monitor(source_factory=lambda: iter(()), source_label="test")
    return TestClient(create_app(monitor))


def test_stats_requires_auth():
    client = _client()
    assert client.get("/api/stats").status_code == 401


def test_bad_token_is_rejected():
    client = _client()
    r = client.get("/api/stats", headers={"Authorization": "Bearer not-a-token"})
    assert r.status_code == 401


def test_login_then_read_stats():
    client = _client()
    assert client.post("/api/login", json={"username": "admin", "password": "wrong"}).status_code == 401

    r = client.post("/api/login", json={"username": "admin", "password": "testpass"})
    assert r.status_code == 200
    token = r.json()["token"]

    s = client.get("/api/stats", headers={"Authorization": f"Bearer {token}"})
    assert s.status_code == 200
    body = s.json()
    assert "packets" in body
    assert "by_category" in body
    assert body["detectors"] >= 6
