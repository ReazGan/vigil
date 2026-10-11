"""FastAPI app and server bootstrap.

Routes are thin: authenticate, then read from the Monitor. The dashboard is
served as static files from the same origin, so there is no CORS surface. The
capture source runs in the Monitor's own thread; uvicorn serves requests.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import auth
from .monitor import Monitor, SourceFactory
from ..store import EventStore

STATIC_DIR = Path(__file__).parent / "static"


class LoginIn(BaseModel):
    username: str
    password: str


def _require_auth(authorization: Optional[str] = Header(default=None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing token")
    try:
        return auth.verify_token(authorization.split(" ", 1)[1])
    except Exception:
        raise HTTPException(status_code=401, detail="invalid token")


def create_app(monitor: Monitor) -> FastAPI:
    app = FastAPI(title="vigil", docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/api/login")
    def login(body: LoginIn):
        if not auth.check_login(body.username, body.password):
            raise HTTPException(status_code=401, detail="bad credentials")
        return {"token": auth.create_token(body.username)}

    @app.get("/api/stats")
    def stats(_: str = Depends(_require_auth)):
        return monitor.snapshot()

    @app.get("/api/events")
    def events(limit: int = 50, _: str = Depends(_require_auth)):
        return monitor.events_list(min(max(limit, 1), 200))

    @app.get("/api/timeseries")
    def timeseries(_: str = Depends(_require_auth)):
        return monitor.timeseries()

    @app.get("/api/rules")
    def rules(_: str = Depends(_require_auth)):
        from ..detect import build_all
        from ..detect.signature import RULES

        detectors = [
            {
                "name": d.name,
                "category": d.category,
                "type": "signature" if d.name == "signature" else "behavioral",
            }
            for d in build_all()
        ]
        signatures = [
            {"id": r.id, "category": r.category, "severity": r.severity.label} for r in RULES
        ]
        return {"detectors": detectors, "signatures": signatures}

    @app.get("/api/config")
    def config(_: str = Depends(_require_auth)):
        import dataclasses

        return dataclasses.asdict(monitor.pipeline.cfg)

    # Dashboard. Mounted last so the API routes above take precedence.
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
    return app


def _build_monitor(pcap, iface, bpf, loop, speed, db) -> Monitor:
    store = EventStore(db) if db else None

    if pcap:
        from ..capture.pcap import PcapSource

        factory: SourceFactory = lambda: iter(PcapSource(pcap))
        label = f"pcap: {os.path.basename(pcap)}" + (" (loop)" if loop else "")
        return Monitor(factory, source_label=label, loop=loop, speed=speed, store=store)

    if iface is not None:
        from ..capture.live import LiveSource

        source = LiveSource(iface=iface, bpf=bpf)
        factory = lambda: iter(source)
        label = f"live: {iface or 'default interface'}"
        return Monitor(factory, source_label=label, loop=False, speed=0.0, store=store)

    raise SystemExit("serve: provide --pcap PATH or --iface NAME")


def run_server(
    pcap: Optional[str] = None,
    iface: Optional[str] = None,
    bpf: Optional[str] = None,
    host: str = "127.0.0.1",
    port: int = 8089,
    loop: bool = True,
    speed: float = 8.0,
    db: Optional[str] = None,
) -> None:
    import uvicorn

    monitor = _build_monitor(pcap, iface, bpf, loop, speed, db)
    monitor.start()
    print(auth.credentials_banner())
    print(f"vigil dashboard: http://{host}:{port}")
    uvicorn.run(create_app(monitor), host=host, port=port, log_level="warning")
