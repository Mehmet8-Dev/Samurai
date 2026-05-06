"""HTTP management API for distributed control plane."""

from __future__ import annotations

import threading
from typing import Any, Callable


def _auth_ok(header: str, expected_token: str) -> bool:
    token = str(expected_token or "").strip()
    if not token:
        return True
    raw = str(header or "").strip()
    if not raw:
        return False
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    return raw == token


def create_management_app(
    *,
    state_provider: Callable[[], dict[str, Any]],
    abort_callback: Callable[[], dict[str, Any]],
    metrics_provider: Callable[[], str] | None = None,
    auth_token: str = "",
):
    from fastapi import FastAPI, Header, HTTPException
    from fastapi.responses import PlainTextResponse

    app = FastAPI(title="DDoSamurai Distributed Management API", version="1.0")

    def _guard(authorization: str | None) -> None:
        if not _auth_ok(str(authorization or ""), str(auth_token or "")):
            raise HTTPException(status_code=401, detail="unauthorized")

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/v1/cluster/summary")
    def cluster_summary(authorization: str | None = Header(default=None)):
        _guard(authorization)
        st = dict(state_provider() or {})
        return {
            "status": "ok",
            "current_job": dict(st.get("current_job") or {}),
            "latest_snapshot": dict(st.get("latest_snapshot") or {}),
            "ha": dict(st.get("ha") or {}),
            "workers_count": int(st.get("workers_count", 0) or 0),
            "shards_reported_count": int(st.get("shards_reported_count", 0) or 0),
        }

    @app.get("/v1/cluster/workers")
    def cluster_workers(authorization: str | None = Header(default=None)):
        _guard(authorization)
        st = dict(state_provider() or {})
        return {"workers": list(st.get("workers") or [])}

    @app.get("/v1/cluster/shards")
    def cluster_shards(authorization: str | None = Header(default=None)):
        _guard(authorization)
        st = dict(state_provider() or {})
        return {"shards": list(st.get("shards") or [])}

    @app.post("/v1/jobs/abort")
    def abort_job(authorization: str | None = Header(default=None)):
        _guard(authorization)
        return dict(abort_callback() or {"aborted": False})

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics(authorization: str | None = Header(default=None)):
        _guard(authorization)
        if metrics_provider is None:
            return ""
        return str(metrics_provider() or "")

    return app


class ManagementAPIServer:
    def __init__(self, listen_addr: str, app) -> None:
        self.listen_addr = str(listen_addr or "127.0.0.1:8089").strip()
        self.app = app
        self._thread = None
        self._server = None

    def start(self) -> None:
        import uvicorn

        host, port_s = self.listen_addr.rsplit(":", 1)
        cfg = uvicorn.Config(
            app=self.app,
            host=str(host),
            port=int(port_s),
            log_level="warning",
            access_log=False,
        )
        self._server = uvicorn.Server(cfg)

        def _run():
            self._server.run()

        self._thread = threading.Thread(target=_run, daemon=True, name="ManagementAPI")
        self._thread.start()

    def stop(self) -> None:
        srv = self._server
        if srv is not None:
            srv.should_exit = True
        th = self._thread
        if th is not None:
            th.join(timeout=2.0)
