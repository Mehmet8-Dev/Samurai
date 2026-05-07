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


def _extract_bearer(header: str) -> str:
    raw = str(header or "").strip()
    if not raw:
        return ""
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    return raw


def create_management_app(
    *,
    state_provider: Callable[[], dict[str, Any]],
    abort_callback: Callable[[], dict[str, Any]],
    metrics_provider: Callable[[], str] | None = None,
    auth_token: str = "",
    auth_role_tokens: dict[str, str] | None = None,
    tenant_namespace: str = "",
):
    from fastapi import FastAPI, Header, HTTPException
    from fastapi.responses import PlainTextResponse

    app = FastAPI(title="DDoSamurai Distributed Management API", version="1.0")

    role_tokens = dict(auth_role_tokens or {})
    app_tenant = str(tenant_namespace or "").strip()
    legacy = str(auth_token or "").strip()
    if legacy and "admin" not in role_tokens:
        role_tokens["admin"] = legacy
    if legacy and "operator" not in role_tokens:
        role_tokens["operator"] = legacy
    if legacy and "viewer" not in role_tokens:
        role_tokens["viewer"] = legacy

    def _resolve_role(authorization: str | None) -> str:
        token = _extract_bearer(str(authorization or ""))
        if not role_tokens:
            return "admin"
        for role in ("admin", "operator", "viewer"):
            exp = str(role_tokens.get(role, "") or "").strip()
            if exp and token == exp:
                return role
        return ""

    def _guard(authorization: str | None, allowed_roles: set[str]) -> None:
        role = _resolve_role(authorization)
        if not role:
            raise HTTPException(status_code=401, detail="unauthorized")
        if role not in set(allowed_roles or set()):
            raise HTTPException(status_code=403, detail="forbidden")

    def _match_tenant(item: dict, tenant: str) -> bool:
        if not tenant:
            return True
        got = str((dict(item or {})).get("tenant_namespace", "") or "").strip()
        return got == tenant

    def _effective_tenant(query_tenant: str | None) -> str:
        qt = str(query_tenant or "").strip()
        if app_tenant and qt and qt != app_tenant:
            raise HTTPException(status_code=403, detail="forbidden_tenant")
        return app_tenant or qt

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/v1/cluster/summary")
    def cluster_summary(authorization: str | None = Header(default=None), tenant_namespace: str | None = None):
        _guard(authorization, {"admin", "operator", "viewer"})
        tenant = _effective_tenant(tenant_namespace)
        st = dict(state_provider() or {})
        workers = [x for x in list(st.get("workers") or []) if _match_tenant(x, tenant)]
        shards = [x for x in list(st.get("shards") or []) if _match_tenant(x, tenant)]
        current_job = dict(st.get("current_job") or {})
        if tenant and str(current_job.get("tenant_namespace", "") or "").strip() != tenant:
            current_job = {"state": "idle", "job_id": "", "tenant_namespace": tenant}
        return {
            "status": "ok",
            "tenant_namespace": tenant,
            "current_job": current_job,
            "latest_snapshot": dict(st.get("latest_snapshot") or {}),
            "ha": dict(st.get("ha") or {}),
            "workers_count": int(len(workers)),
            "shards_reported_count": int(len(shards)),
        }

    @app.get("/v1/cluster/workers")
    def cluster_workers(authorization: str | None = Header(default=None), tenant_namespace: str | None = None):
        _guard(authorization, {"admin", "operator", "viewer"})
        tenant = _effective_tenant(tenant_namespace)
        st = dict(state_provider() or {})
        workers = [x for x in list(st.get("workers") or []) if _match_tenant(x, tenant)]
        return {"tenant_namespace": tenant, "workers": workers}

    @app.get("/v1/cluster/shards")
    def cluster_shards(authorization: str | None = Header(default=None), tenant_namespace: str | None = None):
        _guard(authorization, {"admin", "operator", "viewer"})
        tenant = _effective_tenant(tenant_namespace)
        st = dict(state_provider() or {})
        shards = [x for x in list(st.get("shards") or []) if _match_tenant(x, tenant)]
        return {"tenant_namespace": tenant, "shards": shards}

    @app.get("/v1/cluster/events")
    def cluster_events(authorization: str | None = Header(default=None), tenant_namespace: str | None = None):
        _guard(authorization, {"admin", "operator", "viewer"})
        tenant = _effective_tenant(tenant_namespace)
        st = dict(state_provider() or {})
        events = [x for x in list(st.get("events") or []) if _match_tenant(x, tenant)]
        return {"tenant_namespace": tenant, "events": events}

    @app.post("/v1/jobs/abort")
    def abort_job(authorization: str | None = Header(default=None), tenant_namespace: str | None = None):
        _guard(authorization, {"admin", "operator"})
        _ = _effective_tenant(tenant_namespace)
        return dict(abort_callback() or {"aborted": False})

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics(authorization: str | None = Header(default=None)):
        _guard(authorization, {"admin", "operator", "viewer"})
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
