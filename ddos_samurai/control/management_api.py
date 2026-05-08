"""HTTP management API for distributed control plane."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from typing import Any, Callable

from .jwt_claims import decode_jwt_hs256

try:
    from starlette.requests import Request as StarletteRequest
    from starlette.websockets import WebSocket as StarletteWebSocket
except Exception:  # pragma: no cover - imported lazily where needed
    StarletteRequest = Any  # type: ignore[assignment]
    StarletteWebSocket = Any  # type: ignore[assignment]

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
    jwt_secret: str = "",
    jwt_role_claim: str = "role",
    jwt_tenant_claim: str = "tenant_namespace",
    trusted_identity_header_secret: str = "",
    trusted_identity_secret_header: str = "x-samurai-auth-proxy-secret",
    trusted_identity_role_header: str = "x-auth-request-role",
    trusted_identity_tenant_header: str = "x-auth-request-tenant",
    live_interval_ms: int = 1000,
):
    from fastapi import FastAPI, Header, HTTPException
    from fastapi.responses import PlainTextResponse, StreamingResponse

    app = FastAPI(title="DDoSamurai Distributed Management API", version="1.0")

    role_tokens = dict(auth_role_tokens or {})
    app_tenant = str(tenant_namespace or "").strip()
    jwt_shared_secret = str(jwt_secret or "").strip()
    jwt_role_key = str(jwt_role_claim or "role").strip() or "role"
    jwt_tenant_key = str(jwt_tenant_claim or "tenant_namespace").strip() or "tenant_namespace"
    trusted_secret = str(trusted_identity_header_secret or "").strip()
    trusted_secret_header = str(trusted_identity_secret_header or "x-samurai-auth-proxy-secret").strip().lower()
    trusted_role_header = str(trusted_identity_role_header or "x-auth-request-role").strip().lower()
    trusted_tenant_header = str(trusted_identity_tenant_header or "x-auth-request-tenant").strip().lower()
    live_interval_s = max(0.1, float(int(live_interval_ms or 1000)) / 1000.0)
    legacy = str(auth_token or "").strip()
    if legacy and "admin" not in role_tokens:
        role_tokens["admin"] = legacy
    if legacy and "operator" not in role_tokens:
        role_tokens["operator"] = legacy
    if legacy and "viewer" not in role_tokens:
        role_tokens["viewer"] = legacy

    def _trusted_identity(headers: dict[str, str] | None) -> tuple[str, str]:
        hd = {str(k).lower(): str(v) for k, v in dict(headers or {}).items()}
        if not trusted_secret:
            return "", ""
        if str(hd.get(trusted_secret_header, "") or "").strip() != trusted_secret:
            return "", ""
        role = str(hd.get(trusted_role_header, "") or "").strip().lower()
        tenant = str(hd.get(trusted_tenant_header, "") or "").strip()
        return role, tenant

    def _resolve_role(authorization: str | None, headers: dict[str, str] | None = None) -> str:
        trusted_role, _trusted_tenant = _trusted_identity(headers)
        if trusted_role:
            return trusted_role
        token = _extract_bearer(str(authorization or ""))
        if not role_tokens:
            if jwt_shared_secret:
                try:
                    claims = decode_jwt_hs256(token, jwt_shared_secret)
                    role = str((dict(claims or {})).get(jwt_role_key, "") or "").strip().lower()
                    if role:
                        return role
                except ValueError:
                    pass
            return "admin"
        for role in ("admin", "operator", "viewer"):
            exp = str(role_tokens.get(role, "") or "").strip()
            if exp and token == exp:
                return role
        if jwt_shared_secret:
            try:
                claims = decode_jwt_hs256(token, jwt_shared_secret)
                return str((dict(claims or {})).get(jwt_role_key, "") or "").strip().lower()
            except ValueError:
                return ""
        return ""

    def _resolve_jwt_tenant(authorization: str | None, headers: dict[str, str] | None = None) -> str:
        _trusted_role, trusted_tenant = _trusted_identity(headers)
        if trusted_tenant:
            return trusted_tenant
        if not jwt_shared_secret:
            return ""
        token = _extract_bearer(str(authorization or ""))
        if not token:
            return ""
        try:
            claims = decode_jwt_hs256(token, jwt_shared_secret)
        except ValueError:
            return ""
        return str((dict(claims or {})).get(jwt_tenant_key, "") or "").strip()

    def _guard(authorization: str | None, allowed_roles: set[str], headers: dict[str, str] | None = None) -> None:
        role = _resolve_role(authorization, headers=headers)
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

    def _effective_tenant_with_claims(
        query_tenant: str | None,
        authorization: str | None,
        headers: dict[str, str] | None = None,
    ) -> str:
        tenant = _effective_tenant(query_tenant)
        claim_tenant = _resolve_jwt_tenant(authorization, headers=headers)
        if tenant and claim_tenant and tenant != claim_tenant:
            raise HTTPException(status_code=403, detail="forbidden_tenant_claim")
        return tenant or claim_tenant

    def _extract_tenant_events(events: list[dict], tenant: str, since_ts_ms: int) -> tuple[list[dict], int]:
        out = []
        cursor = int(since_ts_ms or 0)
        for item in list(events or []):
            rec = dict(item or {})
            if not _match_tenant(rec, tenant):
                continue
            ts = int(rec.get("ts_ms", 0) or 0)
            if ts > cursor:
                out.append(rec)
                cursor = max(cursor, ts)
        return out, cursor

    def _live_payload(state: dict, tenant: str, since_ts_ms: int) -> tuple[dict, int]:
        st = dict(state or {})
        workers = [x for x in list(st.get("workers") or []) if _match_tenant(x, tenant)]
        shards = [x for x in list(st.get("shards") or []) if _match_tenant(x, tenant)]
        current_job = dict(st.get("current_job") or {})
        if tenant and str(current_job.get("tenant_namespace", "") or "").strip() != tenant:
            current_job = {"state": "idle", "job_id": "", "tenant_namespace": tenant}
        events, cursor = _extract_tenant_events(list(st.get("events") or []), tenant, since_ts_ms=int(since_ts_ms or 0))
        payload = {
            "type": "snapshot",
            "ts_ms": int(time.time() * 1000),
            "tenant_namespace": tenant,
            "current_job": current_job,
            "latest_snapshot": dict(st.get("latest_snapshot") or {}),
            "ha": dict(st.get("ha") or {}),
            "multi_master": dict(st.get("multi_master") or {}),
            "multi_master_regions": list(st.get("multi_master_regions") or []),
            "multi_master_latest": list(st.get("multi_master_latest") or []),
            "workers_count": int(len(workers)),
            "shards_reported_count": int(len(shards)),
            "events": events,
        }
        return payload, int(cursor)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/v1/cluster/summary")
    def cluster_summary(
        authorization: str | None = Header(default=None),
        tenant_namespace: str | None = None,
        x_auth_request_role: str | None = Header(default=None),
        x_auth_request_tenant: str | None = Header(default=None),
        x_samurai_auth_proxy_secret: str | None = Header(default=None),
    ):
        hdr = {
            "x-auth-request-role": str(x_auth_request_role or ""),
            "x-auth-request-tenant": str(x_auth_request_tenant or ""),
            "x-samurai-auth-proxy-secret": str(x_samurai_auth_proxy_secret or ""),
        }
        _guard(authorization, {"admin", "operator", "viewer"}, headers=hdr)
        tenant = _effective_tenant_with_claims(tenant_namespace, authorization, headers=hdr)
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
            "multi_master": dict(st.get("multi_master") or {}),
            "multi_master_regions": list(st.get("multi_master_regions") or []),
            "multi_master_latest": list(st.get("multi_master_latest") or []),
            "workers_count": int(len(workers)),
            "shards_reported_count": int(len(shards)),
        }

    @app.get("/v1/cluster/workers")
    def cluster_workers(
        authorization: str | None = Header(default=None),
        tenant_namespace: str | None = None,
        x_auth_request_role: str | None = Header(default=None),
        x_auth_request_tenant: str | None = Header(default=None),
        x_samurai_auth_proxy_secret: str | None = Header(default=None),
    ):
        hdr = {
            "x-auth-request-role": str(x_auth_request_role or ""),
            "x-auth-request-tenant": str(x_auth_request_tenant or ""),
            "x-samurai-auth-proxy-secret": str(x_samurai_auth_proxy_secret or ""),
        }
        _guard(authorization, {"admin", "operator", "viewer"}, headers=hdr)
        tenant = _effective_tenant_with_claims(tenant_namespace, authorization, headers=hdr)
        st = dict(state_provider() or {})
        workers = [x for x in list(st.get("workers") or []) if _match_tenant(x, tenant)]
        return {"tenant_namespace": tenant, "workers": workers}

    @app.get("/v1/cluster/shards")
    def cluster_shards(
        authorization: str | None = Header(default=None),
        tenant_namespace: str | None = None,
        x_auth_request_role: str | None = Header(default=None),
        x_auth_request_tenant: str | None = Header(default=None),
        x_samurai_auth_proxy_secret: str | None = Header(default=None),
    ):
        hdr = {
            "x-auth-request-role": str(x_auth_request_role or ""),
            "x-auth-request-tenant": str(x_auth_request_tenant or ""),
            "x-samurai-auth-proxy-secret": str(x_samurai_auth_proxy_secret or ""),
        }
        _guard(authorization, {"admin", "operator", "viewer"}, headers=hdr)
        tenant = _effective_tenant_with_claims(tenant_namespace, authorization, headers=hdr)
        st = dict(state_provider() or {})
        shards = [x for x in list(st.get("shards") or []) if _match_tenant(x, tenant)]
        return {"tenant_namespace": tenant, "shards": shards}

    @app.get("/v1/cluster/events")
    def cluster_events(
        authorization: str | None = Header(default=None),
        tenant_namespace: str | None = None,
        x_auth_request_role: str | None = Header(default=None),
        x_auth_request_tenant: str | None = Header(default=None),
        x_samurai_auth_proxy_secret: str | None = Header(default=None),
    ):
        hdr = {
            "x-auth-request-role": str(x_auth_request_role or ""),
            "x-auth-request-tenant": str(x_auth_request_tenant or ""),
            "x-samurai-auth-proxy-secret": str(x_samurai_auth_proxy_secret or ""),
        }
        _guard(authorization, {"admin", "operator", "viewer"}, headers=hdr)
        tenant = _effective_tenant_with_claims(tenant_namespace, authorization, headers=hdr)
        st = dict(state_provider() or {})
        events = [x for x in list(st.get("events") or []) if _match_tenant(x, tenant)]
        return {"tenant_namespace": tenant, "events": events}

    @app.post("/v1/jobs/abort")
    def abort_job(
        authorization: str | None = Header(default=None),
        tenant_namespace: str | None = None,
        x_auth_request_role: str | None = Header(default=None),
        x_auth_request_tenant: str | None = Header(default=None),
        x_samurai_auth_proxy_secret: str | None = Header(default=None),
    ):
        hdr = {
            "x-auth-request-role": str(x_auth_request_role or ""),
            "x-auth-request-tenant": str(x_auth_request_tenant or ""),
            "x-samurai-auth-proxy-secret": str(x_samurai_auth_proxy_secret or ""),
        }
        _guard(authorization, {"admin", "operator"}, headers=hdr)
        _ = _effective_tenant_with_claims(tenant_namespace, authorization, headers=hdr)
        return dict(abort_callback() or {"aborted": False})

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics(
        authorization: str | None = Header(default=None),
        x_auth_request_role: str | None = Header(default=None),
        x_samurai_auth_proxy_secret: str | None = Header(default=None),
    ):
        hdr = {
            "x-auth-request-role": str(x_auth_request_role or ""),
            "x-samurai-auth-proxy-secret": str(x_samurai_auth_proxy_secret or ""),
        }
        _guard(authorization, {"admin", "operator", "viewer"}, headers=hdr)
        if metrics_provider is None:
            return ""
        return str(metrics_provider() or "")

    @app.get("/v1/cluster/live/sse")
    async def cluster_live_sse(
        request: StarletteRequest,
        authorization: str | None = Header(default=None),
        tenant_namespace: str | None = None,
        since_ts_ms: int = 0,
        x_auth_request_role: str | None = Header(default=None),
        x_auth_request_tenant: str | None = Header(default=None),
        x_samurai_auth_proxy_secret: str | None = Header(default=None),
    ):
        hdr = {
            "x-auth-request-role": str(x_auth_request_role or ""),
            "x-auth-request-tenant": str(x_auth_request_tenant or ""),
            "x-samurai-auth-proxy-secret": str(x_samurai_auth_proxy_secret or ""),
        }
        _guard(authorization, {"admin", "operator", "viewer"}, headers=hdr)
        tenant = _effective_tenant_with_claims(tenant_namespace, authorization, headers=hdr)

        async def _stream():
            cursor = int(since_ts_ms or 0)
            while True:
                if await request.is_disconnected():
                    break
                payload, cursor = _live_payload(state_provider(), tenant, cursor)
                yield "event: snapshot\n"
                yield f"data: {json.dumps(payload, ensure_ascii=True)}\n\n"
                await asyncio.sleep(live_interval_s)

        return StreamingResponse(_stream(), media_type="text/event-stream")

    @app.websocket("/v1/cluster/live/ws")
    async def cluster_live_ws(ws: StarletteWebSocket):
        authz = str(ws.headers.get("authorization", "") or ws.query_params.get("token", "") or "")
        tenant_qs = str(ws.query_params.get("tenant_namespace", "") or "").strip() or None
        since_qs = int(ws.query_params.get("since_ts_ms", "0") or 0)
        hdr = {
            "x-auth-request-role": str(ws.headers.get("x-auth-request-role", "") or ""),
            "x-auth-request-tenant": str(ws.headers.get("x-auth-request-tenant", "") or ""),
            "x-samurai-auth-proxy-secret": str(ws.headers.get("x-samurai-auth-proxy-secret", "") or ""),
        }
        role = _resolve_role(authz, headers=hdr)
        if role not in {"admin", "operator", "viewer"}:
            await ws.close(code=4401)
            return
        try:
            tenant = _effective_tenant_with_claims(tenant_qs, authz, headers=hdr)
        except HTTPException:
            await ws.close(code=4403)
            return
        await ws.accept()
        cursor = int(since_qs or 0)
        while True:
            try:
                payload, cursor = _live_payload(state_provider(), tenant, cursor)
                await ws.send_text(json.dumps(payload, ensure_ascii=True))
                await asyncio.sleep(live_interval_s)
            except Exception:
                break

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
