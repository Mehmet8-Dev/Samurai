"""Master gRPC server skeleton for distributed control plane."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from concurrent import futures

from . import require_distributed
from .auth import load_tls_server_credentials, resolve_role_from_secret, validate_cluster_secret
from .jwt_claims import decode_jwt_hs256
from .proto import load_generated


class _SecretServerInterceptor:
    def __init__(
        self,
        expected_secret: str,
        *,
        rbac_enabled: bool = False,
        role_secrets: dict[str, str] | None = None,
        default_role: str = "viewer",
        jwt_secret: str = "",
        jwt_role_claim: str = "role",
        audit_logger=None,
        audit_success: bool = False,
    ) -> None:
        self._expected = str(expected_secret or "").strip()
        self._rbac_enabled = bool(rbac_enabled)
        self._role_secrets = dict(role_secrets or {})
        self._default_role = str(default_role or "viewer").strip().lower() or "viewer"
        self._jwt_secret = str(jwt_secret or "").strip()
        self._jwt_role_claim = str(jwt_role_claim or "role").strip() or "role"
        self._audit_logger = audit_logger
        self._audit_success = bool(audit_success)

    @staticmethod
    def _rpc_name(method: str) -> str:
        raw = str(method or "").strip()
        if not raw:
            return ""
        if "/" in raw:
            return str(raw.rsplit("/", 1)[-1] or "").strip()
        return raw

    @staticmethod
    def _allowed_roles_for_rpc(rpc_name: str) -> set[str]:
        name = str(rpc_name or "").strip()
        if name in {"AbortJob"}:
            return {"admin"}
        if name in {"GetWorkerStatus", "ForceSync"}:
            return {"admin", "operator", "viewer"}
        if name in {"RegisterWorker", "Heartbeat", "ReportStats", "ReportStatsStream"}:
            return {"admin", "operator", "worker"}
        if name in {"StartShard", "StopShard"}:
            return {"admin", "operator"}
        return {"admin"}

    def _authorized_core(self, md: dict, rpc_name: str) -> tuple[bool, str, str]:
        provided = md.get("x-cluster-secret")
        jwt_claims = None
        if not validate_cluster_secret(self._expected, provided):
            if self._jwt_secret:
                try:
                    jwt_claims = decode_jwt_hs256(str(provided or ""), self._jwt_secret)
                except ValueError:
                    return False, "invalid cluster secret", ""
            else:
                return False, "invalid cluster secret", ""
        if not self._rbac_enabled:
            return True, "", "legacy"
        role = resolve_role_from_secret(provided, self._role_secrets)
        if not role and isinstance(jwt_claims, dict):
            role = str(jwt_claims.get(self._jwt_role_claim, "") or "").strip().lower()
        if not role:
            # Backward-compatible fallback:
            # - If RBAC map is empty, keep single-secret behavior via default role.
            # - If cluster secret is valid but role map has no explicit match, still allow
            #   a configured default role.
            if not self._role_secrets:
                role = self._default_role
            elif self._expected and validate_cluster_secret(self._expected, provided):
                role = self._default_role
            else:
                return False, "unknown role secret", ""
        allowed = self._allowed_roles_for_rpc(rpc_name)
        if role not in allowed:
            return False, f"forbidden for role={role} rpc={rpc_name}", role
        return True, "", role

    # Backward-compatible API for existing tests/callers that expect 2-tuple.
    def _authorized(self, md: dict, rpc_name: str) -> tuple[bool, str]:
        ok, err, _role = self._authorized_core(md, rpc_name)
        return ok, err

    @staticmethod
    def _token_fingerprint(token: str) -> str:
        raw = str(token or "").strip().encode("utf-8")
        if not raw:
            return ""
        return hashlib.sha256(raw).hexdigest()[:16]

    def _audit(self, *, ctx, rpc_name: str, provided_secret: str, role: str, allowed: bool, error: str) -> None:
        logger = self._audit_logger
        if logger is None:
            return
        if allowed and not self._audit_success:
            return
        item = {
            "ts_ms": int(time.time() * 1000),
            "rpc": str(rpc_name),
            "allowed": int(1 if allowed else 0),
            "role": str(role or ""),
            "error": str(error or ""),
            "peer": str(getattr(ctx, "peer", lambda: "")() or ""),
            "token_fp": self._token_fingerprint(provided_secret),
        }
        try:
            logger(dict(item))
        except Exception:
            pass

    def intercept_service(self, continuation, handler_call_details):
        handler = continuation(handler_call_details)
        if handler is None:
            return None
        if not self._expected and not self._rbac_enabled:
            return handler

        rpc_name = self._rpc_name(getattr(handler_call_details, "method", ""))

        def _check(ctx):
            md = dict(ctx.invocation_metadata() or [])
            provided = str(md.get("x-cluster-secret", "") or "")
            ok, err, role = self._authorized_core(md, rpc_name)
            self._audit(ctx=ctx, rpc_name=rpc_name, provided_secret=provided, role=role, allowed=ok, error=err)
            if not ok:
                status = getattr(__import__("grpc"), "StatusCode").PERMISSION_DENIED
                if "invalid cluster secret" in str(err):
                    status = getattr(__import__("grpc"), "StatusCode").UNAUTHENTICATED
                ctx.abort(status, str(err))

        def _unary_unary(req, ctx):
            _check(ctx)
            return handler.unary_unary(req, ctx)

        def _stream_unary(req_iter, ctx):
            _check(ctx)
            return handler.stream_unary(req_iter, ctx)

        import grpc

        if handler.unary_unary:
            return grpc.unary_unary_rpc_method_handler(
                _unary_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.stream_unary:
            return grpc.stream_unary_rpc_method_handler(
                _stream_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        return handler


class _SamuraiServicer:
    def __init__(
        self,
        cluster_id: str = "cluster-v1",
        tenant_namespace: str = "",
        *,
        jwt_secret: str = "",
        jwt_tenant_claim: str = "tenant_namespace",
    ) -> None:
        self.cluster_id = cluster_id
        self.tenant_namespace = str(tenant_namespace or "").strip()
        self._jwt_secret = str(jwt_secret or "").strip()
        self._jwt_tenant_claim = str(jwt_tenant_claim or "tenant_namespace").strip() or "tenant_namespace"
        self._workers_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self.workers = {}
        self.shard_stats = {}
        self._leader_epoch_min = 0

    @staticmethod
    def _invocation_meta(context) -> dict:
        if context is None:
            return {}
        try:
            return dict(context.invocation_metadata() or [])
        except Exception:
            return {}

    def _tenant_from_context(self, context) -> str:
        md = self._invocation_meta(context)
        raw = str(md.get("x-tenant-namespace", "") or "").strip()
        if raw:
            return raw
        if not self._jwt_secret:
            return ""
        try:
            claims = decode_jwt_hs256(str(md.get("x-cluster-secret", "") or ""), self._jwt_secret)
        except ValueError:
            return ""
        return str((dict(claims or {})).get(self._jwt_tenant_claim, "") or "").strip()

    def _tenant_guard(self, context, *, worker_id: str = "") -> bool:
        if not self.tenant_namespace:
            return True
        req_tenant = self._tenant_from_context(context)
        if context is not None:
            if req_tenant == self.tenant_namespace:
                return True
        else:
            if worker_id:
                with self._workers_lock:
                    rec = dict(self.workers.get(str(worker_id)) or {})
                rec_tenant = str(rec.get("tenant_namespace", "") or "").strip()
                if rec_tenant and rec_tenant == self.tenant_namespace:
                    return True
        if context is not None:
            status = getattr(__import__("grpc"), "StatusCode").PERMISSION_DENIED
            context.abort(status, f"tenant namespace mismatch (expected={self.tenant_namespace})")
        return False

    def set_leader_epoch_min(self, epoch: int) -> None:
        self._leader_epoch_min = max(0, int(epoch or 0))

    def RegisterWorker(self, request, context):
        if self.tenant_namespace:
            req_tenant = self._tenant_from_context(context)
            if req_tenant != self.tenant_namespace:
                pb2, _ = load_generated()
                return pb2.RegisterWorkerResponse(
                    accepted=False,
                    cluster_id="",
                    rejection_reason=f"tenant namespace mismatch (expected={self.tenant_namespace})",
                )
        with self._workers_lock:
            self.workers[str(request.worker_id)] = {
                "worker_id": str(request.worker_id),
                "hostname": str(request.hostname),
                "capabilities": dict(request.capabilities or {}),
                "tenant_namespace": self.tenant_namespace or self._tenant_from_context(context),
                "state": "idle",
                "active_shard_id": "",
                "last_heartbeat_ms": int(time.time() * 1000),
                "stats_json": b"{}",
            }
        pb2, _ = load_generated()
        return pb2.RegisterWorkerResponse(accepted=True, cluster_id=self.cluster_id, rejection_reason="")

    def Heartbeat(self, request, context):
        if not self._tenant_guard(context, worker_id=str(request.worker_id)):
            pb2, _ = load_generated()
            return pb2.HeartbeatResponse(acknowledged=False, command="register")
        acknowledged = False
        command = "continue"
        with self._workers_lock:
            wid = str(request.worker_id)
            if wid in self.workers:
                self.workers[wid]["last_heartbeat_ms"] = int(time.time() * 1000)
                acknowledged = True
            else:
                command = "register"
        pb2, _ = load_generated()
        return pb2.HeartbeatResponse(acknowledged=acknowledged, command=command)

    def StartShard(self, request, context):
        if not self._tenant_guard(context):
            pb2, _ = load_generated()
            return pb2.StartShardResponse(started=False, error="tenant namespace mismatch")
        wid = ""
        try:
            payload = json.loads(bytes(request.args_json or b"{}").decode("utf-8"))
            wid = str(payload.get("_worker_id", "") or "")
        except (ValueError, TypeError, UnicodeDecodeError):
            pass
        with self._workers_lock:
            if wid and wid in self.workers:
                self.workers[wid]["state"] = "running"
                self.workers[wid]["active_shard_id"] = str(request.shard_id)
        pb2, _ = load_generated()
        return pb2.StartShardResponse(started=True, error="")

    def StopShard(self, request, context):
        if not self._tenant_guard(context):
            pb2, _ = load_generated()
            return pb2.StopShardResponse(stopped=False)
        sid = str(request.shard_id)
        with self._workers_lock:
            for rec in self.workers.values():
                if str(rec.get("active_shard_id", "")) == sid:
                    rec["state"] = "idle"
                    rec["active_shard_id"] = ""
        pb2, _ = load_generated()
        return pb2.StopShardResponse(stopped=True)

    def ReportStats(self, request, context):
        if not self._tenant_guard(context, worker_id=str(request.worker_id)):
            pb2, _ = load_generated()
            return pb2.ReportStatsResponse(received=False)
        payload = bytes(request.stats_json or b"{}")
        req_epoch = 0
        if self._leader_epoch_min > 0:
            try:
                item = json.loads(payload.decode("utf-8"))
                req_epoch = int((dict(item or {})).get("leader_epoch", 0) or 0)
            except (ValueError, TypeError, UnicodeDecodeError):
                req_epoch = 0
            if req_epoch > 0 and req_epoch < self._leader_epoch_min:
                pb2, _ = load_generated()
                return pb2.ReportStatsResponse(received=False)
        with self._stats_lock:
            self.shard_stats[str(request.shard_id)] = payload
        with self._workers_lock:
            wid = str(request.worker_id)
            if wid in self.workers:
                self.workers[wid]["stats_json"] = payload
        pb2, _ = load_generated()
        return pb2.ReportStatsResponse(received=True)

    def ReportStatsStream(self, request_iterator, context):
        _ = context
        count = 0
        for req in request_iterator:
            _ = self.ReportStats(req, context=None)
            count += 1
        pb2, _ = load_generated()
        return pb2.ReportStatsResponse(received=(count > 0))

    def AbortJob(self, request, context):
        if not self._tenant_guard(context):
            pb2, _ = load_generated()
            return pb2.AbortJobResponse(aborted=False, workers_notified=0)
        _ = request
        with self._workers_lock:
            n = len(self.workers)
            for rec in self.workers.values():
                rec["state"] = "idle"
                rec["active_shard_id"] = ""
        pb2, _ = load_generated()
        return pb2.AbortJobResponse(aborted=True, workers_notified=n)

    def GetWorkerStatus(self, request, context):
        if not self._tenant_guard(context, worker_id=str(request.worker_id)):
            pb2, _ = load_generated()
            return pb2.GetWorkerStatusResponse(
                worker_id=str(request.worker_id),
                state="forbidden",
                active_shard_id="",
                stats_json=b"{}",
                last_heartbeat_ms=0,
            )
        wid = str(request.worker_id)
        with self._workers_lock:
            rec = dict(self.workers.get(wid) or {})
        pb2, _ = load_generated()
        if not rec:
            return pb2.GetWorkerStatusResponse(
                worker_id=wid,
                state="disconnected",
                active_shard_id="",
                stats_json=b"{}",
                last_heartbeat_ms=0,
            )
        return pb2.GetWorkerStatusResponse(
            worker_id=wid,
            state=str(rec.get("state", "idle")),
            active_shard_id=str(rec.get("active_shard_id", "")),
            stats_json=bytes(rec.get("stats_json", b"{}")),
            last_heartbeat_ms=int(rec.get("last_heartbeat_ms", 0) or 0),
        )

    def ForceSync(self, request, context):
        if not self._tenant_guard(context, worker_id=str(request.worker_id)):
            pb2, _ = load_generated()
            return pb2.ForceSyncResponse(stats_json=b"{}", logs_json=b"[]")
        wid = str(request.worker_id)
        with self._workers_lock:
            rec = dict(self.workers.get(wid) or {})
        pb2, _ = load_generated()
        return pb2.ForceSyncResponse(
            stats_json=bytes(rec.get("stats_json", b"{}")),
            logs_json=b"[]",
        )


class MasterControlServer:
    def __init__(
        self,
        listen_addr: str,
        cluster_secret: str = "",
        insecure: bool = False,
        tls_cert: str = "",
        tls_key: str = "",
        tls_client_ca: str = "",
        require_client_auth: bool = False,
        max_workers: int = 16,
        rbac_enabled: bool = False,
        rbac_role_secrets: dict[str, str] | None = None,
        rbac_default_role: str = "viewer",
        tenant_namespace: str = "",
        jwt_secret: str = "",
        jwt_role_claim: str = "role",
        jwt_tenant_claim: str = "tenant_namespace",
        rbac_audit_log_path: str = "",
        rbac_audit_log_success: bool = False,
        tls_watch_files: bool = True,
        tls_reload_interval_s: float = 2.0,
    ) -> None:
        require_distributed()
        self.listen_addr = str(listen_addr)
        self.cluster_secret = str(cluster_secret or "")
        self.insecure = bool(insecure)
        self.tls_cert = str(tls_cert or "")
        self.tls_key = str(tls_key or "")
        self.tls_client_ca = str(tls_client_ca or "")
        self.require_client_auth = bool(require_client_auth)
        self.max_workers = max(4, int(max_workers or 16))
        self.rbac_enabled = bool(rbac_enabled)
        self.rbac_role_secrets = dict(rbac_role_secrets or {})
        self.rbac_default_role = str(rbac_default_role or "viewer").strip().lower() or "viewer"
        self.tenant_namespace = str(tenant_namespace or "").strip()
        self.jwt_secret = str(jwt_secret or "").strip()
        self.jwt_role_claim = str(jwt_role_claim or "role").strip() or "role"
        self.jwt_tenant_claim = str(jwt_tenant_claim or "tenant_namespace").strip() or "tenant_namespace"
        self.rbac_audit_log_path = str(rbac_audit_log_path or "").strip()
        self.rbac_audit_log_success = bool(rbac_audit_log_success)
        self.tls_watch_files = bool(tls_watch_files)
        self.tls_reload_interval_s = max(0.5, float(tls_reload_interval_s or 2.0))
        self.running = False
        self._server = None
        self._server_lock = threading.Lock()
        self._tls_watch_thread = None
        self._tls_watch_stop = threading.Event()
        self._tls_mtime = (0.0, 0.0, 0.0)
        self._audit_lock = threading.Lock()
        self._audit_prev_hash = ""
        self._servicer = _SamuraiServicer(
            tenant_namespace=self.tenant_namespace,
            jwt_secret=self.jwt_secret,
            jwt_tenant_claim=self.jwt_tenant_claim,
        )
        self._audit_prev_hash = self._load_last_audit_hash()

    @staticmethod
    def _file_mtime(path: str) -> float:
        p = str(path or "").strip()
        if not p:
            return 0.0
        try:
            return float(os.path.getmtime(p))
        except OSError:
            return 0.0

    def _current_tls_mtime(self) -> tuple[float, float, float]:
        return (
            self._file_mtime(self.tls_cert),
            self._file_mtime(self.tls_key),
            self._file_mtime(self.tls_client_ca),
        )

    def _append_rbac_audit(self, item: dict) -> None:
        path = str(self.rbac_audit_log_path or "").strip()
        if not path:
            return
        row = dict(item or {})
        row["schema"] = "samurai.rbac.audit.v1"
        with self._audit_lock:
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            row["prev_hash"] = str(self._audit_prev_hash or "")
            row_no_hash = dict(row)
            line_no_hash = json.dumps(row_no_hash, ensure_ascii=True, sort_keys=True)
            row_hash = hashlib.sha256(line_no_hash.encode("utf-8")).hexdigest()
            row["entry_hash"] = row_hash
            line = json.dumps(row, ensure_ascii=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            self._audit_prev_hash = row_hash

    def _load_last_audit_hash(self) -> str:
        path = str(self.rbac_audit_log_path or "").strip()
        if not path or not os.path.isfile(path):
            return ""
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = [ln.strip() for ln in f.readlines() if ln.strip()]
            if not lines:
                return ""
            last = json.loads(lines[-1])
            return str((dict(last or {})).get("entry_hash", "") or "")
        except Exception:
            return ""

    @staticmethod
    def verify_rbac_audit_chain(path: str) -> tuple[bool, str]:
        p = str(path or "").strip()
        if not p:
            return False, "empty path"
        if not os.path.isfile(p):
            return False, "file not found"
        prev = ""
        try:
            with open(p, "r", encoding="utf-8") as f:
                for lineno, raw in enumerate(f, start=1):
                    txt = str(raw or "").strip()
                    if not txt:
                        continue
                    rec = json.loads(txt)
                    if not isinstance(rec, dict):
                        return False, f"line {lineno}: invalid json object"
                    got_prev = str(rec.get("prev_hash", "") or "")
                    if got_prev != prev:
                        return False, f"line {lineno}: prev_hash mismatch"
                    got_hash = str(rec.get("entry_hash", "") or "")
                    if not got_hash:
                        return False, f"line {lineno}: missing entry_hash"
                    data = dict(rec)
                    data.pop("entry_hash", None)
                    calc = hashlib.sha256(
                        json.dumps(data, ensure_ascii=True, sort_keys=True).encode("utf-8")
                    ).hexdigest()
                    if calc != got_hash:
                        return False, f"line {lineno}: entry_hash mismatch"
                    prev = got_hash
        except json.JSONDecodeError as exc:
            return False, f"json decode error: {exc}"
        except OSError as exc:
            return False, f"io error: {exc}"
        return True, "ok"

    def _build_grpc_server(self):
        import grpc

        _, pb2_grpc = load_generated()
        interceptor = _SecretServerInterceptor(
            self.cluster_secret,
            rbac_enabled=self.rbac_enabled,
            role_secrets=self.rbac_role_secrets,
            default_role=self.rbac_default_role,
            jwt_secret=self.jwt_secret,
            jwt_role_claim=self.jwt_role_claim,
            audit_logger=self._append_rbac_audit,
            audit_success=self.rbac_audit_log_success,
        )
        srv = grpc.server(
            futures.ThreadPoolExecutor(max_workers=self.max_workers),
            interceptors=[interceptor],
        )
        pb2_grpc.add_SamuraiControlServicer_to_server(self._servicer, srv)
        # Custom stream-unary endpoint for high-rate stats ingestion.
        pb2, _ = load_generated()
        stream_handlers = {
            "ReportStatsStream": grpc.stream_unary_rpc_method_handler(
                self._servicer.ReportStatsStream,
                request_deserializer=pb2.ReportStatsRequest.FromString,
                response_serializer=pb2.ReportStatsResponse.SerializeToString,
            )
        }
        stream_handler = grpc.method_handlers_generic_handler(
            "samurai.control.v1.SamuraiControl",
            stream_handlers,
        )
        srv.add_generic_rpc_handlers((stream_handler,))
        try:
            from grpc_health.v1 import health, health_pb2
            from grpc_health.v1 import health_pb2_grpc

            hs = health.HealthServicer()
            hs.set("", health_pb2.HealthCheckResponse.SERVING)
            hs.set("samurai.control.v1.SamuraiControl", health_pb2.HealthCheckResponse.SERVING)
            health_pb2_grpc.add_HealthServicer_to_server(hs, srv)
        except Exception:
            # Health service is optional; server remains functional without it.
            pass
        if self.insecure:
            srv.add_insecure_port(self.listen_addr)
        else:
            creds = load_tls_server_credentials(
                self.tls_cert,
                self.tls_key,
                client_ca_path=self.tls_client_ca,
                require_client_auth=self.require_client_auth,
            )
            srv.add_secure_port(self.listen_addr, creds)
        return srv

    def _restart_tls_server(self) -> bool:
        if self.insecure:
            return False
        try:
            _ = load_tls_server_credentials(
                self.tls_cert,
                self.tls_key,
                client_ca_path=self.tls_client_ca,
                require_client_auth=self.require_client_auth,
            )
        except Exception:
            return False
        with self._server_lock:
            old = self._server
            if old is not None:
                old.stop(0.5)
            new_srv = self._build_grpc_server()
            new_srv.start()
            self._server = new_srv
            self._tls_mtime = self._current_tls_mtime()
        return True

    def _tls_watcher_loop(self) -> None:
        while not self._tls_watch_stop.wait(self.tls_reload_interval_s):
            if not self.running or self.insecure:
                continue
            now_mtime = self._current_tls_mtime()
            if now_mtime != self._tls_mtime:
                _ = self._restart_tls_server()

    def _start_tls_watcher(self) -> None:
        if self.insecure or not self.tls_watch_files:
            return
        self._tls_watch_stop.clear()
        self._tls_mtime = self._current_tls_mtime()
        th = threading.Thread(target=self._tls_watcher_loop, daemon=True, name="MasterTLSWatch")
        self._tls_watch_thread = th
        th.start()

    def _stop_tls_watcher(self) -> None:
        self._tls_watch_stop.set()
        th = self._tls_watch_thread
        if th is not None:
            th.join(timeout=2.0)
        self._tls_watch_thread = None

    def start(self) -> None:
        with self._server_lock:
            self._server = self._build_grpc_server()
            self._server.start()
        self.running = True
        self._start_tls_watcher()

    def stop(self, grace: float = 0.0) -> None:
        self._stop_tls_watcher()
        with self._server_lock:
            if self._server is not None:
                self._server.stop(grace)
                self._server = None
        self.running = False

    @property
    def servicer(self):
        return self._servicer
