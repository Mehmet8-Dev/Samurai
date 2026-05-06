"""Master gRPC server skeleton for distributed control plane."""

from __future__ import annotations

import json
import threading
import time
from concurrent import futures

from . import require_distributed
from .auth import load_tls_server_credentials, validate_cluster_secret
from .proto import load_generated


class _SecretServerInterceptor:
    def __init__(self, expected_secret: str) -> None:
        self._expected = str(expected_secret or "").strip()

    def intercept_service(self, continuation, handler_call_details):
        handler = continuation(handler_call_details)
        if not self._expected or handler is None:
            return handler

        def _unauth(req, ctx):
            md = dict(ctx.invocation_metadata() or [])
            if not validate_cluster_secret(self._expected, md.get("x-cluster-secret")):
                ctx.abort(getattr(__import__("grpc"), "StatusCode").UNAUTHENTICATED, "invalid cluster secret")
            return handler.unary_unary(req, ctx)

        import grpc

        return grpc.unary_unary_rpc_method_handler(
            _unauth,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )


class _SamuraiServicer:
    def __init__(self, cluster_id: str = "cluster-v1") -> None:
        self.cluster_id = cluster_id
        self._workers_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self.workers = {}
        self.shard_stats = {}
        self._leader_epoch_min = 0

    def set_leader_epoch_min(self, epoch: int) -> None:
        self._leader_epoch_min = max(0, int(epoch or 0))

    def RegisterWorker(self, request, context):
        _ = context
        with self._workers_lock:
            self.workers[str(request.worker_id)] = {
                "worker_id": str(request.worker_id),
                "hostname": str(request.hostname),
                "capabilities": dict(request.capabilities or {}),
                "state": "idle",
                "active_shard_id": "",
                "last_heartbeat_ms": int(time.time() * 1000),
                "stats_json": b"{}",
            }
        pb2, _ = load_generated()
        return pb2.RegisterWorkerResponse(accepted=True, cluster_id=self.cluster_id, rejection_reason="")

    def Heartbeat(self, request, context):
        _ = context
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
        _ = context
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
        _ = context
        sid = str(request.shard_id)
        with self._workers_lock:
            for rec in self.workers.values():
                if str(rec.get("active_shard_id", "")) == sid:
                    rec["state"] = "idle"
                    rec["active_shard_id"] = ""
        pb2, _ = load_generated()
        return pb2.StopShardResponse(stopped=True)

    def ReportStats(self, request, context):
        _ = context
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
        _ = context
        _ = request
        with self._workers_lock:
            n = len(self.workers)
            for rec in self.workers.values():
                rec["state"] = "idle"
                rec["active_shard_id"] = ""
        pb2, _ = load_generated()
        return pb2.AbortJobResponse(aborted=True, workers_notified=n)

    def GetWorkerStatus(self, request, context):
        _ = context
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
        _ = context
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
        self.running = False
        self._server = None
        self._servicer = _SamuraiServicer()

    def start(self) -> None:
        import grpc

        _, pb2_grpc = load_generated()
        interceptor = _SecretServerInterceptor(self.cluster_secret)
        self._server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=self.max_workers),
            interceptors=[interceptor],
        )
        pb2_grpc.add_SamuraiControlServicer_to_server(self._servicer, self._server)
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
        self._server.add_generic_rpc_handlers((stream_handler,))
        try:
            from grpc_health.v1 import health, health_pb2
            from grpc_health.v1 import health_pb2_grpc

            hs = health.HealthServicer()
            hs.set("", health_pb2.HealthCheckResponse.SERVING)
            hs.set("samurai.control.v1.SamuraiControl", health_pb2.HealthCheckResponse.SERVING)
            health_pb2_grpc.add_HealthServicer_to_server(hs, self._server)
        except Exception:
            # Health service is optional; server remains functional without it.
            pass
        if self.insecure:
            self._server.add_insecure_port(self.listen_addr)
        else:
            creds = load_tls_server_credentials(
                self.tls_cert,
                self.tls_key,
                client_ca_path=self.tls_client_ca,
                require_client_auth=self.require_client_auth,
            )
            self._server.add_secure_port(self.listen_addr, creds)
        self._server.start()
        self.running = True

    def stop(self, grace: float = 0.0) -> None:
        if self._server is not None:
            self._server.stop(grace)
        self.running = False

    @property
    def servicer(self):
        return self._servicer
