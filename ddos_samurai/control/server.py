"""Master gRPC server skeleton for distributed control plane."""

from __future__ import annotations

import json
import threading
import time
import base64
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
        self.lock = threading.Lock()
        self.workers = {}
        self.shard_stats = {}
        self._pending_commands = {}

    def RegisterWorker(self, request, context):
        _ = context
        with self.lock:
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
        command = "continue"
        with self.lock:
            wid = str(request.worker_id)
            if wid in self.workers:
                self.workers[wid]["last_heartbeat_ms"] = int(time.time() * 1000)
            pending = self._pending_commands.pop(wid, None)
            if pending:
                command = str(pending)
        pb2, _ = load_generated()
        return pb2.HeartbeatResponse(acknowledged=True, command=command)

    def StartShard(self, request, context):
        _ = context
        wid = ""
        try:
            payload = json.loads(bytes(request.args_json or b"{}").decode("utf-8"))
            wid = str(payload.get("_worker_id", "") or "")
        except (ValueError, TypeError, UnicodeDecodeError):
            pass
        with self.lock:
            if wid and wid in self.workers:
                self.workers[wid]["state"] = "running"
                self.workers[wid]["active_shard_id"] = str(request.shard_id)
        pb2, _ = load_generated()
        return pb2.StartShardResponse(started=True, error="")

    def StopShard(self, request, context):
        _ = context
        sid = str(request.shard_id)
        with self.lock:
            for rec in self.workers.values():
                if str(rec.get("active_shard_id", "")) == sid:
                    rec["state"] = "idle"
                    rec["active_shard_id"] = ""
        pb2, _ = load_generated()
        return pb2.StopShardResponse(stopped=True)

    def ReportStats(self, request, context):
        _ = context
        with self.lock:
            self.shard_stats[str(request.shard_id)] = bytes(request.stats_json or b"{}")
            wid = str(request.worker_id)
            if wid in self.workers:
                self.workers[wid]["stats_json"] = bytes(request.stats_json or b"{}")
        pb2, _ = load_generated()
        return pb2.ReportStatsResponse(received=True)

    def AbortJob(self, request, context):
        _ = context
        _ = request
        with self.lock:
            n = len(self.workers)
            for rec in self.workers.values():
                rec["state"] = "idle"
                rec["active_shard_id"] = ""
        pb2, _ = load_generated()
        return pb2.AbortJobResponse(aborted=True, workers_notified=n)

    def GetWorkerStatus(self, request, context):
        _ = context
        wid = str(request.worker_id)
        with self.lock:
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
        with self.lock:
            rec = dict(self.workers.get(wid) or {})
        pb2, _ = load_generated()
        return pb2.ForceSyncResponse(
            stats_json=bytes(rec.get("stats_json", b"{}")),
            logs_json=b"[]",
        )

    def queue_start_shard(self, worker_id: str, shard_id: str, job_id: str, args_dict: dict, packet_count: int, timeout_ms: int) -> None:
        payload = {
            "shard_id": str(shard_id),
            "job_id": str(job_id),
            "args_dict": dict(args_dict or {}),
            "packet_count": int(packet_count or 0),
            "timeout_ms": int(timeout_ms or 0),
        }
        encoded = base64.b64encode(json.dumps(payload, ensure_ascii=True).encode("utf-8")).decode("ascii")
        with self.lock:
            self._pending_commands[str(worker_id)] = f"start:{encoded}"
            if str(worker_id) in self.workers:
                self.workers[str(worker_id)]["state"] = "running"
                self.workers[str(worker_id)]["active_shard_id"] = str(shard_id)

    def queue_stop_shard(self, worker_id: str, graceful: bool = True) -> None:
        cmd = "stop" if graceful else "abort"
        with self.lock:
            self._pending_commands[str(worker_id)] = cmd


class MasterControlServer:
    def __init__(self, listen_addr: str, cluster_secret: str = "", insecure: bool = False, tls_cert: str = "", tls_key: str = "") -> None:
        require_distributed()
        self.listen_addr = str(listen_addr)
        self.cluster_secret = str(cluster_secret or "")
        self.insecure = bool(insecure)
        self.tls_cert = str(tls_cert or "")
        self.tls_key = str(tls_key or "")
        self.running = False
        self._server = None
        self._servicer = _SamuraiServicer()

    def start(self) -> None:
        import grpc

        _, pb2_grpc = load_generated()
        interceptor = _SecretServerInterceptor(self.cluster_secret)
        self._server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=16),
            interceptors=[interceptor],
        )
        pb2_grpc.add_SamuraiControlServicer_to_server(self._servicer, self._server)
        if self.insecure:
            self._server.add_insecure_port(self.listen_addr)
        else:
            creds = load_tls_server_credentials(self.tls_cert, self.tls_key)
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
