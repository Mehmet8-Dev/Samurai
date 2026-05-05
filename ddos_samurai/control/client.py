"""Slave gRPC client skeleton for distributed control plane."""

from __future__ import annotations

import json

from . import require_distributed
from .auth import build_cluster_metadata, client_call_credentials, load_tls_client_credentials, split_endpoints
from .proto import load_generated


class SlaveControlClient:
    def __init__(
        self,
        endpoints: str,
        cluster_secret: str = "",
        insecure: bool = False,
        tls_ca: str = "",
    ) -> None:
        require_distributed()
        import grpc

        self.endpoints = split_endpoints(endpoints)
        self.cluster_secret = str(cluster_secret or "")
        self.insecure = bool(insecure)
        self.tls_ca = str(tls_ca or "")
        self._grpc = grpc
        if not self.endpoints:
            raise ValueError("no control endpoints configured")
        self._channels = {}
        self._stubs = {}
        self._last_endpoint_idx = 0
        _, pb2_grpc = load_generated()
        self._stub_cls = pb2_grpc.SamuraiControlStub
        for ep in self.endpoints:
            ch = self._build_channel(ep)
            self._channels[ep] = ch
            self._stubs[ep] = self._stub_cls(ch)

    def _build_channel(self, endpoint: str):
        grpc = self._grpc
        if self.insecure:
            return grpc.insecure_channel(endpoint)
        chan_creds = load_tls_client_credentials(self.tls_ca)
        if self.cluster_secret:
            call_creds = client_call_credentials(self.cluster_secret)
            creds = grpc.composite_channel_credentials(chan_creds, call_creds)
        else:
            creds = chan_creds
        return grpc.secure_channel(endpoint, creds)

    def _iter_endpoints_for_try(self):
        n = len(self.endpoints)
        if n == 0:
            return []
        start = self._last_endpoint_idx % n
        return [self.endpoints[(start + i) % n] for i in range(n)]

    def _call_with_retry(self, fn_name: str, request):
        last_err = None
        metadata = build_cluster_metadata(self.cluster_secret)
        for idx, ep in enumerate(self._iter_endpoints_for_try()):
            stub = self._stubs[ep]
            fn = getattr(stub, fn_name)
            try:
                resp = fn(request, timeout=3.0, metadata=metadata)
                self._last_endpoint_idx = (self._last_endpoint_idx + idx) % max(1, len(self.endpoints))
                return resp
            except self._grpc.RpcError as exc:
                last_err = exc
                continue
        if last_err is not None:
            raise last_err
        raise RuntimeError("no endpoint available")

    def register_worker(self, worker_id: str, hostname: str, capabilities: dict[str, str]) -> dict:
        pb2, _ = load_generated()
        resp = self._call_with_retry(
            "RegisterWorker",
            pb2.RegisterWorkerRequest(
                worker_id=str(worker_id),
                hostname=str(hostname),
                capabilities=dict(capabilities or {}),
            ),
        )
        return {"accepted": bool(resp.accepted), "cluster_id": str(resp.cluster_id), "rejection_reason": str(resp.rejection_reason)}

    def heartbeat(self, worker_id: str, uptime_ms: int, cpu_pct: float = 0.0, mem_pct: float = 0.0, gpu_util_pct: float = 0.0) -> dict:
        pb2, _ = load_generated()
        resp = self._call_with_retry(
            "Heartbeat",
            pb2.HeartbeatRequest(
                worker_id=str(worker_id),
                uptime_ms=int(uptime_ms),
                cpu_pct=float(cpu_pct),
                mem_pct=float(mem_pct),
                gpu_util_pct=float(gpu_util_pct),
            ),
        )
        return {"acknowledged": bool(resp.acknowledged), "command": str(resp.command)}

    def report_stats(self, worker_id: str, shard_id: str, stats: dict, timestamp_ms: int) -> bool:
        pb2, _ = load_generated()
        resp = self._call_with_retry(
            "ReportStats",
            pb2.ReportStatsRequest(
                worker_id=str(worker_id),
                shard_id=str(shard_id),
                stats_json=json.dumps(stats or {}, ensure_ascii=True).encode("utf-8"),
                timestamp_ms=int(timestamp_ms),
            ),
        )
        return bool(resp.received)


class WorkerControlClient:
    """Master-side RPC client used to control a worker endpoint directly."""

    def __init__(self, endpoint: str, cluster_secret: str = "", insecure: bool = False, tls_ca: str = "") -> None:
        require_distributed()
        import grpc

        self.endpoint = str(endpoint or "").strip()
        self.cluster_secret = str(cluster_secret or "")
        self.insecure = bool(insecure)
        self.tls_ca = str(tls_ca or "")
        if not self.endpoint:
            raise ValueError("worker endpoint is empty")
        if self.insecure:
            ch = grpc.insecure_channel(self.endpoint)
        else:
            chan_creds = load_tls_client_credentials(self.tls_ca)
            if self.cluster_secret:
                call_creds = client_call_credentials(self.cluster_secret)
                creds = grpc.composite_channel_credentials(chan_creds, call_creds)
            else:
                creds = chan_creds
            ch = grpc.secure_channel(self.endpoint, creds)
        self._grpc = grpc
        self._channel = ch
        pb2, pb2_grpc = load_generated()
        self._pb2 = pb2
        self._stub = pb2_grpc.SamuraiControlStub(ch)

    def start_shard(self, shard_id: str, job_id: str, args_json: bytes, packet_count: int, timeout_ms: int) -> dict:
        req = self._pb2.StartShardRequest(
            shard_id=str(shard_id),
            job_id=str(job_id),
            args_json=bytes(args_json or b"{}"),
            packet_count=int(packet_count or 0),
            timeout_ms=int(timeout_ms or 0),
        )
        md = build_cluster_metadata(self.cluster_secret)
        try:
            resp = self._stub.StartShard(req, timeout=5.0, metadata=md)
        except self._grpc.RpcError as exc:
            code = str(exc.code().name if hasattr(exc, "code") else "RPC_ERROR")
            details = str(exc.details() if hasattr(exc, "details") else str(exc))
            raise RuntimeError(
                f"E_RPC_STARTSHARD endpoint={self.endpoint} code={code} details={details}"
            ) from exc
        return {"started": bool(resp.started), "error": str(resp.error or "")}

    def stop_shard(self, shard_id: str, graceful: bool = True) -> bool:
        req = self._pb2.StopShardRequest(shard_id=str(shard_id), graceful=bool(graceful))
        md = build_cluster_metadata(self.cluster_secret)
        try:
            resp = self._stub.StopShard(req, timeout=3.0, metadata=md)
        except self._grpc.RpcError as exc:
            code = str(exc.code().name if hasattr(exc, "code") else "RPC_ERROR")
            details = str(exc.details() if hasattr(exc, "details") else str(exc))
            raise RuntimeError(
                f"E_RPC_STOPSHARD endpoint={self.endpoint} code={code} details={details}"
            ) from exc
        return bool(resp.stopped)
