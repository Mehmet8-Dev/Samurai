"""Slave gRPC client skeleton for distributed control plane."""

from __future__ import annotations

import json

from . import require_distributed
from .auth import client_call_credentials, load_tls_client_credentials, split_endpoints
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
        if not self.endpoints:
            raise ValueError("no control endpoints configured")
        target = self.endpoints[0]
        if self.insecure:
            self._channel = grpc.insecure_channel(target)
        else:
            chan_creds = load_tls_client_credentials(self.tls_ca)
            if self.cluster_secret:
                call_creds = client_call_credentials(self.cluster_secret)
                creds = grpc.composite_channel_credentials(chan_creds, call_creds)
            else:
                creds = chan_creds
            self._channel = grpc.secure_channel(target, creds)
        _, pb2_grpc = load_generated()
        self._stub = pb2_grpc.SamuraiControlStub(self._channel)

    def register_worker(self, worker_id: str, hostname: str, capabilities: dict[str, str]) -> dict:
        pb2, _ = load_generated()
        resp = self._stub.RegisterWorker(
            pb2.RegisterWorkerRequest(
                worker_id=str(worker_id),
                hostname=str(hostname),
                capabilities=dict(capabilities or {}),
            )
        )
        return {"accepted": bool(resp.accepted), "cluster_id": str(resp.cluster_id), "rejection_reason": str(resp.rejection_reason)}

    def heartbeat(self, worker_id: str, uptime_ms: int, cpu_pct: float = 0.0, mem_pct: float = 0.0, gpu_util_pct: float = 0.0) -> dict:
        pb2, _ = load_generated()
        resp = self._stub.Heartbeat(
            pb2.HeartbeatRequest(
                worker_id=str(worker_id),
                uptime_ms=int(uptime_ms),
                cpu_pct=float(cpu_pct),
                mem_pct=float(mem_pct),
                gpu_util_pct=float(gpu_util_pct),
            )
        )
        return {"acknowledged": bool(resp.acknowledged), "command": str(resp.command)}

    def report_stats(self, worker_id: str, shard_id: str, stats: dict, timestamp_ms: int) -> bool:
        pb2, _ = load_generated()
        resp = self._stub.ReportStats(
            pb2.ReportStatsRequest(
                worker_id=str(worker_id),
                shard_id=str(shard_id),
                stats_json=json.dumps(stats or {}, ensure_ascii=True).encode("utf-8"),
                timestamp_ms=int(timestamp_ms),
            )
        )
        return bool(resp.received)
