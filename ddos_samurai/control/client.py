"""Slave gRPC client skeleton for distributed control plane."""

from __future__ import annotations

from . import require_distributed
from .auth import split_endpoints


class SlaveControlClient:
    def __init__(self, endpoints: str, cluster_secret: str = "") -> None:
        require_distributed()
        self.endpoints = split_endpoints(endpoints)
        self.cluster_secret = str(cluster_secret or "")

    def register_worker(self, worker_id: str, hostname: str, capabilities: dict[str, str]) -> dict:
        return {
            "accepted": True,
            "worker_id": worker_id,
            "hostname": hostname,
            "capabilities": dict(capabilities or {}),
        }
