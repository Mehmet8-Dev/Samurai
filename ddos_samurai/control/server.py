"""Master gRPC server skeleton for distributed control plane."""

from __future__ import annotations

from . import require_distributed


class MasterControlServer:
    def __init__(self, listen_addr: str, cluster_secret: str = "") -> None:
        require_distributed()
        self.listen_addr = str(listen_addr)
        self.cluster_secret = str(cluster_secret or "")
        self.running = False

    def start(self) -> None:
        self.running = True

    def stop(self, grace: float = 0.0) -> None:
        _ = grace
        self.running = False
