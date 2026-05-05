"""Distributed slave entry point."""

from __future__ import annotations

import socket

from .. import utils
from .client import SlaveControlClient


def run_distributed_slave(args, parser) -> int:
    _ = parser
    client = SlaveControlClient(
        endpoints=str(getattr(args, "control_endpoints", "")),
        cluster_secret=str(getattr(args, "cluster_secret", "")),
    )
    capabilities = {
        "gpu_available": "unknown",
        "xdp_available": "unknown",
    }
    reg = client.register_worker(
        worker_id=socket.gethostname(),
        hostname=socket.gethostname(),
        capabilities=capabilities,
    )
    utils.log_info(
        "Distributed slave connected (skeleton mode). "
        f"accepted={bool(reg.get('accepted', False))} endpoints={','.join(client.endpoints)}"
    )
    return 0
