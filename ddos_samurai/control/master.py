"""Distributed master entry point."""

from __future__ import annotations

from .. import utils
from .server import MasterControlServer


def run_distributed_master(args, parser, report_ctx, runtime_ctx) -> int:
    _ = parser
    _ = report_ctx
    _ = runtime_ctx
    server = MasterControlServer(
        listen_addr=str(getattr(args, "control_listen", "0.0.0.0:5099")),
        cluster_secret=str(getattr(args, "cluster_secret", "")),
    )
    server.start()
    utils.log_info(f"Distributed master started on {server.listen_addr} (skeleton mode).")
    server.stop(0.0)
    return 0
