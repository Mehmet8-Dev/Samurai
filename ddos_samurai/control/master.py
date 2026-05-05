"""Distributed master entry point."""

from __future__ import annotations

import time

from .. import utils
from .server import MasterControlServer


def run_distributed_master(args, parser, report_ctx, runtime_ctx) -> int:
    _ = parser
    _ = report_ctx
    _ = runtime_ctx
    server = MasterControlServer(
        listen_addr=str(getattr(args, "control_listen", "0.0.0.0:5099")),
        cluster_secret=str(getattr(args, "cluster_secret", "")),
        insecure=bool(getattr(args, "control_insecure", False)),
        tls_cert=str(getattr(args, "control_tls_cert", "")),
        tls_key=str(getattr(args, "control_tls_key", "")),
    )
    try:
        server.start()
    except Exception as exc:
        utils.log_critical(f"Distributed master başlatılamadı: {exc}")
        return 1
    utils.log_info(f"Distributed master started on {server.listen_addr}.")

    timeout_s = int(getattr(args, "job_timeout_s", 0) or 0)
    wait_s = timeout_s if timeout_s > 0 else 10
    deadline = time.time() + float(wait_s)
    last_workers = -1
    while time.time() < deadline:
        workers = len(server.servicer.workers)
        if workers != last_workers:
            utils.log_info(f"Registered workers: {workers}")
            last_workers = workers
        time.sleep(1.0)
    snapshot = {
        "workers": len(server.servicer.workers),
        "shards_reported": len(server.servicer.shard_stats),
    }
    utils.log_info(f"Distributed master summary: {snapshot}")
    server.stop(0.0)
    return 0
