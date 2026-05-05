"""Distributed master entry point."""

from __future__ import annotations

import json
import time

from .. import utils
from .server import MasterControlServer
from .shard import split_job_to_shards


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

    wait_workers_s = 30
    worker_deadline = time.time() + float(wait_workers_s)
    while time.time() < worker_deadline and len(server.servicer.workers) == 0:
        time.sleep(0.5)
    worker_ids = sorted(list(server.servicer.workers.keys()))
    if not worker_ids:
        utils.log_warning("No slave registered; master exits without dispatch.")
        server.stop(0.0)
        return 1

    total_count = int(getattr(args, "count", 0) or 0)
    shards = split_job_to_shards(total_count, worker_ids)
    job_id = f"job-{int(time.time())}"
    timeout_ms = int(getattr(args, "job_timeout_s", 0) or 0) * 1000
    for shard in shards:
        wid = str(shard["worker_id"])
        sid = str(shard["shard_id"])
        shard_args = dict(vars(args))
        shard_args["count"] = int(shard["packet_count"])
        shard_args["role"] = "standalone"
        shard_args["_worker_id"] = wid
        server.servicer.queue_start_shard(
            worker_id=wid,
            shard_id=sid,
            job_id=job_id,
            args_dict=shard_args,
            packet_count=int(shard["packet_count"]),
            timeout_ms=timeout_ms,
        )
        utils.log_info(f"Queued shard {sid} -> {wid} count={int(shard['packet_count'])}")

    timeout_s = int(getattr(args, "job_timeout_s", 0) or 0)
    wait_s = timeout_s if timeout_s > 0 else 120
    deadline = time.time() + float(wait_s)
    while time.time() < deadline:
        if len(server.servicer.shard_stats) >= len(shards):
            break
        time.sleep(1.0)

    for shard in shards:
        wid = str(shard["worker_id"])
        server.servicer.queue_stop_shard(wid, graceful=True)

    agg_sent = 0
    agg_errors = 0
    for sid, blob in dict(server.servicer.shard_stats).items():
        try:
            item = json.loads(bytes(blob).decode("utf-8"))
            agg_sent += int(item.get("sent", 0) or 0)
            agg_errors += int(item.get("errors", 0) or 0)
        except (ValueError, TypeError, UnicodeDecodeError):
            utils.log_warning(f"Shard stats decode failed: {sid}")
    for _ in range(2):
        time.sleep(1.0)
    snapshot = {
        "workers": len(server.servicer.workers),
        "shards_reported": len(server.servicer.shard_stats),
        "sent": agg_sent,
        "errors": agg_errors,
    }
    utils.log_info(f"Distributed master summary: {snapshot}")
    server.stop(0.0)
    return 0
