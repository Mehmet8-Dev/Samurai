"""Distributed slave entry point."""

from __future__ import annotations

import json
import multiprocessing
import socket
import time
import base64

from .. import utils
from .. import orchestrator
from .client import SlaveControlClient


def _execute_shard_locally(shard_args_dict: dict, shard_id: str) -> dict:
    progress = multiprocessing.Value("L", 0)
    sent_total = multiprocessing.Value("L", 0)
    errors_total = multiprocessing.Value("L", 0)
    lock = multiprocessing.Lock()
    manager = multiprocessing.Manager()
    events = manager.list()
    resources = manager.dict()
    tls_profile = str(shard_args_dict.get("tls_profile", "none") or "none")

    proc = multiprocessing.Process(
        target=orchestrator.start_worker,
        args=(1, dict(shard_args_dict), progress, lock, tls_profile, events, sent_total, errors_total, resources),
        name=f"ShardWorker-{shard_id}",
    )
    started = time.time()
    proc.start()
    proc.join()
    duration_s = max(0.0, float(time.time() - started))
    return {
        "worker_id": socket.gethostname(),
        "shard_id": str(shard_id),
        "status": "ok" if int(proc.exitcode or 0) == 0 else "error",
        "exitcode": int(proc.exitcode or 0),
        "duration_s": duration_s,
        "progress": int(progress.value),
        "sent": int(sent_total.value),
        "errors": int(errors_total.value),
        "events": list(events),
    }


def run_distributed_slave(args, parser) -> int:
    _ = parser
    client = SlaveControlClient(
        endpoints=str(getattr(args, "control_endpoints", "")),
        cluster_secret=str(getattr(args, "cluster_secret", "")),
        insecure=bool(getattr(args, "control_insecure", False)),
        tls_ca=str(getattr(args, "control_tls_ca", "")),
    )
    capabilities = {
        "gpu_available": "unknown",
        "xdp_available": "unknown",
    }
    worker_id = socket.gethostname()
    reg = client.register_worker(
        worker_id=worker_id,
        hostname=worker_id,
        capabilities=capabilities,
    )
    if not bool(reg.get("accepted", False)):
        utils.log_critical(f"Master worker kaydını reddetti: {reg.get('rejection_reason', 'unknown')}")
        return 1
    utils.log_info(f"Distributed slave connected: endpoints={','.join(client.endpoints)}")

    # v1 live adapter: shard argumanlari local worker dict olarak verildiginde calistirir.
    shard_json = str(getattr(args, "distributed_shard_json", "") or "").strip()
    if shard_json:
        try:
            shard_payload = json.loads(shard_json)
        except (ValueError, TypeError) as exc:
            utils.log_critical(f"Shard payload parse hatası: {exc}")
            return 1
        shard_id = str(shard_payload.get("shard_id", "shard-1") or "shard-1")
        shard_args = dict(shard_payload.get("args_dict") or {})
        stats = _execute_shard_locally(shard_args, shard_id)
        client.report_stats(worker_id=worker_id, shard_id=shard_id, stats=stats, timestamp_ms=int(time.time() * 1000))
        utils.log_info(
            f"Shard completed: shard_id={shard_id} sent={int(stats.get('sent', 0))} "
            f"errors={int(stats.get('errors', 0))} exitcode={int(stats.get('exitcode', 0))}"
        )
        return 0 if int(stats.get("exitcode", 1) or 1) == 0 else 1

    # Master heartbeat command loop.
    hb_ms = int(getattr(args, "heartbeat_interval_ms", 2000) or 2000)
    boot = int(time.time() * 1000)
    run_forever = int(getattr(args, "job_timeout_s", 0) or 0) <= 0
    loops = 0
    while True:
        now = int(time.time() * 1000)
        hb = client.heartbeat(worker_id=worker_id, uptime_ms=max(0, now - boot))
        cmd = str(hb.get("command", "continue") or "continue")
        if cmd.startswith("start:"):
            enc = cmd.split(":", 1)[1]
            try:
                payload = json.loads(base64.b64decode(enc.encode("ascii")).decode("utf-8"))
            except (ValueError, TypeError, UnicodeDecodeError) as exc:
                utils.log_warning(f"Start command parse failed: {exc}")
                time.sleep(max(0.5, hb_ms / 1000.0))
                continue
            shard_id = str(payload.get("shard_id", "shard-1") or "shard-1")
            shard_args = dict(payload.get("args_dict") or {})
            stats = _execute_shard_locally(shard_args, shard_id)
            client.report_stats(worker_id=worker_id, shard_id=shard_id, stats=stats, timestamp_ms=int(time.time() * 1000))
            utils.log_info(
                f"Shard completed: shard_id={shard_id} sent={int(stats.get('sent', 0))} "
                f"errors={int(stats.get('errors', 0))} exitcode={int(stats.get('exitcode', 0))}"
            )
        if cmd in {"stop", "abort"}:
            utils.log_warning(f"Master command received: {cmd}")
            break
        loops += 1
        if not run_forever and loops >= max(3, int(getattr(args, "job_timeout_s", 0) or 0)):
            break
        time.sleep(max(0.5, hb_ms / 1000.0))
    return 0
