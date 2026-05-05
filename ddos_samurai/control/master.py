"""Distributed master entry point."""

from __future__ import annotations

import json
import time

from .. import utils
from .client import WorkerControlClient
from .discovery import EndpointDiscovery
from .server import MasterControlServer
from .shard import split_job_to_shards
from .telemetry import DistributedAggregator


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

    discovery = EndpointDiscovery(
        manual_endpoints=str(getattr(args, "control_endpoints", "")),
        prefer_k8s=bool(getattr(args, "control_discovery_k8s", False)),
        k8s_namespace=str(getattr(args, "control_k8s_namespace", "default")),
        k8s_selector=str(getattr(args, "control_k8s_selector", "")),
        k8s_port=int(getattr(args, "control_k8s_port", 5099) or 5099),
    )
    discovered = discovery.resolve_with_fallback()
    expected_workers = max(1, len(discovered)) if discovered else 1
    if discovered:
        utils.log_info(f"Discovered worker endpoints: {discovered}")

    wait_workers_s = 30
    worker_deadline = time.time() + float(wait_workers_s)
    while time.time() < worker_deadline and len(server.servicer.workers) < expected_workers:
        time.sleep(0.5)
    worker_ids = sorted(list(server.servicer.workers.keys()))
    if not worker_ids:
        utils.log_warning("No slave registered; master exits without dispatch.")
        server.stop(0.0)
        return 1

    total_count = int(getattr(args, "count", 0) or 0)
    shard_strategy = str(getattr(args, "shard_strategy", "equal") or "equal").strip().lower()
    worker_caps = {
        str(wid): dict(rec.get("capabilities") or {})
        for wid, rec in dict(server.servicer.workers).items()
    }
    shards = split_job_to_shards(
        total_count,
        worker_ids,
        strategy=shard_strategy,
        worker_capabilities=worker_caps,
    )
    job_id = f"job-{int(time.time())}"
    timeout_ms = int(getattr(args, "job_timeout_s", 0) or 0) * 1000
    dispatch_failures = []
    for shard in shards:
        wid = str(shard["worker_id"])
        sid = str(shard["shard_id"])
        shard_args = dict(vars(args))
        shard_args["count"] = int(shard["packet_count"])
        shard_args["role"] = "standalone"
        shard_args["_worker_id"] = wid
        direct_sent = False
        try:
            wrec = dict(server.servicer.workers.get(wid) or {})
            caps = dict(wrec.get("capabilities") or {})
            ep = str(caps.get("control_endpoint", "") or "").strip()
            if ep:
                wc = WorkerControlClient(
                    endpoint=ep,
                    cluster_secret=str(getattr(args, "cluster_secret", "")),
                    insecure=bool(getattr(args, "control_insecure", False)),
                    tls_ca=str(getattr(args, "control_tls_ca", "")),
                )
                resp = wc.start_shard(
                    shard_id=sid,
                    job_id=job_id,
                    args_json=json.dumps(shard_args, ensure_ascii=True).encode("utf-8"),
                    packet_count=int(shard["packet_count"]),
                    timeout_ms=timeout_ms,
                )
                direct_sent = bool(resp.get("started", False))
                if not direct_sent:
                    dispatch_failures.append(
                        f"E_STARTSHARD_REJECTED worker={wid} shard={sid} endpoint={ep} error={resp.get('error','')}"
                    )
        except Exception as exc:
            dispatch_failures.append(f"E_STARTSHARD_RPC worker={wid} shard={sid} error={str(exc)}")
            direct_sent = False
        if not direct_sent:
            last = dispatch_failures[-1] if dispatch_failures else f"E_STARTSHARD_UNKNOWN worker={wid} shard={sid}"
            utils.log_critical(f"Direct StartShard RPC failed; aborting job. {last}")
            server.stop(0.0)
            return 1
        utils.log_info(f"Dispatched shard {sid} -> {wid} count={int(shard['packet_count'])} (direct StartShard RPC)")

    timeout_s = int(getattr(args, "job_timeout_s", 0) or 0)
    wait_s = timeout_s if timeout_s > 0 else 120
    hb_timeout_ms = int(getattr(args, "heartbeat_timeout_ms", 6000) or 6000)
    on_worker_loss = str(getattr(args, "on_worker_loss", "continue") or "continue").strip().lower()
    deadline = time.time() + float(wait_s)
    lost_workers = set()
    while time.time() < deadline:
        now_ms = int(time.time() * 1000)
        for wid, rec in dict(server.servicer.workers).items():
            last_hb = int(rec.get("last_heartbeat_ms", 0) or 0)
            if last_hb > 0 and (now_ms - last_hb) > hb_timeout_ms:
                lost_workers.add(str(wid))
        if lost_workers and on_worker_loss == "abort":
            utils.log_critical(f"Worker kaybı algılandı ({sorted(lost_workers)}), job abort ediliyor.")
            for shard in shards:
                wid = str(shard["worker_id"])
                sid = str(shard["shard_id"])
                try:
                    wrec = dict(server.servicer.workers.get(wid) or {})
                    caps = dict(wrec.get("capabilities") or {})
                    ep = str(caps.get("control_endpoint", "") or "").strip()
                    if ep:
                        wc = WorkerControlClient(
                            endpoint=ep,
                            cluster_secret=str(getattr(args, "cluster_secret", "")),
                            insecure=bool(getattr(args, "control_insecure", False)),
                            tls_ca=str(getattr(args, "control_tls_ca", "")),
                        )
                        _ = wc.stop_shard(shard_id=sid, graceful=False)
                except Exception:
                    pass
            server.stop(0.0)
            return 1
        if len(server.servicer.shard_stats) >= len(shards):
            break
        time.sleep(1.0)

    for shard in shards:
        wid = str(shard["worker_id"])
        sid = str(shard["shard_id"])
        stopped = False
        try:
            wrec = dict(server.servicer.workers.get(wid) or {})
            caps = dict(wrec.get("capabilities") or {})
            ep = str(caps.get("control_endpoint", "") or "").strip()
            if ep:
                wc = WorkerControlClient(
                    endpoint=ep,
                    cluster_secret=str(getattr(args, "cluster_secret", "")),
                    insecure=bool(getattr(args, "control_insecure", False)),
                    tls_ca=str(getattr(args, "control_tls_ca", "")),
                )
                stopped = wc.stop_shard(shard_id=sid, graceful=True)
        except Exception:
            stopped = False
        if not stopped:
            utils.log_warning(f"E_STOPSHARD_FAILED worker={wid} shard={sid}")

    aggregator = DistributedAggregator()
    for sid, blob in dict(server.servicer.shard_stats).items():
        try:
            item = json.loads(bytes(blob).decode("utf-8"))
            if "shard_id" not in item:
                item["shard_id"] = sid
            aggregator.add(item)
        except (ValueError, TypeError, UnicodeDecodeError):
            utils.log_warning(f"Shard stats decode failed: {sid}")
    for _ in range(2):
        time.sleep(1.0)
    agg = aggregator.snapshot()
    snapshot = {
        "workers": len(server.servicer.workers),
        "shards_reported": len(server.servicer.shard_stats),
        "lost_workers": sorted(lost_workers),
        "dispatch_failures": list(dispatch_failures),
        "sent": int(agg.get("sent", 0) or 0),
        "errors": int(agg.get("errors", 0) or 0),
        "worker_ids": list(agg.get("worker_ids", [])),
        "shard_ids": list(agg.get("shard_ids", [])),
    }
    utils.log_info(f"Distributed master summary: {snapshot}")
    server.stop(0.0)
    return 0
