"""Distributed master entry point."""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

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

    control_max_workers = int(getattr(args, "control_max_workers", 0) or 0)
    if control_max_workers <= 0:
        control_max_workers = max(16, expected_workers + 8)
    server = MasterControlServer(
        listen_addr=str(getattr(args, "control_listen", "0.0.0.0:5099")),
        cluster_secret=str(getattr(args, "cluster_secret", "")),
        insecure=bool(getattr(args, "control_insecure", False)),
        tls_cert=str(getattr(args, "control_tls_cert", "")),
        tls_key=str(getattr(args, "control_tls_key", "")),
        max_workers=control_max_workers,
    )
    try:
        server.start()
    except Exception as exc:
        utils.log_critical(f"Distributed master başlatılamadı: {exc}")
        return 1
    utils.log_info(
        f"Distributed master started on {server.listen_addr}. "
        f"grpc_max_workers={int(control_max_workers)}"
    )

    wait_workers_s = int(getattr(args, "worker_registration_timeout_s", 30) or 30)
    wait_workers_s = max(1, wait_workers_s)
    worker_deadline = time.time() + float(wait_workers_s)
    while time.time() < worker_deadline and len(server.servicer.workers) < expected_workers:
        time.sleep(0.5)
    worker_ids = sorted(list(server.servicer.workers.keys()))
    if not worker_ids:
        utils.log_warning("No slave registered; master exits without dispatch.")
        server.stop(stop_grace_s)
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
    shard_args_by_sid = {}
    for shard in shards:
        wid = str(shard["worker_id"])
        sid = str(shard["shard_id"])
        shard_args = dict(vars(args))
        shard_args["count"] = int(shard["packet_count"])
        shard_args["role"] = "standalone"
        shard_args["_worker_id"] = wid
        shard_args_by_sid[sid] = shard_args

    def _dispatch_one(shard_item: dict) -> tuple[bool, str]:
        wid = str(shard_item["worker_id"])
        sid = str(shard_item["shard_id"])
        shard_args = dict(shard_args_by_sid.get(sid) or {})
        try:
            wrec = dict(server.servicer.workers.get(wid) or {})
            caps = dict(wrec.get("capabilities") or {})
            ep = str(caps.get("control_endpoint", "") or "").strip()
            if not ep:
                return False, f"E_STARTSHARD_NO_ENDPOINT worker={wid} shard={sid}"
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
                packet_count=int(shard_item["packet_count"]),
                timeout_ms=timeout_ms,
            )
            direct_sent = bool(resp.get("started", False))
            if not direct_sent:
                return (
                    False,
                    f"E_STARTSHARD_REJECTED worker={wid} shard={sid} endpoint={ep} "
                    f"error={resp.get('error', '')}",
                )
        except Exception as exc:
            return False, f"E_STARTSHARD_RPC worker={wid} shard={sid} error={str(exc)}"
        return True, (
            f"Dispatched shard {sid} -> {wid} count={int(shard_item['packet_count'])} "
            "(direct StartShard RPC)"
        )

    dispatch_pool = max(1, min(len(shards), int(getattr(args, "control_dispatch_workers", 32) or 32)))
    with ThreadPoolExecutor(max_workers=dispatch_pool) as pool:
        fut_map = {pool.submit(_dispatch_one, shard): shard for shard in shards}
        for fut in as_completed(fut_map):
            ok, msg = fut.result()
            if ok:
                utils.log_info(msg)
            else:
                dispatch_failures.append(msg)
    if dispatch_failures:
        for err in dispatch_failures:
            utils.log_warning(err)
        last = dispatch_failures[-1]
        utils.log_critical(f"Direct StartShard RPC failed; aborting job. {last}")
        server.stop(stop_grace_s)
        return 1

    timeout_s = int(getattr(args, "job_timeout_s", 0) or 0)
    wait_s = timeout_s if timeout_s > 0 else 120
    hb_timeout_ms = int(getattr(args, "heartbeat_timeout_ms", 6000) or 6000)
    poll_interval_s = max(0.05, float(getattr(args, "master_poll_interval_ms", 250) or 250) / 1000.0)
    worker_status_probe = bool(getattr(args, "worker_status_probe", True))
    on_worker_loss = str(getattr(args, "on_worker_loss", "continue") or "continue").strip().lower()
    deadline = time.time() + float(wait_s)
    lost_workers = set()
    done_shards = set()

    shard_to_worker = {str(s["shard_id"]): str(s["worker_id"]) for s in shards}

    def _endpoint_for_worker(worker_id: str) -> str:
        wrec = dict(server.servicer.workers.get(worker_id) or {})
        caps = dict(wrec.get("capabilities") or {})
        return str(caps.get("control_endpoint", "") or "").strip()

    while time.time() < deadline:
        now_ms = int(time.time() * 1000)
        for wid, rec in dict(server.servicer.workers).items():
            last_hb = int(rec.get("last_heartbeat_ms", 0) or 0)
            if last_hb > 0 and (now_ms - last_hb) > hb_timeout_ms:
                lost_workers.add(str(wid))
        if lost_workers and on_worker_loss == "abort":
            utils.log_critical(f"Worker kaybı algılandı ({sorted(lost_workers)}), job abort ediliyor.")
            stop_dispatches = []
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
                        stop_dispatches.append((wc, sid))
                except Exception:
                    pass
            for wc, sid in stop_dispatches:
                try:
                    _ = wc.stop_shard(shard_id=sid, graceful=False)
                except Exception:
                    pass
            server.stop(stop_grace_s)
            return 1
        if len(server.servicer.shard_stats) >= len(shards):
            break
        if worker_status_probe:
            for sid, wid in shard_to_worker.items():
                if sid in done_shards:
                    continue
                if sid in server.servicer.shard_stats:
                    done_shards.add(sid)
                    continue
                ep = _endpoint_for_worker(wid)
                if not ep:
                    continue
                try:
                    wc = WorkerControlClient(
                        endpoint=ep,
                        cluster_secret=str(getattr(args, "cluster_secret", "")),
                        insecure=bool(getattr(args, "control_insecure", False)),
                        tls_ca=str(getattr(args, "control_tls_ca", "")),
                    )
                    st = wc.get_worker_status(worker_id=wid)
                    state = str(st.get("state", "") or "").strip().lower()
                    active_sid = str(st.get("active_shard_id", "") or "").strip()
                    if state in {"done", "error"} and active_sid in {"", sid}:
                        stats_json = bytes(st.get("stats_json", b"{}") or b"{}")
                        if stats_json and stats_json != b"{}":
                            server.servicer.shard_stats[sid] = stats_json
                        done_shards.add(sid)
                except Exception:
                    continue
            if len(done_shards) >= len(shards):
                break
        time.sleep(poll_interval_s)

    def _stop_one(shard_item: dict) -> tuple[str, bool]:
        wid = str(shard_item["worker_id"])
        sid = str(shard_item["shard_id"])
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
                return sid, wc.stop_shard(shard_id=sid, graceful=True)
        except Exception:
            return sid, False
        return sid, False

    stop_pool = max(1, min(len(shards), int(getattr(args, "control_dispatch_workers", 32) or 32)))
    stop_retries = max(1, int(getattr(args, "stop_shard_retries", 3) or 3))
    stop_retry_delay_ms = max(10, int(getattr(args, "stop_shard_retry_delay_ms", 250) or 250))
    unresolved = set(str(s["shard_id"]) for s in shards)
    for attempt in range(stop_retries):
        targets = [s for s in shards if str(s["shard_id"]) in unresolved]
        if not targets:
            break
        with ThreadPoolExecutor(max_workers=stop_pool) as pool:
            fut_map = {pool.submit(_stop_one, shard): shard for shard in targets}
            for fut in as_completed(fut_map):
                sid, stopped = fut.result()
                if stopped:
                    unresolved.discard(sid)
        if unresolved:
            time.sleep(float(stop_retry_delay_ms) / 1000.0)
    for sid in sorted(unresolved):
        utils.log_warning(f"E_STOPSHARD_FAILED shard={sid} retries={stop_retries}")

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
        "numeric_totals": dict(agg.get("numeric_totals", {})),
    }
    utils.log_info(f"Distributed master summary: {snapshot}")
    server.stop(stop_grace_s)
    return 0
    stop_grace_s = max(0.0, float(getattr(args, "control_stop_grace_s", 1.0) or 0.0))
