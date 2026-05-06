"""Distributed master entry point."""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .. import utils
from .client import WorkerControlClient
from .discovery import EndpointDiscovery
from .server import MasterControlServer
from .telemetry import DistributedAggregator


def _parse_job_queue(args) -> list[dict]:
    raw = str(getattr(args, "job_queue_json", "") or "").strip()
    if not raw:
        return [dict(vars(args))]
    try:
        data = json.loads(raw)
    except Exception:
        utils.log_warning("Invalid --job-queue-json; fallback to single job")
        return [dict(vars(args))]
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or not data:
        return [dict(vars(args))]
    out = []
    base = dict(vars(args))
    for item in data:
        if not isinstance(item, dict):
            continue
        merged = dict(base)
        merged.update(item)
        out.append(merged)
    return out or [dict(vars(args))]


def _chunk_counts(total_count: int, unit: int) -> list[int]:
    total = max(0, int(total_count or 0))
    unit = max(1, int(unit or 1))
    out = []
    rem = total
    while rem > 0:
        c = min(unit, rem)
        out.append(c)
        rem -= c
    return out


def _run_single_job(server: MasterControlServer, job_args: dict, job_id: str) -> tuple[int, dict]:
    total_count = int(job_args.get("count", 0) or 0)
    if total_count <= 0:
        return 1, {"job_id": job_id, "error": "count<=0"}

    timeout_s = int(job_args.get("job_timeout_s", 0) or 0)
    wait_s = timeout_s if timeout_s > 0 else 120
    hb_timeout_ms = int(job_args.get("heartbeat_timeout_ms", 6000) or 6000)
    poll_interval_s = max(0.05, float(job_args.get("master_poll_interval_ms", 250) or 250) / 1000.0)
    worker_status_probe = bool(job_args.get("worker_status_probe", True))
    on_worker_loss = str(job_args.get("on_worker_loss", "continue") or "continue").strip().lower()
    dispatch_pool = max(1, int(job_args.get("control_dispatch_workers", 32) or 32))
    shard_unit_count = int(job_args.get("shard_unit_count", 0) or 0)

    initial_workers = max(1, len(server.servicer.workers))
    if shard_unit_count <= 0:
        shard_unit_count = max(1, total_count // max(4, initial_workers * 4))
    pending_counts = _chunk_counts(total_count, shard_unit_count)

    deadline = time.time() + float(wait_s)
    timeout_ms = int(timeout_s) * 1000
    shard_seq = 0
    dispatch_failures: list[str] = []
    lost_workers: set[str] = set()
    done_shards: set[str] = set()

    pending: list[dict] = []
    for c in pending_counts:
        shard_seq += 1
        pending.append({"shard_id": f"{job_id}-shard-{shard_seq}", "packet_count": int(c), "attempt": 0})

    inflight_by_worker: dict[str, dict] = {}
    inflight_by_sid: dict[str, dict] = {}

    def _endpoint_for_worker(worker_id: str) -> str:
        wrec = dict(server.servicer.workers.get(worker_id) or {})
        caps = dict(wrec.get("capabilities") or {})
        return str(caps.get("control_endpoint", "") or "").strip()

    def _dispatch_one(worker_id: str, shard_item: dict) -> tuple[bool, str]:
        sid = str(shard_item["shard_id"])
        ep = _endpoint_for_worker(worker_id)
        if not ep:
            return False, f"E_STARTSHARD_NO_ENDPOINT worker={worker_id} shard={sid}"
        shard_args = dict(job_args)
        shard_args["count"] = int(shard_item["packet_count"])
        shard_args["role"] = "standalone"
        shard_args["_worker_id"] = worker_id
        try:
            wc = WorkerControlClient(
                endpoint=ep,
                cluster_secret=str(job_args.get("cluster_secret", "")),
                insecure=bool(job_args.get("control_insecure", False)),
                tls_ca=str(job_args.get("control_tls_ca", "")),
            )
            resp = wc.start_shard(
                shard_id=sid,
                job_id=job_id,
                args_json=json.dumps(shard_args, ensure_ascii=True).encode("utf-8"),
                packet_count=int(shard_item["packet_count"]),
                timeout_ms=timeout_ms,
            )
            if not bool(resp.get("started", False)):
                return False, f"E_STARTSHARD_REJECTED worker={worker_id} shard={sid} error={resp.get('error','')}"
            return True, f"Dispatched shard {sid} -> {worker_id} count={int(shard_item['packet_count'])}"
        except Exception as exc:
            return False, f"E_STARTSHARD_RPC worker={worker_id} shard={sid} error={str(exc)}"

    def _worker_state(worker_id: str) -> tuple[str, str, bytes]:
        if not worker_status_probe:
            return "", "", b"{}"
        ep = _endpoint_for_worker(worker_id)
        if not ep:
            return "", "", b"{}"
        try:
            wc = WorkerControlClient(
                endpoint=ep,
                cluster_secret=str(job_args.get("cluster_secret", "")),
                insecure=bool(job_args.get("control_insecure", False)),
                tls_ca=str(job_args.get("control_tls_ca", "")),
            )
            st = wc.get_worker_status(worker_id=worker_id)
            return (
                str(st.get("state", "") or "").strip().lower(),
                str(st.get("active_shard_id", "") or "").strip(),
                bytes(st.get("stats_json", b"{}") or b"{}"),
            )
        except Exception:
            return "", "", b"{}"

    while time.time() < deadline:
        now_ms = int(time.time() * 1000)
        workers_now = sorted(list(server.servicer.workers.keys()))

        # detect lost workers and rebalance inflight shard
        for wid in workers_now:
            rec = dict(server.servicer.workers.get(wid) or {})
            last_hb = int(rec.get("last_heartbeat_ms", 0) or 0)
            if last_hb > 0 and (now_ms - last_hb) > hb_timeout_ms:
                lost_workers.add(wid)

        for wid in list(inflight_by_worker.keys()):
            if wid in lost_workers:
                sh = dict(inflight_by_worker.pop(wid) or {})
                sid = str(sh.get("shard_id", "") or "")
                if sid:
                    inflight_by_sid.pop(sid, None)
                    if sid not in done_shards:
                        sh["attempt"] = int(sh.get("attempt", 0) or 0) + 1
                        if int(sh["attempt"]) <= 2:
                            pending.insert(0, sh)

        if lost_workers and on_worker_loss == "abort":
            return 1, {
                "job_id": job_id,
                "lost_workers": sorted(lost_workers),
                "dispatch_failures": list(dispatch_failures),
                "error": "worker_loss_abort",
            }

        # completion via stats or status probe
        for sid in list(inflight_by_sid.keys()):
            if sid in server.servicer.shard_stats:
                done_shards.add(sid)
                sh = inflight_by_sid.pop(sid, None)
                if sh is not None:
                    inflight_by_worker.pop(str(sh.get("worker_id", "")), None)
                continue
            sh = dict(inflight_by_sid.get(sid) or {})
            wid = str(sh.get("worker_id", "") or "")
            if not wid:
                continue
            state, active_sid, stats_json = _worker_state(wid)
            if state in {"done", "error"} and active_sid in {"", sid}:
                if stats_json and stats_json != b"{}":
                    server.servicer.shard_stats[sid] = stats_json
                done_shards.add(sid)
                inflight_by_sid.pop(sid, None)
                inflight_by_worker.pop(wid, None)

        if not pending and not inflight_by_sid:
            break

        # dispatch pending shards to free workers (dynamic add supported)
        free_workers = []
        for wid in workers_now:
            if wid in lost_workers:
                continue
            if wid in inflight_by_worker:
                continue
            ep = _endpoint_for_worker(wid)
            if ep:
                free_workers.append(wid)

        batch = []
        while pending and free_workers and len(batch) < dispatch_pool:
            wid = free_workers.pop(0)
            sh = pending.pop(0)
            batch.append((wid, sh))

        if batch:
            with ThreadPoolExecutor(max_workers=max(1, min(dispatch_pool, len(batch)))) as pool:
                fut_map = {pool.submit(_dispatch_one, wid, sh): (wid, sh) for wid, sh in batch}
                for fut in as_completed(fut_map):
                    wid, sh = fut_map[fut]
                    ok, msg = fut.result()
                    sid = str(sh["shard_id"])
                    if ok:
                        utils.log_info(msg)
                        rec = dict(sh)
                        rec["worker_id"] = wid
                        inflight_by_worker[wid] = rec
                        inflight_by_sid[sid] = rec
                    else:
                        dispatch_failures.append(msg)
                        sh["attempt"] = int(sh.get("attempt", 0) or 0) + 1
                        if int(sh["attempt"]) <= 2:
                            pending.append(sh)
                        else:
                            utils.log_warning(msg)

        time.sleep(poll_interval_s)

    # best-effort stop remaining inflight
    unresolved = set(inflight_by_sid.keys())
    stop_retries = max(1, int(job_args.get("stop_shard_retries", 3) or 3))
    stop_retry_delay_ms = max(10, int(job_args.get("stop_shard_retry_delay_ms", 250) or 250))
    for _ in range(stop_retries):
        if not unresolved:
            break
        targets = [dict(inflight_by_sid[s]) for s in list(unresolved) if s in inflight_by_sid]
        with ThreadPoolExecutor(max_workers=max(1, min(dispatch_pool, len(targets) or 1))) as pool:
            fut_map = {}
            for sh in targets:
                wid = str(sh.get("worker_id", "") or "")
                sid = str(sh.get("shard_id", "") or "")
                ep = _endpoint_for_worker(wid)
                if not ep:
                    continue
                wc = WorkerControlClient(
                    endpoint=ep,
                    cluster_secret=str(job_args.get("cluster_secret", "")),
                    insecure=bool(job_args.get("control_insecure", False)),
                    tls_ca=str(job_args.get("control_tls_ca", "")),
                )
                fut_map[pool.submit(wc.stop_shard, sid, True)] = sid
            for fut in as_completed(fut_map):
                sid = fut_map[fut]
                try:
                    if bool(fut.result()):
                        unresolved.discard(sid)
                except Exception:
                    pass
        if unresolved:
            time.sleep(float(stop_retry_delay_ms) / 1000.0)

    for sid in sorted(unresolved):
        utils.log_warning(f"E_STOPSHARD_FAILED shard={sid} retries={stop_retries}")

    aggregator = DistributedAggregator()
    for sid, blob in dict(server.servicer.shard_stats).items():
        if not str(sid).startswith(f"{job_id}-shard-"):
            continue
        try:
            item = json.loads(bytes(blob).decode("utf-8"))
            if "shard_id" not in item:
                item["shard_id"] = sid
            aggregator.add(item)
        except (ValueError, TypeError, UnicodeDecodeError):
            utils.log_warning(f"Shard stats decode failed: {sid}")

    agg = aggregator.snapshot()
    snapshot = {
        "job_id": job_id,
        "workers": len(server.servicer.workers),
        "shards_reported": len(agg.get("shard_ids", [])),
        "lost_workers": sorted(lost_workers),
        "dispatch_failures": list(dispatch_failures),
        "sent": int(agg.get("sent", 0) or 0),
        "errors": int(agg.get("errors", 0) or 0),
        "worker_ids": list(agg.get("worker_ids", [])),
        "shard_ids": list(agg.get("shard_ids", [])),
        "numeric_totals": dict(agg.get("numeric_totals", {})),
        "top_error_shards": list(agg.get("top_error_shards", [])),
        "worker_rollup": list(agg.get("worker_rollup", [])),
        "pending_shards_left": len(pending),
        "inflight_shards_left": len(inflight_by_sid),
    }
    rc = 0 if not pending and not inflight_by_sid else 1
    return rc, snapshot


def run_distributed_master(args, parser, report_ctx, runtime_ctx) -> int:
    _ = parser
    _ = report_ctx
    _ = runtime_ctx
    stop_grace_s = max(0.0, float(getattr(args, "control_stop_grace_s", 1.0) or 0.0))

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

    wait_workers_s = max(1, int(getattr(args, "worker_registration_timeout_s", 30) or 30))
    worker_deadline = time.time() + float(wait_workers_s)
    while time.time() < worker_deadline and len(server.servicer.workers) < expected_workers:
        time.sleep(0.5)
    if not server.servicer.workers:
        utils.log_warning("No slave registered; master exits without dispatch.")
        server.stop(stop_grace_s)
        return 1

    jobs = _parse_job_queue(args)
    multi_summary = []
    final_rc = 0
    for idx, job in enumerate(jobs, start=1):
        job_id = f"job-{int(time.time())}-{idx}"
        rc, snap = _run_single_job(server, job, job_id=job_id)
        multi_summary.append(snap)
        utils.log_info(f"Distributed master summary: {snap}")
        if rc != 0:
            final_rc = rc

    if len(multi_summary) > 1:
        utils.log_info(f"Distributed master multi-job summary: jobs={len(multi_summary)} rc={final_rc}")

    server.stop(stop_grace_s)
    return int(final_rc)
