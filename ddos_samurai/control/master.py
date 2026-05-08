"""Distributed master entry point."""

from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .. import utils
from .autoscale import K8sAutoscaleController
from .auth import normalize_role_secrets
from .client import WorkerControlClient
from .discovery import EndpointDiscovery
from .ha import (
    EtcdLeaseLeaderElector,
    FileLeaseLeaderElector,
    NativeRaftLeaderElector,
    RedisLeaseLeaderElector,
    StaticLeaderElector,
)
from .management_api import ManagementAPIServer, create_management_app
from .multimaster import RedisMultiMasterCoordinator
from .proto import load_generated
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


def _job_target_region(job: dict) -> str:
    return str((dict(job or {})).get("target_region", "") or "").strip().lower()


def _should_delegate_job(job: dict, *, multi_master_enabled: bool, region_id: str) -> bool:
    if not multi_master_enabled:
        return False
    rid = str(region_id or "").strip().lower()
    if not rid:
        return False
    trg = _job_target_region(job)
    return bool(trg and trg != rid)


def _apply_distributed_kpi_gate(snapshot: dict, job_args: dict) -> dict:
    profile = str(job_args.get("kpi_gate_profile", "off") or "off").strip().lower()
    hard_fail = bool(job_args.get("kpi_hard_fail", False))
    if profile in {"", "off", "none", "disabled"}:
        snapshot["kpi_gate_profile"] = "off"
        snapshot["kpi_gate_status"] = "pass"
        snapshot["kpi_gate_hard_fail"] = 0
        return snapshot
    try:
        from .. import kpi_gate

        gate = kpi_gate.evaluate(snapshot, profile=profile, hard_fail=hard_fail)
        snapshot.update(gate.as_report_fields())
    except Exception as exc:
        snapshot["kpi_gate_profile"] = profile
        snapshot["kpi_gate_status"] = "fail"
        snapshot["kpi_gate_hard_fail"] = 1 if hard_fail else 0
        snapshot["kpi_gate_error"] = str(exc)
    return snapshot


def _apply_per_shard_kpi_gate(snapshot: dict, job_args: dict) -> dict:
    max_err_rate = float(job_args.get("shard_kpi_max_error_rate_pct", -1.0) or -1.0)
    fail_on_exit = bool(job_args.get("shard_kpi_fail_on_exitcode", True))
    hard_fail = bool(job_args.get("kpi_hard_fail", False))
    per_shard = list(snapshot.get("top_error_shards", []) or [])

    failed = []
    for rec in per_shard:
        sid = str(rec.get("shard_id", "") or "")
        sent = float(rec.get("sent", 0) or 0.0)
        errs = float(rec.get("errors", 0) or 0.0)
        exitcode = int(rec.get("last_exitcode", 0) or 0)
        total = max(0.0, sent + errs)
        err_rate = (errs / total * 100.0) if total > 0 else 0.0
        reasons = []
        if max_err_rate >= 0.0 and err_rate > max_err_rate:
            reasons.append(f"error_rate>{max_err_rate}")
        if fail_on_exit and exitcode != 0:
            reasons.append("exitcode_nonzero")
        if reasons:
            failed.append(
                {
                    "shard_id": sid,
                    "error_rate_pct": round(err_rate, 4),
                    "last_exitcode": exitcode,
                    "reasons": reasons,
                }
            )

    snapshot["per_shard_kpi_status"] = "fail" if failed else "pass"
    snapshot["per_shard_kpi_failed_count"] = int(len(failed))
    snapshot["per_shard_kpi_failed"] = failed[:10]
    snapshot["per_shard_kpi_hard_fail"] = 1 if (hard_fail and failed) else 0
    return snapshot


def _distributed_snapshot_to_prometheus(snapshot: dict, prefix: str = "samurai_distributed") -> str:
    lines = []
    num_fields = {
        "workers",
        "shards_reported",
        "sent",
        "errors",
        "pending_shards_left",
        "inflight_shards_left",
    }
    for key in num_fields:
        try:
            value = float(snapshot.get(key, 0) or 0)
            lines.append(f"{prefix}_{key} {value}")
        except (TypeError, ValueError):
            continue
    gate_status = str(snapshot.get("kpi_gate_status", "") or "").strip().lower()
    if gate_status:
        lines.append(f'{prefix}_kpi_gate_status{{status="{gate_status}"}} 1')
    shard_gate_status = str(snapshot.get("per_shard_kpi_status", "") or "").strip().lower()
    if shard_gate_status:
        lines.append(f'{prefix}_per_shard_kpi_status{{status="{shard_gate_status}"}} 1')
    try:
        lines.append(f"{prefix}_per_shard_kpi_failed_count {float(snapshot.get('per_shard_kpi_failed_count', 0) or 0)}")
    except (TypeError, ValueError):
        pass
    for rec in list(snapshot.get("region_rollup") or []):
        try:
            region = str(rec.get("region", "unknown") or "unknown").replace('"', '\\"')
            lines.append(f'{prefix}_region_sent{{region="{region}"}} {float(rec.get("sent", 0) or 0)}')
            lines.append(f'{prefix}_region_errors{{region="{region}"}} {float(rec.get("errors", 0) or 0)}')
            lines.append(f'{prefix}_region_workers{{region="{region}"}} {float(rec.get("workers", 0) or 0)}')
            lines.append(f'{prefix}_region_shards{{region="{region}"}} {float(rec.get("shards", 0) or 0)}')
        except (TypeError, ValueError):
            continue
    return "\n".join(lines) + ("\n" if lines else "")


def _distributed_state_to_prometheus(state: dict, prefix: str = "samurai_distributed") -> str:
    lines = []
    snap = dict(state.get("latest_snapshot") or {})
    lines.append(_distributed_snapshot_to_prometheus(snap, prefix=prefix).strip())

    workers = list(state.get("workers") or [])
    shards = list(state.get("shards") or [])
    ha = dict(state.get("ha") or {})
    mm = dict(state.get("multi_master") or {})
    mm_regions = list(state.get("multi_master_regions") or [])

    lines.append(f"{prefix}_workers_live {float(len(workers))}")
    lines.append(f"{prefix}_shards_live {float(len(shards))}")

    for rec in workers:
        wid = str(rec.get("worker_id", "") or "").replace('"', '\\"')
        wstate = str(rec.get("state", "") or "unknown").replace('"', '\\"')
        wregion = str(rec.get("region", "unknown") or "unknown").replace('"', '\\"')
        lines.append(f'{prefix}_worker_state{{worker_id="{wid}",state="{wstate}"}} 1')
        lines.append(f'{prefix}_worker_region{{worker_id="{wid}",region="{wregion}"}} 1')
        hb = float(rec.get("last_heartbeat_ms", 0) or 0)
        lines.append(f'{prefix}_worker_last_heartbeat_ms{{worker_id="{wid}"}} {hb}')

    for rec in shards:
        sid = str(rec.get("shard_id", "") or "").replace('"', '\\"')
        sregion = str(rec.get("region", "unknown") or "unknown").replace('"', '\\"')
        sz = float(rec.get("stats_size_bytes", 0) or 0)
        lines.append(f'{prefix}_shard_stats_size_bytes{{shard_id="{sid}"}} {sz}')
        lines.append(f'{prefix}_shard_region{{shard_id="{sid}",region="{sregion}"}} 1')

    mode = str(ha.get("mode", "off") or "off").replace('"', '\\"')
    is_leader = float(ha.get("is_leader", 0) or 0)
    leader_epoch = float(ha.get("leader_epoch", 0) or 0)
    lines.append(f'{prefix}_ha_is_leader{{mode="{mode}"}} {is_leader}')
    lines.append(f'{prefix}_ha_leader_epoch{{mode="{mode}"}} {leader_epoch}')
    lines.append(f"{prefix}_multi_master_enabled {1.0 if bool(mm.get('enabled', False)) else 0.0}")
    lines.append(f"{prefix}_multi_master_regions_live {float(len(mm_regions))}")
    for rec in mm_regions:
        try:
            region = str(rec.get("region_id", "unknown") or "unknown").replace('"', '\\"')
            node_id = str(rec.get("node_id", "") or "").replace('"', '\\"')
            ts_ms = float(rec.get("ts_ms", 0) or 0)
            lines.append(f'{prefix}_multi_master_region_heartbeat_ms{{region="{region}",node_id="{node_id}"}} {ts_ms}')
        except (TypeError, ValueError):
            continue
    out = "\n".join([x for x in lines if x])
    return out + ("\n" if out else "")


def _run_single_job(
    server: MasterControlServer,
    job_args: dict,
    job_id: str,
    leadership_guard=None,
    autoscaler: K8sAutoscaleController | None = None,
) -> tuple[int, dict]:
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
    region_aware_routing = bool(job_args.get("region_aware_routing", False)) or (
        str(job_args.get("shard_strategy", "equal") or "equal").strip().lower() == "region"
    )
    target_region = str(job_args.get("target_region", "") or "").strip().lower()
    master_region = str(job_args.get("worker_region", "") or "").strip().lower()
    cross_region_heartbeat_factor = max(1.0, float(job_args.get("cross_region_heartbeat_factor", 1.6) or 1.6))

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
    leader_epoch = int(job_args.get("_leader_epoch", 0) or 0)
    tenant_namespace = str(job_args.get("tenant_namespace", "") or "").strip()

    pending: list[dict] = []
    for c in pending_counts:
        shard_seq += 1
        item = {"shard_id": f"{job_id}-shard-{shard_seq}", "packet_count": int(c), "attempt": 0}
        if target_region:
            item["target_region"] = target_region
        pending.append(item)

    inflight_by_worker: dict[str, dict] = {}
    inflight_by_sid: dict[str, dict] = {}

    def _endpoint_for_worker(worker_id: str) -> str:
        wrec = dict(server.servicer.workers.get(worker_id) or {})
        caps = dict(wrec.get("capabilities") or {})
        return str(caps.get("control_endpoint", "") or "").strip()

    def _worker_caps(worker_id: str) -> dict:
        wrec = dict(server.servicer.workers.get(worker_id) or {})
        return dict(wrec.get("capabilities") or {})

    def _worker_region(worker_id: str) -> str:
        caps = _worker_caps(worker_id)
        return str(caps.get("region", "") or "").strip().lower()

    def _worker_dispatch_score(worker_id: str, shard_item: dict) -> float:
        caps = _worker_caps(worker_id)
        tr = str((dict(shard_item or {})).get("target_region", target_region) or "").strip().lower()
        wr = _worker_region(worker_id)
        score = 0.0
        if region_aware_routing and tr:
            if wr == tr:
                score += 100.0
            elif wr and wr != tr:
                score -= 20.0
        raw_score = caps.get("capacity_score")
        try:
            if raw_score is not None:
                score += float(int(raw_score))
        except (TypeError, ValueError):
            pass
        if str(caps.get("gpu_available", "")).strip().lower() in {"1", "true", "yes"}:
            score += 2.0
        if str(caps.get("xdp_available", "")).strip().lower() in {"1", "true", "yes"}:
            score += 1.0
        return score

    def _select_worker_for_shard(free_workers: list[str], shard_item: dict) -> str:
        if not free_workers:
            return ""
        if not region_aware_routing:
            return str(free_workers[0])
        ranked = sorted(free_workers, key=lambda wid: _worker_dispatch_score(wid, shard_item), reverse=True)
        return str(ranked[0] if ranked else free_workers[0])

    def _heartbeat_timeout_for_worker(worker_id: str) -> int:
        if not region_aware_routing:
            return hb_timeout_ms
        wr = _worker_region(worker_id)
        if master_region and wr and wr != master_region:
            return int(max(hb_timeout_ms, hb_timeout_ms * cross_region_heartbeat_factor))
        if target_region and wr and wr != target_region:
            return int(max(hb_timeout_ms, hb_timeout_ms * cross_region_heartbeat_factor))
        return hb_timeout_ms

    def _dispatch_one(worker_id: str, shard_item: dict) -> tuple[bool, str]:
        sid = str(shard_item["shard_id"])
        ep = _endpoint_for_worker(worker_id)
        if not ep:
            return False, f"E_STARTSHARD_NO_ENDPOINT worker={worker_id} shard={sid}"
        shard_args = dict(job_args)
        shard_args["count"] = int(shard_item["packet_count"])
        shard_args["role"] = "standalone"
        shard_args["_worker_id"] = worker_id
        shard_args["_leader_epoch"] = int(job_args.get("_leader_epoch", 0) or 0)
        try:
            wc = WorkerControlClient(
                endpoint=ep,
                cluster_secret=str(job_args.get("cluster_secret", "")),
                tenant_namespace=tenant_namespace,
                insecure=bool(job_args.get("control_insecure", False)),
                tls_ca=str(job_args.get("control_tls_ca", "")),
                tls_client_cert=str(job_args.get("control_tls_client_cert", "")),
                tls_client_key=str(job_args.get("control_tls_client_key", "")),
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
                tenant_namespace=tenant_namespace,
                insecure=bool(job_args.get("control_insecure", False)),
                tls_ca=str(job_args.get("control_tls_ca", "")),
                tls_client_cert=str(job_args.get("control_tls_client_cert", "")),
                tls_client_key=str(job_args.get("control_tls_client_key", "")),
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
        if leadership_guard is not None and not bool(leadership_guard()):
            return 1, {
                "job_id": job_id,
                "error": "leadership_lost_abort",
                "leader_epoch": leader_epoch,
                "abort_events": [{"reason": "leadership_lost_abort", "leader_epoch": leader_epoch}],
                "dispatch_failures": list(dispatch_failures),
            }
        now_ms = int(time.time() * 1000)
        workers_now = sorted(list(server.servicer.workers.keys()))
        if autoscaler is not None:
            try:
                scale_res = autoscaler.maybe_scale(
                    pending_shards=len(pending),
                    inflight_shards=len(inflight_by_sid),
                    workers_count=len(workers_now),
                )
                _ = scale_res
            except Exception:
                pass

        # detect lost workers and rebalance inflight shard
        for wid in workers_now:
            rec = dict(server.servicer.workers.get(wid) or {})
            last_hb = int(rec.get("last_heartbeat_ms", 0) or 0)
            timeout_for_worker = _heartbeat_timeout_for_worker(wid)
            if last_hb > 0 and (now_ms - last_hb) > timeout_for_worker:
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
                "leader_epoch": leader_epoch,
                "abort_events": [{"reason": "worker_loss_abort", "leader_epoch": leader_epoch}],
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
            sh = pending.pop(0)
            wid = _select_worker_for_shard(free_workers, sh)
            if not wid:
                pending.insert(0, sh)
                break
            if wid in free_workers:
                free_workers.remove(wid)
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
                    tenant_namespace=tenant_namespace,
                    insecure=bool(job_args.get("control_insecure", False)),
                    tls_ca=str(job_args.get("control_tls_ca", "")),
                    tls_client_cert=str(job_args.get("control_tls_client_cert", "")),
                    tls_client_key=str(job_args.get("control_tls_client_key", "")),
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
        "leader_epoch": leader_epoch,
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
        "region_rollup": list(agg.get("region_rollup", [])),
        "pending_shards_left": len(pending),
        "inflight_shards_left": len(inflight_by_sid),
        "abort_events": [],
    }
    rc = 0 if not pending and not inflight_by_sid else 1
    return rc, snapshot


def run_distributed_master(args, parser, report_ctx, runtime_ctx) -> int:
    _ = parser
    _ = report_ctx
    _ = runtime_ctx
    stop_grace_s = max(0.0, float(getattr(args, "control_stop_grace_s", 1.0) or 0.0))
    ha_enabled = bool(getattr(args, "ha_enable", False))
    ha_mode = str(getattr(args, "ha_mode", "static") or "static").strip().lower()
    ha_node_id = str(getattr(args, "ha_node_id", "") or "").strip()
    ha_peers = str(getattr(args, "ha_peer_nodes", "") or "").strip()
    ha_lease_path = str(getattr(args, "ha_lease_path", "/tmp/ddos_samurai_master_lease.json") or "").strip()
    ha_lease_seconds = float(getattr(args, "ha_lease_seconds", 15.0) or 15.0)
    ha_renew_interval = float(getattr(args, "ha_renew_interval_s", 5.0) or 5.0)
    ha_redis_url = str(getattr(args, "ha_redis_url", "redis://127.0.0.1:6379/0") or "redis://127.0.0.1:6379/0").strip()
    ha_redis_key = str(getattr(args, "ha_redis_key", "samurai:ha:master") or "samurai:ha:master").strip()
    ha_etcd_endpoints = str(getattr(args, "ha_etcd_endpoints", "127.0.0.1:2379") or "127.0.0.1:2379").strip()
    ha_etcd_key = str(getattr(args, "ha_etcd_key", "samurai/ha/master") or "samurai/ha/master").strip()
    ha_etcd_timeout_s = float(getattr(args, "ha_etcd_timeout_s", 3.0) or 3.0)
    ha_raft_listen = str(getattr(args, "ha_raft_listen", "127.0.0.1:7000") or "127.0.0.1:7000").strip()
    ha_raft_peers = str(getattr(args, "ha_raft_peers", "") or "").strip()
    ha_raft_election_min_ms = int(getattr(args, "ha_raft_election_timeout_min_ms", 900) or 900)
    ha_raft_election_max_ms = int(getattr(args, "ha_raft_election_timeout_max_ms", 1500) or 1500)
    ha_raft_hb_ms = int(getattr(args, "ha_raft_heartbeat_interval_ms", 250) or 250)
    ha_raft_snapshot_threshold = int(getattr(args, "ha_raft_snapshot_threshold", 2048) or 2048)
    ha_raft_snapshot_keep_entries = int(getattr(args, "ha_raft_snapshot_keep_entries", 512) or 512)
    autoscale_enable = bool(getattr(args, "control_autoscale_enable", False))
    autoscale_namespace = str(getattr(args, "control_autoscale_namespace", "default") or "default").strip()
    autoscale_target_kind = str(getattr(args, "control_autoscale_target_kind", "deployment") or "deployment").strip().lower()
    autoscale_target_name = str(getattr(args, "control_autoscale_target_name", "") or "").strip()
    autoscale_min = int(getattr(args, "control_autoscale_min_replicas", 1) or 1)
    autoscale_max = int(getattr(args, "control_autoscale_max_replicas", 100) or 100)
    autoscale_step = int(getattr(args, "control_autoscale_step", 1) or 1)
    autoscale_cooldown_s = float(getattr(args, "control_autoscale_cooldown_s", 15.0) or 15.0)
    autoscale_shards_per_worker = int(getattr(args, "control_autoscale_shards_per_worker", 4) or 4)
    autoscale_idle_scale_down_s = float(getattr(args, "control_autoscale_idle_scale_down_s", 60.0) or 60.0)
    tenant_namespace = str(getattr(args, "tenant_namespace", "") or "").strip()
    worker_region = str(getattr(args, "worker_region", "") or "").strip()
    target_region = str(getattr(args, "target_region", "") or "").strip()
    region_aware_routing = bool(getattr(args, "region_aware_routing", False))
    cross_region_heartbeat_factor = float(getattr(args, "cross_region_heartbeat_factor", 1.6) or 1.6)
    control_rbac_enable = bool(getattr(args, "control_rbac_enable", False))
    control_rbac_default_role = str(getattr(args, "control_rbac_default_role", "viewer") or "viewer").strip().lower() or "viewer"
    control_rbac_role_secrets = normalize_role_secrets(
        admin_secret=str(getattr(args, "control_rbac_admin_secret", "") or ""),
        operator_secret=str(getattr(args, "control_rbac_operator_secret", "") or ""),
        viewer_secret=str(getattr(args, "control_rbac_viewer_secret", "") or ""),
        worker_secret=str(getattr(args, "control_rbac_worker_secret", "") or ""),
    )
    mgmt_role_tokens = {
        "admin": str(getattr(args, "management_api_admin_token", "") or "").strip(),
        "operator": str(getattr(args, "management_api_operator_token", "") or "").strip(),
        "viewer": str(getattr(args, "management_api_viewer_token", "") or "").strip(),
    }
    mgmt_role_tokens = {k: v for k, v in mgmt_role_tokens.items() if v}
    control_jwt_secret = str(getattr(args, "control_jwt_secret", "") or "").strip()
    control_jwt_role_claim = str(getattr(args, "control_jwt_role_claim", "role") or "role").strip() or "role"
    control_jwt_tenant_claim = str(
        getattr(args, "control_jwt_tenant_claim", "tenant_namespace") or "tenant_namespace"
    ).strip() or "tenant_namespace"
    mgmt_jwt_secret = str(getattr(args, "management_api_jwt_secret", "") or "").strip()
    mgmt_jwt_role_claim = str(getattr(args, "management_api_jwt_role_claim", "role") or "role").strip() or "role"
    mgmt_jwt_tenant_claim = str(
        getattr(args, "management_api_jwt_tenant_claim", "tenant_namespace") or "tenant_namespace"
    ).strip() or "tenant_namespace"
    mgmt_live_interval_ms = int(getattr(args, "management_api_live_interval_ms", 1000) or 1000)
    control_rbac_audit_log_path = str(getattr(args, "control_rbac_audit_log_path", "") or "").strip()
    control_rbac_audit_success = bool(getattr(args, "control_rbac_audit_success", False))
    control_tls_watch_files = bool(getattr(args, "control_tls_watch_files", True))
    control_tls_reload_interval_s = float(getattr(args, "control_tls_reload_interval_s", 2.0) or 2.0)
    multi_master_enable = bool(getattr(args, "multi_master_enable", False))
    multi_master_region_id = str(getattr(args, "multi_master_region_id", "") or "").strip().lower() or str(worker_region or "").strip().lower()
    multi_master_redis_url = str(getattr(args, "multi_master_redis_url", "redis://127.0.0.1:6379/0") or "redis://127.0.0.1:6379/0").strip()
    multi_master_namespace = str(getattr(args, "multi_master_namespace", "default") or "default").strip() or "default"
    multi_master_heartbeat_ttl_s = int(getattr(args, "multi_master_heartbeat_ttl_s", 15) or 15)
    multi_master_dequeue_max = int(getattr(args, "multi_master_dequeue_max", 3) or 3)
    ha_elector = None
    ha_wait_for_leader = bool(getattr(args, "ha_wait_for_leader", True))
    ha_acquire_timeout_s = float(getattr(args, "ha_acquire_timeout_s", 0.0) or 0.0)
    ha_retry_interval_s = max(0.2, float(getattr(args, "ha_retry_interval_s", 1.0) or 1.0))
    if ha_enabled:
        if ha_mode == "static":
            ha_elector = StaticLeaderElector(node_id=ha_node_id, peers_csv=ha_peers)
            if not ha_elector.is_leader():
                snap = ha_elector.snapshot()
                utils.log_warning(
                    f"HA static mode: this node is follower (node_id={snap.get('node_id')} "
                    f"leader_id={snap.get('leader_id')}). Skipping master run."
                )
                return 0
        else:
            if ha_mode == "file-lock":
                e = FileLeaseLeaderElector(
                    node_id=ha_node_id,
                    lease_path=ha_lease_path,
                    lease_seconds=ha_lease_seconds,
                )
            elif ha_mode == "redis":
                e = RedisLeaseLeaderElector(
                    node_id=ha_node_id,
                    redis_url=ha_redis_url,
                    lease_key=ha_redis_key,
                    lease_seconds=ha_lease_seconds,
                )
            elif ha_mode == "etcd":
                e = EtcdLeaseLeaderElector(
                    node_id=ha_node_id,
                    endpoints_csv=ha_etcd_endpoints,
                    lease_key=ha_etcd_key,
                    lease_seconds=ha_lease_seconds,
                    timeout_seconds=ha_etcd_timeout_s,
                )
            elif ha_mode == "raft":
                e = NativeRaftLeaderElector(
                    node_id=ha_node_id,
                    listen_addr=ha_raft_listen,
                    peers_csv=ha_raft_peers,
                    election_timeout_min_ms=ha_raft_election_min_ms,
                    election_timeout_max_ms=ha_raft_election_max_ms,
                    heartbeat_interval_ms=ha_raft_hb_ms,
                    snapshot_threshold=ha_raft_snapshot_threshold,
                    snapshot_keep_entries=ha_raft_snapshot_keep_entries,
                )
            else:
                raise ValueError(f"unsupported ha mode: {ha_mode}")

            acquired = bool(e.try_acquire())
            if not acquired and ha_wait_for_leader:
                start_wait = time.time()
                while True:
                    if ha_acquire_timeout_s > 0 and (time.time() - start_wait) >= ha_acquire_timeout_s:
                        break
                    time.sleep(ha_retry_interval_s)
                    if e.try_acquire():
                        acquired = True
                        break
            if not acquired:
                snap = e.snapshot()
                utils.log_warning(
                    f"HA {ha_mode} mode: this node is follower (node_id={snap.get('node_id')} "
                    f"leader_id={snap.get('leader_id')}). Skipping master run."
                )
                return 0
            renew_interval_s = ha_renew_interval
            if ha_mode == "raft":
                renew_interval_s = max(0.05, float(ha_raft_hb_ms) / 1000.0)
            e.start_renew_loop(interval_seconds=renew_interval_s)
            ha_elector = e
    ha_state = dict(ha_elector.snapshot()) if ha_elector is not None else {"mode": "off", "is_leader": 1, "leader_epoch": 0}
    mm_coordinator = RedisMultiMasterCoordinator(
        enabled=multi_master_enable,
        redis_url=multi_master_redis_url,
        namespace=multi_master_namespace,
        region_id=multi_master_region_id,
        node_id=ha_node_id or "master",
        heartbeat_ttl_s=multi_master_heartbeat_ttl_s,
    )
    if multi_master_enable and not bool(mm_coordinator.enabled):
        mm_snap = dict(mm_coordinator.snapshot() or {})
        utils.log_warning(
            f"Multi-master coordinator disabled; reason={str(mm_snap.get('error', '') or 'unknown')}"
        )

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
    autoscaler = K8sAutoscaleController(
        enabled=autoscale_enable,
        namespace=autoscale_namespace,
        target_kind=autoscale_target_kind,
        target_name=autoscale_target_name,
        min_replicas=autoscale_min,
        max_replicas=autoscale_max,
        step=autoscale_step,
        cooldown_s=autoscale_cooldown_s,
        shards_per_worker=autoscale_shards_per_worker,
        idle_scale_down_s=autoscale_idle_scale_down_s,
    )

    control_max_workers = int(getattr(args, "control_max_workers", 0) or 0)
    if control_max_workers <= 0:
        control_max_workers = max(16, expected_workers + 8)
    server = MasterControlServer(
        listen_addr=str(getattr(args, "control_listen", "0.0.0.0:5099")),
        cluster_secret=str(getattr(args, "cluster_secret", "")),
        insecure=bool(getattr(args, "control_insecure", False)),
        tls_cert=str(getattr(args, "control_tls_cert", "")),
        tls_key=str(getattr(args, "control_tls_key", "")),
        tls_client_ca=str(getattr(args, "control_tls_client_ca", "")),
        require_client_auth=bool(getattr(args, "control_require_client_auth", False)),
        max_workers=control_max_workers,
        rbac_enabled=control_rbac_enable,
        rbac_role_secrets=control_rbac_role_secrets,
        rbac_default_role=control_rbac_default_role,
        tenant_namespace=tenant_namespace,
        jwt_secret=control_jwt_secret,
        jwt_role_claim=control_jwt_role_claim,
        jwt_tenant_claim=control_jwt_tenant_claim,
        rbac_audit_log_path=control_rbac_audit_log_path,
        rbac_audit_log_success=control_rbac_audit_success,
        tls_watch_files=control_tls_watch_files,
        tls_reload_interval_s=control_tls_reload_interval_s,
    )
    mgmt_server = None
    latest_snapshot: dict = {}
    current_job: dict = {
        "state": "idle",
        "job_id": "",
        "tenant_namespace": tenant_namespace,
        "region_id": multi_master_region_id,
    }
    events: list[dict] = []
    events_max = max(10, int(getattr(args, "management_events_max", 200) or 200))
    event_seq = {"next": 1}

    def _push_event(kind: str, replicate: bool = False, **extra) -> None:
        item = {
            "event_id": int(event_seq["next"]),
            "ts_ms": int(time.time() * 1000),
            "kind": str(kind),
            "tenant_namespace": tenant_namespace,
        }
        event_seq["next"] = int(event_seq["next"]) + 1
        item.update({str(k): v for k, v in dict(extra or {}).items()})
        events.append(item)
        if len(events) > events_max:
            del events[0 : len(events) - events_max]
        if replicate and ha_elector is not None and hasattr(ha_elector, "replicate_command"):
            try:
                _ = ha_elector.replicate_command(
                    {"type": "event", "kind": str(kind), "payload": dict(item)},
                    wait_commit_s=0.4,
                )
            except Exception:
                pass
        if bool(mm_coordinator.enabled):
            try:
                _ = mm_coordinator.publish_event(dict(item))
            except Exception:
                pass

    def _state_provider() -> dict:
        workers = []
        with server.servicer._workers_lock:
            for wid, rec in dict(server.servicer.workers).items():
                workers.append(
                    {
                        "worker_id": str(wid),
                        "tenant_namespace": str(rec.get("tenant_namespace", "") or ""),
                        "region": str((dict(rec.get("capabilities") or {})).get("region", "") or ""),
                        "state": str(rec.get("state", "")),
                        "active_shard_id": str(rec.get("active_shard_id", "")),
                        "last_heartbeat_ms": int(rec.get("last_heartbeat_ms", 0) or 0),
                    }
                )
        shards = []
        with server.servicer._stats_lock:
            for sid, blob in dict(server.servicer.shard_stats).items():
                region = ""
                try:
                    item = json.loads(bytes(blob).decode("utf-8"))
                    region = str((dict(item or {})).get("region", "") or "")
                except (ValueError, TypeError, UnicodeDecodeError):
                    region = ""
                shards.append(
                    {
                        "shard_id": str(sid),
                        "tenant_namespace": tenant_namespace,
                        "region": region,
                        "stats_size_bytes": len(bytes(blob or b"")),
                    }
                )
        if ha_elector is not None:
            try:
                ha_state.clear()
                ha_state.update(dict(ha_elector.snapshot()))
            except Exception:
                pass
        mm_regions = []
        mm_latest = []
        if bool(mm_coordinator.enabled):
            try:
                _ = mm_coordinator.heartbeat(
                    {
                        "workers_count": int(len(workers)),
                        "shards_count": int(len(shards)),
                        "is_leader": int(ha_state.get("is_leader", 0) or 0),
                    }
                )
            except Exception:
                pass
            try:
                mm_regions = list(mm_coordinator.regions_state() or [])
            except Exception:
                mm_regions = []
            try:
                mm_latest = list(mm_coordinator.latest_region_snapshots() or [])
            except Exception:
                mm_latest = []
        return {
            "workers": workers,
            "workers_count": len(workers),
            "shards": shards,
            "shards_reported_count": len(shards),
            "latest_snapshot": dict(latest_snapshot),
            "current_job": dict(current_job),
            "ha": dict(ha_state),
            "events": list(events),
            "multi_master": dict(mm_coordinator.snapshot()),
            "multi_master_regions": mm_regions,
            "multi_master_latest": mm_latest,
        }

    def _abort_callback() -> dict:
        pb2, _ = load_generated()
        resp = server.servicer.AbortJob(pb2.AbortJobRequest(job_id=str(current_job.get("job_id", ""))), context=None)
        _push_event(
            "abort_api",
            replicate=True,
            job_id=str(current_job.get("job_id", "")),
            workers_notified=int(resp.workers_notified or 0),
            leader_epoch=int(ha_state.get("leader_epoch", 0) or 0),
        )
        return {"aborted": bool(resp.aborted), "workers_notified": int(resp.workers_notified or 0)}
    try:
        server.start()
    except Exception as exc:
        if ha_elector is not None and hasattr(ha_elector, "stop"):
            try:
                ha_elector.stop()
            except Exception:
                pass
        utils.log_critical(f"Distributed master başlatılamadı: {exc}")
        return 1
    utils.log_info(
        f"Distributed master started on {server.listen_addr}. "
        f"grpc_max_workers={int(control_max_workers)}"
    )
    _push_event("master_started", replicate=True, listen_addr=str(server.listen_addr))
    if bool(getattr(args, "management_api_enable", False)):
        mgmt_app = create_management_app(
            state_provider=_state_provider,
            abort_callback=_abort_callback,
            metrics_provider=lambda: _distributed_state_to_prometheus(
                _state_provider(),
                prefix=str(getattr(args, "distributed_metrics_prefix", "samurai_distributed") or "samurai_distributed"),
            ),
            auth_token=str(getattr(args, "management_api_auth_token", "")),
            auth_role_tokens=mgmt_role_tokens,
            tenant_namespace=tenant_namespace,
            jwt_secret=mgmt_jwt_secret,
            jwt_role_claim=mgmt_jwt_role_claim,
            jwt_tenant_claim=mgmt_jwt_tenant_claim,
            live_interval_ms=mgmt_live_interval_ms,
        )
        mgmt_server = ManagementAPIServer(
            listen_addr=str(getattr(args, "management_api_listen", "127.0.0.1:8089")),
            app=mgmt_app,
        )
        mgmt_server.start()
        utils.log_info(f"Management API started on {str(getattr(args, 'management_api_listen', '127.0.0.1:8089'))}")

    wait_workers_s = max(1, int(getattr(args, "worker_registration_timeout_s", 30) or 30))
    worker_deadline = time.time() + float(wait_workers_s)
    while time.time() < worker_deadline and len(server.servicer.workers) < expected_workers:
        time.sleep(0.5)
    if not server.servicer.workers:
        utils.log_warning("No slave registered; master exits without dispatch.")
        _push_event("master_exit_no_workers")
        if mgmt_server is not None:
            mgmt_server.stop()
        server.stop(stop_grace_s)
        if ha_elector is not None and hasattr(ha_elector, "stop"):
            try:
                ha_elector.stop()
            except Exception:
                pass
        return 1

    jobs = _parse_job_queue(args)
    if bool(mm_coordinator.enabled) and multi_master_region_id:
        try:
            delegated = list(mm_coordinator.dequeue_jobs(max_count=multi_master_dequeue_max) or [])
        except Exception:
            delegated = []
        if delegated:
            jobs.extend(delegated)
            _push_event("multi_master_jobs_dequeued", count=int(len(delegated)), region_id=multi_master_region_id)
    multi_summary = []
    final_rc = 0
    distributed_metrics_textfile = str(getattr(args, "distributed_metrics_textfile", "") or "").strip()
    distributed_metrics_prefix = str(getattr(args, "distributed_metrics_prefix", "samurai_distributed") or "samurai_distributed").strip() or "samurai_distributed"
    for idx, job in enumerate(jobs, start=1):
        job_id = f"job-{int(time.time())}-{idx}"
        job_run = dict(job)
        job_run["tenant_namespace"] = tenant_namespace
        job_run.setdefault("worker_region", worker_region)
        job_run.setdefault("target_region", target_region)
        job_run.setdefault("region_aware_routing", region_aware_routing)
        job_run.setdefault("cross_region_heartbeat_factor", cross_region_heartbeat_factor)
        if _should_delegate_job(job_run, multi_master_enabled=bool(mm_coordinator.enabled), region_id=multi_master_region_id):
            trg = _job_target_region(job_run)
            enq_ok = False
            try:
                enq_ok = bool(mm_coordinator.enqueue_job(trg, job_run))
            except Exception:
                enq_ok = False
            _push_event(
                "multi_master_job_delegated",
                replicate=False,
                job_id=job_id,
                from_region=multi_master_region_id,
                to_region=trg,
                enqueued=int(1 if enq_ok else 0),
            )
            continue
        if ha_elector is not None and hasattr(ha_elector, "leader_epoch"):
            try:
                job_run["_leader_epoch"] = int(getattr(ha_elector, "leader_epoch", 0) or 0)
            except Exception:
                job_run["_leader_epoch"] = 0
        else:
            job_run["_leader_epoch"] = 0
        current_job["state"] = "running"
        current_job["job_id"] = job_id
        current_job["region_id"] = multi_master_region_id
        current_job["target_region"] = _job_target_region(job_run) or target_region
        _push_event(
            "job_started",
            replicate=True,
            job_id=job_id,
            leader_epoch=int(job_run.get("_leader_epoch", 0) or 0),
        )
        server.servicer.set_leader_epoch_min(int(job_run.get("_leader_epoch", 0) or 0))
        guard = (lambda: bool(ha_elector.is_leader())) if ha_elector is not None else None
        rc, snap = _run_single_job(server, job_run, job_id=job_id, leadership_guard=guard, autoscaler=autoscaler)
        snap = _apply_distributed_kpi_gate(snap, job_run)
        snap = _apply_per_shard_kpi_gate(snap, job_run)
        latest_snapshot.clear()
        latest_snapshot.update(dict(snap))
        if bool(mm_coordinator.enabled):
            try:
                _ = mm_coordinator.publish_snapshot(dict(snap))
            except Exception:
                pass
        multi_summary.append(snap)
        utils.log_info(f"Distributed master summary: {snap}")
        if distributed_metrics_textfile:
            try:
                parent = os.path.dirname(distributed_metrics_textfile)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                with open(distributed_metrics_textfile, "w", encoding="utf-8") as f:
                    f.write(_distributed_snapshot_to_prometheus(snap, prefix=distributed_metrics_prefix))
            except Exception as exc:
                utils.log_warning(f"Distributed metrics export failed: {exc}")
        if rc != 0:
            final_rc = rc
        if int(snap.get("kpi_gate_hard_fail", 0) or 0) == 1:
            final_rc = 1
        if int(snap.get("per_shard_kpi_hard_fail", 0) or 0) == 1:
            final_rc = 1
        current_job["state"] = "done" if int(rc) == 0 else "error"
        _push_event(
            "job_finished",
            replicate=True,
            job_id=job_id,
            rc=int(rc),
            sent=int(snap.get("sent", 0) or 0),
            errors=int(snap.get("errors", 0) or 0),
            leader_epoch=int(snap.get("leader_epoch", 0) or 0),
            error=str(snap.get("error", "") or ""),
        )

    if len(multi_summary) > 1:
        utils.log_info(f"Distributed master multi-job summary: jobs={len(multi_summary)} rc={final_rc}")
        _push_event("multi_job_summary", jobs=int(len(multi_summary)), rc=int(final_rc))

    if mgmt_server is not None:
        mgmt_server.stop()
    server.stop(stop_grace_s)
    _push_event("master_stopped", rc=int(final_rc))
    if ha_elector is not None and hasattr(ha_elector, "stop"):
        try:
            ha_elector.stop()
        except Exception:
            pass
    return int(final_rc)
