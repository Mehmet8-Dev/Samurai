"""CLI-specific reporting helpers."""

from __future__ import annotations

import os
import shutil

from .. import utils


def publish_metrics_prom_to_textfile(metrics_prom_path: str) -> None:
    """Best-effort publish for run metrics into node-exporter textfile collector."""
    src = str(metrics_prom_path or "").strip()
    if not src:
        return
    if not os.path.isfile(src):
        return
    dest = str(
        os.environ.get(
            "SAMURAI_PROM_TEXTFILE_RESULTS",
            os.path.join("monitoring", "textfile", "samurai_results.prom"),
        )
        or ""
    ).strip()
    if not dest:
        return
    try:
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        tmp = dest + ".tmp"
        shutil.copyfile(src, tmp)
        os.replace(tmp, dest)
        utils.log_info(f"Prom textfile güncellendi: {dest}")
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError) as e:
        utils.log_warning(f"Prom textfile güncellenemedi ({dest}): {e}")


def aggregate_worker_events(events):
    summary = {
        "workers_total": 0,
        "workers_ok": 0,
        "workers_failed": 0,
        "workers_interrupted": 0,
        "attempted_total": 0,
        "sent_total": 0,
        "errors_total": 0,
        "bytes_sent_est_total": 0,
        "duration_s_sum": 0.0,
        "duration_s_max": 0.0,
        "by_vector": {},
        "by_backend": {},
        "by_status": {},
    }
    for ev in list(events or []):
        if not isinstance(ev, dict):
            continue
        summary["workers_total"] += 1
        status = str(ev.get("status", "unknown"))
        if status == "ok":
            summary["workers_ok"] += 1
        elif status == "interrupted":
            summary["workers_interrupted"] += 1
        else:
            summary["workers_failed"] += 1
        summary["by_status"][status] = int(summary["by_status"].get(status, 0)) + 1

        dur = float(ev.get("duration_s", 0.0) or 0.0)
        summary["duration_s_sum"] += dur
        summary["duration_s_max"] = max(summary["duration_s_max"], dur)

        st = ev.get("stats") or {}
        attempted = int(st.get("attempted", 0) or 0)
        sent = int(st.get("sent", 0) or 0)
        errors = int(st.get("errors", 0) or 0)
        bytes_sent = int(st.get("bytes_sent_est", 0) or 0)

        summary["attempted_total"] += attempted
        summary["sent_total"] += sent
        summary["errors_total"] += errors
        summary["bytes_sent_est_total"] += bytes_sent

        vec = str(ev.get("attack_vector", "unknown"))
        be = str(ev.get("compute_backend", "unknown"))

        v = summary["by_vector"].setdefault(vec, {"attempted": 0, "sent": 0, "errors": 0, "workers": 0})
        v["attempted"] += attempted
        v["sent"] += sent
        v["errors"] += errors
        v["workers"] += 1

        b = summary["by_backend"].setdefault(be, {"attempted": 0, "sent": 0, "errors": 0, "workers": 0})
        b["attempted"] += attempted
        b["sent"] += sent
        b["errors"] += errors
        b["workers"] += 1

    return summary


def report_inputs_from_args(args) -> dict:
    return {
        "target": str(getattr(args, "target", "")),
        "port": int(getattr(args, "port", 0) or 0),
        "protocol": str(getattr(args, "protocol", "")),
        "attack_vector": str(getattr(args, "attack_vector", "")),
        "compute_backend": str(getattr(args, "compute_backend", "")),
        "count": int(getattr(args, "count", 0) or 0),
        "workers": int(getattr(args, "workers", 0) or 0),
        "rps": float(getattr(args, "rps", 0) or 0),
        "pacing_mode": str(getattr(args, "pacing_mode", "none")),
        "ninja_mode": bool(getattr(args, "ninja_mode", False)),
        "spoof": bool(getattr(args, "spoof", False)),
        "spoof_mode": str(getattr(args, "spoof_mode", "")),
        "http_scheme": str(getattr(args, "http_scheme", "http")),
        "http_method": str(getattr(args, "http_method", "GET")),
        "ws_scenario": bool(getattr(args, "ws_scenario", False)),
        "tls_profile": str(getattr(args, "tls_profile", "none")),
        "h2_profile": str(getattr(args, "h2_profile", "none")),
        "h2_transport": str(getattr(args, "h2_transport", "auto")),
        "soak_profile": str(getattr(args, "soak_profile", "none")),
        "soak_warmup_s": int(getattr(args, "soak_warmup_s", 0) or 0),
        "gpu_template_pool_size_l4": int(getattr(args, "gpu_template_pool_size_l4", 10) or 10),
        "gpu_template_pool_size_l7": int(getattr(args, "gpu_template_pool_size_l7", 50) or 50),
        "gpu_ring_capacity": int(getattr(args, "gpu_ring_capacity", 3) or 3),
        "gpu_batch_size": int(getattr(args, "gpu_batch_size", 100000) or 100000),
        "gpu_stream_count": int(getattr(args, "gpu_stream_count", 3) or 3),
        "gpu_pipeline_depth": int(getattr(args, "gpu_pipeline_depth", 2) or 2),
        "gpu_full_variation": bool(getattr(args, "gpu_full_variation", True)),
        "gpu_pinned_max_mb": int(getattr(args, "gpu_pinned_max_mb", 512) or 512),
        "gpu_packet_zerocopy_output": bool(getattr(args, "gpu_packet_zerocopy_output", False)),
        "gpu_kernel_mode": str(getattr(args, "gpu_kernel_mode", "batch") or "batch"),
        "gpu_stream_api": str(getattr(args, "gpu_stream_api", "compat") or "compat"),
        "gpu_epoch_ms": int(getattr(args, "gpu_epoch_ms", 50) or 50),
        "gpu_queue_count": int(getattr(args, "gpu_queue_count", 1) or 1),
        "gpu_heartbeat_ms": int(getattr(args, "gpu_heartbeat_ms", 500) or 500),
        "gpu_no_progress_ms": int(getattr(args, "gpu_no_progress_ms", 2000) or 2000),
        "gpu_rng_seed": int(getattr(args, "gpu_rng_seed", 1234) or 0) if getattr(args, "gpu_rng_seed", None) is not None else None,
        "state_table_size": int(getattr(args, "state_table_size", 65536) or 65536),
        "state_lock_count": int(getattr(args, "state_lock_count", 256) or 256),
        "state_timeout_sec": int(getattr(args, "state_timeout_sec", 60) or 60),
        "state_sweep_interval_ms": int(getattr(args, "state_sweep_interval_ms", 1000) or 1000),
        "loss_telemetry": str(getattr(args, "loss_telemetry", "auto")),
        "loss_iface": str(getattr(args, "loss_iface", "")),
        "loss_fail_pct": float(getattr(args, "loss_fail_pct", 5.0) or 5.0),
        "sender_backend": str(getattr(args, "sender_backend", "auto")),
        "sender_fallback_policy": str(getattr(args, "sender_fallback_policy", "allow")),
        "dataplane_core_mode": str(getattr(args, "dataplane_core_mode", "off")),
        "afpacket_hugepage_mode": str(getattr(args, "afpacket_hugepage_mode", "off")),
    }


def build_loss_summary(results: dict, finished_utc: str) -> dict:
    src = dict(results or {})
    return {
        "schema_version": "1",
        "generated_at_utc": str(finished_utc or ""),
        "attempted_total": int(src.get("attempted_total", 0) or 0),
        "sent_total": int(src.get("sent_total", 0) or 0),
        "errors_total": int(src.get("errors_total", 0) or 0),
        "sender_paths_used": dict(src.get("sender_paths_used", {}) or {}),
        "sender_fallback_reason": str(src.get("sender_fallback_reason", "none") or "none"),
        "wire_loss_est_packets": int(src.get("wire_loss_est_packets", 0) or 0),
        "wire_loss_est_pct": float(src.get("wire_loss_est_pct", 0.0) or 0.0),
        "wire_loss_raw_packets": int(src.get("wire_loss_raw_packets", 0) or 0),
        "wire_loss_raw_pct": float(src.get("wire_loss_raw_pct", 0.0) or 0.0),
        "wire_loss_fail_pct": float(src.get("wire_loss_fail_pct", 5.0) or 5.0),
        "wire_loss_status": str(src.get("wire_loss_status", "ok") or "ok"),
        "txring_flush_call_count": int(src.get("txring_flush_call_count", 0) or 0),
        "txring_flush_error_count": int(src.get("txring_flush_error_count", 0) or 0),
        "txring_flush_eagain_count": int(src.get("txring_flush_eagain_count", 0) or 0),
        "txring_flush_enobufs_count": int(src.get("txring_flush_enobufs_count", 0) or 0),
        "txring_flush_ebusy_count": int(src.get("txring_flush_ebusy_count", 0) or 0),
        "txring_flush_other_errno_count": int(src.get("txring_flush_other_errno_count", 0) or 0),
        "txring_flush_last_errno": int(src.get("txring_flush_last_errno", 0) or 0),
        "txring_flush_last_errno_name": str(src.get("txring_flush_last_errno_name", "") or ""),
        "txring_tp_packets": int(src.get("txring_tp_packets", 0) or 0),
        "txring_tp_drops": int(src.get("txring_tp_drops", 0) or 0),
        "txring_tp_freeze_q_cnt": int(src.get("txring_tp_freeze_q_cnt", 0) or 0),
        "afpacket_ring_block_size": int(src.get("afpacket_ring_block_size", 0) or 0),
        "afpacket_ring_block_nr": int(src.get("afpacket_ring_block_nr", 0) or 0),
        "afpacket_ring_size_bytes": int(src.get("afpacket_ring_size_bytes", 0) or 0),
        "wire_tx_accounted_packets": int(src.get("wire_tx_accounted_packets", 0) or 0),
        "wire_tx_over_attempted_packets": int(src.get("wire_tx_over_attempted_packets", 0) or 0),
    }
