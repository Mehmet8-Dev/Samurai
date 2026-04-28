import asyncio
import time
from typing import Any, Dict

from .. import utils
from ..l7 import telemetry as l7_telemetry
from ..pacing import PacingMode

log_warning = utils.log_warning


def _stats(attempted: int = 0, sent: int = 0, errors: int = 0, bytes_sent_est: int = 0, **extra):
    out = {
        "attempted": int(attempted),
        "sent": int(sent),
        "errors": int(errors),
        "bytes_sent_est": int(bytes_sent_est),
        "buffer_copy_count": 0,
        "buffer_copy_bytes": 0,
        "eagain_retry_count": 0,
        "partial_send_retry_count": 0,
        "buffer_reuse_hits": 0,
        "sender_fallback_reason": "none",
        "sender_backend_requested": "auto",
        "sender_fallback_policy": "fail",
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
        "gpu_template_h2d_copy_count": 0,
        "gpu_template_h2d_copy_bytes": 0,
        "gpu_rng_state_alloc_count": 0,
        "gpu_rng_state_reuse_count": 0,
        "l7_active_sessions_peak": 0,
        "l7_conn_rate": 0.0,
        "l7_handshake_p99_ms": 0.0,
        "l7_step_fail_ratio": 0.0,
        "l7_flow_attempted": 0,
        "l7_flow_completed": 0,
        "l7_conn_attempted": 0,
        "l7_conn_established": 0,
        "l7_conn_reused": 0,
        "l7_rx_bytes": 0,
        "l7_tx_bytes": 0,
        "l7_status_2xx": 0,
        "l7_status_3xx": 0,
        "l7_status_4xx": 0,
        "l7_status_5xx": 0,
        "l7_expectation_failures": 0,
        "l7_scheduler_backpressure_count": 0,
        "session_success_rate": 0.0,
        "retry_success_rate": 0.0,
        "dp_queue_id": -1,
        "dp_queue_strategy": "unknown",
        "dp_affinity_cpu": -1,
    }
    for k, v in extra.items():
        if isinstance(v, bool):
            out[k] = int(v)
        elif isinstance(v, (int, float)):
            out[k] = float(v) if isinstance(v, float) else int(v)
        elif isinstance(v, str):
            out[k] = v
    return out


def _normalize_l7_output(
    raw_stats: Dict[str, Any],
    *,
    attempted_default: int = 0,
    sender_path: str = "",
    engine_path_used: str = "",
    fallback_reason: str = "none",
    route=None,
) -> Dict[str, Any]:
    out = l7_telemetry.normalize_l7_stats(
        raw_stats,
        attempted_default=attempted_default,
        sender_path=sender_path,
        engine_path_used=engine_path_used,
        fallback_reason=fallback_reason,
    )
    if route is not None:
        out.update(route.as_stats())
    if engine_path_used:
        out["l7_engine_path_used"] = str(engine_path_used)
    return out


def _update_live(val, inc):
    try:
        if val is not None and inc:
            val.value += int(inc)
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        pass


def _env_flag(name: str, default: str = "1") -> bool:
    raw = str(default if default is not None else "0")
    value = str(__import__("os").environ.get(name, raw) or raw).strip().lower()
    return value not in {"0", "false", "no", "off", ""}


def _estimate_paced_packets(
    pacing_config,
    elapsed_s: float,
    progress_budget: int,
) -> int:
    if pacing_config is None:
        return 0
    if elapsed_s <= 0.0 or progress_budget <= 0:
        return 0
    try:
        cfg_mode = pacing_config.pacing_mode
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        return 0
    est = 0
    try:
        if cfg_mode == PacingMode.RPS:
            target_rps = float(getattr(pacing_config, "target_rps", 0.0) or 0.0)
            if target_rps > 0.0:
                est = int(elapsed_s * target_rps)
        elif cfg_mode == PacingMode.IPG:
            ipg_ns = int(getattr(pacing_config, "ipg_ns", 0) or 0)
            if ipg_ns > 0:
                est = int((elapsed_s * 1_000_000_000.0) / float(ipg_ns))
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        est = 0
    if est <= 0:
        return 0
    return min(progress_budget, est)


class _PacedSendRuntimeError(RuntimeError):
    def __init__(self, cause: Exception, progress_emitted: int):
        super().__init__(str(cause))
        self.cause = cause
        self.progress_emitted = int(progress_emitted)


async def _run_paced_send_with_live_progress(
    send_call,
    *,
    pacing_config,
    progress_budget: int,
    live_progress=None,
) -> tuple[int, int]:
    loop = asyncio.get_running_loop()
    future = loop.run_in_executor(None, send_call)
    start_t = time.monotonic()
    progress_emitted = 0
    while True:
        done, _ = await asyncio.wait({future}, timeout=0.05)
        elapsed = time.monotonic() - start_t
        should_emit = _estimate_paced_packets(pacing_config, elapsed, progress_budget)
        delta = max(0, should_emit - progress_emitted)
        if delta > 0:
            _update_live(live_progress, delta)
            progress_emitted += delta
        if done:
            break
    try:
        sent = int(future.result() or 0)
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError) as exc:
        raise _PacedSendRuntimeError(exc, progress_emitted) from exc
    sent = max(0, min(int(progress_budget), sent))
    if sent > progress_emitted:
        tail = sent - progress_emitted
        _update_live(live_progress, tail)
        progress_emitted += tail
    return sent, progress_emitted


def _apply_pacing_stats(out: dict, stats: dict | None) -> dict:
    d = dict(out or {})
    st = dict(stats or {})

    d["actual_rps"] = float(st.get("actual_rps", 0.0) or 0.0)
    d["rate_accuracy_pct"] = float(st.get("rate_accuracy_pct", 0.0) or 0.0)
    d["jitter_p99_ns"] = float(st.get("jitter_p99_ns", 0.0) or 0.0)
    d["ipg_mean_ns"] = float(st.get("ipg_mean_ns", 0.0) or 0.0)
    d["sleep_calls"] = int(st.get("sleep_calls", 0) or 0)
    d["busywait_cycles"] = int(st.get("busywait_cycles", 0) or 0)
    d["so_txtime_active"] = int(bool(st.get("so_txtime_active", 0)))
    d["txtime_errors"] = int(st.get("txtime_errors", 0) or 0)

    d["txring_flush_call_count"] = int(st.get("txring_flush_call_count", 0) or 0)
    d["txring_flush_error_count"] = int(st.get("txring_flush_error_count", 0) or 0)
    d["txring_flush_eagain_count"] = int(st.get("txring_flush_eagain_count", 0) or 0)
    d["txring_flush_enobufs_count"] = int(st.get("txring_flush_enobufs_count", 0) or 0)
    d["txring_flush_ebusy_count"] = int(st.get("txring_flush_ebusy_count", 0) or 0)
    d["txring_flush_other_errno_count"] = int(st.get("txring_flush_other_errno_count", 0) or 0)
    d["txring_flush_last_errno"] = int(st.get("txring_flush_last_errno", 0) or 0)
    d["txring_flush_last_errno_name"] = str(
        st.get("txring_flush_last_errno_name", "NONE") or "NONE"
    )
    d["txring_frame_wait_ns"] = int(st.get("txring_frame_wait_ns", 0) or 0)
    d["txring_poll_count"] = int(st.get("txring_poll_count", 0) or 0)
    d["txring_tp_packets"] = int(st.get("txring_tp_packets", 0) or 0)
    d["txring_tp_drops"] = int(st.get("txring_tp_drops", 0) or 0)
    d["txring_tp_freeze_q_cnt"] = int(st.get("txring_tp_freeze_q_cnt", 0) or 0)
    d["txring_packet_version"] = int(st.get("txring_packet_version", 0) or 0)
    d["txring_packet_version_name"] = str(
        st.get("txring_packet_version_name", "TPACKET_UNKNOWN") or "TPACKET_UNKNOWN"
    )
    d["afpacket_hugepage_mode"] = str(st.get("afpacket_hugepage_mode", "off") or "off")
    d["afpacket_hugepage_effective"] = int(st.get("afpacket_hugepage_effective", 0) or 0)
    d["afpacket_hugepage_reason"] = str(st.get("afpacket_hugepage_reason", "none") or "none")
    d["afpacket_hugepage_size_kb"] = int(st.get("afpacket_hugepage_size_kb", 0) or 0)
    d["afpacket_madvise_hugepage_ok"] = int(st.get("afpacket_madvise_hugepage_ok", 0) or 0)
    d["afpacket_mlock_ok"] = int(st.get("afpacket_mlock_ok", 0) or 0)
    d["afpacket_prefault_pages"] = int(st.get("afpacket_prefault_pages", 0) or 0)
    d["afpacket_smaps_kernel_page_kb"] = int(st.get("afpacket_smaps_kernel_page_kb", 0) or 0)
    d["afpacket_smaps_anon_hugepages_kb"] = int(st.get("afpacket_smaps_anon_hugepages_kb", 0) or 0)
    d["afpacket_ring_block_size"] = int(st.get("afpacket_ring_block_size", 0) or 0)
    d["afpacket_ring_block_nr"] = int(st.get("afpacket_ring_block_nr", 0) or 0)
    d["afpacket_ring_size_bytes"] = int(st.get("afpacket_ring_size_bytes", 0) or 0)
    d["xdp_mode_requested"] = int(st.get("xdp_mode_requested", 0) or 0)
    d["xdp_mode_effective"] = int(st.get("xdp_mode_effective", 0) or 0)
    d["xdp_mode2_policy"] = str(st.get("xdp_mode2_policy", "soft") or "soft")
    d["xdp_mode2_probe_status"] = str(st.get("xdp_mode2_probe_status", "not_run") or "not_run")
    d["xdp_mode2_probe_reason"] = str(st.get("xdp_mode2_probe_reason", "not_run") or "not_run")
    d["xdp_sender_fallback_reason_detail"] = str(
        st.get("xdp_sender_fallback_reason_detail", "") or ""
    )
    if (
        str(d.get("afpacket_hugepage_mode", "off") or "off").strip().lower() == "required"
        and int(d.get("afpacket_hugepage_effective", 0) or 0) <= 0
    ):
        curr_reason = str(d.get("sender_fallback_reason", "none") or "none").strip().lower()
        if curr_reason in {"", "none"}:
            d["sender_fallback_reason"] = "afpacket_hugepage_required_not_met"
        d["fallback_count"] = max(1, int(d.get("fallback_count", 0) or 0))
    return d


def _recompute_loss_metrics(out: dict) -> dict:
    d = dict(out or {})
    attempted = max(0, int(d.get("attempted", 0) or 0))
    tx_packets = max(0, int(d.get("txring_tp_packets", 0) or 0))
    tx_drops = max(0, int(d.get("txring_tp_drops", 0) or 0))
    wire_tx_packets = max(0, int(d.get("wire_tx_packets_delta", 0) or 0))
    wire_counter_available = int(
        bool(
            int(
                d.get(
                    "wire_counter_available",
                    1 if ("wire_tx_packets_delta" in d or "host_tx_packets_delta" in d) else 0,
                )
                or 0
            )
        )
    )
    wire_counter_confidence = max(0.0, min(1.0, float(d.get("wire_counter_confidence", 0.0) or 0.0)))
    wire_counter_source = str(d.get("wire_counter_source", "none") or "none")
    wire_counter_reason = str(d.get("wire_counter_reason", "") or "")
    nicq_counter_available = int(
        bool(
            int(
                d.get(
                    "nicq_counter_available",
                    1 if ("nicq_pressure_delta" in d or "nicq_drop_delta" in d) else 0,
                )
                or 0
            )
        )
    )
    nicq_counter_confidence = max(0.0, min(1.0, float(d.get("nicq_counter_confidence", 0.0) or 0.0)))
    nicq_counter_source = str(d.get("nicq_counter_source", "none") or "none")
    nicq_counter_reason = str(d.get("nicq_counter_reason", "") or "")
    nicq_drop_delta = max(0, int(d.get("nicq_drop_delta", 0) or 0))
    nicq_fifo_delta = max(0, int(d.get("nicq_fifo_delta", 0) or 0))
    nicq_timeout_delta = max(0, int(d.get("nicq_timeout_delta", 0) or 0))
    nicq_restart_delta = max(0, int(d.get("nicq_restart_delta", 0) or 0))
    nicq_busy_delta = max(0, int(d.get("nicq_busy_delta", 0) or 0))
    nicq_pressure_delta = max(0, int(d.get("nicq_pressure_delta", 0) or 0))
    nicq_pressure_delta = max(
        nicq_pressure_delta,
        nicq_drop_delta + nicq_fifo_delta + nicq_timeout_delta + nicq_restart_delta + nicq_busy_delta,
    )
    legacy_host_tx_packets = max(0, int(d.get("host_tx_packets_delta", 0) or 0))
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
    host_tx_dropped = max(0, int(d.get("host_tx_dropped_delta", 0) or 0))
    existing_est = max(0, int(d.get("wire_loss_est_packets", 0) or 0))
    existing_raw = max(
        0,
        int(d.get("wire_loss_raw_packets", 0) or 0),
        int(d.get("wire_loss_raw_uncapped_packets", 0) or 0),
    )
    flush_calls = max(0, int(d.get("txring_flush_call_count", 0) or 0))
    flush_errors = max(0, int(d.get("txring_flush_error_count", 0) or 0))
    flush_eagain = max(0, int(d.get("txring_flush_eagain_count", 0) or 0))
    flush_enobufs = max(0, int(d.get("txring_flush_enobufs_count", 0) or 0))
    flush_ebusy = max(0, int(d.get("txring_flush_ebusy_count", 0) or 0))
    flush_other_errno = max(0, int(d.get("txring_flush_other_errno_count", 0) or 0))

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
        if host_tx_dropped > 0:
            raw_loss_packets = max(raw_loss_packets, host_tx_dropped)
            est_loss_packets = min(attempted, max(est_loss_packets, host_tx_dropped))
            measurement_mode = "host_tx_dropped_fallback"

    raw_over_attempted = max(0, raw_loss_packets - attempted)
    raw_over_attempted_pct = float((100.0 * raw_over_attempted) / max(1, attempted))

    d["wire_counter_available"] = int(wire_counter_available)
    d["wire_counter_source"] = str(wire_counter_source)
    d["wire_counter_confidence"] = float(wire_counter_confidence)
    d["wire_counter_reason"] = str(wire_counter_reason)
    d["nicq_counter_available"] = int(nicq_counter_available)
    d["nicq_counter_source"] = str(nicq_counter_source)
    d["nicq_counter_confidence"] = float(nicq_counter_confidence)
    d["nicq_counter_reason"] = str(nicq_counter_reason)
    d["nicq_pressure_delta"] = int(nicq_pressure_delta) if nicq_counter_available else 0
    d["nicq_drop_delta"] = int(nicq_drop_delta) if nicq_counter_available else 0
    d["nicq_fifo_delta"] = int(nicq_fifo_delta) if nicq_counter_available else 0
    d["nicq_timeout_delta"] = int(nicq_timeout_delta) if nicq_counter_available else 0
    d["nicq_restart_delta"] = int(nicq_restart_delta) if nicq_counter_available else 0
    d["nicq_busy_delta"] = int(nicq_busy_delta) if nicq_counter_available else 0
    d["nicq_pressure_status"] = (
        "warn" if int(d["nicq_pressure_delta"]) > 0 else "ok"
    ) if nicq_counter_available else "unknown"
    d["wire_tx_accounted_packets"] = int(wire_tx_accounted_packets)
    d["wire_tx_over_attempted_packets"] = int(wire_tx_over_attempted_packets)
    d["wire_loss_measurement_mode"] = str(measurement_mode)
    d["wire_loss_raw_packets"] = int(raw_loss_packets)
    d["wire_loss_raw_uncapped_packets"] = int(raw_loss_packets)
    d["wire_loss_raw_pct"] = float((100.0 * raw_loss_packets) / max(1, attempted))
    d["wire_loss_raw_pct_of_attempted"] = float(d["wire_loss_raw_pct"])
    d["wire_loss_raw_over_attempted_packets"] = int(raw_over_attempted)
    d["wire_loss_raw_over_attempted_pct"] = float(raw_over_attempted_pct)
    d["wire_loss_raw_gt_attempted"] = int(raw_over_attempted > 0)
    d["wire_loss_est_packets"] = int(est_loss_packets)
    d["wire_loss_est_pct"] = float((100.0 * est_loss_packets) / max(1, attempted))
    d["wire_loss_estimation_capped"] = int(raw_loss_packets > est_loss_packets)
    d["txring_drop_ratio_pct"] = float((100.0 * tx_drops_bounded) / max(1, tx_packets))
    d["txring_flush_error_ratio_pct"] = float((100.0 * flush_errors) / max(1, flush_calls))
    d["txring_flush_eagain_ratio_pct"] = float((100.0 * flush_eagain) / max(1, flush_calls))
    d["txring_flush_enobufs_ratio_pct"] = float((100.0 * flush_enobufs) / max(1, flush_calls))
    d["txring_flush_ebusy_ratio_pct"] = float((100.0 * flush_ebusy) / max(1, flush_calls))
    d["txring_flush_other_errno_ratio_pct"] = float((100.0 * flush_other_errno) / max(1, flush_calls))
    return d


def _loss_telemetry_enabled() -> bool:
    os = __import__("os")
    mode = str(os.environ.get("SAMURAI_LOSS_TELEMETRY", "auto") or "auto").strip().lower()
    return mode not in {"0", "false", "off", "no", "disabled"}


def _resolve_loss_iface(preferred_iface=None):
    os = __import__("os")
    env_iface = str(os.environ.get("SAMURAI_LOSS_IFACE", "") or "").strip()
    if env_iface:
        return env_iface
    return preferred_iface


def _take_loss_snapshot(preferred_iface=None):
    if not _loss_telemetry_enabled():
        return {}
    try:
        from .. import loss_telemetry
        return dict(loss_telemetry.snapshot(iface=_resolve_loss_iface(preferred_iface)) or {})
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        return {}


def _take_loss_delta(before: dict, preferred_iface=None) -> dict:
    if not isinstance(before, dict) or not before:
        return {}
    try:
        from .. import loss_telemetry
        after = dict(loss_telemetry.snapshot(iface=_resolve_loss_iface(preferred_iface)) or {})
        return dict(loss_telemetry.delta(before, after) or {})
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        return {}


def _attach_loss_telemetry(stats_out: dict, before_snapshot: dict, preferred_iface=None) -> dict:
    out = dict(stats_out or {})
    delta = _take_loss_delta(before_snapshot, preferred_iface=preferred_iface)

    out["host_tx_packets_delta"] = int(delta.get("host_tx_packets_delta", 0) or 0)
    out["host_tx_dropped_delta"] = int(delta.get("host_tx_dropped_delta", 0) or 0)
    out["host_tx_errors_delta"] = int(delta.get("host_tx_errors_delta", 0) or 0)
    out["softnet_dropped_delta"] = int(delta.get("softnet_dropped_delta", 0) or 0)
    out["softnet_time_squeeze_delta"] = int(delta.get("softnet_time_squeeze_delta", 0) or 0)
    out["wire_counter_available"] = int(delta.get("wire_counter_available", 0) or 0)
    out["wire_counter_source"] = str(delta.get("wire_counter_source", "none") or "none")
    out["wire_counter_confidence"] = float(delta.get("wire_counter_confidence", 0.0) or 0.0)
    out["wire_counter_reason"] = str(delta.get("wire_counter_reason", "") or "")
    out["wire_tx_packets_delta"] = int(delta.get("wire_tx_packets_delta", 0) or 0)
    out["wire_tx_dropped_delta"] = int(delta.get("wire_tx_dropped_delta", 0) or 0)
    out["wire_tx_errors_delta"] = int(delta.get("wire_tx_errors_delta", 0) or 0)
    out["wire_tx_bytes_delta"] = int(delta.get("wire_tx_bytes_delta", 0) or 0)
    out["nicq_counter_available"] = int(delta.get("nicq_counter_available", 0) or 0)
    out["nicq_counter_source"] = str(delta.get("nicq_counter_source", "none") or "none")
    out["nicq_counter_confidence"] = float(delta.get("nicq_counter_confidence", 0.0) or 0.0)
    out["nicq_counter_reason"] = str(delta.get("nicq_counter_reason", "") or "")
    out["nicq_pressure_delta"] = int(delta.get("nicq_pressure_delta", 0) or 0)
    out["nicq_drop_delta"] = int(delta.get("nicq_drop_delta", 0) or 0)
    out["nicq_fifo_delta"] = int(delta.get("nicq_fifo_delta", 0) or 0)
    out["nicq_timeout_delta"] = int(delta.get("nicq_timeout_delta", 0) or 0)
    out["nicq_restart_delta"] = int(delta.get("nicq_restart_delta", 0) or 0)
    out["nicq_busy_delta"] = int(delta.get("nicq_busy_delta", 0) or 0)
    return _recompute_loss_metrics(out)


def _merge_stats(*items):
    acc = _stats(
        buffer_copy_count=0,
        buffer_copy_bytes=0,
        eagain_retry_count=0,
        partial_send_retry_count=0,
        buffer_reuse_hits=0,
        permission_error_count=0,
        fallback_count=0,
        sender_fallback_reason="none",
        sender_backend_requested="auto",
        sender_fallback_policy="allow",
        txring_batch_target=0,
        txring_backoff_ns=0,
        l7_active_sessions_peak=0,
        l7_conn_rate=0.0,
        l7_handshake_p99_ms=0.0,
        l7_step_fail_ratio=0.0,
        session_success_rate=0.0,
        retry_success_rate=0.0,
        dp_queue_id=-1,
        dp_queue_strategy="unknown",
        dp_affinity_cpu=-1,
    )
    for it in items:
        if not isinstance(it, dict):
            continue
        acc["attempted"] += int(it.get("attempted", 0) or 0)
        acc["sent"] += int(it.get("sent", 0) or 0)
        acc["errors"] += int(it.get("errors", 0) or 0)
        acc["bytes_sent_est"] += int(it.get("bytes_sent_est", 0) or 0)
        acc["buffer_copy_count"] += int(it.get("buffer_copy_count", 0) or 0)
        acc["buffer_copy_bytes"] += int(it.get("buffer_copy_bytes", 0) or 0)
        acc["eagain_retry_count"] += int(it.get("eagain_retry_count", 0) or 0)
        acc["partial_send_retry_count"] += int(it.get("partial_send_retry_count", 0) or 0)
        acc["buffer_reuse_hits"] += int(it.get("buffer_reuse_hits", 0) or 0)
        item_actual_rps = float(it.get("actual_rps", 0.0) or 0.0)
        if item_actual_rps > 0.0 or float(acc.get("actual_rps", 0.0) or 0.0) == 0.0:
            acc["actual_rps"] = item_actual_rps
        item_rate_accuracy = float(it.get("rate_accuracy_pct", 0.0) or 0.0)
        if item_rate_accuracy > 0.0 or float(acc.get("rate_accuracy_pct", 0.0) or 0.0) == 0.0:
            acc["rate_accuracy_pct"] = item_rate_accuracy
        item_jitter_p99 = float(it.get("jitter_p99_ns", 0.0) or 0.0)
        if item_jitter_p99 > 0.0 or float(acc.get("jitter_p99_ns", 0.0) or 0.0) == 0.0:
            acc["jitter_p99_ns"] = item_jitter_p99
        item_ipg_mean = float(it.get("ipg_mean_ns", 0.0) or 0.0)
        if item_ipg_mean > 0.0 or float(acc.get("ipg_mean_ns", 0.0) or 0.0) == 0.0:
            acc["ipg_mean_ns"] = item_ipg_mean
        acc["sleep_calls"] += int(it.get("sleep_calls", 0) or 0)
        acc["busywait_cycles"] += int(it.get("busywait_cycles", 0) or 0)
        acc["so_txtime_active"] = max(
            int(acc.get("so_txtime_active", 0) or 0),
            int(bool(it.get("so_txtime_active", 0))),
        )
        acc["txtime_errors"] += int(it.get("txtime_errors", 0) or 0)
        acc["permission_error_count"] += int(it.get("permission_error_count", 0) or 0)
        acc["fallback_count"] += int(it.get("fallback_count", 0) or 0)
        item_fallback_reason = str(it.get("sender_fallback_reason", "") or "").strip()
        if item_fallback_reason:
            curr_reason = str(acc.get("sender_fallback_reason", "") or "").strip()
            if not curr_reason or curr_reason == "none":
                acc["sender_fallback_reason"] = item_fallback_reason
            elif curr_reason != item_fallback_reason and curr_reason != "mixed":
                acc["sender_fallback_reason"] = "mixed"
        item_sender_backend_requested = str(it.get("sender_backend_requested", "") or "").strip()
        if item_sender_backend_requested:
            curr_backend = str(acc.get("sender_backend_requested", "") or "").strip()
            if not curr_backend or curr_backend == "auto":
                acc["sender_backend_requested"] = item_sender_backend_requested
            elif curr_backend != item_sender_backend_requested and curr_backend != "mixed":
                acc["sender_backend_requested"] = "mixed"
        item_sender_fallback_policy = str(it.get("sender_fallback_policy", "") or "").strip()
        if item_sender_fallback_policy:
            curr_policy = str(acc.get("sender_fallback_policy", "") or "").strip()
            if not curr_policy or curr_policy == "allow":
                acc["sender_fallback_policy"] = item_sender_fallback_policy
            elif curr_policy != item_sender_fallback_policy and curr_policy != "mixed":
                acc["sender_fallback_policy"] = "mixed"
        acc["txring_flush_call_count"] += int(it.get("txring_flush_call_count", 0) or 0)
        acc["txring_flush_error_count"] += int(it.get("txring_flush_error_count", 0) or 0)
        acc["txring_flush_eagain_count"] += int(it.get("txring_flush_eagain_count", 0) or 0)
        acc["txring_flush_enobufs_count"] += int(it.get("txring_flush_enobufs_count", 0) or 0)
        acc["txring_flush_ebusy_count"] += int(it.get("txring_flush_ebusy_count", 0) or 0)
        acc["txring_flush_other_errno_count"] += int(it.get("txring_flush_other_errno_count", 0) or 0)
        _item_last_errno = int(it.get("txring_flush_last_errno", 0) or 0)
        _item_last_errno_name = str(it.get("txring_flush_last_errno_name", "") or "").strip()
        if _item_last_errno or _item_last_errno_name:
            acc["txring_flush_last_errno"] = _item_last_errno
            acc["txring_flush_last_errno_name"] = _item_last_errno_name or "OTHER"
        acc["txring_frame_wait_ns"] += int(it.get("txring_frame_wait_ns", 0) or 0)
        acc["txring_poll_count"] += int(it.get("txring_poll_count", 0) or 0)
        item_flush_mode = str(it.get("flush_mode", "") or "").strip()
        if item_flush_mode:
            curr_flush_mode = str(acc.get("flush_mode", "") or "").strip()
            if not curr_flush_mode or curr_flush_mode == "unknown":
                acc["flush_mode"] = item_flush_mode
            elif curr_flush_mode != item_flush_mode and curr_flush_mode != "mixed":
                acc["flush_mode"] = "mixed"
        acc["txring_tp_packets"] += int(it.get("txring_tp_packets", 0) or 0)
        acc["txring_tp_drops"] += int(it.get("txring_tp_drops", 0) or 0)
        acc["txring_tp_freeze_q_cnt"] += int(it.get("txring_tp_freeze_q_cnt", 0) or 0)
        acc["txring_batch_target"] = max(
            int(acc.get("txring_batch_target", 0) or 0),
            int(it.get("txring_batch_target", 0) or 0),
        )
        acc["txring_backoff_ns"] += int(it.get("txring_backoff_ns", 0) or 0)
        item_txring_ver = int(it.get("txring_packet_version", 0) or 0)
        item_txring_ver_name = str(it.get("txring_packet_version_name", "") or "").strip()
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
        item_hp_mode = str(it.get("afpacket_hugepage_mode", "") or "").strip().lower()
        if item_hp_mode:
            current_hp_mode = str(acc.get("afpacket_hugepage_mode", "") or "").strip().lower()
            if not current_hp_mode or current_hp_mode in {"off", "none", "unknown"}:
                acc["afpacket_hugepage_mode"] = item_hp_mode
                acc["afpacket_hugepage_effective"] = int(it.get("afpacket_hugepage_effective", 0) or 0)
                acc["afpacket_hugepage_reason"] = str(it.get("afpacket_hugepage_reason", "none") or "none")
            elif current_hp_mode != item_hp_mode and current_hp_mode != "mixed":
                acc["afpacket_hugepage_mode"] = "mixed"
                acc["afpacket_hugepage_reason"] = "mixed"
                acc["afpacket_hugepage_effective"] = min(
                    int(acc.get("afpacket_hugepage_effective", 0) or 0),
                    int(it.get("afpacket_hugepage_effective", 0) or 0),
                )
            else:
                acc["afpacket_hugepage_effective"] = min(
                    int(acc.get("afpacket_hugepage_effective", 0) or 0),
                    int(it.get("afpacket_hugepage_effective", 0) or 0),
                )
                item_hp_reason = str(it.get("afpacket_hugepage_reason", "") or "").strip()
                curr_hp_reason = str(acc.get("afpacket_hugepage_reason", "") or "").strip()
                if item_hp_reason:
                    if not curr_hp_reason or curr_hp_reason in {"none", "disabled"}:
                        acc["afpacket_hugepage_reason"] = item_hp_reason
                    elif curr_hp_reason != item_hp_reason and curr_hp_reason != "mixed":
                        acc["afpacket_hugepage_reason"] = "mixed"
        acc["afpacket_hugepage_size_kb"] = max(
            int(acc.get("afpacket_hugepage_size_kb", 0) or 0),
            int(it.get("afpacket_hugepage_size_kb", 0) or 0),
        )
        acc["afpacket_madvise_hugepage_ok"] = max(
            int(acc.get("afpacket_madvise_hugepage_ok", 0) or 0),
            int(it.get("afpacket_madvise_hugepage_ok", 0) or 0),
        )
        acc["afpacket_mlock_ok"] = max(
            int(acc.get("afpacket_mlock_ok", 0) or 0),
            int(it.get("afpacket_mlock_ok", 0) or 0),
        )
        acc["afpacket_prefault_pages"] += int(it.get("afpacket_prefault_pages", 0) or 0)
        acc["afpacket_smaps_kernel_page_kb"] = max(
            int(acc.get("afpacket_smaps_kernel_page_kb", 0) or 0),
            int(it.get("afpacket_smaps_kernel_page_kb", 0) or 0),
        )
        acc["afpacket_smaps_anon_hugepages_kb"] = max(
            int(acc.get("afpacket_smaps_anon_hugepages_kb", 0) or 0),
            int(it.get("afpacket_smaps_anon_hugepages_kb", 0) or 0),
        )
        acc["afpacket_ring_block_size"] = max(
            int(acc.get("afpacket_ring_block_size", 0) or 0),
            int(it.get("afpacket_ring_block_size", 0) or 0),
        )
        acc["afpacket_ring_block_nr"] = max(
            int(acc.get("afpacket_ring_block_nr", 0) or 0),
            int(it.get("afpacket_ring_block_nr", 0) or 0),
        )
        acc["afpacket_ring_size_bytes"] = max(
            int(acc.get("afpacket_ring_size_bytes", 0) or 0),
            int(it.get("afpacket_ring_size_bytes", 0) or 0),
        )
        acc["host_tx_packets_delta"] += int(it.get("host_tx_packets_delta", 0) or 0)
        acc["host_tx_dropped_delta"] += int(it.get("host_tx_dropped_delta", 0) or 0)
        acc["host_tx_errors_delta"] += int(it.get("host_tx_errors_delta", 0) or 0)
        acc["softnet_dropped_delta"] += int(it.get("softnet_dropped_delta", 0) or 0)
        acc["softnet_time_squeeze_delta"] += int(it.get("softnet_time_squeeze_delta", 0) or 0)
        item_wire_avail = int(
            it.get(
                "wire_counter_available",
                1 if ("wire_tx_packets_delta" in it or "host_tx_packets_delta" in it) else 0,
            )
            or 0
        )
        acc["wire_counter_available"] = max(int(acc.get("wire_counter_available", 0) or 0), item_wire_avail)
        item_wire_source = str(it.get("wire_counter_source", "") or "").strip()
        if item_wire_source:
            curr_wire_source = str(acc.get("wire_counter_source", "") or "").strip()
            if not curr_wire_source or curr_wire_source in ("none", "unknown"):
                acc["wire_counter_source"] = item_wire_source
            elif curr_wire_source != item_wire_source and curr_wire_source != "mixed":
                acc["wire_counter_source"] = "mixed"
        item_wire_reason = str(it.get("wire_counter_reason", "") or "").strip()
        if item_wire_reason:
            curr_wire_reason = str(acc.get("wire_counter_reason", "") or "").strip()
            if not curr_wire_reason:
                acc["wire_counter_reason"] = item_wire_reason
            elif item_wire_reason not in curr_wire_reason:
                acc["wire_counter_reason"] = f"{curr_wire_reason};{item_wire_reason}"
        acc["wire_counter_confidence"] = max(
            float(acc.get("wire_counter_confidence", 0.0) or 0.0),
            float(it.get("wire_counter_confidence", 0.0) or 0.0),
        )
        acc["wire_tx_packets_delta"] += int(it.get("wire_tx_packets_delta", 0) or 0)
        acc["wire_tx_dropped_delta"] += int(it.get("wire_tx_dropped_delta", 0) or 0)
        acc["wire_tx_errors_delta"] += int(it.get("wire_tx_errors_delta", 0) or 0)
        acc["wire_tx_bytes_delta"] += int(it.get("wire_tx_bytes_delta", 0) or 0)
        item_nicq_avail = int(
            it.get(
                "nicq_counter_available",
                1 if ("nicq_pressure_delta" in it or "nicq_drop_delta" in it) else 0,
            )
            or 0
        )
        acc["nicq_counter_available"] = max(int(acc.get("nicq_counter_available", 0) or 0), item_nicq_avail)
        item_nicq_source = str(it.get("nicq_counter_source", "") or "").strip()
        if item_nicq_source:
            curr_nicq_source = str(acc.get("nicq_counter_source", "") or "").strip()
            if not curr_nicq_source or curr_nicq_source in ("none", "unknown"):
                acc["nicq_counter_source"] = item_nicq_source
            elif curr_nicq_source != item_nicq_source and curr_nicq_source != "mixed":
                acc["nicq_counter_source"] = "mixed"
        item_nicq_reason = str(it.get("nicq_counter_reason", "") or "").strip()
        if item_nicq_reason:
            curr_nicq_reason = str(acc.get("nicq_counter_reason", "") or "").strip()
            if not curr_nicq_reason:
                acc["nicq_counter_reason"] = item_nicq_reason
            elif item_nicq_reason not in curr_nicq_reason:
                acc["nicq_counter_reason"] = f"{curr_nicq_reason};{item_nicq_reason}"
        acc["nicq_counter_confidence"] = max(
            float(acc.get("nicq_counter_confidence", 0.0) or 0.0),
            float(it.get("nicq_counter_confidence", 0.0) or 0.0),
        )
        acc["nicq_pressure_delta"] += int(it.get("nicq_pressure_delta", 0) or 0)
        acc["nicq_drop_delta"] += int(it.get("nicq_drop_delta", 0) or 0)
        acc["nicq_fifo_delta"] += int(it.get("nicq_fifo_delta", 0) or 0)
        acc["nicq_timeout_delta"] += int(it.get("nicq_timeout_delta", 0) or 0)
        acc["nicq_restart_delta"] += int(it.get("nicq_restart_delta", 0) or 0)
        acc["nicq_busy_delta"] += int(it.get("nicq_busy_delta", 0) or 0)
        acc["wire_loss_est_packets"] += int(it.get("wire_loss_est_packets", 0) or 0)
        _raw_uncapped = int(it.get("wire_loss_raw_uncapped_packets", it.get("wire_loss_raw_packets", 0)) or 0)
        acc["wire_loss_raw_packets"] += int(it.get("wire_loss_raw_packets", _raw_uncapped) or 0)
        acc["wire_loss_raw_uncapped_packets"] += _raw_uncapped
        acc["gpu_template_h2d_copy_count"] += int(it.get("gpu_template_h2d_copy_count", 0) or 0)
        acc["gpu_template_h2d_copy_bytes"] += int(it.get("gpu_template_h2d_copy_bytes", 0) or 0)
        acc["gpu_rng_state_alloc_count"] += int(it.get("gpu_rng_state_alloc_count", 0) or 0)
        acc["gpu_rng_state_reuse_count"] += int(it.get("gpu_rng_state_reuse_count", 0) or 0)
        acc["l7_active_sessions_peak"] = max(
            int(acc.get("l7_active_sessions_peak", 0) or 0),
            int(it.get("l7_active_sessions_peak", 0) or 0),
        )
        item_l7_conn_rate = float(it.get("l7_conn_rate", 0.0) or 0.0)
        if item_l7_conn_rate > 0.0 or float(acc.get("l7_conn_rate", 0.0) or 0.0) == 0.0:
            acc["l7_conn_rate"] = item_l7_conn_rate
        acc["l7_handshake_p99_ms"] = max(
            float(acc.get("l7_handshake_p99_ms", 0.0) or 0.0),
            float(it.get("l7_handshake_p99_ms", 0.0) or 0.0),
        )
        item_l7_step_fail_ratio = float(it.get("l7_step_fail_ratio", 0.0) or 0.0)
        if item_l7_step_fail_ratio > 0.0 or float(acc.get("l7_step_fail_ratio", 0.0) or 0.0) == 0.0:
            acc["l7_step_fail_ratio"] = item_l7_step_fail_ratio
        item_session_success_rate = float(it.get("session_success_rate", 0.0) or 0.0)
        if item_session_success_rate > 0.0 or float(acc.get("session_success_rate", 0.0) or 0.0) == 0.0:
            acc["session_success_rate"] = item_session_success_rate
        item_retry_success_rate = float(it.get("retry_success_rate", 0.0) or 0.0)
        if item_retry_success_rate > 0.0 or float(acc.get("retry_success_rate", 0.0) or 0.0) == 0.0:
            acc["retry_success_rate"] = item_retry_success_rate
        item_dp_queue_id = int(it.get("dp_queue_id", -1) or -1)
        if item_dp_queue_id >= 0:
            curr_dp_queue_id = int(acc.get("dp_queue_id", -1) or -1)
            if curr_dp_queue_id < 0:
                acc["dp_queue_id"] = item_dp_queue_id
            elif curr_dp_queue_id != item_dp_queue_id:
                acc["dp_queue_id"] = -2
        item_dp_queue_strategy = str(it.get("dp_queue_strategy", "") or "").strip()
        if item_dp_queue_strategy:
            curr_dp_queue_strategy = str(acc.get("dp_queue_strategy", "") or "").strip()
            if not curr_dp_queue_strategy or curr_dp_queue_strategy == "unknown":
                acc["dp_queue_strategy"] = item_dp_queue_strategy
            elif curr_dp_queue_strategy != item_dp_queue_strategy and curr_dp_queue_strategy != "mixed":
                acc["dp_queue_strategy"] = "mixed"
        item_dp_affinity_cpu = int(it.get("dp_affinity_cpu", -1) or -1)
        if item_dp_affinity_cpu >= 0:
            curr_dp_affinity_cpu = int(acc.get("dp_affinity_cpu", -1) or -1)
            if curr_dp_affinity_cpu < 0:
                acc["dp_affinity_cpu"] = item_dp_affinity_cpu
            elif curr_dp_affinity_cpu != item_dp_affinity_cpu:
                acc["dp_affinity_cpu"] = -2
        if "sender_path" in it:
            acc["sender_path"] = str(it.get("sender_path") or "")
    return _recompute_loss_metrics(acc)
