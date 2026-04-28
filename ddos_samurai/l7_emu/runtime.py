from __future__ import annotations

import asyncio
from typing import Any, Dict

from .. import utils
from .types import L7EmuProfile, RunResult, RuntimeConfig

log_warning = utils.log_warning

try:
    from .. import _l7_emu_native as _native
except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):  # pragma: no cover
    _native = None


def _unavailable_stats(profile: L7EmuProfile) -> Dict[str, Any]:
    attempted = int(profile.flow_attempted)
    out = {
        "attempted": attempted,
        "sent": 0,
        "errors": attempted,
        "sender_path": str(profile.sender_path),
        "sender_fallback_reason": "l7_emu_native_unavailable",
        "l7_engine_path_used": "L7_EMU_NATIVE",
        "l7_fallback_reason": "l7_emu_native_unavailable",
        "l7_flow_attempted": attempted,
        "l7_flow_completed": 0,
        "l7_conn_attempted": 0,
        "l7_conn_established": 0,
        "l7_conn_reused": 0,
        "l7_rx_bytes": 0,
        "l7_tx_bytes": 0,
        "l7_cps": 0.0,
        "l7_rps": 0.0,
        "l7_active_conn_peak": 0,
        "l7_h1_conn_reuse_ratio": 0.0,
        "l7_h2_lane_reuse_ratio": 0.0,
        "l7_epoll_wakeups": 0,
        "l7_scheduler_queue_depth_peak": 0,
        "l7_idle_evictions": 0,
        "l7_rx_syscalls": 0,
        "l7_tx_syscalls": 0,
        "l7_alloc_bytes": 0,
        "l7_alloc_count": 0,
        "l7_tls_handshake_p50_ms": 0.0,
        "l7_tls_handshake_p95_ms": 0.0,
        "l7_tls_handshake_p99_ms": 0.0,
        "l7_request_latency_p50_ms": 0.0,
        "l7_request_latency_p95_ms": 0.0,
        "l7_request_latency_p99_ms": 0.0,
        "l7_profile_enabled": 0,
        "l7_profile_snapshot_count": 0,
        "runtime_reactor_backend": "socket_epoll",
        "runtime_transport_backend": str(profile.connection_template.transport_backend),
        "runtime_tls_backend": "openssl" if _native is not None else "unavailable",
        "runtime_http2_backend": "nghttp2_native" if _native is not None else "unavailable",
        "runtime_native_hot_path_level": "userspace_reactor_templates" if _native is not None else "basic",
        "l7_status_2xx": 0,
        "l7_status_3xx": 0,
        "l7_status_4xx": 0,
        "l7_status_5xx": 0,
        "l7_expectation_failures": attempted,
        "l7_scheduler_backpressure_count": 0,
        "h2_goaway_replacements": 0,
        "h2_drain_evictions": 0,
        "h2_replace_now_decisions": 0,
        "h2_replace_after_idle_decisions": 0,
        "h2_stream_pool_reuse_hits": 0,
    }
    if str(profile.protocol or "").strip().lower() == "quic":
        out.update(
            {
                "sender_path": "L7_QUIC_CUSTOM",
                "sender_fallback_reason": "quic_capability_unavailable",
                "l7_engine_path_used": "L7_QUIC_CUSTOM",
                "l7_fallback_reason": "quic_capability_unavailable",
                "quic_stack_mode": "unavailable",
                "quic_capability_available": 0,
                "quic_conn_pool_size": max(1, int(getattr(profile.connection_template, "max_connections", 1) or 1)),
                "quic_connection_attempts": attempted,
                "quic_connection_success": 0,
                "quic_requests_sent": attempted,
                "quic_responses_received": 0,
                "quic_timeouts": attempted,
                "quic_errors": attempted,
                "quic_handshake_success_ratio": 0.0,
                "quic_alpn_h3_ratio": 0.0,
            }
        )
    return out


async def run_l7_profile(
    profile: L7EmuProfile,
    runtime_cfg: RuntimeConfig,
) -> RunResult:
    if _native is None:
        log_warning("L7 emulation native module unavailable; run will fail-visible.")
        return RunResult(stats=_unavailable_stats(profile))
    stats = await asyncio.to_thread(_native.run_profile, profile.as_dict(), runtime_cfg.as_dict())
    return RunResult(stats=dict(stats or {}))
