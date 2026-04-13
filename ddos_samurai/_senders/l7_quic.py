from __future__ import annotations

import asyncio
from typing import Any

from ..l7_emu import compile_l7_profile as _compile_l7_profile
from ..l7_emu import run_l7_profile as _run_l7_profile
from ..l7_emu.types import RuntimeConfig
from . import runtime as _sender_runtime


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def _parity_metrics(raw: dict[str, Any] | None = None) -> dict[str, float]:
    src = raw or {}
    phase = max(1, _to_int(src.get("quic_h3_parity_phase", 1), 1))
    target = max(1, _to_int(src.get("quic_h3_parity_target_phase", 5), 5))
    return {
        "quic_h3_parity_phase": phase,
        "quic_h3_parity_target_phase": target,
        "quic_h3_parity_progress_ratio": _to_float(src.get("quic_h3_parity_progress_ratio", float(phase / float(target))), float(phase / float(target))),
        "quic_h3_parity_gap": max(0, _to_int(src.get("quic_h3_parity_gap", target - phase), target - phase)),
        "quic_h3_control_stream_ready": max(0, _to_int(src.get("quic_h3_control_stream_ready", 1), 1)),
        "quic_h3_qpack_dynamic_ready": max(0, _to_int(src.get("quic_h3_qpack_dynamic_ready", 0), 0)),
        "quic_h3_goaway_ready": max(0, _to_int(src.get("quic_h3_goaway_ready", 0), 0)),
        "quic_h3_priority_update_ready": max(0, _to_int(src.get("quic_h3_priority_update_ready", 0), 0)),
        "quic_h3_extended_connect_ready": max(0, _to_int(src.get("quic_h3_extended_connect_ready", 0), 0)),
        "quic_h3_datagram_ready": max(0, _to_int(src.get("quic_h3_datagram_ready", 0), 0)),
        "quic_h3_server_push_ready": max(0, _to_int(src.get("quic_h3_server_push_ready", 0), 0)),
        "quic_h3_goaway_events": max(0, _to_int(src.get("quic_h3_goaway_events", 0), 0)),
        "quic_h3_drain_cycles": max(0, _to_int(src.get("quic_h3_drain_cycles", 0), 0)),
        "quic_h3_replace_now": max(0, _to_int(src.get("quic_h3_replace_now", 0), 0)),
        "quic_h3_replace_after_idle": max(0, _to_int(src.get("quic_h3_replace_after_idle", 0), 0)),
        "quic_h3_control_plane_failures": max(0, _to_int(src.get("quic_h3_control_plane_failures", 0), 0)),
        "quic_h3_graceful_close_ratio": _to_float(src.get("quic_h3_graceful_close_ratio", 0.0), 0.0),
    }


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
    request_plan=None,
    live_sent=None,
    live_errors=None,
    live_progress=None,
    *,
    stats_fn,
    normalize_l7_output_fn,
    update_live_fn,
):
    _ = (
        verbose,
        ssl_context,
        retries,
        l7_fallback_policy,
        l7_capability_strict,
        lab_profile,
        quic_requests_per_conn,
        quic_expect_status_min,
        quic_expect_status_max,
        quic_require_response_headers,
        quic_require_response_body,
        quic_min_response_body_bytes,
        quic_expect_header_name,
        quic_expect_header_value_contains,
        quic_expect_body_substring,
    )
    attempted = max(0, _to_int(count, 0))
    pool_size = max(1, _to_int(quic_conn_pool_size, 1))
    stream_budget = max(1, _to_int(quic_streams_per_conn, max(1, _to_int(concurrency, 1))))

    if attempted <= 0:
        out = stats_fn(
            attempted=0,
            sent=0,
            errors=0,
            sender_path="L7_QUIC_CUSTOM",
            sender_fallback_reason="none",
            l7_engine_path_used="L7_QUIC_CUSTOM",
            l7_fallback_reason="none",
            quic_stack_mode="custom_native",
            quic_conn_pool_size=pool_size,
            quic_connection_attempts=0,
            quic_connection_success=0,
            quic_requests_sent=0,
            quic_responses_received=0,
            quic_timeouts=0,
            quic_errors=0,
            quic_handshake_success_ratio=0.0,
            quic_alpn_h3_ratio=0.0,
            **_parity_metrics(),
        )
        return normalize_l7_output_fn(
            out,
            attempted_default=0,
            sender_path="L7_QUIC_CUSTOM",
            engine_path_used="L7_QUIC_CUSTOM",
            fallback_reason="none",
        )

    native_available = bool(_sender_runtime.has_l7_native_quic())
    requested_engine = str(l7_quic_engine or "auto").strip().lower()

    if requested_engine == "python":
        out = stats_fn(
            attempted=attempted,
            sent=0,
            errors=attempted,
            sender_path="L7_QUIC_CUSTOM",
            sender_fallback_reason="quic_engine_python_removed",
            l7_engine_path_used="L7_QUIC_CUSTOM",
            l7_fallback_reason="quic_engine_python_removed",
            l7_flow_attempted=attempted,
            l7_flow_completed=0,
            l7_conn_attempted=attempted,
            l7_conn_established=0,
            l7_expectation_failures=attempted,
            quic_stack_mode="unavailable",
            quic_capability_available=0,
            quic_conn_pool_size=pool_size,
            quic_connection_attempts=attempted,
            quic_connection_success=0,
            quic_requests_sent=attempted,
            quic_responses_received=0,
            quic_timeouts=attempted,
            quic_errors=attempted,
            quic_handshake_success_ratio=0.0,
            quic_alpn_h3_ratio=0.0,
            **_parity_metrics(),
        )
        update_live_fn(live_errors, attempted)
        update_live_fn(live_progress, attempted)
        return normalize_l7_output_fn(
            out,
            attempted_default=attempted,
            sender_path="L7_QUIC_CUSTOM",
            engine_path_used="L7_QUIC_CUSTOM",
            fallback_reason="quic_engine_python_removed",
        )

    try:
        profile = _compile_l7_profile(
            protocol="quic",
            target_ip=str(target_ip),
            target_port=int(target_port),
            scheme="https",
            transport_backend="custom_tcp",
            stateful_runtime_backend="afxdp",
            stateful_runtime_strict=False,
            legacy_mode=True,
            template_mode="compat",
            compat_mode="quic",
            verify=bool(quic_verify),
            timeout_s=max(0.1, _to_float(timeout_s, 3.0)),
            concurrency=max(1, pool_size),
            http_method=str(quic_method or "GET").strip().upper() or "GET",
            http_path=str(quic_path or "/") or "/",
            payloads=[],
            request_plan=request_plan,
            max_streams_per_connection=stream_budget,
        )
        runtime_cfg = RuntimeConfig(concurrency=max(1, _to_int(concurrency, 1)))
        bounded = max(0.5, _to_float(timeout_s, 3.0)) * float(max(1, attempted))
        raw = dict((await asyncio.wait_for(_run_l7_profile(profile, runtime_cfg), timeout=bounded)).as_dict() or {})
    except Exception:
        raw = {
            "attempted": attempted,
            "sent": 0,
            "errors": attempted,
            "sender_path": "L7_QUIC_CUSTOM",
            "sender_fallback_reason": "quic_runtime_error",
            "l7_engine_path_used": "L7_QUIC_CUSTOM",
            "l7_fallback_reason": "quic_runtime_error",
            "l7_flow_attempted": attempted,
            "l7_flow_completed": 0,
            "l7_conn_attempted": attempted,
            "l7_conn_established": 0,
            "l7_expectation_failures": attempted,
            "quic_capability_available": 0,
        }

    cap = _to_int(raw.get("quic_capability_available", 1 if native_available else 0), 0)
    stack_mode = "custom_native" if cap > 0 else "unavailable"

    sent = max(0, _to_int(raw.get("sent", 0), 0))
    errors = max(0, _to_int(raw.get("errors", max(0, attempted - sent)), max(0, attempted - sent)))

    if bool(l7_quic_require_native) and cap <= 0:
        sent = 0
        errors = attempted
        raw["sender_fallback_reason"] = "quic_capability_unavailable"
        raw["l7_fallback_reason"] = "quic_capability_unavailable"

    conn_attempts = max(0, _to_int(raw.get("quic_connection_attempts", raw.get("l7_conn_attempted", attempted)), attempted))
    conn_success = max(0, _to_int(raw.get("quic_connection_success", raw.get("l7_conn_established", sent)), sent))
    req_sent = max(0, _to_int(raw.get("quic_requests_sent", attempted), attempted))
    resp_recv = max(0, _to_int(raw.get("quic_responses_received", sent), sent))
    timeouts = max(0, _to_int(
        raw.get(
            "quic_timeouts",
            _to_int(raw.get("quic_connect_timeout_count", 0), 0) + _to_int(raw.get("quic_handshake_timeout_count", 0), 0),
        ),
        0,
    ))
    quic_errors = max(0, _to_int(raw.get("quic_errors", errors), errors))
    denom = float(max(1, attempted))

    out = stats_fn(
        attempted=attempted,
        sent=sent,
        errors=errors,
        sender_path="L7_QUIC_CUSTOM",
        sender_fallback_reason=str(raw.get("sender_fallback_reason", "none") or "none"),
        l7_engine_path_used="L7_QUIC_CUSTOM",
        l7_fallback_reason=str(raw.get("l7_fallback_reason", "none") or "none"),
        l7_flow_attempted=_to_int(raw.get("l7_flow_attempted", attempted), attempted),
        l7_flow_completed=_to_int(raw.get("l7_flow_completed", sent), sent),
        l7_conn_attempted=_to_int(raw.get("l7_conn_attempted", conn_attempts), conn_attempts),
        l7_conn_established=_to_int(raw.get("l7_conn_established", conn_success), conn_success),
        l7_conn_reused=_to_int(raw.get("l7_conn_reused", 0), 0),
        l7_rx_bytes=_to_int(raw.get("l7_rx_bytes", 0), 0),
        l7_tx_bytes=_to_int(raw.get("l7_tx_bytes", 0), 0),
        l7_status_2xx=_to_int(raw.get("l7_status_2xx", sent), sent),
        l7_status_3xx=_to_int(raw.get("l7_status_3xx", 0), 0),
        l7_status_4xx=_to_int(raw.get("l7_status_4xx", 0), 0),
        l7_status_5xx=_to_int(raw.get("l7_status_5xx", 0), 0),
        l7_expectation_failures=_to_int(raw.get("l7_expectation_failures", errors), errors),
        quic_stack_mode=stack_mode,
        quic_capability_available=cap,
        quic_conn_pool_size=pool_size,
        quic_connection_attempts=conn_attempts,
        quic_connection_success=conn_success,
        quic_requests_sent=req_sent,
        quic_responses_received=resp_recv,
        quic_timeouts=timeouts,
        quic_errors=quic_errors,
        quic_handshake_success_ratio=float(conn_success / denom),
        quic_alpn_h3_ratio=float(resp_recv / denom),
        **_parity_metrics(raw),
    )

    for key, value in raw.items():
        if key in out and key not in {"sender_path", "sender_fallback_reason", "l7_engine_path_used", "l7_fallback_reason"}:
            continue
        if isinstance(value, (int, float, str, bool)):
            out[key] = int(value) if isinstance(value, bool) else value

    update_live_fn(live_sent, _to_int(out.get("sent", 0), 0))
    update_live_fn(live_errors, _to_int(out.get("errors", 0), 0))
    update_live_fn(live_progress, attempted)

    return normalize_l7_output_fn(
        out,
        attempted_default=attempted,
        sender_path="L7_QUIC_CUSTOM",
        engine_path_used="L7_QUIC_CUSTOM",
        fallback_reason=str(out.get("l7_fallback_reason", "none") or "none"),
    )
