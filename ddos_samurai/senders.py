import os
from typing import TYPE_CHECKING, Any, Dict

if TYPE_CHECKING:
    from .gpu_payload import H2RequestPlan

from . import utils
from . import packet as packet_utils
from . import cpu_packet_engine
from .l7 import telemetry as l7_telemetry
from .l7_emu import compile_l7_profile as _compile_l7_profile
from .l7_emu import load_l7_profile_file, run_l7_profile as _run_l7_profile
from .l7_emu.types import RuntimeConfig
from .scapy_support import ScapyUnavailableError, require_scapy

log_info = utils.log_info
log_error = utils.log_error
log_warning = utils.log_warning

_GATEWAY_CACHE = {}
_GATEWAY_CACHE_TTL_SEC = float(os.environ.get("SAMURAI_GATEWAY_CACHE_TTL_SEC", "60"))


# Internal modularization bindings (strict public API compatibility).
from ._senders import runtime as _sender_runtime
from ._senders import stats_core as _sender_stats_core
from ._senders.buffer_norm import _normalize_packets_buffer as _normalize_packets_buffer
# Public compat re-export: external callers import close_sender_context from facade.
from ._senders.context import close_sender_context as close_sender_context

_resolve_sender_backend = _sender_runtime.resolve_sender_backend
_resolve_sender_fallback_policy = _sender_runtime.resolve_sender_fallback_policy
_scapy = lambda: _sender_runtime.scapy_getter(require_scapy_fn=require_scapy)

_stats = _sender_stats_core._stats
_normalize_l7_output = _sender_stats_core._normalize_l7_output
_update_live = _sender_stats_core._update_live
_env_flag = _sender_stats_core._env_flag
_estimate_paced_packets = _sender_stats_core._estimate_paced_packets
_PacedSendRuntimeError = _sender_stats_core._PacedSendRuntimeError
_run_paced_send_with_live_progress = _sender_stats_core._run_paced_send_with_live_progress
_apply_pacing_stats = _sender_stats_core._apply_pacing_stats
_recompute_loss_metrics = _sender_stats_core._recompute_loss_metrics
_loss_telemetry_enabled = _sender_stats_core._loss_telemetry_enabled
_resolve_loss_iface = _sender_stats_core._resolve_loss_iface
_take_loss_snapshot = _sender_stats_core._take_loss_snapshot
_take_loss_delta = _sender_stats_core._take_loss_delta
_attach_loss_telemetry = _sender_stats_core._attach_loss_telemetry
_merge_stats = _sender_stats_core._merge_stats


def compile_l7_profile_public(**kwargs):
    return _compile_l7_profile(**kwargs)


async def run_l7_profile_public(profile, **kwargs):
    runtime_cfg = RuntimeConfig(
        concurrency=max(1, int(kwargs.get("concurrency", 1) or 1)),
        live_progress=kwargs.get("live_progress") is not None,
        live_sent=kwargs.get("live_sent") is not None,
        live_errors=kwargs.get("live_errors") is not None,
    )
    result = await _run_l7_profile(profile, runtime_cfg)
    return result.as_dict()


compile_l7_profile = compile_l7_profile_public
run_l7_profile = run_l7_profile_public


def _unsupported_l7_v1_stats(sender_path: str, count: int) -> Dict[str, Any]:
    attempted = max(0, int(count or 0))
    return _normalize_l7_output(
        {
            "attempted": attempted,
            "sent": 0,
            "errors": attempted,
            "sender_path": str(sender_path),
            "sender_fallback_reason": "unsupported_in_l7_emu_v1",
            "l7_engine_path_used": "L7_EMU_NATIVE",
            "l7_fallback_reason": "unsupported_in_l7_emu_v1",
            "l7_flow_attempted": attempted,
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
            "l7_expectation_failures": attempted,
            "l7_scheduler_backpressure_count": 0,
        },
        attempted_default=attempted,
        sender_path=str(sender_path),
        engine_path_used="L7_EMU_NATIVE",
        fallback_reason="unsupported_in_l7_emu_v1",
    )

async def send_packet_async(packet, verbose, packet_no, loop, protocol):
    from ._senders import legacy_packet as _legacy_packet

    return await _legacy_packet.send_packet_async(
        packet,
        verbose,
        packet_no,
        loop,
        protocol,
        scapy_getter=_scapy,
        ScapyUnavailableError=ScapyUnavailableError,
    )

async def packet_sender(packet_config, count, delay=0.0, rps=0.0, jitter=0.0, ramp=0.0, verbose=False, live_sent=None, live_errors=None, live_progress=None):
    from ._senders import legacy_packet as _legacy_packet

    return await _legacy_packet.packet_sender(
        packet_config,
        count,
        delay=delay,
        rps=rps,
        jitter=jitter,
        ramp=ramp,
        verbose=verbose,
        live_sent=live_sent,
        live_errors=live_errors,
        live_progress=live_progress,
        scapy_getter=_scapy,
        stats_fn=_stats,
        update_live_fn=_update_live,
        log_error=log_error,
        cpu_packet_engine=cpu_packet_engine,
        packet_utils=packet_utils,
        ScapyUnavailableError=ScapyUnavailableError,
    )

FAST_SENDER_AVAILABLE, fast_sender = _sender_runtime.load_fast_sender(package=__package__)

_pacing = _sender_runtime.load_pacing_engine(package=__package__)
PACING_ENGINE_AVAILABLE = bool(_pacing.get("PACING_ENGINE_AVAILABLE", False))
PacingConfig = _pacing.get("PacingConfig")
PacingMode = _pacing.get("PacingMode")
JitterModel = _pacing.get("JitterModel")
paced_send = _pacing.get("paced_send")
paced_send_l2 = _pacing.get("paced_send_l2")
paced_send_xdp = _pacing.get("paced_send_xdp")
get_stats = _pacing.get("get_stats")
reset_stats = _pacing.get("reset_stats")
format_stats = _pacing.get("format_stats")
cleanup_l2 = _pacing.get("cleanup_l2")

_xdp = _sender_runtime.load_xdp_sender(package=__package__)
XDP_AVAILABLE = bool(_xdp.get("XDP_AVAILABLE", False))
XDPSender = _xdp.get("XDPSender")
XDPIntegration = _xdp.get("XDPIntegration")
check_xdp_available = _xdp.get("check_xdp_available")


def get_gateway_info(target_ip):
    from ._senders import l2l3_entry as _l2l3_entry

    return _l2l3_entry.get_gateway_info(
        target_ip,
        gateway_cache=_GATEWAY_CACHE,
        gateway_cache_ttl_sec=float(_GATEWAY_CACHE_TTL_SEC),
        scapy_getter=_scapy,
        log_info=log_info,
        log_error=log_error,
    )


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
    xdp_mode: int = 0,
    batch_size: int = 64,
    sender_fallback_policy: str = "allow",
    fallback_backend: str = "python",
    sender_context: Dict[str, Any] | None = None,
    pacing_config=None,
    paced_send_xdp_fn=None,
) -> dict:
    from ._senders import l2l3_entry as _l2l3_entry

    return await _l2l3_entry.xdp_sender(
        packets_buffer=packets_buffer,
        target_ip=target_ip,
        target_port=target_port,
        count=count,
        verbose=verbose,
        interface=interface,
        queue_id=queue_id,
        xdp_mode=xdp_mode,
        batch_size=batch_size,
        sender_fallback_policy=sender_fallback_policy,
        fallback_backend=fallback_backend,
        sender_context=sender_context,
        pacing_config=pacing_config,
        paced_send_xdp_fn=paced_send_xdp_fn,
        resolve_sender_fallback_policy_fn=_resolve_sender_fallback_policy,
        resolve_sender_backend_fn=_resolve_sender_backend,
        raw_socket_sender_fn=raw_socket_sender,
        normalize_packets_buffer_fn=_normalize_packets_buffer,
        stats_fn=_stats,
        log_info=log_info,
        log_warning=log_warning,
        log_error=log_error,
        XDP_AVAILABLE=bool(XDP_AVAILABLE),
        XDPSender=XDPSender,
        check_xdp_available=check_xdp_available,
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
    xdp_mode: int = 0,
):
    from ._senders import l2l3_raw as _l2l3_raw

    return await _l2l3_raw.raw_socket_sender(
        packets_buffer,
        target_ip,
        target_port,
        count,
        verbose,
        live_sent=live_sent,
        live_errors=live_errors,
        live_progress=live_progress,
        force_l2=force_l2,
        sender_backend=sender_backend,
        sender_fallback_policy=sender_fallback_policy,
        sender_context=sender_context,
        xdp_enable=xdp_enable,
        xdp_interface=xdp_interface,
        xdp_queue_id=xdp_queue_id,
        xdp_mode=xdp_mode,
        resolve_sender_backend_fn=_resolve_sender_backend,
        resolve_sender_fallback_policy_fn=_resolve_sender_fallback_policy,
        xdp_sender_fn=xdp_sender,
        normalize_packets_buffer_fn=_normalize_packets_buffer,
        resolve_loss_iface_fn=_resolve_loss_iface,
        take_loss_snapshot_fn=_take_loss_snapshot,
        attach_loss_telemetry_fn=_attach_loss_telemetry,
        update_live_fn=_update_live,
        stats_fn=_stats,
        get_gateway_info_fn=get_gateway_info,
        FAST_SENDER_AVAILABLE_flag=bool(FAST_SENDER_AVAILABLE),
        fast_sender_module=fast_sender if FAST_SENDER_AVAILABLE else None,
        log_info=log_info,
        log_error=log_error,
    )


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
    xdp_mode: int = 0,
):
    from ._senders import l2l3_raw as _l2l3_raw

    return await _l2l3_raw.paced_raw_socket_sender(
        packets_buffer,
        target_ip,
        target_port,
        count,
        verbose,
        pacing_config=pacing_config,
        force_l2=force_l2,
        live_sent=live_sent,
        live_errors=live_errors,
        live_progress=live_progress,
        sender_backend=sender_backend,
        sender_fallback_policy=sender_fallback_policy,
        sender_context=sender_context,
        xdp_enable=xdp_enable,
        xdp_interface=xdp_interface,
        xdp_queue_id=xdp_queue_id,
        xdp_mode=xdp_mode,
        resolve_sender_backend_fn=_resolve_sender_backend,
        resolve_sender_fallback_policy_fn=_resolve_sender_fallback_policy,
        xdp_sender_fn=xdp_sender,
        raw_socket_sender_fn=raw_socket_sender,
        normalize_packets_buffer_fn=_normalize_packets_buffer,
        resolve_loss_iface_fn=_resolve_loss_iface,
        take_loss_snapshot_fn=_take_loss_snapshot,
        attach_loss_telemetry_fn=_attach_loss_telemetry,
        update_live_fn=_update_live,
        stats_fn=_stats,
        apply_pacing_stats_fn=_apply_pacing_stats,
        run_paced_send_with_live_progress_fn=_run_paced_send_with_live_progress,
        PacedSendRuntimeError_cls=_PacedSendRuntimeError,
        get_gateway_info_fn=get_gateway_info,
        FAST_SENDER_AVAILABLE_flag=bool(FAST_SENDER_AVAILABLE),
        PACING_ENGINE_AVAILABLE_flag=bool(PACING_ENGINE_AVAILABLE),
        reset_stats_fn=reset_stats,
        paced_send_l2_fn=paced_send_l2 if PACING_ENGINE_AVAILABLE else None,
        paced_send_xdp_fn=paced_send_xdp if PACING_ENGINE_AVAILABLE else None,
        paced_send_fn=paced_send if PACING_ENGINE_AVAILABLE else None,
        get_stats_fn=get_stats if PACING_ENGINE_AVAILABLE else None,
        format_stats_fn=format_stats if PACING_ENGINE_AVAILABLE else None,
        cleanup_l2_fn=cleanup_l2 if PACING_ENGINE_AVAILABLE else None,
        log_info=log_info,
        log_error=log_error,
        log_warning=log_warning,
    )

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
    l7_profile_file="",
    l7_template_mode="compat",
):
    if l7_profile_file:
        loaded = load_l7_profile_file(l7_profile_file)
        profile = compile_l7_profile(
            protocol=str(loaded.get("protocol", "http2") or "http2"),
            target_ip=str(loaded.get("target_ip", target_ip) or target_ip),
            target_port=int(loaded.get("target_port", target_port) or target_port),
            scheme=str(loaded.get("scheme", scheme) or scheme),
            template_mode=str(loaded.get("template_mode", l7_template_mode) or l7_template_mode),
            compat_mode=str(loaded.get("compat_mode", "http2") or "http2"),
            verify=bool(loaded.get("verify", verify)),
            timeout_s=float(loaded.get("timeout_s", 5.0) or 5.0),
            concurrency=int(loaded.get("http2_connections", http2_connections) or http2_connections),
            http_method=str(loaded.get("http_method", http_method) or http_method),
            http_path=loaded.get("http_path", http_path),
            request_plan=request_plan,
            profile_data=loaded,
            tls_profile_name=str(loaded.get("tls_profile_name", h2_profile_name or "none") or (h2_profile_name or "none")),
            max_streams_per_connection=int(loaded.get("http2_streams_per_conn", http2_streams_per_conn) or http2_streams_per_conn),
        )
    else:
        profile = compile_l7_profile(
            protocol="http2",
            target_ip=target_ip,
            target_port=target_port,
            scheme=scheme,
            template_mode=l7_template_mode,
            compat_mode="http2",
            verify=verify,
            timeout_s=5.0,
            concurrency=http2_connections,
            http_method=http_method,
            http_path=http_path,
            request_plan=request_plan,
            tls_profile_name=h2_profile_name or "none",
            max_streams_per_connection=http2_streams_per_conn,
        )
    out = await run_l7_profile_public(
        profile,
        concurrency=max(1, int(concurrency or http2_connections or 1)),
        live_sent=live_sent,
        live_errors=live_errors,
        live_progress=live_progress,
    )
    out.setdefault("sender_path", "L7_EMU_H2")
    out.setdefault("l7_engine_path_used", "L7_EMU_NATIVE")
    out.setdefault("h2_transport", "native")
    out.setdefault("h2_request_plan_used", int(bool(request_plan)))
    out.setdefault("h2_request_plan_items", int(len(getattr(request_plan, "items", []) or [])))
    return _normalize_l7_output(
        out,
        attempted_default=int(out.get("attempted", count) or count),
        sender_path="L7_EMU_H2",
        engine_path_used="L7_EMU_NATIVE",
        fallback_reason=str(out.get("l7_fallback_reason", "none") or "none"),
    )

async def http_app_sender(
    target_ip, target_port, count, concurrency, http_method, http_path, payloads, verbose,
    scheme="http", verify=True, timeout_s=5.0, retries=0, ssl_context=None,
    cookies=None, user_agent=None,
    live_sent=None, live_errors=None, live_progress=None,
    l7_profile_file="", l7_template_mode="compat",
):
    if l7_profile_file:
        loaded = load_l7_profile_file(l7_profile_file)
        profile = compile_l7_profile(
            protocol=str(loaded.get("protocol", "http1") or "http1"),
            target_ip=str(loaded.get("target_ip", target_ip) or target_ip),
            target_port=int(loaded.get("target_port", target_port) or target_port),
            scheme=str(loaded.get("scheme", scheme) or scheme),
            template_mode=str(loaded.get("template_mode", l7_template_mode) or l7_template_mode),
            compat_mode=str(loaded.get("compat_mode", "http1_simple") or "http1_simple"),
            verify=bool(loaded.get("verify", verify)),
            timeout_s=float(loaded.get("timeout_s", timeout_s) or timeout_s),
            concurrency=int(loaded.get("concurrency", concurrency) or concurrency),
            http_method=str(loaded.get("http_method", http_method) or http_method),
            http_path=loaded.get("http_path", http_path),
            payloads=loaded.get("payloads", payloads),
            profile_data=loaded,
            tls_profile_name=str(loaded.get("tls_profile_name", "none") or "none"),
        )
    else:
        profile = compile_l7_profile(
            protocol="http1",
            target_ip=target_ip,
            target_port=target_port,
            scheme=scheme,
            template_mode=l7_template_mode,
            compat_mode="http1_simple",
            verify=verify,
            timeout_s=timeout_s,
            concurrency=concurrency,
            http_method=http_method,
            http_path=http_path,
            payloads=payloads,
            tls_profile_name="none",
        )
    out = await run_l7_profile_public(
        profile,
        concurrency=max(1, int(concurrency or 1)),
        live_sent=live_sent,
        live_errors=live_errors,
        live_progress=live_progress,
    )
    return _normalize_l7_output(
        out,
        attempted_default=int(out.get("attempted", count) or count),
        sender_path="L7_EMU_HTTP1",
        engine_path_used="L7_EMU_NATIVE",
        fallback_reason=str(out.get("l7_fallback_reason", "none") or "none"),
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
    lab_profile="off",
    l7_fallback_policy="allow",
    l7_capability_strict=False,
    request_plan: "H2RequestPlan | None" = None,
    live_sent=None, live_errors=None, live_progress=None,
    l7_profile_file="", l7_template_mode="compat",
):
    if l7_profile_file:
        loaded = load_l7_profile_file(l7_profile_file)
        profile = compile_l7_profile(
            protocol=str(loaded.get("protocol", "http1") or "http1"),
            target_ip=str(loaded.get("target_ip", target_ip) or target_ip),
            target_port=int(loaded.get("target_port", target_port) or target_port),
            scheme=str(loaded.get("scheme", scheme) or scheme),
            template_mode=str(loaded.get("template_mode", l7_template_mode) or l7_template_mode),
            compat_mode=str(loaded.get("compat_mode", "http1_stateful") or "http1_stateful"),
            verify=bool(loaded.get("verify", verify)),
            timeout_s=float(loaded.get("timeout_s", timeout_s) or timeout_s),
            concurrency=int(loaded.get("concurrency", concurrency) or concurrency),
            http_method=str(loaded.get("http_method", http_method) or http_method),
            http_path=loaded.get("http_path", http_path),
            payloads=loaded.get("payloads", payloads),
            request_plan=request_plan,
            profile_data=loaded,
            session_repeats=int(loaded.get("session_repeats", session_repeats) or session_repeats),
        )
    else:
        profile = compile_l7_profile(
            protocol="http1",
            target_ip=target_ip,
            target_port=target_port,
            scheme=scheme,
            template_mode=l7_template_mode,
            compat_mode="http1_stateful",
            verify=verify,
            timeout_s=timeout_s,
            concurrency=concurrency,
            http_method=http_method,
            http_path=http_path,
            payloads=payloads,
            request_plan=request_plan,
            session_repeats=session_repeats,
        )
    out = await run_l7_profile_public(
        profile,
        concurrency=max(1, int(concurrency or 1)),
        live_sent=live_sent,
        live_errors=live_errors,
        live_progress=live_progress,
    )
    out.setdefault("total_vus", int(vu_count))
    if int(out.get("attempted", 0) or 0) > 0:
        out.setdefault("session_success_rate", float(out.get("sent", 0) or 0) / float(out.get("attempted", 1) or 1))
        out.setdefault("cookie_set_apply_rate", 0.0)
        out.setdefault("retries_used", int(retries or 0))
    return _normalize_l7_output(
        out,
        attempted_default=int(out.get("attempted", vu_count) or vu_count),
        sender_path="L7_EMU_HTTP1",
        engine_path_used="L7_EMU_NATIVE",
        fallback_reason=str(out.get("l7_fallback_reason", "none") or "none"),
    )


async def amplification_sender(victim_ip, count, rps, reflector_file, amp_type, verbose, live_sent=None, live_errors=None, live_progress=None):
    from ._senders import legacy_attacks as _legacy_attacks

    return await _legacy_attacks.amplification_sender(
        victim_ip,
        count,
        rps,
        reflector_file,
        amp_type,
        verbose,
        live_sent=live_sent,
        live_errors=live_errors,
        live_progress=live_progress,
        stats_fn=_stats,
        update_live_fn=_update_live,
        log_info=log_info,
        log_error=log_error,
        packet_utils=packet_utils,
        send_packet_async_fn=send_packet_async,
    )

async def slow_attack_sender(target_ip, target_port, count, concurrency, attack_type, verbose, ssl_context=None, live_sent=None, live_errors=None, live_progress=None):
    from ._senders import legacy_attacks as _legacy_attacks

    return await _legacy_attacks.slow_attack_sender(
        target_ip,
        target_port,
        count,
        concurrency,
        attack_type,
        verbose,
        ssl_context=ssl_context,
        live_sent=live_sent,
        live_errors=live_errors,
        live_progress=live_progress,
        stats_fn=_stats,
        update_live_fn=_update_live,
        log_info=log_info,
    )

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
    lab_profile="off",
    l7_fallback_policy="allow",
    l7_capability_strict=False,
    request_plan: "H2RequestPlan | None" = None,
    ssl_context=None,
    live_sent=None,
    live_errors=None,
    live_progress=None,
):
    return _unsupported_l7_v1_stats("L7_EMU_WS_UNSUPPORTED", count)

async def websocket_sender(target_ip, target_port, count, concurrency, ws_path, ws_message, verbose, ssl_context=None, live_sent=None, live_errors=None, live_progress=None):
    return _unsupported_l7_v1_stats("L7_EMU_WS_UNSUPPORTED", count)

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
    return _unsupported_l7_v1_stats("L7_EMU_QUIC_UNSUPPORTED", count)
