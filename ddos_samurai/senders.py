import os
from typing import TYPE_CHECKING, Any, Dict

if TYPE_CHECKING:
    from .gpu_payload import H2RequestPlan

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


# Internal modularization bindings (strict public API compatibility).
from ._senders import runtime as _sender_runtime
from ._senders import stats_core as _sender_stats_core
from ._senders.buffer_norm import _normalize_packets_buffer as _normalize_packets_buffer
# Public compat re-export: external callers import close_sender_context from facade.
from ._senders.context import close_sender_context as close_sender_context

HTTPX_AVAILABLE, httpx = _sender_runtime.load_httpx()
WEBSOCKETS_AVAILABLE, websockets = _sender_runtime.load_websockets()
_aioquic = _sender_runtime.load_aioquic()
AIOQUIC_AVAILABLE = bool(_aioquic.get("AIOQUIC_AVAILABLE", False))
connect = _aioquic.get("connect")
QuicConfiguration = _aioquic.get("QuicConfiguration")
H3_ALPN = _aioquic.get("H3_ALPN")
H3Connection = _aioquic.get("H3Connection")
StreamDataReceived = _aioquic.get("StreamDataReceived")
HYPER_H2_AVAILABLE, _h2_transport = _sender_runtime.load_h2_transport(package=__package__)

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
):
    from ._senders import l7_http2 as _l7_http2

    return await _l7_http2.http2_sender(
        target_ip,
        target_port,
        count,
        concurrency,
        http_path,
        http_method,
        verbose,
        scheme=scheme,
        cookies=cookies,
        user_agent=user_agent,
        ssl_context=ssl_context,
        h2_profile_name=h2_profile_name,
        h2_transport_name=h2_transport_name,
        request_plan=request_plan,
        verify=verify,
        http2_connections=http2_connections,
        http2_streams_per_conn=http2_streams_per_conn,
        l7_http2_engine=l7_http2_engine,
        l7_fallback_policy=l7_fallback_policy,
        l7_capability_strict=l7_capability_strict,
        lab_profile=lab_profile,
        live_sent=live_sent,
        live_errors=live_errors,
        live_progress=live_progress,
        stats_fn=_stats,
        normalize_l7_output_fn=_normalize_l7_output,
        update_live_fn=_update_live,
        log_info=log_info,
        log_error=log_error,
        log_warning=log_warning,
        l7_dispatch_mod=l7_dispatch,
        L7RouteRequest_cls=L7RouteRequest,
        l7_c_adapter_mod=l7_c_adapter,
        l7_legacy_mod=l7_legacy,
        HTTPX_AVAILABLE=bool(HTTPX_AVAILABLE),
        httpx_module=httpx if HTTPX_AVAILABLE else None,
        HYPER_H2_AVAILABLE=bool(HYPER_H2_AVAILABLE),
        h2_transport_module=_h2_transport,
    )

async def http_app_sender(
    target_ip, target_port, count, concurrency, http_method, http_path, payloads, verbose,
    scheme="http", verify=True, timeout_s=5.0, retries=0, ssl_context=None,
    cookies=None, user_agent=None,
    live_sent=None, live_errors=None, live_progress=None
):
    from ._senders import l7_http1_simple as _l7_http1_simple

    return await _l7_http1_simple.http_app_sender(
        target_ip,
        target_port,
        count,
        concurrency,
        http_method,
        http_path,
        payloads,
        verbose,
        scheme=scheme,
        verify=verify,
        timeout_s=timeout_s,
        retries=retries,
        ssl_context=ssl_context,
        cookies=cookies,
        user_agent=user_agent,
        live_sent=live_sent,
        live_errors=live_errors,
        live_progress=live_progress,
        HTTPX_AVAILABLE=bool(HTTPX_AVAILABLE),
        httpx_module=httpx if HTTPX_AVAILABLE else None,
        stats_fn=_stats,
        update_live_fn=_update_live,
        log_info=log_info,
        log_error=log_error,
        utils_mod=utils,
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
    from ._senders import l7_http1_stateful as _l7_http1_stateful

    return await _l7_http1_stateful.http_stateful_sender(
        target_ip,
        target_port,
        vu_count,
        concurrency,
        workflow_steps,
        verbose,
        scheme=scheme,
        verify=verify,
        timeout_s=timeout_s,
        user_agent=user_agent,
        ssl_context=ssl_context,
        retries=retries,
        http_method=http_method,
        http_path=http_path,
        payloads=payloads,
        session_repeats=session_repeats,
        max_active_sessions=max_active_sessions,
        session_keepalive=session_keepalive,
        l7_engine=l7_engine,
        legacy_path_enable=legacy_path_enable,
        lab_profile=lab_profile,
        l7_fallback_policy=l7_fallback_policy,
        l7_capability_strict=l7_capability_strict,
        request_plan=request_plan,
        live_sent=live_sent,
        live_errors=live_errors,
        live_progress=live_progress,
        stats_fn=_stats,
        update_live_fn=_update_live,
        log_info=log_info,
        log_warning=log_warning,
        l7_dispatch_mod=l7_dispatch,
        L7RouteRequest_cls=L7RouteRequest,
        l7_c_adapter_mod=l7_c_adapter,
        l7_legacy_mod=l7_legacy,
        l7_telemetry_mod=l7_telemetry,
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
    from ._senders import l7_ws_scenario as _l7_ws_scenario

    return await _l7_ws_scenario.websocket_scenario_sender(
        target_ip,
        target_port,
        count,
        concurrency,
        ws_path,
        verbose,
        auth_message=auth_message,
        subscribe_messages=subscribe_messages,
        ping_message=ping_message,
        ping_count=ping_count,
        await_response=await_response,
        l7_engine=l7_engine,
        legacy_path_enable=legacy_path_enable,
        lab_profile=lab_profile,
        l7_fallback_policy=l7_fallback_policy,
        l7_capability_strict=l7_capability_strict,
        request_plan=request_plan,
        ssl_context=ssl_context,
        live_sent=live_sent,
        live_errors=live_errors,
        live_progress=live_progress,
        stats_fn=_stats,
        normalize_l7_output_fn=_normalize_l7_output,
        update_live_fn=_update_live,
        log_info=log_info,
        log_error=log_error,
        log_warning=log_warning,
        l7_dispatch_mod=l7_dispatch,
        L7RouteRequest_cls=L7RouteRequest,
        l7_c_adapter_mod=l7_c_adapter,
        l7_legacy_mod=l7_legacy,
        l7_telemetry_mod=l7_telemetry,
        WEBSOCKETS_AVAILABLE=bool(WEBSOCKETS_AVAILABLE),
        websockets_module=websockets if WEBSOCKETS_AVAILABLE else None,
    )

async def websocket_sender(target_ip, target_port, count, concurrency, ws_path, ws_message, verbose, ssl_context=None, live_sent=None, live_errors=None, live_progress=None):
    from ._senders import l7_ws_simple as _l7_ws_simple

    return await _l7_ws_simple.websocket_sender(
        target_ip,
        target_port,
        count,
        concurrency,
        ws_path,
        ws_message,
        verbose,
        ssl_context=ssl_context,
        live_sent=live_sent,
        live_errors=live_errors,
        live_progress=live_progress,
        WEBSOCKETS_AVAILABLE=bool(WEBSOCKETS_AVAILABLE),
        websockets_module=websockets if WEBSOCKETS_AVAILABLE else None,
        stats_fn=_stats,
        update_live_fn=_update_live,
        log_info=log_info,
        log_error=log_error,
    )

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
    from ._senders import l7_quic as _l7_quic

    return await _l7_quic.quic_sender(
        target_ip,
        target_port,
        count,
        concurrency,
        quic_path,
        quic_method,
        verbose,
        ssl_context=ssl_context,
        retries=retries,
        timeout_s=timeout_s,
        quic_verify=quic_verify,
        l7_quic_engine=l7_quic_engine,
        l7_quic_require_native=l7_quic_require_native,
        l7_fallback_policy=l7_fallback_policy,
        l7_capability_strict=l7_capability_strict,
        lab_profile=lab_profile,
        quic_streams_per_conn=quic_streams_per_conn,
        quic_requests_per_conn=quic_requests_per_conn,
        quic_conn_pool_size=quic_conn_pool_size,
        quic_expect_status_min=quic_expect_status_min,
        quic_expect_status_max=quic_expect_status_max,
        quic_require_response_headers=quic_require_response_headers,
        quic_require_response_body=quic_require_response_body,
        quic_min_response_body_bytes=quic_min_response_body_bytes,
        quic_expect_header_name=quic_expect_header_name,
        quic_expect_header_value_contains=quic_expect_header_value_contains,
        quic_expect_body_substring=quic_expect_body_substring,
        request_plan=request_plan,
        live_sent=live_sent,
        live_errors=live_errors,
        live_progress=live_progress,
        stats_fn=_stats,
        normalize_l7_output_fn=_normalize_l7_output,
        update_live_fn=_update_live,
        log_info=log_info,
        log_error=log_error,
        log_warning=log_warning,
        l7_dispatch_mod=l7_dispatch,
        L7RouteRequest_cls=L7RouteRequest,
        l7_c_adapter_mod=l7_c_adapter,
        l7_legacy_mod=l7_legacy,
        AIOQUIC_AVAILABLE=bool(AIOQUIC_AVAILABLE),
        connect_fn=connect if AIOQUIC_AVAILABLE else None,
        QuicConfiguration_cls=QuicConfiguration if AIOQUIC_AVAILABLE else None,
        H3_ALPN_val=H3_ALPN if AIOQUIC_AVAILABLE else None,
        H3Connection_cls=H3Connection if AIOQUIC_AVAILABLE else None,
    )
