import asyncio
import inspect
import os
import time
from typing import TYPE_CHECKING, Any, Dict

if TYPE_CHECKING:
    from .gpu_cuda_payload import H2RequestPlan

from . import utils
from . import cpu_packet_engine
from . import cpu_packet_engine as packet_utils
from .l7 import telemetry as l7_telemetry
from .l7_emu import compile_l7_profile as _compile_l7_profile
from .l7_emu import load_l7_profile_file, run_l7_profile as _run_l7_profile
from .l7_emu.types import RuntimeConfig
from .l7_emu import runtime as _l7_runtime
from .stateful_runtime import open_session as open_stateful_runtime_session

log_info = utils.log_info
log_error = utils.log_error
log_warning = utils.log_warning

_GATEWAY_CACHE = {}
_GATEWAY_CACHE_TTL_SEC = float(os.environ.get("SAMURAI_GATEWAY_CACHE_TTL_SEC", "60"))


# Internal modularization bindings (strict public API compatibility).
from ._senders import runtime as _sender_runtime
from ._senders import stats_core as _sender_stats_core
from ._senders import custom_tcp_bridge as _custom_tcp_bridge
from ._senders.buffer_norm import _normalize_packets_buffer as _normalize_packets_buffer
# Public compat re-export: external callers import close_sender_context from facade.
from ._senders.context import close_sender_context as close_sender_context

_resolve_sender_backend = _sender_runtime.resolve_sender_backend
_resolve_sender_fallback_policy = _sender_runtime.resolve_sender_fallback_policy

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


def _resolve_l7_transport_backend(
    requested_backend: Any = None,
    *,
    protocol: str = "http1",
) -> str:
    backend = str(requested_backend or "").strip().lower()
    if backend and backend != "custom_tcp":
        log_warning(
            f"[L7] transport_backend={backend!r} is removed; using mandatory 'custom_tcp'"
        )
    return "custom_tcp"


def _resolve_custom_tcp_backend(requested_backend: Any = None) -> str:
    backend = str(
        requested_backend
        or os.environ.get("SAMURAI_CUSTOM_TCP_BACKEND", "af_xdp")
        or "af_xdp"
    ).strip().lower()
    if backend not in {"af_xdp"}:
        return "af_xdp"
    return backend


def _resolve_custom_tcp_rx_iface(requested_iface: Any = None, xdp_interface: Any = None) -> str:
    iface = str(
        requested_iface
        or os.environ.get("SAMURAI_CUSTOM_TCP_RX_IFACE", "")
        or xdp_interface
        or os.environ.get("SAMURAI_XDP_INTERFACE", "")
        or ""
    ).strip()
    return iface


def _profile_uses_custom_tcp(profile: Any) -> bool:
    conn = getattr(profile, "connection_template", None)
    backend = getattr(conn, "transport_backend", "custom_tcp")
    return str(backend or "custom_tcp").strip().lower() == "custom_tcp"


def _resolve_stateful_runtime_backend(requested_backend: Any = None) -> str:
    backend = str(
        requested_backend
        or os.environ.get("SAMURAI_STATEFUL_RUNTIME_BACKEND", "afxdp")
        or "afxdp"
    ).strip().lower()
    if backend not in {"afxdp"}:
        return "afxdp"
    return backend


def _stateful_runtime_metadata(profile: Any, runtime_cfg: RuntimeConfig) -> Dict[str, Any]:
    conn = getattr(profile, "connection_template", None)
    runtime_backend = _resolve_stateful_runtime_backend(
        runtime_cfg.stateful_runtime_backend or getattr(conn, "stateful_runtime_backend", "afxdp")
    )
    transport_backend = str(getattr(conn, "transport_backend", "custom_tcp") or "custom_tcp")
    legacy_mode = bool(runtime_cfg.legacy_mode)
    hot_path_level = "phase1_hybrid_afxdp"
    if runtime_backend == "afxdp":
        hot_path_level = "phase1_hybrid_afxdp"
    elif runtime_backend == "dpdk":
        hot_path_level = "phase1_stub_dpdk"
    if transport_backend == "custom_tcp":
        hot_path_level = f"{hot_path_level}_custom_tcp"
    return {
        "runtime_backend": runtime_backend,
        "stateful_runtime_backend": runtime_backend,
        "runtime_hot_path_level": hot_path_level,
        "legacy_path_used": int(legacy_mode),
    }


def _stateful_runtime_fail_visible_stats(
    profile: Any,
    runtime_cfg: RuntimeConfig,
    *,
    reason: str,
    detail: str = "",
    preflight: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    attempted = int(getattr(profile, "flow_attempted", 0) or 0)
    sender_path = str(getattr(profile, "sender_path", "unknown") or "unknown")
    stats = {
        "attempted": attempted,
        "sent": 0,
        "errors": attempted,
        "sender_path": sender_path,
        "sender_fallback_reason": str(reason or "stateful_runtime_unavailable"),
        "l7_engine_path_used": "L7_EMU_NATIVE",
        "l7_fallback_reason": str(reason or "stateful_runtime_unavailable"),
        "l7_capability_status": "missing",
        "stateful_runtime_status": "unavailable",
        "stateful_runtime_reason": str(reason or "stateful_runtime_unavailable"),
        "stateful_runtime_detail": str(detail or ""),
    }
    stats.update(_stateful_runtime_metadata(profile, runtime_cfg))
    stats.update(_stateful_runtime_preflight_fields(status="failed", reason=reason, detail=detail, transport_plan=preflight))
    return stats


def _stateful_runtime_preflight_fields(
    *,
    status: str,
    reason: str = "none",
    detail: str = "",
    transport_plan: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    plan = dict(transport_plan or {})
    return {
        "stateful_runtime_preflight_status": str(status or "skipped"),
        "stateful_runtime_preflight_reason": str(reason or "none"),
        "stateful_runtime_preflight_detail": str(detail or ""),
        "stateful_runtime_preflight_backend_requested": str(
            plan.get("custom_tcp_bridge_backend_requested", "") or ""
        ),
        "stateful_runtime_preflight_backend_used": str(
            plan.get("custom_tcp_bridge_backend_used", "") or ""
        ),
        "stateful_runtime_preflight_backend_match": int(
            plan.get("custom_tcp_bridge_backend_match", 0) or 0
        ),
        "stateful_runtime_preflight_xdp_interface": str(
            plan.get("custom_tcp_bridge_xdp_interface", "") or ""
        ),
        "stateful_runtime_preflight_xdp_queue_id": int(
            plan.get("custom_tcp_bridge_xdp_queue_id", -1) or -1
        ),
        "stateful_runtime_preflight_xdp_available": int(
            plan.get("custom_tcp_bridge_xdp_available", 0) or 0
        ),
        "stateful_runtime_preflight_xdp_enabled": int(
            plan.get("custom_tcp_bridge_xdp_enabled", 0) or 0
        ),
    }


def _stateful_runtime_preflight(
    profile: Any,
    runtime_cfg: RuntimeConfig,
    *,
    custom_tcp_backend: Any = None,
    custom_tcp_xdp_interface: Any = None,
) -> Dict[str, Any] | None:
    runtime_backend = _resolve_stateful_runtime_backend(runtime_cfg.stateful_runtime_backend)
    if not bool(runtime_cfg.stateful_runtime_strict):
        return None

    conn = getattr(profile, "connection_template", None)
    transport_backend = str(getattr(conn, "transport_backend", "custom_tcp") or "custom_tcp").strip().lower()
    if transport_backend != "custom_tcp":
        return _stateful_runtime_fail_visible_stats(
            profile,
            runtime_cfg,
            reason="stateful_runtime_transport_unavailable",
            detail=f"runtime backend '{runtime_backend}' requires custom_tcp transport",
        )

    if runtime_backend == "dpdk":
        return _stateful_runtime_fail_visible_stats(
            profile,
            runtime_cfg,
            reason="not_implemented_hard_fail",
            detail="stateful_runtime_backend=dpdk strict path is not implemented",
        )

    if runtime_backend != "afxdp":
        return _stateful_runtime_fail_visible_stats(
            profile,
            runtime_cfg,
            reason="stateful_runtime_backend_unavailable",
            detail=f"unsupported strict runtime backend '{runtime_backend}'",
        )

    transport_plan = _resolve_custom_tcp_flush_transport(
        requested_backend=custom_tcp_backend or "af_xdp",
        xdp_interface=custom_tcp_xdp_interface,
        xdp_queue_id=0,
    )
    if (
        str(transport_plan.get("custom_tcp_bridge_backend_used", "") or "") != "xdp"
        or int(transport_plan.get("custom_tcp_bridge_degraded", 0) or 0) == 1
    ):
        return _stateful_runtime_fail_visible_stats(
            profile,
            runtime_cfg,
            reason=str(
                transport_plan.get("custom_tcp_bridge_fallback_reason", "stateful_runtime_afxdp_unavailable")
                or "stateful_runtime_afxdp_unavailable"
            ),
            detail=str(
                transport_plan.get("custom_tcp_bridge_fallback_detail", "")
                or "AF_XDP strict runtime preflight failed"
            ),
            preflight=transport_plan,
        )
    return _stateful_runtime_preflight_fields(
        status="passed",
        reason="none",
        detail="AF_XDP strict runtime preflight passed",
        transport_plan=transport_plan,
    )


def _enforce_phase3_strict_h1_contract(
    stats: Dict[str, Any],
    profile: Any,
    runtime_cfg: RuntimeConfig,
    *,
    observed_runtime_transport_backend: Any = None,
) -> Dict[str, Any]:
    if not bool(runtime_cfg.stateful_runtime_strict):
        return stats
    runtime_backend = _resolve_stateful_runtime_backend(runtime_cfg.stateful_runtime_backend)
    conn = getattr(profile, "connection_template", None)
    protocol = str(getattr(conn, "protocol", "") or "").strip().lower()
    if protocol != "http1":
        return stats
    if observed_runtime_transport_backend is None:
        observed_runtime_transport_backend = stats.get(
            "runtime_transport_backend",
            getattr(conn, "transport_backend", "custom_tcp"),
        )
    runtime_transport_backend = str(observed_runtime_transport_backend or "custom_tcp").strip().lower()
    if runtime_transport_backend == "custom_tcp":
        return stats
    return _stateful_runtime_fail_visible_stats(
        profile,
        runtime_cfg,
        reason="stateful_runtime_transport_contract_violation",
        detail=(
            "phase3 strict H1 contract violation: runtime transport backend must be custom_tcp; "
            f"got '{runtime_transport_backend}'"
        ),
    )


def _native_custom_tcp_bridge_api():
    native = getattr(_l7_runtime, "_native", None)
    if native is None:
        return None
    if not hasattr(native, "peek_custom_tcp_tx_buffer_strided"):
        return None
    if not hasattr(native, "consume_custom_tcp_tx_packets"):
        return None
    if not hasattr(native, "ingest_custom_tcp_rx_frame"):
        return None
    return native


def _resolve_custom_tcp_bridge_api(explicit_api: Any = None):
    if explicit_api is not None:
        return explicit_api
    native_api = _native_custom_tcp_bridge_api()
    run_module = str(getattr(_run_l7_profile, "__module__", "") or "")
    if (
        native_api is not None
        and inspect.iscoroutinefunction(_run_l7_profile)
        and run_module == "ddos_samurai.l7_emu.runtime"
    ):
        return native_api
    return custom_tcp_dataplane


def _custom_tcp_runtime_poll_snapshot(runtime_api: Any = None) -> Dict[str, Any]:
    api = runtime_api if runtime_api is not None else custom_tcp_dataplane
    if api is None:
        return {}
    out: Dict[str, Any] = {}
    poll_fn = getattr(api, "poll_tcp_dataplane", None)
    if callable(poll_fn):
        try:
            actions = poll_fn(time.perf_counter_ns(), 4096)
            if isinstance(actions, (list, tuple, set)):
                out["runtime_transport_poll_actions"] = len(actions)
            else:
                out["runtime_transport_poll_actions"] = int(actions or 0)
            out["runtime_transport_rx_poll_enabled"] = 1
            out["runtime_transport_poll_calls"] = 1
        except Exception:
            out["runtime_transport_rx_poll_enabled"] = 0
    snapshot_fn = getattr(api, "snapshot_tcp_dataplane", None)
    if callable(snapshot_fn):
        try:
            snapshot = dict(snapshot_fn() or {})
            out["runtime_transport_snapshot_available"] = 1
            for key, value in snapshot.items():
                if str(key).startswith("tcp_"):
                    out[str(key)] = value
        except Exception:
            out.setdefault("runtime_transport_snapshot_available", 0)
    return out


def _merge_bridge_stats(base: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    return _custom_tcp_bridge.merge_bridge_stats(base, extra)


def _extract_contiguous_drain_batch(value: Any) -> tuple[Any, Any, int, int, int]:
    return _custom_tcp_bridge.extract_contiguous_drain_batch(value)


def _extract_strided_peek_batch(value: Any) -> tuple[Any, Any, int, int, int, int]:
    return _custom_tcp_bridge.extract_strided_peek_batch(value)


def _resolve_custom_tcp_flush_transport(
    *,
    requested_backend: Any = None,
    xdp_interface: Any = None,
    xdp_queue_id: Any = 0,
) -> Dict[str, Any]:
    return _custom_tcp_bridge.resolve_custom_tcp_flush_transport(
        requested_backend=requested_backend,
        xdp_interface=xdp_interface,
        xdp_queue_id=xdp_queue_id,
        resolve_custom_tcp_backend_fn=_resolve_custom_tcp_backend,
        xdp_available_flag=bool(XDP_AVAILABLE),
        check_xdp_available_fn=check_xdp_available,
    )


async def _flush_custom_tcp_tx_packets(
    *,
    profile: Any,
    verbose: bool,
    pacing_config: Any = None,
    bridge_api: Any = None,
    live_sent: Any = None,
    live_errors: Any = None,
    live_progress: Any = None,
    custom_tcp_backend: Any = None,
    custom_tcp_xdp_interface: Any = None,
    custom_tcp_xdp_queue_id: Any = 0,
    custom_tcp_xdp_mode: Any = 0,
    custom_tcp_bridge_strict: bool = True,
) -> Dict[str, Any]:
    return await _custom_tcp_bridge.flush_custom_tcp_tx_packets(
        profile=profile,
        verbose=verbose,
        pacing_config=pacing_config,
        bridge_api=bridge_api,
        default_bridge_api=custom_tcp_dataplane,
        live_sent=live_sent,
        live_errors=live_errors,
        live_progress=live_progress,
        custom_tcp_backend=custom_tcp_backend,
        custom_tcp_xdp_interface=custom_tcp_xdp_interface,
        custom_tcp_xdp_queue_id=custom_tcp_xdp_queue_id,
        custom_tcp_xdp_mode=custom_tcp_xdp_mode,
        custom_tcp_bridge_strict=custom_tcp_bridge_strict,
        resolve_transport_fn=_resolve_custom_tcp_flush_transport,
        paced_raw_socket_sender_fn=paced_raw_socket_sender,
        xdp_sender_fn=xdp_sender,
        update_live_fn=_update_live,
        paced_send_xdp_fn=paced_send_xdp,
        pacing_engine_available=bool(PACING_ENGINE_AVAILABLE),
    )


async def _service_custom_tcp_runtime(
    stop_event: asyncio.Event,
    *,
    profile: Any,
    verbose: bool,
    bridge_api: Any = None,
    live_sent: Any = None,
    live_errors: Any = None,
    live_progress: Any = None,
    custom_tcp_backend: Any = None,
    custom_tcp_xdp_interface: Any = None,
    custom_tcp_xdp_queue_id: Any = 0,
    custom_tcp_xdp_mode: Any = 0,
) -> Dict[str, Any]:
    return await _custom_tcp_bridge.service_custom_tcp_runtime(
        stop_event,
        profile=profile,
        verbose=verbose,
        bridge_api=bridge_api,
        default_bridge_api=custom_tcp_dataplane,
        live_sent=live_sent,
        live_errors=live_errors,
        live_progress=live_progress,
        custom_tcp_backend=custom_tcp_backend,
        custom_tcp_xdp_interface=custom_tcp_xdp_interface,
        custom_tcp_xdp_queue_id=custom_tcp_xdp_queue_id,
        custom_tcp_xdp_mode=custom_tcp_xdp_mode,
        runtime_poll_snapshot_fn=_custom_tcp_runtime_poll_snapshot,
        flush_fn=_flush_custom_tcp_tx_packets,
    )


def compile_l7_profile_public(**kwargs):
    return _compile_l7_profile(**kwargs)


async def run_l7_profile_public(profile, **kwargs):
    stateful_runtime_backend = _resolve_stateful_runtime_backend(kwargs.get("stateful_runtime_backend"))
    stateful_runtime_strict = bool(kwargs.get("stateful_runtime_strict", False))
    legacy_mode = bool(kwargs.get("legacy_mode", False))
    runtime_cfg = RuntimeConfig(
        concurrency=max(1, int(kwargs.get("concurrency", 1) or 1)),
        stateful_runtime_backend=stateful_runtime_backend,
        stateful_runtime_strict=stateful_runtime_strict,
        legacy_mode=legacy_mode,
        live_progress=kwargs.get("live_progress") is not None,
        live_sent=kwargs.get("live_sent") is not None,
        live_errors=kwargs.get("live_errors") is not None,
        profile_l7=bool(kwargs.get("profile_l7", False)),
        profile_sample_limit=max(0, int(kwargs.get("profile_sample_limit", 0) or 0)),
    )
    session = open_stateful_runtime_session(runtime_cfg.as_dict())
    session.load_profile(profile)
    runtime_metadata = _stateful_runtime_metadata(profile, runtime_cfg)
    preflight = _stateful_runtime_preflight(
        profile,
        runtime_cfg,
        custom_tcp_backend=kwargs.get("custom_tcp_backend"),
        custom_tcp_xdp_interface=kwargs.get("custom_tcp_xdp_interface"),
    )
    if preflight is not None and str(preflight.get("stateful_runtime_preflight_status", "")) == "failed":
        session.close()
        reason = str(preflight.get("stateful_runtime_preflight_reason", "stateful_runtime_preflight_failed") or "stateful_runtime_preflight_failed")
        detail = str(preflight.get("stateful_runtime_preflight_detail", "") or "")
        fail_stats = _stateful_runtime_fail_visible_stats(
            profile,
            runtime_cfg,
            reason=reason,
            detail=detail,
        )
        fail_stats.update(preflight)
        fail_stats.update(session.snapshot())
        return fail_stats
    if not _profile_uses_custom_tcp(profile):
        session.close()
        return _stateful_runtime_fail_visible_stats(
            profile,
            runtime_cfg,
            reason="kernel_socket_transport_disabled",
            detail="L7 kernel_socket transport path is disabled; custom_tcp is mandatory.",
        )

    rx_iface = _resolve_custom_tcp_rx_iface(
        kwargs.get("custom_tcp_rx_interface"),
        kwargs.get("custom_tcp_xdp_interface"),
    )
    custom_tcp_backend = _resolve_custom_tcp_backend(kwargs.get("custom_tcp_backend"))
    previous_rx_iface = os.environ.get("SAMURAI_CUSTOM_TCP_RX_IFACE")
    previous_custom_tcp_backend = os.environ.get("SAMURAI_CUSTOM_TCP_BACKEND")
    if rx_iface:
        os.environ["SAMURAI_CUSTOM_TCP_RX_IFACE"] = rx_iface
    os.environ["SAMURAI_CUSTOM_TCP_BACKEND"] = custom_tcp_backend
    stop_event = asyncio.Event()
    bridge_task = asyncio.create_task(
        _service_custom_tcp_runtime(
            stop_event,
            profile=profile,
            verbose=bool(kwargs.get("verbose", False)),
            bridge_api=_resolve_custom_tcp_bridge_api(kwargs.get("custom_tcp_bridge_api")),
            live_sent=kwargs.get("live_sent"),
            live_errors=kwargs.get("live_errors"),
            live_progress=kwargs.get("live_progress"),
            custom_tcp_backend=custom_tcp_backend,
            custom_tcp_xdp_interface=kwargs.get("custom_tcp_xdp_interface"),
            custom_tcp_xdp_queue_id=kwargs.get("custom_tcp_xdp_queue_id", 0),
            custom_tcp_xdp_mode=kwargs.get("custom_tcp_xdp_mode", 0),
        )
    )
    result = None
    bridge_stats: Dict[str, Any] = {}
    try:
        result = await _run_l7_profile(profile, runtime_cfg)
    finally:
        stop_event.set()
        try:
            bridge_stats = await bridge_task
        finally:
            if previous_custom_tcp_backend is None:
                os.environ.pop("SAMURAI_CUSTOM_TCP_BACKEND", None)
            else:
                os.environ["SAMURAI_CUSTOM_TCP_BACKEND"] = previous_custom_tcp_backend
            if rx_iface:
                if previous_rx_iface is None:
                    os.environ.pop("SAMURAI_CUSTOM_TCP_RX_IFACE", None)
                else:
                    os.environ["SAMURAI_CUSTOM_TCP_RX_IFACE"] = previous_rx_iface
            session.close()
    stats = result.as_dict() if result is not None else {}
    observed_transport_backend = stats.get("runtime_transport_backend")
    if bridge_stats:
        stats = _merge_bridge_stats(stats, bridge_stats)
    stats.update(runtime_metadata)
    if preflight:
        stats.update(preflight)
        if str(stats.get("stateful_runtime_status", "") or "").strip().lower() in {"", "ok", "ready"}:
            stats.setdefault("stateful_runtime_status", "ready")
            stats.setdefault("stateful_runtime_reason", "none")
            stats.setdefault("stateful_runtime_detail", "")
    else:
        stats.update(_stateful_runtime_preflight_fields(status="skipped"))
    stats.update(session.snapshot())
    stats = _enforce_phase3_strict_h1_contract(
        stats,
        profile,
        runtime_cfg,
        observed_runtime_transport_backend=observed_transport_backend,
    )
    return stats


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
        stats_fn=_stats,
        update_live_fn=_update_live,
        log_error=log_error,
        cpu_packet_engine=cpu_packet_engine,
        packet_utils=packet_utils,
    )

FAST_SENDER_AVAILABLE, fast_sender = _sender_runtime.load_fast_sender(package=__package__)
try:
    from . import custom_tcp_dataplane as custom_tcp_dataplane

    CUSTOM_TCP_DATAPLANE_AVAILABLE = True
except Exception:
    custom_tcp_dataplane = None
    CUSTOM_TCP_DATAPLANE_AVAILABLE = False

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
    packet_size_override: int | None = None,
    packet_stride: int = 0,
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
        packet_size_override=packet_size_override,
        packet_stride=packet_stride,
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
    transport_backend=None,
    stateful_runtime_backend="afxdp",
    stateful_runtime_strict=False,
    legacy_mode=False,
):
    if l7_profile_file:
        loaded = load_l7_profile_file(l7_profile_file)
        profile = compile_l7_profile(
            protocol=str(loaded.get("protocol", "http2") or "http2"),
            target_ip=str(loaded.get("target_ip", target_ip) or target_ip),
            target_port=int(loaded.get("target_port", target_port) or target_port),
            scheme=str(loaded.get("scheme", scheme) or scheme),
            transport_backend=str(
                loaded.get("transport_backend", _resolve_l7_transport_backend(transport_backend, protocol="http2"))
                or _resolve_l7_transport_backend(transport_backend, protocol="http2")
            ),
            stateful_runtime_backend=str(loaded.get("stateful_runtime_backend", stateful_runtime_backend) or stateful_runtime_backend),
            stateful_runtime_strict=bool(loaded.get("stateful_runtime_strict", stateful_runtime_strict)),
            legacy_mode=bool(loaded.get("legacy_mode", legacy_mode)),
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
            transport_backend=_resolve_l7_transport_backend(transport_backend, protocol="http2"),
            stateful_runtime_backend=stateful_runtime_backend,
            stateful_runtime_strict=stateful_runtime_strict,
            legacy_mode=legacy_mode,
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
        stateful_runtime_backend=stateful_runtime_backend,
        stateful_runtime_strict=stateful_runtime_strict,
        legacy_mode=legacy_mode,
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
    transport_backend=None,
    custom_tcp_backend=None,
    custom_tcp_rx_interface=None,
    custom_tcp_xdp_interface=None,
    custom_tcp_xdp_queue_id=0,
    custom_tcp_xdp_mode=0,
    stateful_runtime_backend="afxdp",
    stateful_runtime_strict=False,
    legacy_mode=False,
):
    if l7_profile_file:
        loaded = load_l7_profile_file(l7_profile_file)
        profile = compile_l7_profile(
            protocol=str(loaded.get("protocol", "http1") or "http1"),
            target_ip=str(loaded.get("target_ip", target_ip) or target_ip),
            target_port=int(loaded.get("target_port", target_port) or target_port),
            scheme=str(loaded.get("scheme", scheme) or scheme),
            transport_backend=str(
                loaded.get("transport_backend", _resolve_l7_transport_backend(transport_backend, protocol="http1"))
                or _resolve_l7_transport_backend(transport_backend, protocol="http1")
            ),
            stateful_runtime_backend=str(loaded.get("stateful_runtime_backend", stateful_runtime_backend) or stateful_runtime_backend),
            stateful_runtime_strict=bool(loaded.get("stateful_runtime_strict", stateful_runtime_strict)),
            legacy_mode=bool(loaded.get("legacy_mode", legacy_mode)),
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
            transport_backend=_resolve_l7_transport_backend(transport_backend, protocol="http1"),
            stateful_runtime_backend=stateful_runtime_backend,
            stateful_runtime_strict=stateful_runtime_strict,
            legacy_mode=legacy_mode,
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
        verbose=verbose,
        stateful_runtime_backend=stateful_runtime_backend,
        stateful_runtime_strict=stateful_runtime_strict,
        legacy_mode=legacy_mode,
        live_sent=live_sent,
        live_errors=live_errors,
        live_progress=live_progress,
        custom_tcp_backend=custom_tcp_backend,
        custom_tcp_rx_interface=custom_tcp_rx_interface,
        custom_tcp_xdp_interface=custom_tcp_xdp_interface,
        custom_tcp_xdp_queue_id=custom_tcp_xdp_queue_id,
        custom_tcp_xdp_mode=custom_tcp_xdp_mode,
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
    transport_backend=None,
    custom_tcp_backend=None,
    custom_tcp_rx_interface=None,
    custom_tcp_xdp_interface=None,
    custom_tcp_xdp_queue_id=0,
    custom_tcp_xdp_mode=0,
    stateful_runtime_backend="afxdp",
    stateful_runtime_strict=False,
    legacy_mode=False,
):
    if l7_profile_file:
        loaded = load_l7_profile_file(l7_profile_file)
        profile = compile_l7_profile(
            protocol=str(loaded.get("protocol", "http1") or "http1"),
            target_ip=str(loaded.get("target_ip", target_ip) or target_ip),
            target_port=int(loaded.get("target_port", target_port) or target_port),
            scheme=str(loaded.get("scheme", scheme) or scheme),
            transport_backend=str(
                loaded.get("transport_backend", _resolve_l7_transport_backend(transport_backend, protocol="http1"))
                or _resolve_l7_transport_backend(transport_backend, protocol="http1")
            ),
            stateful_runtime_backend=str(loaded.get("stateful_runtime_backend", stateful_runtime_backend) or stateful_runtime_backend),
            stateful_runtime_strict=bool(loaded.get("stateful_runtime_strict", stateful_runtime_strict)),
            legacy_mode=bool(loaded.get("legacy_mode", legacy_mode)),
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
            transport_backend=_resolve_l7_transport_backend(transport_backend, protocol="http1"),
            stateful_runtime_backend=stateful_runtime_backend,
            stateful_runtime_strict=stateful_runtime_strict,
            legacy_mode=legacy_mode,
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
        verbose=verbose,
        stateful_runtime_backend=stateful_runtime_backend,
        stateful_runtime_strict=stateful_runtime_strict,
        legacy_mode=legacy_mode,
        live_sent=live_sent,
        live_errors=live_errors,
        live_progress=live_progress,
        custom_tcp_backend=custom_tcp_backend,
        custom_tcp_rx_interface=custom_tcp_rx_interface,
        custom_tcp_xdp_interface=custom_tcp_xdp_interface,
        custom_tcp_xdp_queue_id=custom_tcp_xdp_queue_id,
        custom_tcp_xdp_mode=custom_tcp_xdp_mode,
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
    )
