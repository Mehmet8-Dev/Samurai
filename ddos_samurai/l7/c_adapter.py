from __future__ import annotations

import os
from typing import Any, Dict

from .. import l7_engine as _adapter
from . import quic_h3_bridge

_FN_BY_PROTOCOL = {
    "http1": "run_http1_stateful",
    "ws": "run_websocket_stateful",
    "http2": "run_http2_stateful",
    "quic": "run_quic_stateful",
}

_UNAVAILABLE_REASON = {
    "http1": "l7_state_engine_unavailable",
    "ws": "l7_state_engine_unavailable",
    "http2": "h2_capability_unavailable",
    "quic": "quic_capability_unavailable",
}

_UNAVAILABLE_PATH = {
    "http1": "C_STATE_HTTP1_UNAVAILABLE",
    "ws": "C_STATE_WS_UNAVAILABLE",
    "http2": "C_STATE_H2_UNAVAILABLE",
    "quic": "C_STATE_QUIC_UNAVAILABLE",
}


def _env_flag(name: str, default: str = "0") -> bool:
    raw = str(os.environ.get(name, default) or default).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def capability_map() -> Dict[str, Any]:
    core = getattr(_adapter, "_l7_core", None)

    def _has(protocol_runner: str, support_probe: str | None = None) -> bool:
        if core is None or not hasattr(core, protocol_runner):
            return False
        if support_probe and hasattr(core, support_probe):
            try:
                return bool(getattr(core, support_probe)())
            except Exception:
                return False
        return True

    quic_mode = "unavailable"
    quic_mode_core = "unavailable"
    if core is not None and hasattr(core, "quic_stack_mode"):
        try:
            quic_mode_core = str(getattr(core, "quic_stack_mode")() or "unavailable")
            quic_mode = str(quic_mode_core)
        except Exception:
            quic_mode = "unavailable"
            quic_mode_core = "unavailable"

    bridge_mode = str(quic_h3_bridge.stack_mode() or "unavailable")
    if not str(quic_mode).startswith("h3_stateful") and str(bridge_mode).startswith("h3_stateful"):
        quic_mode = bridge_mode

    quic_supported = _has("run_quic_stateful", "quic_supported")
    quic_native_h3_stateful = str(quic_mode_core).startswith("h3_stateful")
    quic_bridge_h3_stateful = str(bridge_mode).startswith("h3_stateful")
    quic_h3_stateful = str(quic_mode).startswith("h3_stateful")
    if quic_native_h3_stateful or quic_bridge_h3_stateful:
        quic_supported = True

    quic_effective_path = "unavailable"
    if quic_native_h3_stateful:
        quic_effective_path = "c_native"
    elif quic_bridge_h3_stateful:
        quic_effective_path = "py_bridge"

    return {
        "core_available": bool(core is not None),
        "http1": _has("run_http1_stateful"),
        "ws": _has("run_websocket_stateful"),
        "http2": _has("run_http2_stateful", "h2_supported"),
        "quic": bool(quic_supported),
        "quic_stack_mode": quic_mode,
        "quic_h3_stateful": bool(quic_h3_stateful),
        "quic_core_stack_mode": str(quic_mode_core),
        "quic_bridge_stack_mode": str(bridge_mode),
        "quic_native_h3_stateful": bool(quic_native_h3_stateful),
        "quic_bridge_h3_stateful": bool(quic_bridge_h3_stateful),
        "quic_effective_path": str(quic_effective_path),
    }


def make_config(
    *,
    target_ip: str,
    target_port: int,
    count: int,
    concurrency: int,
    mode: str,
    extra: Dict[str, Any] | None = None,
    session_repeats: int = 1,
    max_active_sessions: int = 0,
) -> _adapter.L7EngineConfig:
    payload_extra = dict(extra or {})
    if str(mode or "http1_stateful").strip().lower() == "quic_stateful":
        if "enable_quic_py_bridge" not in payload_extra:
            caps = capability_map()
            prefer_native = _env_flag("SAMURAI_L7_QUIC_PREFER_NATIVE", "1")
            native_ready = bool(caps.get("quic_native_h3_stateful", False))
            payload_extra["enable_quic_py_bridge"] = 0 if (prefer_native and native_ready) else 1
        payload_extra.setdefault(
            "require_native_quic",
            1 if _env_flag("SAMURAI_L7_QUIC_REQUIRE_NATIVE", "0") else 0,
        )
    return _adapter.L7EngineConfig(
        engine="c_state",
        target_ip=str(target_ip),
        target_port=int(target_port or 0),
        count=int(count or 0),
        concurrency=int(concurrency or 1),
        session_repeats=int(session_repeats or 1),
        max_active_sessions=int(max_active_sessions or 0),
        mode=str(mode or "http1_stateful"),
        extra=payload_extra,
    )


def _unavailable_result(protocol: str, count: int) -> _adapter.L7EngineResult:
    proto = str(protocol or "").strip().lower()
    return _adapter.L7EngineResult(
        handled=True,
        attempted=max(0, int(count or 0)),
        sent=0,
        errors=max(0, int(count or 0)),
        sender_path=str(_UNAVAILABLE_PATH.get(proto, "C_STATE_UNAVAILABLE")),
        sender_fallback_reason=str(_UNAVAILABLE_REASON.get(proto, "l7_state_engine_unavailable")),
        allow_legacy_fallback=True,
    )


async def run(protocol: str, config: _adapter.L7EngineConfig) -> _adapter.L7EngineResult:
    proto = str(protocol or "").strip().lower()
    fn_name = _FN_BY_PROTOCOL.get(proto)
    if not fn_name:
        return _unavailable_result(proto, int(config.count or 0))

    fn = getattr(_adapter, fn_name, None)
    if fn is None:
        return _unavailable_result(proto, int(config.count or 0))

    out = await fn(config)
    if out is None:
        return _unavailable_result(proto, int(config.count or 0))
    return out
