from __future__ import annotations

import os
from typing import Any, Dict

from .. import l7_engine as _adapter
from . import quic_h3_bridge, quic_mode

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

    mode_effective = "unavailable"
    mode_core = "unavailable"
    if core is not None and hasattr(core, "quic_stack_mode"):
        try:
            mode_core = quic_mode.normalize(getattr(core, "quic_stack_mode")())
            mode_effective = str(mode_core)
        except Exception:
            mode_effective = "unavailable"
            mode_core = "unavailable"
    quic_probe_reason = "unknown"
    if core is not None and hasattr(core, "quic_stack_probe_reason"):
        try:
            quic_probe_reason = str(getattr(core, "quic_stack_probe_reason")() or "unknown")
        except Exception:
            quic_probe_reason = "unknown"

    bridge_mode = quic_mode.normalize(quic_h3_bridge.stack_mode())
    bridge_autopromote = _env_flag("SAMURAI_L7_QUIC_BRIDGE_AUTOPROMOTE", "0")
    if bridge_autopromote and not quic_mode.is_h3_stateful(mode_effective) and quic_mode.is_h3_stateful(bridge_mode):
        mode_effective = bridge_mode

    quic_supported_probe = _has("run_quic_stateful", "quic_supported")
    quic_native_h3_stateful = quic_mode.is_native_h3_stateful(mode_core)
    quic_bridge_h3_stateful = quic_mode.is_bridge_h3_stateful(bridge_mode)
    quic_h3_stateful = quic_mode.is_h3_stateful(mode_effective)
    quic_supported = bool(quic_supported_probe and quic_native_h3_stateful)
    if bridge_autopromote and quic_bridge_h3_stateful:
        quic_supported = True

    quic_effective_path = "unavailable"
    if quic_native_h3_stateful:
        quic_effective_path = "c_native"
    elif bridge_autopromote and quic_bridge_h3_stateful:
        quic_effective_path = "py_bridge"

    return {
        "core_available": bool(core is not None),
        "http1": _has("run_http1_stateful"),
        "ws": _has("run_websocket_stateful"),
        "http2": _has("run_http2_stateful", "h2_supported"),
        "quic": bool(quic_supported),
        "quic_stack_mode": mode_effective,
        "quic_h3_stateful": bool(quic_h3_stateful),
        "quic_core_stack_mode": str(mode_core),
        "quic_stack_probe_reason": str(quic_probe_reason),
        "quic_bridge_stack_mode": str(bridge_mode),
        "quic_bridge_autopromote": bool(bridge_autopromote),
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
            auto_bridge = _env_flag("SAMURAI_L7_QUIC_AUTO_BRIDGE", "0")
            native_ready = bool(caps.get("quic_native_h3_stateful", False))
            payload_extra["enable_quic_py_bridge"] = 1 if (auto_bridge and not (prefer_native and native_ready)) else 0
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
