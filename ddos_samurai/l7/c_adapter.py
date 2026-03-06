from __future__ import annotations

from typing import Any, Dict

from .. import l7_engine as _adapter

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


def capability_map() -> Dict[str, Any]:
    core = getattr(_adapter, "_l7_core", None)
    return {
        "core_available": bool(core is not None),
        "http1": bool(core is not None and hasattr(core, "run_http1_stateful")),
        "ws": bool(core is not None and hasattr(core, "run_websocket_stateful")),
        "http2": bool(core is not None and hasattr(core, "run_http2_stateful")),
        "quic": bool(core is not None and hasattr(core, "run_quic_stateful")),
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
    return _adapter.L7EngineConfig(
        engine="c_state",
        target_ip=str(target_ip),
        target_port=int(target_port or 0),
        count=int(count or 0),
        concurrency=int(concurrency or 1),
        session_repeats=int(session_repeats or 1),
        max_active_sessions=int(max_active_sessions or 0),
        mode=str(mode or "http1_stateful"),
        extra=dict(extra or {}),
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

