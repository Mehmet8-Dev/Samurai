from __future__ import annotations

import asyncio
import logging
import threading
from dataclasses import dataclass, field
from types import ModuleType
from typing import Any, Dict, Optional, Tuple

from .l7 import quic_h3_bridge

log = logging.getLogger(__name__)

try:
    from . import l7_state_engine as _l7_core
except Exception:
    _l7_core = None

_HANDLE_LOCK = threading.Lock()
_CORE_HANDLE: Any = None


@dataclass
class L7EngineConfig:
    engine: str = "python"
    target_ip: str = ""
    target_port: int = 0
    count: int = 0
    concurrency: int = 1
    session_repeats: int = 1
    max_active_sessions: int = 0
    mode: str = "http1_stateful"
    extra: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        out = {
            "engine": str(self.engine or "python"),
            "target_ip": str(self.target_ip or ""),
            "target_port": int(self.target_port or 0),
            "count": int(self.count or 0),
            "concurrency": int(self.concurrency or 1),
            "session_repeats": int(self.session_repeats or 1),
            "max_active_sessions": int(self.max_active_sessions or 0),
            "mode": str(self.mode or "http1_stateful"),
        }
        if self.extra:
            out.update(dict(self.extra))
        return out


@dataclass
class L7EngineResult:
    handled: bool = False
    attempted: int = 0
    sent: int = 0
    errors: int = 0
    sender_path: str = ""
    sender_fallback_reason: str = "none"
    allow_legacy_fallback: bool = False
    l7_active_sessions_peak: int = 0
    l7_conn_rate: float = 0.0
    l7_handshake_p99_ms: float = 0.0
    l7_step_fail_ratio: float = 0.0
    session_success_rate: float = 0.0
    retry_success_rate: float = 0.0
    retry_attempts: int = 0
    retry_successes: int = 0
    extra: Dict[str, Any] = field(default_factory=dict)

    def as_stats(self) -> Dict[str, Any]:
        out = {
            "attempted": int(self.attempted),
            "sent": int(self.sent),
            "errors": int(self.errors),
            "sender_path": str(self.sender_path or ""),
            "sender_fallback_reason": str(self.sender_fallback_reason or "none"),
            "l7_active_sessions_peak": int(self.l7_active_sessions_peak),
            "l7_conn_rate": float(self.l7_conn_rate),
            "l7_handshake_p99_ms": float(self.l7_handshake_p99_ms),
            "l7_step_fail_ratio": float(self.l7_step_fail_ratio),
            "session_success_rate": float(self.session_success_rate),
            "retry_success_rate": float(self.retry_success_rate),
            "retry_attempts": int(self.retry_attempts),
            "retry_successes": int(self.retry_successes),
        }
        for k, v in dict(self.extra or {}).items():
            if isinstance(v, bool):
                out[str(k)] = int(v)
            elif isinstance(v, (int, float, str)):
                out[str(k)] = v
        return out


def is_c_state_available() -> bool:
    return _l7_core is not None


def quic_py_bridge_supported() -> bool:
    return bool(quic_h3_bridge.supported())


def _quic_core_native_status() -> tuple[bool, str]:
    if _l7_core is None or not hasattr(_l7_core, "run_quic_stateful"):
        return False, "unavailable"
    mode = "unknown"
    if hasattr(_l7_core, "quic_stack_mode"):
        try:
            mode = str(_l7_core.quic_stack_mode() or "unavailable")
        except Exception:
            mode = "unknown"
    supported = str(mode).startswith("h3_stateful")
    if hasattr(_l7_core, "quic_supported"):
        try:
            supported = bool(_l7_core.quic_supported())
        except Exception:
            pass
    if supported and mode == "unknown":
        mode = "h3_stateful"
    if not supported and mode == "unknown":
        mode = "unavailable"
    return bool(supported), str(mode)


def _normalize_engine(name: str | None) -> str:
    e = str(name or "python").strip().lower()
    if e in {"c", "c_state", "state", "cstate"}:
        return "c_state"
    return "python"


def _from_core_result(raw: Dict[str, Any], *, default_count: int, sender_path: str) -> L7EngineResult:
    attempted = int(raw.get("attempted", default_count) or default_count)
    sent = int(raw.get("sent", 0) or 0)
    errors = int(raw.get("errors", max(0, attempted - sent)) or 0)
    reason = str(raw.get("sender_fallback_reason", "none") or "none")
    reason_l = reason.strip().lower()
    allow_legacy = bool(
        sent <= 0
        and (
            reason_l.startswith("unsupported_")
            or reason_l.startswith("tls_")
            or reason_l.startswith("ws_")
            or reason_l.startswith("h2_")
            or reason_l.startswith("quic_")
            or reason_l in {
                "l7_state_engine_unavailable",
                "tls_not_supported",
                "ws_scenario_unsupported",
                "h2_capability_unavailable",
                "quic_capability_unavailable",
                "capability_unavailable",
                "connect_fail",
                "tls_fail",
                "stream_fail",
                "invalid_config",
                "target_ip_missing",
                "target_port_invalid",
                "target_ip_invalid",
            }
        )
    )
    return L7EngineResult(
        handled=True,
        attempted=attempted,
        sent=sent,
        errors=errors,
        sender_path=str(raw.get("sender_path", sender_path) or sender_path),
        sender_fallback_reason=reason,
        allow_legacy_fallback=allow_legacy,
        l7_active_sessions_peak=int(raw.get("l7_active_sessions_peak", 0) or 0),
        l7_conn_rate=float(raw.get("l7_conn_rate", 0.0) or 0.0),
        l7_handshake_p99_ms=float(raw.get("l7_handshake_p99_ms", 0.0) or 0.0),
        l7_step_fail_ratio=float(raw.get("l7_step_fail_ratio", 0.0) or 0.0),
        session_success_rate=float(raw.get("session_success_rate", 0.0) or 0.0),
        retry_success_rate=float(raw.get("retry_success_rate", 0.0) or 0.0),
        retry_attempts=int(raw.get("retry_attempts", 0) or 0),
        retry_successes=int(raw.get("retry_successes", 0) or 0),
        extra=dict(raw),
    )


def _ensure_core_handle() -> Any:
    global _CORE_HANDLE
    if _l7_core is None or not hasattr(_l7_core, "open"):
        return None
    if _CORE_HANDLE is not None:
        return _CORE_HANDLE
    with _HANDLE_LOCK:
        if _CORE_HANDLE is not None:
            return _CORE_HANDLE
        try:
            _CORE_HANDLE = _l7_core.open({})
        except Exception:
            _CORE_HANDLE = None
    return _CORE_HANDLE


def _snapshot_core_handle(handle: Any) -> Dict[str, Any]:
    if handle is None or _l7_core is None or not hasattr(_l7_core, "snapshot"):
        return {}
    try:
        raw = _l7_core.snapshot(handle)
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}
    return dict(raw)


def _invoke_core_runner(fn_name: str, payload: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    if _l7_core is None:
        return {}, {}
    fn = getattr(_l7_core, fn_name, None)
    if fn is None:
        return {}, {}

    handle = _ensure_core_handle()
    raw: Any
    if handle is not None:
        try:
            raw = fn(handle, payload)
        except TypeError:
            raw = fn(payload)
        except Exception:
            raw = fn(payload)
    else:
        raw = fn(payload)

    if not isinstance(raw, dict):
        raw = {}

    snap = _snapshot_core_handle(handle)
    return dict(raw), snap


async def _invoke_core_runner_async(fn_name: str, payload: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    # C extension path can block (epoll/socket loop), keep it off the event loop.
    if isinstance(_l7_core, ModuleType):
        return await asyncio.to_thread(_invoke_core_runner, fn_name, payload)
    # Mock/fake cores in tests are cheap and avoid spinning extra thread executors.
    return _invoke_core_runner(fn_name, payload)


async def run_http1_stateful(config: L7EngineConfig) -> Optional[L7EngineResult]:
    if _normalize_engine(config.engine) != "c_state":
        return None

    count = max(0, int(config.count or 0))
    if count <= 0:
        return L7EngineResult(handled=True, attempted=0, sent=0, errors=0, sender_path="C_STATE_HTTP1")

    if _l7_core is None:
        return L7EngineResult(
            handled=True,
            attempted=count,
            sent=0,
            errors=count,
            sender_path="C_STATE_UNAVAILABLE",
            sender_fallback_reason="l7_state_engine_unavailable",
            allow_legacy_fallback=True,
        )

    payload = config.as_dict()
    try:
        raw, snap = await _invoke_core_runner_async("run_http1_stateful", payload)
        if snap:
            for k, v in snap.items():
                raw.setdefault(f"l7_handle_{k}", v)
        return _from_core_result(raw, default_count=count, sender_path="C_STATE_HTTP1")
    except Exception as exc:
        log.warning("l7_state_engine.run_http1_stateful failed: %s", exc)
        return L7EngineResult(
            handled=True,
            attempted=count,
            sent=0,
            errors=count,
            sender_path="C_STATE_HTTP1_FAILED",
            sender_fallback_reason=f"l7_state_engine_error:{type(exc).__name__}",
            allow_legacy_fallback=True,
        )


async def run_websocket_stateful(config: L7EngineConfig) -> Optional[L7EngineResult]:
    if _normalize_engine(config.engine) != "c_state":
        return None

    count = max(0, int(config.count or 0))
    if count <= 0:
        return L7EngineResult(handled=True, attempted=0, sent=0, errors=0, sender_path="C_STATE_WS")

    if _l7_core is None:
        return L7EngineResult(
            handled=True,
            attempted=count,
            sent=0,
            errors=count,
            sender_path="C_STATE_UNAVAILABLE",
            sender_fallback_reason="l7_state_engine_unavailable",
            allow_legacy_fallback=True,
        )

    payload = config.as_dict()
    try:
        raw, snap = await _invoke_core_runner_async("run_websocket_stateful", payload)
        if snap:
            for k, v in snap.items():
                raw.setdefault(f"l7_handle_{k}", v)
        return _from_core_result(raw, default_count=count, sender_path="C_STATE_WS")
    except Exception as exc:
        log.warning("l7_state_engine.run_websocket_stateful failed: %s", exc)
        return L7EngineResult(
            handled=True,
            attempted=count,
            sent=0,
            errors=count,
            sender_path="C_STATE_WS_FAILED",
            sender_fallback_reason=f"l7_state_engine_error:{type(exc).__name__}",
            allow_legacy_fallback=True,
        )


async def run_http2_stateful(config: L7EngineConfig) -> Optional[L7EngineResult]:
    if _normalize_engine(config.engine) != "c_state":
        return None

    count = max(0, int(config.count or 0))
    if count <= 0:
        return L7EngineResult(handled=True, attempted=0, sent=0, errors=0, sender_path="C_STATE_H2")

    if _l7_core is None:
        return L7EngineResult(
            handled=True,
            attempted=count,
            sent=0,
            errors=count,
            sender_path="C_STATE_UNAVAILABLE",
            sender_fallback_reason="l7_state_engine_unavailable",
            allow_legacy_fallback=True,
        )
    if not hasattr(_l7_core, "run_http2_stateful"):
        return L7EngineResult(
            handled=True,
            attempted=count,
            sent=0,
            errors=count,
            sender_path="C_STATE_H2_UNAVAILABLE",
            sender_fallback_reason="h2_capability_unavailable",
            allow_legacy_fallback=True,
        )
    if hasattr(_l7_core, "h2_supported") and not bool(_l7_core.h2_supported()):
        return L7EngineResult(
            handled=True,
            attempted=count,
            sent=0,
            errors=count,
            sender_path="C_STATE_H2_UNAVAILABLE",
            sender_fallback_reason="h2_capability_unavailable",
            allow_legacy_fallback=True,
        )

    payload = config.as_dict()
    try:
        raw, snap = await _invoke_core_runner_async("run_http2_stateful", payload)
        if snap:
            for k, v in snap.items():
                raw.setdefault(f"l7_handle_{k}", v)
        return _from_core_result(raw, default_count=count, sender_path="C_STATE_H2")
    except Exception as exc:
        log.warning("l7_state_engine.run_http2_stateful failed: %s", exc)
        return L7EngineResult(
            handled=True,
            attempted=count,
            sent=0,
            errors=count,
            sender_path="C_STATE_H2_FAILED",
            sender_fallback_reason=f"h2_engine_error:{type(exc).__name__}",
            allow_legacy_fallback=True,
        )


async def run_quic_stateful(config: L7EngineConfig) -> Optional[L7EngineResult]:
    if _normalize_engine(config.engine) != "c_state":
        return None

    count = max(0, int(config.count or 0))
    if count <= 0:
        return L7EngineResult(handled=True, attempted=0, sent=0, errors=0, sender_path="C_STATE_QUIC")

    payload = config.as_dict()
    bridge_enabled = bool(int(payload.get("enable_quic_py_bridge", 0) or 0))
    require_native = bool(int(payload.get("require_native_quic", 0) or 0))
    native_supported, native_mode = _quic_core_native_status()

    if require_native and not native_supported:
        return L7EngineResult(
            handled=True,
            attempted=count,
            sent=0,
            errors=count,
            sender_path="C_STATE_QUIC_NATIVE_REQUIRED",
            sender_fallback_reason=f"quic_native_required:{native_mode}",
            allow_legacy_fallback=False,
            extra={"quic_stack_mode": str(native_mode)},
        )

    if native_supported:
        try:
            raw, snap = await _invoke_core_runner_async("run_quic_stateful", payload)
            if snap:
                for k, v in snap.items():
                    raw.setdefault(f"l7_handle_{k}", v)
            out = _from_core_result(raw, default_count=count, sender_path="C_STATE_QUIC")
            out.extra.setdefault("quic_stack_mode", str(native_mode))
            if int(out.sent or 0) > 0:
                out.allow_legacy_fallback = False
                return out

            reason_l = str(out.sender_fallback_reason or "").strip().lower()
            recoverable_for_bridge = reason_l in {
                "h3_stateful_not_implemented",
                "quic_capability_unavailable",
                "capability_unavailable",
            }
            if require_native:
                out.allow_legacy_fallback = False
                return out
            if not bridge_enabled or not quic_h3_bridge.supported() or not recoverable_for_bridge:
                return out
            log.warning(
                "l7 native quic path returned recoverable reason=%s; trying h3 py-bridge",
                out.sender_fallback_reason,
            )
        except Exception as exc:
            if require_native or not bridge_enabled or not quic_h3_bridge.supported():
                log.warning("l7_state_engine.run_quic_stateful(native) failed: %s", exc)
                return L7EngineResult(
                    handled=True,
                    attempted=count,
                    sent=0,
                    errors=count,
                    sender_path="C_STATE_QUIC_FAILED",
                    sender_fallback_reason=f"quic_engine_error:{type(exc).__name__}",
                    allow_legacy_fallback=not bool(require_native),
                )
            log.warning("l7 native quic path failed (%s); trying h3 py-bridge", exc)

    if bridge_enabled and quic_h3_bridge.supported():
        try:
            raw = await quic_h3_bridge.run_stateful(payload)
            out = _from_core_result(raw, default_count=count, sender_path="C_STATE_QUIC_H3PY")
            # Bridge path is already the final H3 execution path.
            out.allow_legacy_fallback = False
            return out
        except Exception as exc:
            log.warning("l7 quic_h3_bridge.run_stateful failed: %s", exc)
            return L7EngineResult(
                handled=True,
                attempted=count,
                sent=0,
                errors=count,
                sender_path="C_STATE_QUIC_H3PY_FAILED",
                sender_fallback_reason=f"quic_h3_bridge_error:{type(exc).__name__}",
                allow_legacy_fallback=False,
            )

    if _l7_core is None:
        return L7EngineResult(
            handled=True,
            attempted=count,
            sent=0,
            errors=count,
            sender_path="C_STATE_UNAVAILABLE",
            sender_fallback_reason="l7_state_engine_unavailable",
            allow_legacy_fallback=True,
        )
    if not hasattr(_l7_core, "run_quic_stateful"):
        return L7EngineResult(
            handled=True,
            attempted=count,
            sent=0,
            errors=count,
            sender_path="C_STATE_QUIC_UNAVAILABLE",
            sender_fallback_reason="quic_capability_unavailable",
            allow_legacy_fallback=True,
        )
    if hasattr(_l7_core, "quic_supported") and not bool(_l7_core.quic_supported()):
        return L7EngineResult(
            handled=True,
            attempted=count,
            sent=0,
            errors=count,
            sender_path="C_STATE_QUIC_UNAVAILABLE",
            sender_fallback_reason="quic_capability_unavailable",
            allow_legacy_fallback=True,
        )

    try:
        raw, snap = await _invoke_core_runner_async("run_quic_stateful", payload)
        if snap:
            for k, v in snap.items():
                raw.setdefault(f"l7_handle_{k}", v)
        return _from_core_result(raw, default_count=count, sender_path="C_STATE_QUIC")
    except Exception as exc:
        log.warning("l7_state_engine.run_quic_stateful failed: %s", exc)
        return L7EngineResult(
            handled=True,
            attempted=count,
            sent=0,
            errors=count,
            sender_path="C_STATE_QUIC_FAILED",
            sender_fallback_reason=f"quic_engine_error:{type(exc).__name__}",
            allow_legacy_fallback=True,
        )
