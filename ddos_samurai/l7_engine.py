from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

try:
    from . import l7_state_engine as _l7_core
except Exception:
    _l7_core = None


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


def _normalize_engine(name: str | None) -> str:
    e = str(name or "python").strip().lower()
    if e in {"c", "c_state", "state", "cstate"}:
        return "c_state"
    return "python"


def _from_core_result(raw: Dict[str, Any], *, default_count: int, sender_path: str) -> L7EngineResult:
    attempted = int(raw.get("attempted", default_count) or default_count)
    sent = int(raw.get("sent", 0) or 0)
    errors = int(raw.get("errors", max(0, attempted - sent)) or 0)
    return L7EngineResult(
        handled=True,
        attempted=attempted,
        sent=sent,
        errors=errors,
        sender_path=str(raw.get("sender_path", sender_path) or sender_path),
        sender_fallback_reason=str(raw.get("sender_fallback_reason", "none") or "none"),
        allow_legacy_fallback=False,
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
        raw = await asyncio.to_thread(_l7_core.run_http1_stateful, payload)
        if not isinstance(raw, dict):
            raw = {}
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
        raw = await asyncio.to_thread(_l7_core.run_websocket_stateful, payload)
        if not isinstance(raw, dict):
            raw = {}
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
