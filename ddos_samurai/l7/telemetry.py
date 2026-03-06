from __future__ import annotations

from typing import Any, Dict, Iterable

from .types import L7NormalizedResult


_DEFAULTS: Dict[str, Any] = {
    "attempted": 0,
    "sent": 0,
    "errors": 0,
    "sender_path": "",
    "sender_fallback_reason": "none",
    "l7_engine_path_used": "",
    "l7_fallback_reason": "none",
    "session_success_rate": 0.0,
    "retry_success_rate": 0.0,
    "l7_step_fail_ratio": 0.0,
    "l7_handshake_p99_ms": 0.0,
    "h2_stream_reset_ratio": 0.0,
    "h2_goaway_count": 0,
    "quic_stream_fail_ratio": 0.0,
    "quic_handshake_fail_ratio": 0.0,
    "l7_capability_status": "ok",
}


def _infer_capability_status(out: Dict[str, Any]) -> str:
    sender_path = str(out.get("sender_path", "") or "").strip().upper()
    fallback_reason = str(out.get("l7_fallback_reason", out.get("sender_fallback_reason", "none")) or "none").strip().lower()

    if (
        "CAPABILITY_UNAVAILABLE" in sender_path
        or sender_path.endswith("_UNAVAILABLE")
        or fallback_reason == "l7_state_engine_unavailable"
        or fallback_reason == "tls_not_supported"
        or "capability_unavailable" in fallback_reason
    ):
        return "missing"
    if fallback_reason in {"", "none"}:
        return "ok"
    return "partial"


def normalize_l7_stats(
    raw: Dict[str, Any] | None,
    *,
    attempted_default: int = 0,
    sender_path: str = "",
    engine_path_used: str = "",
    fallback_reason: str = "none",
) -> Dict[str, Any]:
    src = dict(raw or {})
    result = L7NormalizedResult(
        attempted=int(src.get("attempted", attempted_default) or attempted_default),
        sent=int(src.get("sent", 0) or 0),
        errors=int(src.get("errors", 0) or 0),
        sender_path=str(src.get("sender_path", sender_path) or sender_path),
        sender_fallback_reason=str(src.get("sender_fallback_reason", "none") or "none"),
        l7_engine_path_used=str(src.get("l7_engine_path_used", engine_path_used) or engine_path_used),
        l7_fallback_reason=str(src.get("l7_fallback_reason", fallback_reason) or fallback_reason),
        extra=src,
    )
    out = dict(_DEFAULTS)
    out.update(result.as_dict())
    for key, value in src.items():
        if isinstance(value, bool):
            out[str(key)] = int(value)
        elif isinstance(value, (int, float, str)):
            out[str(key)] = value
    if not out.get("l7_engine_path_used"):
        out["l7_engine_path_used"] = str(out.get("sender_path", ""))
    if str(out.get("l7_fallback_reason", "none")).strip().lower() == "none":
        out["l7_fallback_reason"] = str(out.get("sender_fallback_reason", "none") or "none")
    out["l7_capability_status"] = _infer_capability_status(out)
    return out


def aggregate_l7_stats(items: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    total_attempted = 0
    total_sent = 0
    total_errors = 0
    total_h2_goaway = 0
    weighted_h2_reset = 0.0
    weighted_quic_stream_fail = 0.0
    weighted_quic_hs_fail = 0.0
    weighted_step_fail = 0.0
    cap_missing = 0
    cap_partial = 0

    for item in list(items or []):
        row = normalize_l7_stats(item)
        attempted = max(0, int(row.get("attempted", 0) or 0))
        sent = max(0, int(row.get("sent", 0) or 0))
        errors = max(0, int(row.get("errors", 0) or 0))
        total_attempted += attempted
        total_sent += sent
        total_errors += errors
        total_h2_goaway += max(0, int(row.get("h2_goaway_count", 0) or 0))
        weighted_h2_reset += float(row.get("h2_stream_reset_ratio", 0.0) or 0.0) * attempted
        weighted_quic_stream_fail += float(row.get("quic_stream_fail_ratio", 0.0) or 0.0) * attempted
        weighted_quic_hs_fail += float(row.get("quic_handshake_fail_ratio", 0.0) or 0.0) * attempted
        weighted_step_fail += float(row.get("l7_step_fail_ratio", 0.0) or 0.0) * attempted
        status = str(row.get("l7_capability_status", "ok") or "ok").strip().lower()
        if status == "missing":
            cap_missing += 1
        elif status == "partial":
            cap_partial += 1

    denom = float(max(1, total_attempted))
    capability_status = "ok"
    if cap_missing > 0:
        capability_status = "missing"
    elif cap_partial > 0:
        capability_status = "partial"
    return {
        "attempted": int(total_attempted),
        "sent": int(total_sent),
        "errors": int(max(total_errors, total_attempted - total_sent)),
        "h2_goaway_count": int(total_h2_goaway),
        "h2_stream_reset_ratio": float(weighted_h2_reset / denom),
        "quic_stream_fail_ratio": float(weighted_quic_stream_fail / denom),
        "quic_handshake_fail_ratio": float(weighted_quic_hs_fail / denom),
        "l7_step_fail_ratio": float(weighted_step_fail / denom),
        "l7_capability_status": capability_status,
    }
