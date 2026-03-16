from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from .types import (
    SUPPORTED_EVENT_TYPES,
    SUPPORTED_LABELS,
    SUPPORTED_PROTOCOLS,
    SessionEvent,
    SessionPlan,
    TrafficPlan,
)

_REQUEST_EVENTS = {"http_request", "http2_headers", "quic_request"}


@dataclass
class ValidationResult:
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def _validate_event(session_id: str, event: SessionEvent, prev_idx: int) -> List[str]:
    out: List[str] = []
    if event.step_index != prev_idx + 1:
        out.append(f"{session_id}: step index jump at {event.step_index} (prev={prev_idx})")
    if event.event_type not in SUPPORTED_EVENT_TYPES:
        out.append(f"{session_id}: unsupported event_type={event.event_type}")
    if int(event.delay_ms) < 0:
        out.append(f"{session_id}: negative delay_ms={event.delay_ms}")
    if event.event_type in _REQUEST_EVENTS:
        if not str(event.method or "").strip():
            out.append(f"{session_id}: request event missing method at step={event.step_index}")
        if not str(event.path or "").strip():
            out.append(f"{session_id}: request event missing path at step={event.step_index}")
    return out


def _validate_session_plan(session_plan: SessionPlan) -> List[str]:
    out: List[str] = []
    if session_plan.protocol not in SUPPORTED_PROTOCOLS:
        out.append(f"{session_plan.session_id}: unsupported protocol={session_plan.protocol}")
    if session_plan.label not in SUPPORTED_LABELS:
        out.append(f"{session_plan.session_id}: unsupported label={session_plan.label}")
    if not session_plan.events:
        out.append(f"{session_plan.session_id}: empty event sequence")
        return out
    prev = -1
    for ev in session_plan.events:
        out.extend(_validate_event(session_plan.session_id, ev, prev))
        prev = int(ev.step_index)
    return out


def validate(plan: TrafficPlan) -> ValidationResult:
    errors: List[str] = []
    warnings: List[str] = []
    if not str(plan.plan_id or "").strip():
        errors.append("plan_id is required")
    if not str(plan.model_name or "").strip():
        errors.append("model_name is required")
    if not plan.session_plans:
        errors.append("session_plans must be non-empty")
    for session_plan in plan.session_plans:
        errors.extend(_validate_session_plan(session_plan))
    if len(plan.session_plans) < 2:
        warnings.append("very small plan: session_plans < 2")
    return ValidationResult(valid=(len(errors) == 0), errors=errors, warnings=warnings)

