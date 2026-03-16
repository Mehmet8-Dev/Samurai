from __future__ import annotations

import random
from typing import Dict, List

from .types import PlanRequest, SessionEvent, SessionPlan, TrafficPlan

_PROTOCOL_OPEN = {
    "http1": "http_request",
    "http2": "http2_headers",
    "websocket": "ws_open",
    "quic": "quic_open",
}


def _normalize_mix(label_mix: Dict[str, float]) -> List[str]:
    if not label_mix:
        return ["benign", "evasive", "aggressive"]
    labels: List[str] = []
    for label, weight in sorted(label_mix.items()):
        repeats = max(1, int(float(weight) * 100))
        labels.extend([str(label)] * repeats)
    return labels or ["benign"]


def _build_events(protocol: str, session_len: int, label: str, rng: random.Random) -> List[SessionEvent]:
    events: List[SessionEvent] = []
    events.append(SessionEvent(step_index=0, event_type="connect_open", delay_ms=int(rng.randint(1, 15))))
    if protocol in {"http1", "http2", "quic"}:
        events.append(SessionEvent(step_index=1, event_type="tls_client_hello", delay_ms=int(rng.randint(1, 20))))
    next_idx = len(events)
    req_event = _PROTOCOL_OPEN.get(protocol, "http_request")
    path_root = "/api/v1/resource"
    for i in range(max(1, int(session_len) - next_idx - 1)):
        ev_type = req_event
        if protocol == "websocket" and i > 0:
            ev_type = "ws_frame"
        if protocol == "quic" and i > 0 and rng.random() < 0.2:
            ev_type = "retry"
        mutation_flags = []
        if label in {"evasive", "aggressive"} and rng.random() < 0.6:
            mutation_flags.append("header_shuffle")
        if label == "aggressive" and rng.random() < 0.5:
            mutation_flags.append("retry_burst")
        events.append(
            SessionEvent(
                step_index=next_idx + i,
                event_type=ev_type,
                delay_ms=int(rng.randint(2, 80)),
                method="GET" if protocol != "websocket" else None,
                path=path_root if protocol != "websocket" else "/ws",
                header_profile="modern_browser",
                payload_class="small_json",
                mutation_flags=mutation_flags,
                expect_response_class="2xx",
            )
        )
    events.append(
        SessionEvent(
            step_index=len(events),
            event_type="close",
            delay_ms=int(rng.randint(1, 10)),
            mutation_flags=[],
        )
    )
    return events


def generate_deterministic_plan(
    request: PlanRequest,
    *,
    model_name: str = "static-fallback",
    checkpoint_id: str = "none",
) -> TrafficPlan:
    rng = random.Random(int(request.seed))
    protocols = [str(p) for p in list(request.protocols or []) if str(p).strip()]
    protocols = protocols or ["http1"]
    label_pool = _normalize_mix(dict(request.label_mix or {}))
    session_plans: List[SessionPlan] = []
    for idx in range(max(0, int(request.session_count))):
        protocol = protocols[idx % len(protocols)]
        label = str(label_pool[rng.randint(0, len(label_pool) - 1)])
        session_id = f"s-{idx:06d}"
        events = _build_events(protocol=protocol, session_len=int(request.session_len), label=label, rng=rng)
        session_plans.append(
            SessionPlan(session_id=session_id, protocol=protocol, label=label, events=events)  # type: ignore[arg-type]
        )
    plan_id = (
        f"fallback-{int(request.seed)}-"
        f"{int(request.session_count)}-{int(request.session_len)}-"
        f"{'-'.join(protocols)}"
    )
    return TrafficPlan(
        plan_id=plan_id,
        model_name=str(model_name),
        checkpoint_id=str(checkpoint_id),
        seed=int(request.seed),
        session_plans=session_plans,
    )
