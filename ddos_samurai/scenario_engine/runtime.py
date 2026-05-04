from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import random
from typing import Any

from ..gpu_cuda_payload import H2RequestPlan, H2RequestPlanItem
from .metrics import FlowRuntimeMetrics


@dataclass(frozen=True)
class ScheduledRequestBatch:
    delay_s: float
    request_plan: H2RequestPlan


class VUState(str, Enum):
    QUEUED = "queued"
    INITIALIZING = "initializing"
    RUNNING = "running"
    THINK_TIME = "think_time"
    RETRYING = "retrying"
    FAILED = "failed"
    COMPLETED = "completed"


@dataclass(frozen=True)
class VirtualUserSnapshot:
    vu_id: int
    flow: str
    state: VUState
    step_attempted: int
    step_failed: int
    retries_used: int
    timeout_count: int


def _as_item_dict(item: H2RequestPlanItem) -> dict[str, Any]:
    return {
        "method": str(item.method),
        "path": str(item.path),
        "headers": dict(item.headers or {}),
        "user_agent": item.user_agent,
    }


def serialize_batches(batches: list[ScheduledRequestBatch]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for b in list(batches or []):
        out.append(
            {
                "delay_s": float(max(0.0, b.delay_s)),
                "items": [_as_item_dict(it) for it in list(getattr(b.request_plan, "items", []) or [])],
            }
        )
    return out


def deserialize_batches(payload: list[dict[str, Any]]) -> list[ScheduledRequestBatch]:
    out: list[ScheduledRequestBatch] = []
    for row in list(payload or []):
        items = []
        for it in list((row or {}).get("items", []) or []):
            items.append(
                H2RequestPlanItem(
                    method=str((it or {}).get("method", "GET") or "GET"),
                    path=str((it or {}).get("path", "/") or "/"),
                    headers=dict((it or {}).get("headers") or {}),
                    user_agent=(it or {}).get("user_agent"),
                )
            )
        out.append(
            ScheduledRequestBatch(
                delay_s=float((row or {}).get("delay_s", 0.0) or 0.0),
                request_plan=H2RequestPlan(items=items),
            )
        )
    return out


def build_vu_lifecycle_batches(
    *,
    scenario_sessions: list[dict[str, Any]],
    ramp_seconds: int,
    max_session_seconds: int,
    seed: int,
    bucket_ms: int = 50,
) -> tuple[list[ScheduledRequestBatch], dict[str, Any]]:
    sessions = list(scenario_sessions or [])
    if not sessions:
        return [], {
            "vus_spawned": 0,
            "vus_active_peak": 0,
            "step_attempted": 0,
            "step_failed": 0,
        }
    rng = random.Random(int(seed))
    total_sessions = len(sessions)
    ramp_s = max(0, int(ramp_seconds))
    max_sess_s = max(1, int(max_session_seconds))
    bucket = max(1, int(bucket_ms))
    timeline: dict[int, list[H2RequestPlanItem]] = {}
    step_attempted = 0
    step_failed = 0
    active_markers: list[tuple[float, int]] = []

    vu_expected_steps: dict[str, int] = {}
    vu_flow: dict[str, str] = {}
    for si, session in enumerate(sessions):
        vu_id = si + 1
        spawn_at = 0.0 if total_sessions <= 1 else (float(ramp_s) * float(si) / float(total_sessions - 1))
        t = spawn_at
        deadline = spawn_at + float(max_sess_s)
        events = list((session or {}).get("events", []) or [])
        flow = str((session or {}).get("flow", "unknown") or "unknown")
        vu_flow[str(vu_id)] = flow
        vu_expected_steps[str(vu_id)] = int(
            sum(1 for ev in events if str((ev or {}).get("event_type", "") or "").strip().lower() in {"http_request", "http2_headers"})
        )
        active_markers.append((spawn_at, +1))
        for ev in events:
            et = str((ev or {}).get("event_type", "") or "").strip().lower()
            if et == "think_time":
                min_ms = max(0, int((ev or {}).get("min_ms", 0) or 0))
                max_ms = max(min_ms, int((ev or {}).get("max_ms", min_ms) or min_ms))
                t += float(rng.randint(min_ms, max_ms)) / 1000.0
                continue
            if et not in {"http_request", "http2_headers"}:
                continue
            if t > deadline:
                step_failed += 1
                continue
            step_attempted += 1
            method = str((ev or {}).get("method", "GET") or "GET").upper()
            path = str((ev or {}).get("path", "/") or "/")
            headers = dict((ev or {}).get("headers") or {})
            retry_count = max(0, int((ev or {}).get("retry_count", 0) or 0))
            headers["x-scenario-flow"] = flow
            headers["x-scenario-vu-id"] = str(vu_id)
            key = int((t * 1000.0) // bucket)
            timeline.setdefault(key, []).append(H2RequestPlanItem(method=method, path=path, headers=headers))
            # Model retry lifecycle deterministically as future attempts in plan timeline.
            for r in range(retry_count):
                t_retry = t + (0.05 * float(r + 1))
                if t_retry > deadline:
                    step_failed += 1
                    continue
                step_attempted += 1
                key_retry = int((t_retry * 1000.0) // bucket)
                timeline.setdefault(key_retry, []).append(H2RequestPlanItem(method=method, path=path, headers=headers))
        active_markers.append((min(deadline, t), -1))

    batches: list[ScheduledRequestBatch] = []
    for k in sorted(timeline.keys()):
        items = list(timeline.get(k, []) or [])
        if not items:
            continue
        delay_s = (float(k * bucket) / 1000.0)
        batches.append(ScheduledRequestBatch(delay_s=delay_s, request_plan=H2RequestPlan(items=items)))

    active_markers.sort(key=lambda x: (x[0], -x[1]))
    active = 0
    active_peak = 0
    for _, d in active_markers:
        active += int(d)
        active_peak = max(active_peak, active)

    metrics = {
        "vus_spawned": int(total_sessions),
        "vus_active_peak": int(active_peak),
        "step_attempted": int(step_attempted),
        "step_failed": int(step_failed),
        "vu_expected_steps": dict(vu_expected_steps),
        "vu_flow": dict(vu_flow),
    }
    return batches, metrics


def simulate_vu_state_machine(
    *,
    scenario_sessions: list[dict[str, Any]],
    observed_error_ratio: float,
    observed_timeout_ratio: float,
    seed: int,
) -> list[VirtualUserSnapshot]:
    rng = random.Random(int(seed))
    out: list[VirtualUserSnapshot] = []
    for i, sess in enumerate(list(scenario_sessions or []), start=1):
        flow = str((sess or {}).get("flow", "unknown") or "unknown")
        events = list((sess or {}).get("events", []) or [])
        attempted = 0
        failed = 0
        retries = 0
        timeouts = 0
        state = VUState.QUEUED
        state = VUState.INITIALIZING
        state = VUState.RUNNING
        for ev in events:
            et = str((ev or {}).get("event_type", "") or "").strip().lower()
            if et == "think_time":
                state = VUState.THINK_TIME
                state = VUState.RUNNING
                continue
            if et not in {"http_request", "http2_headers"}:
                continue
            attempted += 1
            if rng.random() < max(0.0, min(1.0, observed_timeout_ratio)):
                timeouts += 1
                failed += 1
                state = VUState.RETRYING
                retries += 1
                continue
            if rng.random() < max(0.0, min(1.0, observed_error_ratio)):
                failed += 1
                state = VUState.RETRYING
                retries += 1
                continue
            state = VUState.RUNNING
        if failed > 0 and attempted == failed:
            state = VUState.FAILED
        else:
            state = VUState.COMPLETED
        out.append(
            VirtualUserSnapshot(
                vu_id=i,
                flow=flow,
                state=state,
                step_attempted=attempted,
                step_failed=failed,
                retries_used=retries,
                timeout_count=timeouts,
            )
        )
    return out


def collect_per_flow_metrics(vus: list[VirtualUserSnapshot], duration_s: float) -> dict[str, dict[str, float]]:
    by_flow_raw: dict[str, FlowRuntimeMetrics] = {}
    for vu in list(vus or []):
        row = by_flow_raw.setdefault(vu.flow, FlowRuntimeMetrics())
        row.sessions_total += 1
        row.sessions_completed += 1 if vu.state == VUState.COMPLETED else 0
        row.step_attempted += int(vu.step_attempted)
        row.step_failed += int(vu.step_failed)
    d = max(0.001, float(duration_s or 0.001))
    by_flow: dict[str, dict[str, float]] = {}
    for name, row in by_flow_raw.items():
        by_flow[name] = {
            "sessions": float(row.sessions_total),
            "completed": float(row.sessions_completed),
            "failed": float(row.sessions_total - row.sessions_completed),
            "step_attempted": float(row.step_attempted),
            "step_failed": float(row.step_failed),
            "retries_used": 0.0,
            "timeouts": 0.0,
            "session_completion_rate": float(row.sessions_completed / max(1, row.sessions_total)),
            "step_fail_ratio": float(row.step_failed / max(1, row.step_attempted)),
            "conn_rate": float(row.sessions_total / d),
        }
    return by_flow
