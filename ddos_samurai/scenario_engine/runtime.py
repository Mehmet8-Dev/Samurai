from __future__ import annotations

from dataclasses import dataclass
import random
from typing import Any

from ..gpu_cuda_payload import H2RequestPlan, H2RequestPlanItem


@dataclass(frozen=True)
class ScheduledRequestBatch:
    delay_s: float
    request_plan: H2RequestPlan


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

    for si, session in enumerate(sessions):
        spawn_at = 0.0 if total_sessions <= 1 else (float(ramp_s) * float(si) / float(total_sessions - 1))
        t = spawn_at
        deadline = spawn_at + float(max_sess_s)
        events = list((session or {}).get("events", []) or [])
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
    }
    return batches, metrics
