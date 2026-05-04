from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import random
import asyncio
import inspect
from typing import Any
from collections import defaultdict

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


@dataclass
class VirtualUserInstance:
    vu_id: int
    flow: str
    expected_steps: int
    state: VUState = VUState.QUEUED
    step_attempted: int = 0
    step_failed: int = 0
    retries_used: int = 0
    timeout_count: int = 0
    spawned_at_s: float = 0.0
    deadline_s: float = 0.0


@dataclass(frozen=True)
class FlowRuntimePolicy:
    max_retries: int = 1
    backoff_base_ms: int = 50
    backoff_max_ms: int = 2000
    timeout_action: str = "retry"  # retry | abort


class VUPool:
    def __init__(
        self,
        *,
        scenario_sessions: list[dict[str, Any]],
        ramp_seconds: int,
        max_session_seconds: int,
        ramp_curve: str = "linear",
        ramp_step_interval_s: int = 1,
        ramp_custom_points: list[tuple[float, int]] | None = None,
        retry_backoff_base_ms: int = 50,
        retry_backoff_max_ms: int = 2000,
        flow_policies: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        sessions = list(scenario_sessions or [])
        self._vus: dict[str, VirtualUserInstance] = {}
        self._spawn_order: list[str] = []
        self._spawn_schedule: list[float] = []
        self._active_peak = 0
        self._retry_backoff_base_ms = max(1, int(retry_backoff_base_ms or 50))
        self._retry_backoff_max_ms = max(self._retry_backoff_base_ms, int(retry_backoff_max_ms or 2000))
        self._next_retry_at_s: dict[str, float] = {}
        self._flow_policies_raw = dict(flow_policies or {})
        self._controller = RampController(
            target_vus=len(sessions),
            ramp_seconds=max(0, int(ramp_seconds)),
            curve=str(ramp_curve or "linear"),
            step_interval_s=max(1, int(ramp_step_interval_s or 1)),
            custom_points=tuple((ramp_custom_points or [])),
        )
        self._spawn_schedule = self._controller.spawn_schedule()
        max_s = max(1, int(max_session_seconds))
        for i, sess in enumerate(sessions, start=1):
            flow = str((sess or {}).get("flow", "unknown") or "unknown")
            events = list((sess or {}).get("events", []) or [])
            expected = int(
                sum(1 for ev in events if str((ev or {}).get("event_type", "") or "").strip().lower() in {"http_request", "http2_headers"})
            )
            spawn_at = float(self._spawn_schedule[i - 1]) if (i - 1) < len(self._spawn_schedule) else 0.0
            vu = VirtualUserInstance(
                vu_id=i,
                flow=flow,
                expected_steps=max(0, expected),
                spawned_at_s=spawn_at,
                deadline_s=spawn_at + float(max_s),
            )
            key = str(i)
            self._vus[key] = vu
            self._spawn_order.append(key)

    def _policy_for_flow(self, flow: str) -> FlowRuntimePolicy:
        raw = dict(self._flow_policies_raw.get(str(flow or "unknown"), {}) or {})
        return FlowRuntimePolicy(
            max_retries=max(0, int(raw.get("max_retries", 1) or 1)),
            backoff_base_ms=max(1, int(raw.get("backoff_base_ms", self._retry_backoff_base_ms) or self._retry_backoff_base_ms)),
            backoff_max_ms=max(
                max(1, int(raw.get("backoff_base_ms", self._retry_backoff_base_ms) or self._retry_backoff_base_ms)),
                int(raw.get("backoff_max_ms", self._retry_backoff_max_ms) or self._retry_backoff_max_ms),
            ),
            timeout_action=str(raw.get("timeout_action", "retry") or "retry").strip().lower(),
        )

    def spawn_until(self, elapsed_s: float) -> int:
        now = max(0.0, float(elapsed_s))
        spawned = 0
        for key in self._spawn_order:
            vu = self._vus[key]
            if vu.state != VUState.QUEUED:
                continue
            if vu.spawned_at_s <= now:
                vu.state = VUState.INITIALIZING
                vu.state = VUState.RUNNING
                spawned += 1
        self._active_peak = max(self._active_peak, self.active_count())
        return spawned

    def ingest_step_results(self, rows: list[dict[str, Any]]) -> None:
        for row in list(rows or []):
            vu_id = str((row or {}).get("vu_id", "") or "")
            if not vu_id or vu_id not in self._vus:
                continue
            vu = self._vus[vu_id]
            if vu.state in {VUState.COMPLETED, VUState.FAILED}:
                continue
            vu.state = VUState.RUNNING
            vu.step_attempted += 1
            ok = bool((row or {}).get("success", False))
            timeout = bool((row or {}).get("timeout", False))
            policy = self._policy_for_flow(vu.flow)
            if not ok:
                vu.step_failed += 1
                if timeout:
                    vu.timeout_count += 1
                should_retry = vu.retries_used < int(policy.max_retries)
                if timeout and policy.timeout_action == "abort":
                    should_retry = False
                if should_retry:
                    vu.retries_used += 1
                    vu.state = VUState.RETRYING
                    # Exponential backoff with cap; retry gate is resolved by tick_retries().
                    backoff_ms = min(policy.backoff_max_ms, policy.backoff_base_ms * (2 ** max(0, vu.retries_used - 1)))
                    self._next_retry_at_s[vu_id] = max(vu.spawned_at_s, self._next_retry_at_s.get(vu_id, 0.0)) + (float(backoff_ms) / 1000.0)
                else:
                    vu.state = VUState.FAILED
            if vu.expected_steps > 0 and vu.step_attempted >= vu.expected_steps:
                if vu.step_failed == 0:
                    vu.state = VUState.COMPLETED
                else:
                    vu.state = VUState.FAILED
            if vu.state in {VUState.COMPLETED, VUState.FAILED}:
                self._next_retry_at_s.pop(vu_id, None)
        self._active_peak = max(self._active_peak, self.active_count())

    def tick_retries(self, elapsed_s: float) -> int:
        now = max(0.0, float(elapsed_s))
        moved = 0
        for vu_id, when_s in list(self._next_retry_at_s.items()):
            vu = self._vus.get(vu_id)
            if vu is None:
                self._next_retry_at_s.pop(vu_id, None)
                continue
            if vu.state == VUState.RETRYING and now >= when_s and vu.state not in {VUState.COMPLETED, VUState.FAILED}:
                vu.state = VUState.RUNNING
                moved += 1
                self._next_retry_at_s.pop(vu_id, None)
        return moved

    def finalize_timeouts(self, elapsed_s: float) -> int:
        now = max(0.0, float(elapsed_s))
        marked = 0
        for vu in self._vus.values():
            if vu.state in {VUState.COMPLETED, VUState.FAILED, VUState.QUEUED}:
                continue
            if now > vu.deadline_s:
                vu.state = VUState.FAILED
                vu.step_failed += 1
                vu.timeout_count += 1
                marked += 1
        return marked

    def active_count(self) -> int:
        return int(sum(1 for v in self._vus.values() if v.state in {VUState.INITIALIZING, VUState.RUNNING, VUState.THINK_TIME, VUState.RETRYING}))

    def snapshots(self) -> list[VirtualUserSnapshot]:
        out: list[VirtualUserSnapshot] = []
        for key in sorted(self._vus.keys(), key=lambda x: int(x)):
            v = self._vus[key]
            out.append(
                VirtualUserSnapshot(
                    vu_id=v.vu_id,
                    flow=v.flow,
                    state=v.state,
                    step_attempted=v.step_attempted,
                    step_failed=v.step_failed,
                    retries_used=v.retries_used,
                    timeout_count=v.timeout_count,
                )
            )
        return out

    def summary_metrics(self) -> dict[str, Any]:
        snaps = self.snapshots()
        attempted = int(sum(s.step_attempted for s in snaps))
        failed = int(sum(s.step_failed for s in snaps))
        return {
            "vus_spawned": int(sum(1 for s in snaps if s.state != VUState.QUEUED)),
            "vus_active_peak": int(self._active_peak),
            "step_attempted": attempted,
            "step_failed": failed,
            "sessions_completed": int(sum(1 for s in snaps if s.state == VUState.COMPLETED)),
            "sessions_failed": int(sum(1 for s in snaps if s.state == VUState.FAILED)),
        }

    def per_flow_metrics(self, duration_s: float) -> dict[str, dict[str, float]]:
        snaps = self.snapshots()
        by_flow: dict[str, FlowRuntimeMetrics] = defaultdict(FlowRuntimeMetrics)
        for s in snaps:
            row = by_flow.setdefault(s.flow, FlowRuntimeMetrics())
            row.sessions_total += 1
            row.sessions_completed += 1 if s.state == VUState.COMPLETED else 0
            row.step_attempted += s.step_attempted
            row.step_failed += s.step_failed
        d = max(0.001, float(duration_s or 0.001))
        out: dict[str, dict[str, float]] = {}
        for flow, row in by_flow.items():
            out[flow] = {
                "sessions": float(row.sessions_total),
                "completed": float(row.sessions_completed),
                "step_attempted": float(row.step_attempted),
                "step_failed": float(row.step_failed),
                "session_completion_rate": float(row.sessions_completed / max(1, row.sessions_total)),
                "step_fail_ratio": float(row.step_failed / max(1, row.step_attempted)),
                "conn_rate": float(row.sessions_total / d),
            }
        return out

    def drive_with_observed_ratios(
        self,
        *,
        observed_error_ratio: float,
        observed_timeout_ratio: float,
        seed: int,
        duration_s: float,
    ) -> list[VirtualUserSnapshot]:
        rng = random.Random(int(seed))
        dur = max(0.001, float(duration_s or 0.001))
        self.spawn_until(dur)
        for key in self._spawn_order:
            vu = self._vus[key]
            if vu.state == VUState.QUEUED:
                continue
            if vu.expected_steps <= 0:
                vu.state = VUState.COMPLETED
                continue
            for _ in range(vu.expected_steps):
                if vu.state in {VUState.COMPLETED, VUState.FAILED}:
                    break
                is_timeout = rng.random() < max(0.0, min(1.0, observed_timeout_ratio))
                is_error = (not is_timeout) and (rng.random() < max(0.0, min(1.0, observed_error_ratio)))
                self.ingest_step_results(
                    [
                        {
                            "vu_id": key,
                            "flow": vu.flow,
                            "success": not (is_timeout or is_error),
                            "timeout": bool(is_timeout),
                        }
                    ]
                )
                self.tick_retries(min(dur, vu.deadline_s))
                if vu.step_attempted >= vu.expected_steps:
                    break
            if vu.state not in {VUState.COMPLETED, VUState.FAILED}:
                vu.state = VUState.COMPLETED if vu.step_failed == 0 else VUState.FAILED
        self.finalize_timeouts(dur)
        return self.snapshots()

    async def drive_with_step_batches(
        self,
        *,
        duration_s: float,
        step_batch_provider: Any,
        tick_ms: int = 20,
    ) -> list[VirtualUserSnapshot]:
        dur = max(0.001, float(duration_s or 0.001))
        tick = max(1, int(tick_ms or 20))
        elapsed = 0.0
        while elapsed <= dur:
            self.spawn_until(elapsed)
            self.tick_retries(elapsed)
            rows = []
            if callable(step_batch_provider):
                maybe = step_batch_provider(elapsed)
                if inspect.isawaitable(maybe):
                    maybe = await maybe
                rows = list(maybe or [])
            if rows:
                self.ingest_step_results(rows)
            self.finalize_timeouts(elapsed)
            await asyncio.sleep(0)
            elapsed += float(tick) / 1000.0
        self.spawn_until(dur)
        self.tick_retries(dur)
        self.finalize_timeouts(dur)
        return self.snapshots()


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
    ramp_curve: str = "linear",
    ramp_step_interval_s: int = 1,
    ramp_custom_points: list[tuple[float, int]] | None = None,
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
    rc = RampController(
        target_vus=total_sessions,
        ramp_seconds=ramp_s,
        curve=str(ramp_curve or "linear"),
        step_interval_s=max(1, int(ramp_step_interval_s or 1)),
        custom_points=tuple((ramp_custom_points or [])),
    )
    spawn_schedule = rc.spawn_schedule()
    for si, session in enumerate(sessions):
        vu_id = si + 1
        spawn_at = float(spawn_schedule[si]) if si < len(spawn_schedule) else 0.0
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
@dataclass(frozen=True)
class RampController:
    target_vus: int
    ramp_seconds: int
    curve: str = "linear"
    step_interval_s: int = 1
    custom_points: tuple[tuple[float, int], ...] = ()

    def active_vus_at(self, elapsed_s: float) -> int:
        total = max(1, int(self.target_vus))
        ramp = max(0.0, float(self.ramp_seconds))
        t = max(0.0, float(elapsed_s))
        mode = str(self.curve or "linear").strip().lower()
        if ramp <= 0.0:
            return total
        if mode == "step":
            iv = max(1, int(self.step_interval_s or 1))
            steps = max(1, int(ramp // float(iv)))
            done = min(steps, int(t // float(iv)))
            return min(total, max(1, int((done * total) / max(1, steps))))
        if mode == "spike":
            # Fast front-load: reach 70% by first 20% of ramp window.
            if t >= ramp:
                return total
            p = t / ramp
            if p <= 0.2:
                return min(total, max(1, int(total * (0.7 * (p / 0.2)))))
            return min(total, max(1, int(total * (0.7 + (0.3 * ((p - 0.2) / 0.8))))))
        if mode == "custom" and self.custom_points:
            pts = sorted([(max(0.0, float(x[0])), max(0, int(x[1]))) for x in self.custom_points], key=lambda x: x[0])
            if t <= pts[0][0]:
                return min(total, pts[0][1])
            for i in range(1, len(pts)):
                t0, v0 = pts[i - 1]
                t1, v1 = pts[i]
                if t <= t1:
                    if t1 <= t0:
                        return min(total, v1)
                    frac = (t - t0) / (t1 - t0)
                    return min(total, max(0, int(v0 + ((v1 - v0) * frac))))
            return min(total, pts[-1][1])
        # linear default
        return min(total, max(1, int(total * min(1.0, t / ramp))))

    def spawn_schedule(self) -> list[float]:
        total = max(1, int(self.target_vus))
        if total == 1:
            return [0.0]
        out: list[float] = []
        last = 0
        horizon = max(1, int(max(1, self.ramp_seconds) * 1000))
        for ms in range(0, horizon + 1):
            active = self.active_vus_at(float(ms) / 1000.0)
            while last < active and len(out) < total:
                out.append(float(ms) / 1000.0)
                last += 1
            if len(out) >= total:
                break
        while len(out) < total:
            out.append(float(max(0, self.ramp_seconds)))
        return out
