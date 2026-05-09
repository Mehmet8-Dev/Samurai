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


def _infer_content_type_from_template(body_template: str) -> str | None:
    text = str(body_template or "").strip()
    if not text:
        return None
    if (text.startswith("{") and text.endswith("}")) or (text.startswith("[") and text.endswith("]")):
        return "application/json"
    return "text/plain; charset=utf-8"


def _session_count(sessions: list[dict[str, Any]]) -> int:
    total = 0
    for sess in list(sessions or []):
        if bool((sess or {}).get("packed_soa", False)):
            offs = list((sess or {}).get("session_offsets", []) or [])
            total += max(0, len(offs) - 1)
        else:
            total += 1
    return int(total)


def _iter_session_views(sessions: list[dict[str, Any]]):
    for sess in list(sessions or []):
        if not bool((sess or {}).get("packed_soa", False)):
            yield sess
            continue
        offsets = list((sess or {}).get("session_offsets", []) or [])
        flows = list((sess or {}).get("session_flow", []) or [])
        personas = list((sess or {}).get("session_persona", []) or [])
        attempts = list((sess or {}).get("session_step_attempted", []) or [])
        timeouts = list((sess or {}).get("session_timeout_ms", []) or [])
        for i in range(max(0, len(offsets) - 1)):
            yield {
                "flow": str(flows[i] if i < len(flows) else "unknown"),
                "persona": str(personas[i] if i < len(personas) else ""),
                "session_timeout_ms": int(timeouts[i] if i < len(timeouts) else 0),
                "packed": True,
                "__soa": sess,
                "__start": int(offsets[i]),
                "__end": int(offsets[i + 1]),
                "__step_attempted": int(attempts[i] if i < len(attempts) else 0),
            }


def _packed_session_arrays(session: dict[str, Any]) -> dict[str, Any]:
    src = dict((session or {}).get("__soa") or {}) if "__soa" in (session or {}) else dict(session or {})
    s0 = max(0, int((session or {}).get("__start", 0) or 0))
    s1 = max(s0, int((session or {}).get("__end", 0) or 0)) if "__soa" in (session or {}) else len(list((src or {}).get("event_kind", []) or []))
    ek = list((src or {}).get("event_kind", []) or [])
    n = max(0, min(len(ek), s1) - s0)
    return {
        "s0": s0,
        "s1": s1,
        "n": n,
        "ek": ek,
        "rk": list((src or {}).get("request_kind", []) or []),
        "methods": list((src or {}).get("method", []) or []),
        "paths": list((src or {}).get("path", []) or []),
        "headers_list": list((src or {}).get("headers", []) or []),
        "cookies_list": list((src or {}).get("cookies", []) or []),
        "headers_idx": list((src or {}).get("headers_idx", []) or []),
        "cookies_idx": list((src or {}).get("cookies_idx", []) or []),
        "headers_pool": list((src or {}).get("headers_pool", []) or []),
        "cookies_pool": list((src or {}).get("cookies_pool", []) or []),
        "retry_list": list((src or {}).get("retry_count", []) or []),
        "on_failure_list": list((src or {}).get("on_failure", []) or []),
        "body_templates": list((src or {}).get("body_template", []) or []),
        "think_min": list((src or {}).get("think_min_ms", []) or []),
        "think_max": list((src or {}).get("think_max_ms", []) or []),
        "think_dist": list((src or {}).get("think_distribution", []) or []),
        "think_mean": list((src or {}).get("think_mean_ms", []) or []),
        "think_stddev": list((src or {}).get("think_stddev_ms", []) or []),
    }

def _expected_steps_for_session(session: dict[str, Any]) -> int:
    packed_mode = bool((session or {}).get("packed", False))
    if packed_mode:
        pa = _packed_session_arrays(session)
        s0, n = int(pa["s0"]), int(pa["n"])
        ek = list(pa["ek"])
        req_count = 0
        for i in range(s0, s0 + n):
            if int(ek[i] if i < len(ek) else 0) != 1:
                req_count += 1
        return int(req_count)
    events = list((session or {}).get("events", []) or [])
    return int(sum(1 for ev in events if str((ev or {}).get("event_type", "") or "").strip().lower() in {"http_request", "http2_headers"}))


def _emit_request_item(
    *,
    t_s: float,
    bucket_ms: int,
    timeline: dict[int, list[H2RequestPlanItem]],
    method: str,
    path: str,
    headers: dict[str, str],
    body_template: str,
) -> None:
    body_bytes = body_template.encode("utf-8") if body_template else None
    content_type = _infer_content_type_from_template(body_template)
    key = int((t_s * 1000.0) // max(1, int(bucket_ms)))
    timeline.setdefault(key, []).append(
        H2RequestPlanItem(
            method=str(method or "GET").upper(),
            path=str(path or "/"),
            headers=dict(headers or {}),
            body=body_bytes,
            content_type=content_type,
        )
    )


def _materialize_session_into_timeline(
    *,
    session: dict[str, Any],
    vu_id: int,
    flow: str,
    spawn_at: float,
    deadline: float,
    rng: random.Random,
    bucket_ms: int,
    timeline: dict[int, list[H2RequestPlanItem]],
) -> tuple[int, int, float]:
    packed_mode = bool((session or {}).get("packed", False))
    t = float(spawn_at)
    step_attempted = 0
    step_failed = 0
    if packed_mode:
        pa = _packed_session_arrays(session)
        s0, n = int(pa["s0"]), int(pa["n"])
        ek = list(pa["ek"])
        rk = list(pa["rk"])
        methods = list(pa["methods"])
        paths = list(pa["paths"])
        headers_list = list(pa["headers_list"])
        cookies_list = list(pa["cookies_list"])
        headers_idx = list(pa["headers_idx"])
        cookies_idx = list(pa["cookies_idx"])
        headers_pool = list(pa["headers_pool"])
        cookies_pool = list(pa["cookies_pool"])
        retry_list = list(pa["retry_list"])
        on_failure_list = list(pa["on_failure_list"])
        body_templates = list(pa["body_templates"])
        think_min = list(pa["think_min"])
        think_max = list(pa["think_max"])
        think_dist = list(pa["think_dist"])
        think_mean = list(pa["think_mean"])
        think_stddev = list(pa["think_stddev"])
        for i in range(s0, s0 + n):
            kind = int(ek[i] if i < len(ek) else 0)
            if kind == 1:
                t += _sample_think_seconds(
                    rng=rng,
                    distribution=str(think_dist[i] if i < len(think_dist) else "uniform"),
                    min_ms=max(0, int(think_min[i] if i < len(think_min) else 0)),
                    max_ms=max(0, int(think_max[i] if i < len(think_max) else 0)),
                    mean_ms=int(think_mean[i] if i < len(think_mean) else 0),
                    stddev_ms=int(think_stddev[i] if i < len(think_stddev) else 0),
                )
                continue
            et = str(rk[i] if i < len(rk) else "http_request").strip().lower()
            if et not in {"http_request", "http2_headers"}:
                continue
            if t > deadline:
                step_failed += 1
                continue
            step_attempted += 1
            if i < len(headers_idx) and headers_pool:
                hidx = int(headers_idx[i] or 0)
                headers = dict(headers_pool[hidx] if 0 <= hidx < len(headers_pool) else {})
            else:
                headers = dict(headers_list[i] if i < len(headers_list) else {})
            if i < len(cookies_idx) and cookies_pool:
                cidx = int(cookies_idx[i] or 0)
                cookies = dict(cookies_pool[cidx] if 0 <= cidx < len(cookies_pool) else {})
            else:
                cookies = dict(cookies_list[i] if i < len(cookies_list) else {})
            retry_count = max(0, int(retry_list[i] if i < len(retry_list) else 0))
            on_failure = str(on_failure_list[i] if i < len(on_failure_list) else "retry").strip().lower()
            if on_failure not in {"retry", "skip", "abort"}:
                on_failure = "retry"
            headers["x-scenario-flow"] = flow
            headers["x-scenario-vu-id"] = str(vu_id)
            headers["x-scenario-on-failure"] = on_failure
            if cookies:
                headers["cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
            _emit_request_item(
                t_s=t,
                bucket_ms=bucket_ms,
                timeline=timeline,
                method=str(methods[i] if i < len(methods) else "GET"),
                path=str(paths[i] if i < len(paths) else "/"),
                headers=headers,
                body_template=str(body_templates[i] if i < len(body_templates) else ""),
            )
            if on_failure != "retry":
                retry_count = 0
            for r in range(retry_count):
                t_retry = t + (0.05 * float(r + 1))
                if t_retry > deadline:
                    step_failed += 1
                    continue
                step_attempted += 1
                _emit_request_item(
                    t_s=t_retry,
                    bucket_ms=bucket_ms,
                    timeline=timeline,
                    method=str(methods[i] if i < len(methods) else "GET"),
                    path=str(paths[i] if i < len(paths) else "/"),
                    headers=headers,
                    body_template=str(body_templates[i] if i < len(body_templates) else ""),
                )
        return step_attempted, step_failed, t

    for ev in list((session or {}).get("events", []) or []):
        et = str((ev or {}).get("event_type", "") or "").strip().lower()
        if et == "think_time":
            t += _sample_think_seconds(
                rng=rng,
                distribution=str((ev or {}).get("distribution", "uniform") or "uniform"),
                min_ms=max(0, int((ev or {}).get("min_ms", 0) or 0)),
                max_ms=max(0, int((ev or {}).get("max_ms", 0) or 0)),
                mean_ms=int((ev or {}).get("mean_ms", 0) or 0),
                stddev_ms=int((ev or {}).get("stddev_ms", 0) or 0),
            )
            continue
        if et not in {"http_request", "http2_headers"}:
            continue
        if t > deadline:
            step_failed += 1
            continue
        step_attempted += 1
        headers = dict((ev or {}).get("headers") or {})
        retry_count = max(0, int((ev or {}).get("retry_count", 0) or 0))
        on_failure = str((ev or {}).get("on_failure", "retry") or "retry").strip().lower()
        if on_failure not in {"retry", "skip", "abort"}:
            on_failure = "retry"
        headers["x-scenario-flow"] = flow
        headers["x-scenario-vu-id"] = str(vu_id)
        headers["x-scenario-on-failure"] = on_failure
        _emit_request_item(
            t_s=t,
            bucket_ms=bucket_ms,
            timeline=timeline,
            method=str((ev or {}).get("method", "GET") or "GET"),
            path=str((ev or {}).get("path", "/") or "/"),
            headers=headers,
            body_template=str((ev or {}).get("body_template", "") or ""),
        )
        if on_failure != "retry":
            retry_count = 0
        for r in range(retry_count):
            t_retry = t + (0.05 * float(r + 1))
            if t_retry > deadline:
                step_failed += 1
                continue
            step_attempted += 1
            _emit_request_item(
                t_s=t_retry,
                bucket_ms=bucket_ms,
                timeline=timeline,
                method=str((ev or {}).get("method", "GET") or "GET"),
                path=str((ev or {}).get("path", "/") or "/"),
                headers=headers,
                body_template=str((ev or {}).get("body_template", "") or ""),
            )
    return step_attempted, step_failed, t


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
        total_sessions = _session_count(sessions)
        self._vus: dict[str, VirtualUserInstance] = {}
        self._spawn_order: list[str] = []
        self._spawn_schedule: list[float] = []
        self._active_peak = 0
        self._retry_backoff_base_ms = max(1, int(retry_backoff_base_ms or 50))
        self._retry_backoff_max_ms = max(self._retry_backoff_base_ms, int(retry_backoff_max_ms or 2000))
        self._next_retry_at_s: dict[str, float] = {}
        self._flow_policies_raw = dict(flow_policies or {})
        self._controller = RampController(
            target_vus=total_sessions,
            ramp_seconds=max(0, int(ramp_seconds)),
            curve=str(ramp_curve or "linear"),
            step_interval_s=max(1, int(ramp_step_interval_s or 1)),
            custom_points=tuple((ramp_custom_points or [])),
        )
        self._spawn_schedule = self._controller.spawn_schedule()
        self._spawn_cursor = 0
        max_s = max(1, int(max_session_seconds))
        for i, sess in enumerate(_iter_session_views(sessions), start=1):
            flow = str((sess or {}).get("flow", "unknown") or "unknown")
            packed = bool((sess or {}).get("packed", False))
            if packed:
                if "__soa" in (sess or {}):
                    src = dict((sess or {}).get("__soa") or {})
                    s0 = max(0, int((sess or {}).get("__start", 0) or 0))
                    s1 = max(s0, int((sess or {}).get("__end", s0) or s0))
                    kinds = list((src or {}).get("event_kind", []) or [])
                    expected = int(sum(1 for j in range(s0, min(s1, len(kinds))) if int(kinds[j]) != 1))
                else:
                    kinds = list((sess or {}).get("event_kind", []) or [])
                    expected = int(sum(1 for k in kinds if int(k) != 1))
            else:
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
        total = len(self._spawn_order)
        while self._spawn_cursor < total:
            key = self._spawn_order[self._spawn_cursor]
            vu = self._vus[key]
            if vu.spawned_at_s > now:
                break
            if vu.state == VUState.QUEUED:
                vu.state = VUState.INITIALIZING
                vu.state = VUState.RUNNING
                spawned += 1
            self._spawn_cursor += 1
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
            on_failure = str((row or {}).get("on_failure", "retry") or "retry").strip().lower()
            if on_failure not in {"retry", "skip", "abort"}:
                on_failure = "retry"
            if not ok:
                vu.step_failed += 1
                if timeout:
                    vu.timeout_count += 1
                if on_failure == "skip":
                    should_retry = False
                    vu.state = VUState.RUNNING
                else:
                    should_retry = (on_failure == "retry") and (vu.retries_used < int(policy.max_retries))
                    if timeout and policy.timeout_action == "abort":
                        should_retry = False
                    if on_failure == "abort":
                        should_retry = False
                if should_retry:
                    vu.retries_used += 1
                    vu.state = VUState.RETRYING
                    # Exponential backoff with cap; retry gate is resolved by tick_retries().
                    backoff_ms = min(policy.backoff_max_ms, policy.backoff_base_ms * (2 ** max(0, vu.retries_used - 1)))
                    self._next_retry_at_s[vu_id] = max(vu.spawned_at_s, self._next_retry_at_s.get(vu_id, 0.0)) + (float(backoff_ms) / 1000.0)
                elif on_failure != "skip":
                    vu.state = VUState.FAILED
            if vu.expected_steps > 0 and vu.step_attempted >= vu.expected_steps:
                if vu.state == VUState.RETRYING:
                    # Do not close the session while a retry is already scheduled.
                    pass
                elif vu.state != VUState.FAILED:
                    vu.state = VUState.COMPLETED
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
                "failed": float(max(0, row.sessions_total - row.sessions_completed)),
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
        max_rows_per_tick: int = 100000,
        provider_timeout_ms: int = 2000,
    ) -> list[VirtualUserSnapshot]:
        dur = max(0.001, float(duration_s or 0.001))
        tick = max(1, int(tick_ms or 20))
        row_cap = max(1, int(max_rows_per_tick or 1))
        provider_timeout_s = max(0.001, float(provider_timeout_ms or 2000) / 1000.0)
        elapsed = 0.0
        while elapsed <= dur:
            self.spawn_until(elapsed)
            self.tick_retries(elapsed)
            rows = []
            if callable(step_batch_provider):
                maybe = step_batch_provider(elapsed)
                if inspect.isawaitable(maybe):
                    maybe = await asyncio.wait_for(maybe, timeout=provider_timeout_s)
                rows = list(maybe or [])
            if rows:
                for i in range(0, len(rows), row_cap):
                    self.ingest_step_results(rows[i:i + row_cap])
            self.finalize_timeouts(elapsed)
            await asyncio.sleep(0)
            elapsed += float(tick) / 1000.0
        self.spawn_until(dur)
        self.tick_retries(dur)
        self.finalize_timeouts(dur)
        return self.snapshots()


def _as_item_dict(item: H2RequestPlanItem) -> dict[str, Any]:
    body = getattr(item, "body", None)
    body_text = None
    if body:
        try:
            body_text = bytes(body).decode("utf-8")
        except Exception:
            body_text = bytes(body).decode("latin-1")
    return {
        "method": str(item.method),
        "path": str(item.path),
        "headers": dict(item.headers or {}),
        "user_agent": item.user_agent,
        "body": body_text,
        "content_type": getattr(item, "content_type", None),
    }


def _sample_think_seconds(
    *,
    rng: random.Random,
    distribution: str,
    min_ms: int,
    max_ms: int,
    mean_ms: int,
    stddev_ms: int,
) -> float:
    dist = str(distribution or "uniform").strip().lower()
    lo = max(0, int(min_ms or 0))
    hi = max(lo, int(max_ms or lo))
    if dist == "gaussian":
        mu = float(mean_ms if int(mean_ms or 0) > 0 else ((lo + hi) / 2.0))
        sigma = float(max(1, int(stddev_ms or 0)))
        sampled = int(round(rng.gauss(mu, sigma)))
        sampled = max(lo, sampled)
        if hi > lo:
            sampled = min(hi, sampled)
        return float(sampled) / 1000.0
    return float(rng.randint(lo, hi)) / 1000.0


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
            raw_body = (it or {}).get("body", None)
            body = None if raw_body is None else str(raw_body).encode("utf-8")
            items.append(
                H2RequestPlanItem(
                    method=str((it or {}).get("method", "GET") or "GET"),
                    path=str((it or {}).get("path", "/") or "/"),
                    headers=dict((it or {}).get("headers") or {}),
                    user_agent=(it or {}).get("user_agent"),
                    body=body,
                    content_type=((it or {}).get("content_type") or None),
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
    total_sessions = _session_count(sessions)
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
    for si, session in enumerate(_iter_session_views(sessions)):
        vu_id = si + 1
        spawn_at = float(spawn_schedule[si]) if si < len(spawn_schedule) else 0.0
        sess_timeout_ms = max(0, int((session or {}).get("session_timeout_ms", 0) or 0))
        session_timeout_s = (float(sess_timeout_ms) / 1000.0) if sess_timeout_ms > 0 else float(max_sess_s)
        deadline = spawn_at + max(0.001, session_timeout_s)
        flow = str((session or {}).get("flow", "unknown") or "unknown")
        vu_flow[str(vu_id)] = flow
        vu_expected_steps[str(vu_id)] = _expected_steps_for_session(session)
        active_markers.append((spawn_at, +1))
        sess_attempted, sess_failed, end_t = _materialize_session_into_timeline(
            session=session,
            vu_id=vu_id,
            flow=flow,
            spawn_at=spawn_at,
            deadline=deadline,
            rng=rng,
            bucket_ms=bucket,
            timeline=timeline,
        )
        step_attempted += int(sess_attempted)
        step_failed += int(sess_failed)
        active_markers.append((min(deadline, end_t), -1))

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


def iter_vu_lifecycle_batches(
    *,
    scenario_sessions: list[dict[str, Any]],
    ramp_seconds: int,
    max_session_seconds: int,
    seed: int,
    window_ms: int = 500,
    bucket_ms: int = 50,
    ramp_curve: str = "linear",
    ramp_step_interval_s: int = 1,
    ramp_custom_points: list[tuple[float, int]] | None = None,
):
    """
    Streaming batch iterator over lifecycle output.
    Yields (ScheduledRequestBatch, delta_metrics) tuples.
    """
    sessions = list(scenario_sessions or [])
    win = max(1, int(window_ms))
    bucket = max(1, int(bucket_ms))
    if not sessions:
        yield ScheduledRequestBatch(delay_s=0.0, request_plan=H2RequestPlan(items=[])), {
            "final": True,
            "vus_spawned": 0,
            "vus_active_peak": 0,
            "step_attempted": 0,
            "step_failed": 0,
            "vu_expected_steps": {},
            "vu_flow": {},
        }
        return

    rng = random.Random(int(seed))
    total_sessions = _session_count(sessions)
    ramp_s = max(0, int(ramp_seconds))
    max_sess_s = max(1, int(max_session_seconds))
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

    def _emit_flushed(up_to_bucket_exclusive: int):
        keys = [k for k in timeline.keys() if int(k) < int(up_to_bucket_exclusive)]
        for k in sorted(keys):
            items = list(timeline.pop(k, []) or [])
            if not items:
                continue
            delay_s = (float(k * bucket) / 1000.0)
            yield ScheduledRequestBatch(delay_s=delay_s, request_plan=H2RequestPlan(items=items)), {
                "window_id": int((k * bucket) // win),
                "window_ms": int(win),
                "final": False,
            }

    for si, session in enumerate(_iter_session_views(sessions)):
        vu_id = si + 1
        spawn_at = float(spawn_schedule[si]) if si < len(spawn_schedule) else 0.0
        next_spawn_at = float(spawn_schedule[si + 1]) if (si + 1) < len(spawn_schedule) else float("inf")
        sess_timeout_ms = max(0, int((session or {}).get("session_timeout_ms", 0) or 0))
        session_timeout_s = (float(sess_timeout_ms) / 1000.0) if sess_timeout_ms > 0 else float(max_sess_s)
        deadline = spawn_at + max(0.001, session_timeout_s)
        flow = str((session or {}).get("flow", "unknown") or "unknown")
        vu_flow[str(vu_id)] = flow
        vu_expected_steps[str(vu_id)] = _expected_steps_for_session(session)
        active_markers.append((spawn_at, +1))
        sess_attempted, sess_failed, end_t = _materialize_session_into_timeline(
            session=session,
            vu_id=vu_id,
            flow=flow,
            spawn_at=spawn_at,
            deadline=deadline,
            rng=rng,
            bucket_ms=bucket,
            timeline=timeline,
        )
        step_attempted += int(sess_attempted)
        step_failed += int(sess_failed)
        active_markers.append((min(deadline, end_t), -1))

        cutoff_bucket = int((next_spawn_at * 1000.0) // bucket) if next_spawn_at != float("inf") else (1 << 60)
        for row in _emit_flushed(cutoff_bucket):
            yield row

    for row in _emit_flushed(1 << 62):
        yield row

    active_markers.sort(key=lambda x: (x[0], -x[1]))
    active = 0
    active_peak = 0
    for _, d in active_markers:
        active += int(d)
        active_peak = max(active_peak, active)
    yield ScheduledRequestBatch(delay_s=0.0, request_plan=H2RequestPlan(items=[])), {
        "final": True,
        "vus_spawned": int(total_sessions),
        "vus_active_peak": int(active_peak),
        "step_attempted": int(step_attempted),
        "step_failed": int(step_failed),
        "vu_expected_steps": dict(vu_expected_steps),
        "vu_flow": dict(vu_flow),
    }


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

    def _normalized_custom_points(self) -> list[tuple[float, int]]:
        pts = [(max(0.0, float(x[0])), max(0, int(x[1]))) for x in self.custom_points]
        if not pts:
            return []
        pts.sort(key=lambda x: x[0])
        dedup: list[tuple[float, int]] = []
        for t, v in pts:
            if dedup and abs(dedup[-1][0] - t) < 1e-9:
                dedup[-1] = (t, v)
            else:
                dedup.append((t, v))
        return dedup

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
            return min(total, max(0, int((done * total) / max(1, steps))))
        if mode == "spike":
            # Fast front-load: reach 70% by first 20% of ramp window.
            if t >= ramp:
                return total
            p = t / ramp
            if p <= 0.2:
                return min(total, max(0, int(total * (0.7 * (p / 0.2)))))
            return min(total, max(0, int(total * (0.7 + (0.3 * ((p - 0.2) / 0.8))))))
        if mode == "custom" and self.custom_points:
            pts = self._normalized_custom_points()
            if not pts:
                return 0
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
        return min(total, max(0, int(total * min(1.0, t / ramp))))

    def should_spawn(self, elapsed_s: float, current_active: int) -> int:
        target = int(self.active_vus_at(elapsed_s))
        return max(0, target - max(0, int(current_active)))

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
