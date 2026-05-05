from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
import math
from typing import Any


@dataclass
class FlowRuntimeMetrics:
    sessions_total: int = 0
    sessions_completed: int = 0
    step_attempted: int = 0
    step_failed: int = 0


@dataclass
class ScenarioRuntimeMetrics:
    vus_spawned: int = 0
    vus_active_peak: int = 0
    step_attempted: int = 0
    step_failed: int = 0
    sessions_completed: int = 0
    sessions_failed: int = 0
    step_retried: int = 0
    step_timeout: int = 0
    ramp_target_vus: int = 0
    ramp_actual_vus: int = 0
    ramp_accuracy_pct: float = 0.0
    sla_status: str = "unknown"
    flow: dict[str, FlowRuntimeMetrics] = field(default_factory=dict)

    def to_dict(self, duration_s: float = 1.0) -> dict[str, dict[str, float] | float | int]:
        out_flow: dict[str, dict[str, float]] = {}
        d = max(0.001, float(duration_s or 0.001))
        for name, row in self.flow.items():
            out_flow[name] = {
                "sessions": float(row.sessions_total),
                "completed": float(row.sessions_completed),
                "step_attempted": float(row.step_attempted),
                "step_failed": float(row.step_failed),
                "session_completion_rate": float(row.sessions_completed / max(1, row.sessions_total)),
                "step_fail_ratio": float(row.step_failed / max(1, row.step_attempted)),
                "conn_rate": float(row.sessions_total / d),
            }
        return {
            "vus_spawned": int(self.vus_spawned),
            "vus_active_peak": int(self.vus_active_peak),
            "step_attempted": int(self.step_attempted),
            "step_failed": int(self.step_failed),
            "sessions_completed": int(self.sessions_completed),
            "sessions_failed": int(self.sessions_failed),
            "step_retried": int(self.step_retried),
            "step_timeout": int(self.step_timeout),
            "ramp_target_vus": int(self.ramp_target_vus),
            "ramp_actual_vus": int(self.ramp_actual_vus),
            "ramp_accuracy_pct": float(self.ramp_accuracy_pct),
            "sla_status": str(self.sla_status or "unknown"),
            "per_flow": out_flow,
        }


def build_flow_runtime_metrics(
    vu_flow: dict[str, str],
    vu_expected_steps: dict[str, int],
    vu_progress: dict[str, int],
    vu_failed: dict[str, int],
) -> dict[str, FlowRuntimeMetrics]:
    per_flow: dict[str, FlowRuntimeMetrics] = defaultdict(FlowRuntimeMetrics)
    for vu_id, flow in (vu_flow or {}).items():
        key = str(flow or "unknown")
        row = per_flow[key]
        row.sessions_total += 1
        attempted = int((vu_progress or {}).get(str(vu_id), 0) or 0)
        failed = int((vu_failed or {}).get(str(vu_id), 0) or 0)
        row.step_attempted += attempted
        row.step_failed += failed
        expected = int((vu_expected_steps or {}).get(str(vu_id), 0) or 0)
        if expected > 0 and attempted >= expected and failed == 0:
            row.sessions_completed += 1
    return dict(per_flow)


def percentile(values: list[float], q: float) -> float:
    vals = sorted(float(x) for x in list(values or []))
    if not vals:
        return 0.0
    qq = max(0.0, min(1.0, float(q)))
    pos = qq * float(len(vals) - 1)
    lo = int(pos)
    hi = min(len(vals) - 1, lo + 1)
    if lo == hi:
        return float(vals[lo])
    w = pos - float(lo)
    return float(vals[lo] * (1.0 - w) + vals[hi] * w)


@dataclass
class LatencyDigest:
    # Constant-memory centroid sketch (t-digest-like merge/compress).
    max_centroids: int = 200
    _centroids: list[tuple[float, int]] = field(default_factory=list)
    _count: int = 0

    def _compress(self) -> None:
        if len(self._centroids) <= int(self.max_centroids):
            return
        self._centroids.sort(key=lambda x: x[0])
        target = max(2, int(self.max_centroids))
        merged: list[tuple[float, int]] = []
        bucket = max(1, int(math.ceil(len(self._centroids) / float(target))))
        for i in range(0, len(self._centroids), bucket):
            part = self._centroids[i:i + bucket]
            w = sum(int(c) for _, c in part)
            if w <= 0:
                continue
            mu = sum(float(m) * int(c) for m, c in part) / float(w)
            merged.append((float(mu), int(w)))
        self._centroids = merged[:target]

    def add(self, value_ms: float) -> None:
        v = float(value_ms)
        if v < 0.0:
            return
        self._count += 1
        self._centroids.append((v, 1))
        if len(self._centroids) > int(self.max_centroids) * 2:
            self._compress()

    def quantile(self, q: float) -> float:
        if not self._centroids:
            return 0.0
        self._compress()
        pts = sorted(self._centroids, key=lambda x: x[0])
        total = max(1, sum(int(c) for _, c in pts))
        target = max(0.0, min(1.0, float(q))) * float(total - 1)
        run = 0.0
        prev_m = float(pts[0][0])
        prev_r = 0.0
        for m, c in pts:
            cur = run + float(int(c))
            if target <= cur:
                if cur <= prev_r:
                    return float(m)
                frac = (target - prev_r) / max(1e-9, (cur - prev_r))
                return float(prev_m + (float(m) - prev_m) * frac)
            prev_m = float(m)
            prev_r = cur
            run = cur
        return float(pts[-1][0])

    def merge(self, other: "LatencyDigest") -> None:
        for m, c in list(getattr(other, "_centroids", []) or []):
            self._centroids.append((float(m), int(c)))
            self._count += int(c)
        self._compress()

    def as_dict(self) -> dict[str, Any]:
        return {
            "count": int(self._count),
            "max_centroids": int(self.max_centroids),
            "centroids": [[float(m), int(c)] for m, c in list(self._centroids or [])],
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "LatencyDigest":
        d = cls(max_centroids=max(8, int((raw or {}).get("max_centroids", 200) or 200)))
        d._count = int((raw or {}).get("count", 0) or 0)
        out: list[tuple[float, int]] = []
        for row in list((raw or {}).get("centroids", []) or []):
            if not isinstance(row, (list, tuple)) or len(row) != 2:
                continue
            m = float(row[0])
            c = max(1, int(row[1]))
            if m >= 0.0:
                out.append((m, c))
        d._centroids = out[: max(8, int(d.max_centroids) * 2)]
        d._compress()
        return d


def build_scenario_summary(
    *,
    scenario_vus_target: int,
    scenario_runtime_metrics_by_worker: list[dict[str, Any]] | None,
    sla_passed: bool | None = None,
) -> dict[str, Any]:
    workers = list(scenario_runtime_metrics_by_worker or [])
    target = max(0, int(scenario_vus_target or 0))
    actual = int(sum(int((row or {}).get("vus_active_peak", 0) or 0) for row in workers))
    acc = float((100.0 * min(float(actual), float(target))) / max(1.0, float(target)))
    return {
        "ramp_target_vus": int(target),
        "ramp_actual_vus": int(actual),
        "ramp_accuracy_pct": float(acc),
        "sla_status": "pass" if bool(sla_passed) else "fail",
    }
