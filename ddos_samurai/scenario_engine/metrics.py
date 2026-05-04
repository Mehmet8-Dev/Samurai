from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field


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
