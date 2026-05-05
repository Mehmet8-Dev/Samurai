from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SlaEvaluation:
    passed: bool
    reasons: list[str]
    metrics: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        return {
            "pass": bool(self.passed),
            "reasons": list(self.reasons),
            "metrics": dict(self.metrics),
        }


def evaluate_scenario_sla(
    *,
    sessions_started: int,
    sessions_completed: int,
    step_attempted: int,
    step_failed: int,
    sla: dict[str, Any],
    per_flow_metrics: dict[str, dict[str, float]] | None = None,
    latency_p95_ms: float | None = None,
) -> SlaEvaluation:
    min_completion_rate = float((sla or {}).get("min_completion_rate", 0.95) or 0.95)
    max_step_fail_ratio = float((sla or {}).get("max_step_fail_ratio", 0.05) or 0.05)
    max_latency_p95_ms = (sla or {}).get("max_latency_p95_ms", None)
    completion_rate = float(sessions_completed / max(1, sessions_started))
    step_fail_ratio = float(step_failed / max(1, step_attempted))
    reasons: list[str] = []
    if completion_rate < min_completion_rate:
        reasons.append("completion_rate_below_threshold")
    if step_fail_ratio > max_step_fail_ratio:
        reasons.append("step_fail_ratio_above_threshold")
    if max_latency_p95_ms is not None and latency_p95_ms is not None:
        if float(latency_p95_ms) > float(max_latency_p95_ms):
            reasons.append("latency_p95_above_threshold")
    per_flow = dict((sla or {}).get("per_flow") or {})
    for flow_name, flow_sla_obj in per_flow.items():
        flow_sla = dict(flow_sla_obj or {})
        fm = dict((per_flow_metrics or {}).get(str(flow_name), {}) or {})
        if not fm:
            reasons.append(f"per_flow_missing:{flow_name}")
            continue
        f_comp = float(fm.get("session_completion_rate", 0.0) or 0.0)
        f_fail = float(fm.get("step_fail_ratio", 0.0) or 0.0)
        f_p95 = float(fm.get("latency_p95_ms", 0.0) or 0.0)
        if "min_completion_rate" in flow_sla and f_comp < float(flow_sla.get("min_completion_rate", 0.0) or 0.0):
            reasons.append(f"per_flow_completion_below:{flow_name}")
        if "max_step_fail_ratio" in flow_sla and f_fail > float(flow_sla.get("max_step_fail_ratio", 1.0) or 1.0):
            reasons.append(f"per_flow_step_fail_above:{flow_name}")
        if flow_sla.get("max_latency_p95_ms", None) is not None and f_p95 > float(flow_sla.get("max_latency_p95_ms", 0.0) or 0.0):
            reasons.append(f"per_flow_latency_p95_above:{flow_name}")
    return SlaEvaluation(
        passed=(len(reasons) == 0),
        reasons=reasons,
        metrics={
            "session_completion_rate": completion_rate,
            "step_fail_ratio": step_fail_ratio,
            "latency_p95_ms": float(latency_p95_ms or 0.0),
        },
    )
