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
    return SlaEvaluation(
        passed=(len(reasons) == 0),
        reasons=reasons,
        metrics={
            "session_completion_rate": completion_rate,
            "step_fail_ratio": step_fail_ratio,
            "latency_p95_ms": float(latency_p95_ms or 0.0),
        },
    )
