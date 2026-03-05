from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class KpiGateRule:
    name: str
    metric: str
    op: str
    threshold: Any
    required: bool = True


@dataclass
class KpiGateResult:
    profile: str = "off"
    status: str = "pass"
    hard_fail: int = 0
    violations: List[str] = field(default_factory=list)
    score_eligible: int = 0
    evaluated_rules: List[Dict[str, Any]] = field(default_factory=list)

    def as_report_fields(self) -> Dict[str, Any]:
        return {
            "kpi_gate_profile": str(self.profile),
            "kpi_gate_status": str(self.status),
            "kpi_gate_hard_fail": int(self.hard_fail),
            "kpi_violations": list(self.violations),
            "score_eligible": int(self.score_eligible),
        }


_DEFAULT_PROFILE_GATES: Dict[str, Dict[str, Any]] = {
    "developer_fallback": {
        "run_quality": "valid",
        "send_success_ratio_pct_min": 99.0,
        "wire_loss_est_pct_max": 5.0,
        "rate_accuracy_pct_min": 90.0,
        "txring_flush_error_ratio_pct_max": 2.0,
        "txring_flush_eagain_ratio_pct_max": 5.0,
        "txring_hold_block_pressure_pct_max": 60.0,
        "session_success_rate_min": 95.0,
        "retry_success_rate_min": 70.0,
        "l7_step_fail_ratio_max": 0.05,
    },
    "dedicated_lab": {
        "run_quality": "valid",
        "send_success_ratio_pct_min": 99.0,
        "wire_loss_est_pct_max": 1.0,
        "rate_accuracy_pct_min": 98.0,
        "txring_flush_error_ratio_pct_max": 0.5,
        "txring_flush_eagain_ratio_pct_max": 2.0,
        "txring_hold_block_pressure_pct_max": 35.0,
        "session_success_rate_min": 99.0,
        "retry_success_rate_min": 90.0,
        "l7_step_fail_ratio_max": 0.01,
    },
}


def _normalize_profile(profile: str | None) -> str:
    p = str(profile or "off").strip().lower()
    if p in {"off", "none", "disabled"}:
        return "off"
    if p in {"dedicated", "dedicated-lab", "dedicated_lab"}:
        return "dedicated_lab"
    if p in {"developer", "dev", "developer_fallback", "developer-fallback"}:
        return "developer_fallback"
    return "off"


def _load_profile_from_parity(profile: str, parity_matrix_path: Optional[str] = None) -> Dict[str, Any]:
    if profile == "off":
        return {}

    path = Path(parity_matrix_path) if parity_matrix_path else (Path(__file__).resolve().parents[1] / "benchmarks" / "parity_matrix.json")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        profiles = (data.get("profiles") or {}) if isinstance(data, dict) else {}
        gates = ((profiles.get(profile) or {}).get("gates") or {})
        if isinstance(gates, dict) and gates:
            return dict(gates)
    except Exception:
        pass
    return {}


def _merge_gate_defaults(profile: str, parity_matrix_path: Optional[str] = None) -> Dict[str, Any]:
    base = dict(_DEFAULT_PROFILE_GATES.get(profile, {}))
    parity = _load_profile_from_parity(profile, parity_matrix_path=parity_matrix_path)
    if not parity:
        return base

    # Backward compatibility with existing parity_matrix keys.
    if "run_quality" in parity:
        base["run_quality"] = parity["run_quality"]
    if "wire_loss_est_pct_max" in parity:
        base["wire_loss_est_pct_max"] = parity["wire_loss_est_pct_max"]
    if "rate_accuracy_pct_min" in parity:
        base["rate_accuracy_pct_min"] = parity["rate_accuracy_pct_min"]
    if "session_success_rate_min" in parity:
        base["session_success_rate_min"] = parity["session_success_rate_min"]
    if "retry_success_rate_min" in parity:
        base["retry_success_rate_min"] = parity["retry_success_rate_min"]
    if "send_success_ratio_pct_min" in parity:
        base["send_success_ratio_pct_min"] = parity["send_success_ratio_pct_min"]
    if "txring_flush_error_ratio_pct_max" in parity:
        base["txring_flush_error_ratio_pct_max"] = parity["txring_flush_error_ratio_pct_max"]
    if "txring_flush_eagain_ratio_pct_max" in parity:
        base["txring_flush_eagain_ratio_pct_max"] = parity["txring_flush_eagain_ratio_pct_max"]
    if "txring_hold_block_pressure_pct_max" in parity:
        base["txring_hold_block_pressure_pct_max"] = parity["txring_hold_block_pressure_pct_max"]
    if "l7_step_fail_ratio_max" in parity:
        base["l7_step_fail_ratio_max"] = parity["l7_step_fail_ratio_max"]
    return base


def _to_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except Exception:
        return None


def _build_rules(gates: Dict[str, Any]) -> List[KpiGateRule]:
    return [
        KpiGateRule("run_quality", "run_quality", "eq", gates.get("run_quality", "valid"), required=True),
        KpiGateRule(
            "send_success_ratio_pct",
            "send_success_ratio_pct",
            "min",
            float(gates.get("send_success_ratio_pct_min", 99.0) or 99.0),
            required=True,
        ),
        KpiGateRule(
            "wire_loss_est_pct",
            "wire_loss_est_pct",
            "max",
            float(gates.get("wire_loss_est_pct_max", 1.0) or 1.0),
            required=True,
        ),
        KpiGateRule(
            "rate_accuracy_pct",
            "rate_accuracy_pct",
            "min",
            float(gates.get("rate_accuracy_pct_min", 98.0) or 98.0),
            required=False,
        ),
        KpiGateRule(
            "txring_flush_error_ratio_pct",
            "txring_flush_error_ratio_pct",
            "max",
            float(gates.get("txring_flush_error_ratio_pct_max", 0.5) or 0.5),
            required=False,
        ),
        KpiGateRule(
            "txring_flush_eagain_ratio_pct",
            "txring_flush_eagain_ratio_pct",
            "max",
            float(gates.get("txring_flush_eagain_ratio_pct_max", 2.0) or 2.0),
            required=False,
        ),
        KpiGateRule(
            "txring_hold_block_pressure_pct",
            "txring_hold_block_pressure_pct",
            "max",
            float(gates.get("txring_hold_block_pressure_pct_max", 35.0) or 35.0),
            required=False,
        ),
        KpiGateRule(
            "session_success_rate",
            "session_success_rate",
            "min",
            float(gates.get("session_success_rate_min", 99.0) or 99.0),
            required=False,
        ),
        KpiGateRule(
            "retry_success_rate",
            "retry_success_rate",
            "min",
            float(gates.get("retry_success_rate_min", 90.0) or 90.0),
            required=False,
        ),
        KpiGateRule(
            "l7_step_fail_ratio",
            "l7_step_fail_ratio",
            "max",
            float(gates.get("l7_step_fail_ratio_max", 0.01) or 0.01),
            required=False,
        ),
    ]


def evaluate(
    results: Dict[str, Any],
    *,
    profile: str = "off",
    hard_fail: bool = False,
    parity_matrix_path: Optional[str] = None,
) -> KpiGateResult:
    profile_norm = _normalize_profile(profile)
    run_quality = str((results or {}).get("run_quality", "") or "").strip().lower()

    if profile_norm == "off":
        return KpiGateResult(
            profile="off",
            status="pass",
            hard_fail=0,
            violations=[],
            score_eligible=int(run_quality == "valid"),
            evaluated_rules=[],
        )

    gates = _merge_gate_defaults(profile_norm, parity_matrix_path=parity_matrix_path)
    rules = _build_rules(gates)

    violations: List[str] = []
    evaluated: List[Dict[str, Any]] = []

    for rule in rules:
        value = (results or {}).get(rule.metric)
        passed = True
        detail = "ok"

        if value is None:
            if rule.required:
                passed = False
                detail = "missing_metric"
            else:
                detail = "missing_optional_metric"
        elif rule.op == "eq":
            lhs = str(value).strip().lower()
            rhs = str(rule.threshold).strip().lower()
            passed = lhs == rhs
            if not passed:
                detail = f"expected={rhs} actual={lhs}"
        elif rule.op == "min":
            fv = _to_float(value)
            if fv is None:
                passed = False
                detail = "non_numeric"
            else:
                passed = fv >= float(rule.threshold)
                if not passed:
                    detail = f"expected>={float(rule.threshold):.6g} actual={fv:.6g}"
        elif rule.op == "max":
            fv = _to_float(value)
            if fv is None:
                passed = False
                detail = "non_numeric"
            else:
                passed = fv <= float(rule.threshold)
                if not passed:
                    detail = f"expected<={float(rule.threshold):.6g} actual={fv:.6g}"

        evaluated.append(
            {
                "name": rule.name,
                "metric": rule.metric,
                "op": rule.op,
                "threshold": rule.threshold,
                "value": value,
                "required": bool(rule.required),
                "passed": bool(passed),
                "detail": detail,
            }
        )

        if not passed:
            violations.append(f"{rule.name}:{detail}")

    if violations:
        status = "fail" if profile_norm == "dedicated_lab" else "warn"
    else:
        status = "pass"

    hard_fail_flag = int(bool(hard_fail) and profile_norm == "dedicated_lab" and status == "fail")
    score_eligible = int(run_quality == "valid" and status == "pass")

    return KpiGateResult(
        profile=profile_norm,
        status=status,
        hard_fail=hard_fail_flag,
        violations=violations,
        score_eligible=score_eligible,
        evaluated_rules=evaluated,
    )
