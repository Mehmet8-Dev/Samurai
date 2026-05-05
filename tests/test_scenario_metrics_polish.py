from __future__ import annotations

from ddos_samurai.scenario_engine.metrics import (
    FlowRuntimeMetrics,
    ScenarioRuntimeMetrics,
    build_scenario_summary,
    percentile,
)


def test_percentile_empty_is_zero() -> None:
    assert percentile([], 0.95) == 0.0


def test_percentile_linear_interpolation() -> None:
    vals = [10.0, 20.0, 30.0, 40.0]
    assert percentile(vals, 0.5) == 25.0
    assert percentile(vals, 0.95) == 38.5


def test_percentile_bounds_clamped() -> None:
    vals = [1.0, 3.0, 2.0]
    assert percentile(vals, -1.0) == 1.0
    assert percentile(vals, 2.0) == 3.0


def test_build_scenario_summary_computes_ramp_accuracy_and_status() -> None:
    out = build_scenario_summary(
        scenario_vus_target=100,
        scenario_runtime_metrics_by_worker=[{"vus_active_peak": 30}, {"vus_active_peak": 40}],
        sla_passed=True,
    )
    assert out["ramp_target_vus"] == 100
    assert out["ramp_actual_vus"] == 70
    assert out["ramp_accuracy_pct"] == 70.0
    assert out["sla_status"] == "pass"


def test_build_scenario_summary_caps_ramp_accuracy_at_100() -> None:
    out = build_scenario_summary(
        scenario_vus_target=100,
        scenario_runtime_metrics_by_worker=[{"vus_active_peak": 90}, {"vus_active_peak": 40}],
        sla_passed=False,
    )
    assert out["ramp_actual_vus"] == 130
    assert out["ramp_accuracy_pct"] == 100.0
    assert out["sla_status"] == "fail"


def test_scenario_runtime_metrics_to_dict_includes_polish_fields() -> None:
    m = ScenarioRuntimeMetrics(
        vus_spawned=10,
        vus_active_peak=8,
        step_attempted=50,
        step_failed=4,
        sessions_completed=6,
        sessions_failed=2,
        step_retried=3,
        step_timeout=1,
        ramp_target_vus=10,
        ramp_actual_vus=8,
        ramp_accuracy_pct=80.0,
        sla_status="pass",
        flow={
            "browse": FlowRuntimeMetrics(
                sessions_total=5,
                sessions_completed=4,
                step_attempted=20,
                step_failed=1,
            )
        },
    )
    out = m.to_dict(duration_s=2.0)
    assert out["sessions_completed"] == 6
    assert out["sessions_failed"] == 2
    assert out["step_retried"] == 3
    assert out["step_timeout"] == 1
    assert out["ramp_target_vus"] == 10
    assert out["ramp_actual_vus"] == 8
    assert out["ramp_accuracy_pct"] == 80.0
    assert out["sla_status"] == "pass"
    assert out["per_flow"]["browse"]["session_completion_rate"] == 0.8

