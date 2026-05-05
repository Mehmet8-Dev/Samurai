from __future__ import annotations

import tempfile
import textwrap
from pathlib import Path

from ddos_samurai.scenario_engine import evaluate_scenario_sla, load_raw_scenario, migrate_schema
from ddos_samurai.scenario_engine.runtime import build_vu_lifecycle_batches


def _write_tmp_yaml(text: str) -> str:
    tmp = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8")
    tmp.write(text)
    tmp.flush()
    tmp.close()
    return str(Path(tmp.name))


def test_migrate_schema_v1_to_v2_sets_defaults() -> None:
    raw = {
        "schema_version": 1,
        "personas": {"p1": {"device_profile": "web", "headers": {}, "cookies": {}, "retry_policy": {}, "timeout_policy": {}}},
        "flows": {"f1": {"persona": "p1", "steps": [{"type": "request", "method": "GET", "path": "/"}]}},
        "load_model": {"concurrent_vus": 1, "ramp_seconds": 0, "max_session_seconds": 5, "backend": "http2"},
        "sla": {"min_completion_rate": 0.9, "max_step_fail_ratio": 0.2},
    }
    out = migrate_schema(raw, target_version=2)
    assert int(out["schema_version"]) == 2
    assert out["flows"]["f1"]["steps"][0]["on_failure"] == "retry"


def test_migrate_schema_v2_to_v3_sets_l4_backend_when_l4_steps_exist() -> None:
    raw = {
        "schema_version": 2,
        "personas": {"p1": {"device_profile": "l4_tcp", "headers": {}, "cookies": {}, "retry_policy": {}, "timeout_policy": {}}},
        "flows": {"f1": {"persona": "p1", "steps": [{"type": "tcp_connect", "dst_port": 80}, {"type": "tcp_expect", "condition": "state == established"}]}},
        "load_model": {"concurrent_vus": 1, "ramp_seconds": 0, "max_session_seconds": 5, "backend": "http"},
        "sla": {"min_completion_rate": 0.9, "max_step_fail_ratio": 0.2},
    }
    out = migrate_schema(raw, target_version=3)
    assert int(out["schema_version"]) == 3
    assert str(out["load_model"]["backend"]) == "l4_tcp"
    assert int(out["flows"]["f1"]["steps"][1]["timeout_ms"]) >= 1
    assert int(out["personas"]["p1"]["tcp_mimicry"]["window"]) > 0
    assert int(out["personas"]["p1"]["tcp_mimicry"]["mss"]) > 0
    assert 1 <= int(out["personas"]["p1"]["tcp_mimicry"]["ttl"]) <= 255


def test_load_raw_scenario_rejects_l4_tcp_without_tcp_mimicry() -> None:
    p = _write_tmp_yaml(
        textwrap.dedent(
            """
            schema_version: 3
            personas:
              p1:
                device_profile: l4_tcp
                headers: {}
                cookies: {}
                retry_policy: {max_retries: 0}
                timeout_policy: {connect_timeout_ms: 1000}
            flows:
              f1:
                persona: p1
                steps:
                  - type: tcp_connect
                    dst_port: 80
                  - type: end_session
            load_model:
              concurrent_vus: 1
              ramp_seconds: 0
              max_session_seconds: 5
              backend: l4_tcp
            sla:
              min_completion_rate: 0.9
              max_step_fail_ratio: 0.1
            """
        ).strip()
    )
    try:
        _ = load_raw_scenario(p)
        assert False, "expected ValueError for missing tcp_mimicry on l4_tcp backend"
    except ValueError:
        pass


def test_load_raw_scenario_interpolates_body_template_variables() -> None:
    p = _write_tmp_yaml(
        textwrap.dedent(
            """
            schema_version: 2
            variables:
              product_id: "42"
            personas:
              p1:
                device_profile: web
                headers: {}
                cookies: {}
                retry_policy: {max_retries: 0}
                timeout_policy: {request_timeout_ms: 1000}
            flows:
              f1:
                persona: p1
                steps:
                  - type: request
                    method: POST
                    path: /buy
                    body_template: '{"product":"${product_id}"}'
            load_model:
              concurrent_vus: 1
              ramp_seconds: 0
              max_session_seconds: 5
              backend: http2
            sla:
              min_completion_rate: 0.9
              max_step_fail_ratio: 0.1
            """
        ).strip()
    )
    raw = load_raw_scenario(p)
    body = raw["flows"]["f1"]["steps"][0]["body_template"]
    assert body == '{"product":"42"}'


def test_session_timeout_ms_enforced_in_lifecycle_batches() -> None:
    sessions = [
        {
            "flow": "f1",
            "packed": True,
            "session_timeout_ms": 1,
            "event_kind": [1, 0],
            "request_kind": ["", "http2_headers"],
            "method": ["", "GET"],
            "path": ["", "/x"],
            "headers_idx": [0, 0],
            "cookies_idx": [0, 0],
            "headers_pool": [{}],
            "cookies_pool": [{}],
            "device_profile": ["", "web"],
            "timeout_ms": [0, 1000],
            "retry_count": [0, 0],
            "on_failure": ["retry", "retry"],
            "think_min_ms": [10, 0],
            "think_max_ms": [10, 0],
            "think_distribution": ["uniform", "uniform"],
            "think_mean_ms": [0, 0],
            "think_stddev_ms": [0, 0],
        }
    ]
    _, metrics = build_vu_lifecycle_batches(
        scenario_sessions=sessions,
        ramp_seconds=0,
        max_session_seconds=10,
        seed=7,
    )
    assert int(metrics.get("step_failed", 0)) >= 1


def test_sla_per_flow_missing_reason() -> None:
    out = evaluate_scenario_sla(
        sla={"min_completion_rate": 0.9, "max_step_fail_ratio": 0.1, "per_flow": {"checkout": {"min_completion_rate": 1.0}}},
        sessions_started=10,
        sessions_completed=10,
        step_attempted=20,
        step_failed=0,
        per_flow_metrics={"browse": {"session_completion_rate": 1.0, "step_fail_ratio": 0.0, "latency_p95_ms": 10.0}},
        latency_p95_ms=10.0,
    )
    assert not out.passed
    assert any(str(r).startswith("per_flow_missing:checkout") for r in out.reasons)


def test_sla_per_flow_latency_reason() -> None:
    out = evaluate_scenario_sla(
        sla={"min_completion_rate": 0.9, "max_step_fail_ratio": 0.1, "per_flow": {"checkout": {"max_latency_p95_ms": 50}}},
        sessions_started=10,
        sessions_completed=10,
        step_attempted=20,
        step_failed=0,
        per_flow_metrics={"checkout": {"session_completion_rate": 1.0, "step_fail_ratio": 0.0, "latency_p95_ms": 120.0}},
        latency_p95_ms=10.0,
    )
    assert not out.passed
    assert any(str(r).startswith("per_flow_latency_p95_above:checkout") for r in out.reasons)
