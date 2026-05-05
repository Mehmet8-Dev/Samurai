from __future__ import annotations

from .types import (
    FlowSpec,
    LoadModelSpec,
    OnFailurePolicy,
    PersonaSpec,
    ScenarioSpec,
    SlaGateSpec,
    StepSpec,
    StepType,
    ThinkTimeSpec,
)


def _parse_step_type(raw: object) -> StepType:
    s = str(raw or "").strip().lower()
    try:
        return StepType(s)
    except ValueError:
        return StepType.END_SESSION


def _parse_on_failure(raw: object) -> OnFailurePolicy:
    s = str(raw or "").strip().lower()
    try:
        return OnFailurePolicy(s)
    except ValueError:
        return OnFailurePolicy.RETRY


def scenario_spec_to_dict(spec: ScenarioSpec) -> dict:
    return {
        "schema_version": int(spec.schema_version),
        "personas": {
            name: {
                "device_profile": p.device_profile,
                "headers": dict(p.headers),
                "cookies": dict(p.cookies),
                "retry_policy": dict(p.retry_policy),
                "timeout_policy": dict(p.timeout_policy),
                "weight": float(p.weight),
            }
            for name, p in spec.personas.items()
        },
        "flows": {
            name: {
                "persona": f.persona,
                "steps": [
                    {
                        "type": s.step_type.value,
                        "method": s.method,
                        "path": s.path,
                        "body_template": s.body_template,
                        "flow": s.flow,
                        "repeat": int(s.repeat),
                        "probability": float(s.probability),
                        "on_failure": s.on_failure.value,
                        "conditions": dict(s.conditions),
                        "dst_port": int(s.dst_port),
                        "payload_template": s.payload_template,
                        "condition": s.condition,
                        "timeout_ms": int(s.timeout_ms),
                        "think_time": {
                            "min_ms": int(s.think_time.min_ms),
                            "max_ms": int(s.think_time.max_ms),
                            "distribution": s.think_time.distribution,
                            "mean_ms": int(s.think_time.mean_ms),
                            "stddev_ms": int(s.think_time.stddev_ms),
                        },
                    }
                    for s in f.steps
                ],
            }
            for name, f in spec.flows.items()
        },
        "load_model": {
            "concurrent_vus": int(spec.load_model.concurrent_vus),
            "ramp_seconds": int(spec.load_model.ramp_seconds),
            "max_session_seconds": int(spec.load_model.max_session_seconds),
            "backend": str(spec.load_model.backend),
        },
        "sla": {
            "min_completion_rate": float(spec.sla.min_completion_rate),
            "max_step_fail_ratio": float(spec.sla.max_step_fail_ratio),
            "max_latency_p95_ms": spec.sla.max_latency_p95_ms,
            "per_flow": dict(spec.sla.per_flow or {}),
        },
    }


def scenario_spec_from_dict(raw: dict[str, object]) -> ScenarioSpec:
    personas = {
        str(name): PersonaSpec(
            name=str(name),
            device_profile=str((data or {}).get("device_profile", "web") or "web"),
            headers=dict((data or {}).get("headers") or {}),
            cookies=dict((data or {}).get("cookies") or {}),
            retry_policy=dict((data or {}).get("retry_policy") or {}),
            timeout_policy=dict((data or {}).get("timeout_policy") or {}),
            weight=float((data or {}).get("weight", 1.0) or 1.0),
        )
        for name, data in dict(raw.get("personas") or {}).items()
    }
    flows = {}
    for name, data in dict(raw.get("flows") or {}).items():
        steps = []
        for row in list((data or {}).get("steps") or []):
            tt = dict((row or {}).get("think_time") or {})
            steps.append(
                StepSpec(
                    step_type=_parse_step_type((row or {}).get("type", "")),
                    method=str((row or {}).get("method", "GET") or "GET").strip().upper(),
                    path=str((row or {}).get("path", "/") or "/").strip(),
                    body_template=str((row or {}).get("body_template", "") or ""),
                    flow=str((row or {}).get("flow", "") or "").strip(),
                    repeat=max(1, int((row or {}).get("repeat", 1) or 1)),
                    probability=float((row or {}).get("probability", 1.0) or 1.0),
                    on_failure=_parse_on_failure((row or {}).get("on_failure", "retry")),
                    conditions=dict((row or {}).get("conditions") or {}),
                    dst_port=max(0, int((row or {}).get("dst_port", 0) or 0)),
                    payload_template=str((row or {}).get("payload_template", "") or ""),
                    condition=str((row or {}).get("condition", "") or "").strip(),
                    timeout_ms=max(0, int((row or {}).get("timeout_ms", 0) or 0)),
                    think_time=ThinkTimeSpec(
                        min_ms=max(0, int(tt.get("min_ms", 0) or 0)),
                        max_ms=max(0, int(tt.get("max_ms", 0) or 0)),
                        distribution=str(tt.get("distribution", "uniform") or "uniform").strip().lower(),
                        mean_ms=max(0, int(tt.get("mean_ms", 0) or 0)),
                        stddev_ms=max(0, int(tt.get("stddev_ms", 0) or 0)),
                    ),
                )
            )
        flows[str(name)] = FlowSpec(
            name=str(name),
            persona=str((data or {}).get("persona", "") or ""),
            steps=steps,
        )
    lm = dict(raw.get("load_model") or {})
    sla = dict(raw.get("sla") or {})
    return ScenarioSpec(
        schema_version=max(1, int(raw.get("schema_version", 1) or 1)),
        personas=personas,
        flows=flows,
        load_model=LoadModelSpec(
            concurrent_vus=max(1, int(lm.get("concurrent_vus", 1) or 1)),
            ramp_seconds=max(0, int(lm.get("ramp_seconds", 0) or 0)),
            max_session_seconds=max(1, int(lm.get("max_session_seconds", 30) or 30)),
            backend=str(lm.get("backend", "http") or "http").strip().lower(),
        ),
        sla=SlaGateSpec(
            min_completion_rate=float(sla.get("min_completion_rate", 0.95) or 0.95),
            max_step_fail_ratio=float(sla.get("max_step_fail_ratio", 0.05) or 0.05),
            max_latency_p95_ms=(
                float(sla.get("max_latency_p95_ms"))
                if sla.get("max_latency_p95_ms", None) is not None
                else None
            ),
            per_flow=dict(sla.get("per_flow") or {}),
        ),
    )
