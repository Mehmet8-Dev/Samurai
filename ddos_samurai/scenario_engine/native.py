from __future__ import annotations

from typing import Any

from .compiler import scenario_spec_to_dict
from .types import ScenarioSpec

try:
    from .. import _scenario_native as _native
except Exception as exc:  # pragma: no cover
    _native = None
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


def require_native() -> None:
    if _native is None:
        raise RuntimeError(
            f"Scenario native module unavailable: {_IMPORT_ERROR}. "
            "Build with: python setup.py build_ext --inplace"
        )


def _as_spec_dict(spec: dict[str, Any] | ScenarioSpec) -> dict[str, Any]:
    if isinstance(spec, ScenarioSpec):
        return scenario_spec_to_dict(spec)
    return dict(spec or {})


def compile_session_plan(spec: dict[str, Any] | ScenarioSpec, flow_name: str, seed: int) -> dict[str, Any]:
    require_native()
    # GAP-2: force columnar/packed output path for all callers.
    if hasattr(_native, "compile_session_plan_packed"):
        return dict(_native.compile_session_plan_packed(_as_spec_dict(spec), str(flow_name), int(seed)))
    return dict(_native.compile_session_plan(_as_spec_dict(spec), str(flow_name), int(seed)))


def compile_session_plan_packed(spec: dict[str, Any] | ScenarioSpec, flow_name: str, seed: int) -> dict[str, Any]:
    require_native()
    if hasattr(_native, "compile_session_plan_packed"):
        return dict(_native.compile_session_plan_packed(_as_spec_dict(spec), str(flow_name), int(seed)))
    return dict(_native.compile_session_plan(_as_spec_dict(spec), str(flow_name), int(seed)))


def compile_session_plans_packed_bulk(
    spec: dict[str, Any] | ScenarioSpec,
    flow_names: list[str],
    seeds: list[int],
) -> list[dict[str, Any]]:
    require_native()
    if hasattr(_native, "compile_session_plans_packed_bulk"):
        out = _native.compile_session_plans_packed_bulk(
            _as_spec_dict(spec),
            [str(x) for x in list(flow_names or [])],
            [int(x) for x in list(seeds or [])],
        )
        return [dict(row) for row in list(out or [])]
    rows: list[dict[str, Any]] = []
    for i, flow_name in enumerate(list(flow_names or [])):
        seed = int(seeds[i]) if i < len(seeds) else (i + 1)
        rows.append(compile_session_plan_packed(spec, str(flow_name), seed))
    return rows


def build_worker_session_plans(
    spec: dict[str, Any] | ScenarioSpec,
    worker_counts: list[int],
    seed: int,
) -> tuple[list[list[dict[str, Any]]], dict[str, Any]]:
    require_native()
    plans_obj, metrics_obj = _native.build_worker_session_plans(
        _as_spec_dict(spec),
        [int(x) for x in list(worker_counts or [])],
        int(seed),
    )
    plans = [[dict(row) for row in list(worker_rows or [])] for worker_rows in list(plans_obj or [])]
    return plans, dict(metrics_obj or {})


def evaluate_sla(
    sla: dict[str, Any],
    sessions_started: int,
    sessions_completed: int,
    step_attempted: int,
    step_failed: int,
    latency_p95_ms: float | None = None,
) -> tuple[bool, dict[str, Any]]:
    require_native()
    ok, detail = _native.evaluate_sla(
        dict(sla or {}),
        int(sessions_started),
        int(sessions_completed),
        int(step_attempted),
        int(step_failed),
        latency_p95_ms,
    )
    return bool(ok), dict(detail or {})
