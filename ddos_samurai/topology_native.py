from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

try:
    from . import _l7_emu_native as _native  # type: ignore
except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):  # pragma: no cover
    _native = None


@dataclass(frozen=True)
class TopologySpec:
    raw: Dict[str, Any]
    clients: List[Dict[str, Any]]
    servers: List[Dict[str, Any]]
    templates: List[Dict[str, Any]]
    links: List[Dict[str, Any]]
    constraints: Dict[str, Any]
    tuple_gen: Dict[str, Any]


@dataclass(frozen=True)
class CompiledTopologyPlan:
    spec: TopologySpec
    plan_id: str
    seed: int
    client_pool_size: int
    server_pool_size: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": str(self.plan_id),
            "seed": int(self.seed),
            "client_pool_size": int(self.client_pool_size),
            "server_pool_size": int(self.server_pool_size),
            "spec": dict(self.spec.raw),
        }


def compiled_topology_plan_from_dict(raw: Dict[str, Any]) -> CompiledTopologyPlan:
    if not isinstance(raw, dict):
        raise ValueError("compiled_topology_plan_must_be_object")
    raw_spec = dict(raw.get("spec", {}) or {})
    spec = TopologySpec(
        raw=raw_spec,
        clients=list(raw_spec.get("clients", []) or []),
        servers=list(raw_spec.get("servers", []) or []),
        templates=list(raw_spec.get("templates", []) or []),
        links=list(raw_spec.get("links", []) or []),
        constraints=dict(raw_spec.get("constraints", {}) or {}),
        tuple_gen=dict(raw_spec.get("tuple_gen", {}) or {}),
    )
    return CompiledTopologyPlan(
        spec=spec,
        plan_id=str(raw.get("plan_id", "") or ""),
        seed=int(raw.get("seed", 0) or 0),
        client_pool_size=int(raw.get("client_pool_size", 0) or 0),
        server_pool_size=int(raw.get("server_pool_size", 0) or 0),
    )


def _require_native_api(name: str):
    if _native is None or not hasattr(_native, name):
        raise RuntimeError(f"native_topology_api_missing:{name}")


def parse_compile_topology_spec(*, topo_spec_json: str, topo_seed: int, topo_strict: bool = True) -> CompiledTopologyPlan:
    _require_native_api("parse_compile_topology_json")
    native_out = _native.parse_compile_topology_json(
        str(topo_spec_json or ""),
        int(topo_seed),
        bool(topo_strict),
    )
    if not isinstance(native_out, dict):
        raise RuntimeError("native_topology_parse_invalid_output")
    return compiled_topology_plan_from_dict(native_out)


def topology_tuple_preview(plan: CompiledTopologyPlan, *, sample_size: int = 8) -> List[Dict[str, Any]]:
    _require_native_api("topology_tuple_preview")
    native_preview = _native.topology_tuple_preview(plan.as_dict(), int(sample_size))
    if not isinstance(native_preview, list):
        raise RuntimeError("native_topology_preview_invalid_output")
    return [dict(x) for x in native_preview]


def topology_tuple_for_index(plan: CompiledTopologyPlan, *, tuple_index: int) -> Dict[str, Any]:
    idx = max(0, int(tuple_index or 0))
    rows = topology_tuple_preview(plan, sample_size=idx + 1)
    if len(rows) <= idx:
        raise RuntimeError("native_topology_preview_out_of_range")
    return dict(rows[idx])
