from __future__ import annotations

from typing import Any

ALLOWED_STEP_TYPES = {"request", "pause", "branch", "loop", "assert", "end_session"}
ALLOWED_BACKENDS = {"http", "http2"}


def validate_raw_schema(raw: dict[str, Any]) -> None:
    if not isinstance(raw, dict):
        raise ValueError("scenario root must be an object")
    if int(raw.get("schema_version", 0) or 0) < 1:
        raise ValueError("schema_version must be >= 1")
    personas = raw.get("personas")
    flows = raw.get("flows")
    if not isinstance(personas, dict) or not personas:
        raise ValueError("personas must be a non-empty object")
    if not isinstance(flows, dict) or not flows:
        raise ValueError("flows must be a non-empty object")
    load_model = raw.get("load_model") or {}
    backend = str(load_model.get("backend", "http") or "http").strip().lower()
    if backend not in ALLOWED_BACKENDS:
        raise ValueError("load_model.backend must be http or http2")
    for pname, pdata in personas.items():
        if not isinstance(pdata, dict):
            raise ValueError(f"persona '{pname}' must be an object")
        for req_key in ("device_profile", "headers", "cookies", "retry_policy", "timeout_policy"):
            if req_key not in pdata:
                raise ValueError(f"persona '{pname}' missing required key: {req_key}")
    for fname, fdata in flows.items():
        if not isinstance(fdata, dict):
            raise ValueError(f"flow '{fname}' must be an object")
        persona_name = str(fdata.get("persona", "") or "").strip()
        if persona_name not in personas:
            raise ValueError(f"flow '{fname}' references unknown persona '{persona_name}'")
        steps = fdata.get("steps")
        if not isinstance(steps, list) or not steps:
            raise ValueError(f"flow '{fname}' must have non-empty steps")
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                raise ValueError(f"flow '{fname}' step[{i}] must be an object")
            st = str(step.get("type", "") or "").strip().lower()
            if st not in ALLOWED_STEP_TYPES:
                raise ValueError(f"flow '{fname}' step[{i}] has invalid type '{st}'")
            if st == "request":
                if not str(step.get("path", "") or "").strip():
                    raise ValueError(f"flow '{fname}' step[{i}] request path is required")
            if st == "loop":
                ref_flow = str(step.get("flow", "") or "").strip()
                if ref_flow and ref_flow == fname:
                    raise ValueError(f"flow '{fname}' step[{i}] has direct self-loop")
                if ref_flow and ref_flow not in flows:
                    raise ValueError(f"flow '{fname}' step[{i}] references unknown flow '{ref_flow}'")
            if st == "branch":
                ref_flow = str(step.get("flow", "") or "").strip()
                if ref_flow and ref_flow not in flows:
                    raise ValueError(f"flow '{fname}' step[{i}] references unknown flow '{ref_flow}'")

    _validate_flow_graph(dict(flows))


def _validate_flow_graph(flows: dict[str, Any]) -> None:
    # Graph-level protections: unresolved references are handled above.
    # Here we detect cycles that have no request/end_session opportunity.
    edges: dict[str, list[str]] = {}
    terminals: dict[str, bool] = {}
    for fname, fdata in flows.items():
        refs: list[str] = []
        has_terminal_or_request = False
        for step in list((fdata or {}).get("steps") or []):
            st = str((step or {}).get("type", "") or "").strip().lower()
            if st in {"request", "end_session"}:
                has_terminal_or_request = True
            if st in {"loop", "branch"}:
                ref_flow = str((step or {}).get("flow", "") or "").strip()
                if ref_flow:
                    refs.append(ref_flow)
        edges[fname] = refs
        terminals[fname] = has_terminal_or_request

    visited: set[str] = set()
    stack: set[str] = set()

    def _dfs(node: str) -> None:
        if node in stack:
            # cycle detected: ensure at least one node in cycle has progress step.
            cycle_nodes = list(stack)
            if not any(terminals.get(x, False) for x in cycle_nodes):
                raise ValueError(f"flow graph contains non-progress cycle: {','.join(cycle_nodes)}")
            return
        if node in visited:
            return
        visited.add(node)
        stack.add(node)
        for nxt in edges.get(node, []):
            _dfs(nxt)
        stack.remove(node)

    for fname in flows.keys():
        _dfs(fname)
