from __future__ import annotations

from typing import Any

ALLOWED_STEP_TYPES = {
    "request",
    "pause",
    "branch",
    "loop",
    "assert",
    "end_session",
    "tcp_connect",
    "tcp_send",
    "tcp_expect",
    "tcp_close",
}
ALLOWED_BACKENDS = {"http", "http2", "l4_tcp"}


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
        raise ValueError("load_model.backend must be http or http2 or l4_tcp")
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
                if "body_template" in step and not isinstance(step.get("body_template"), str):
                    raise ValueError(f"flow '{fname}' step[{i}] body_template must be a string")
                on_failure = str(step.get("on_failure", "retry") or "retry").strip().lower()
                if on_failure not in {"retry", "skip", "abort"}:
                    raise ValueError(f"flow '{fname}' step[{i}] on_failure must be retry|skip|abort")
                extract = step.get("extract", {})
                if extract is not None and not isinstance(extract, dict):
                    raise ValueError(f"flow '{fname}' step[{i}] extract must be an object")
                if isinstance(extract, dict):
                    for ek, ev in extract.items():
                        if not str(ek or "").strip() or not isinstance(ev, str):
                            raise ValueError(f"flow '{fname}' step[{i}] extract entries must be non-empty string map")
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
            if st == "assert":
                cond = str(step.get("condition", "") or "").strip()
                if not cond:
                    raise ValueError(f"flow '{fname}' step[{i}] assert requires 'condition'")
            if st == "pause":
                tt = dict(step.get("think_time") or {})
                dist = str(tt.get("distribution", "uniform") or "uniform").strip().lower()
                if dist not in {"uniform", "gaussian"}:
                    raise ValueError(f"flow '{fname}' step[{i}] think_time.distribution must be uniform|gaussian")
            if st == "tcp_connect":
                dst_port = int(step.get("dst_port", 0) or 0)
                if dst_port < 1 or dst_port > 65535:
                    raise ValueError(f"flow '{fname}' step[{i}] tcp_connect dst_port must be 1..65535")
            if st == "tcp_send":
                payload_template = step.get("payload_template", "")
                if not isinstance(payload_template, str) or not payload_template:
                    raise ValueError(f"flow '{fname}' step[{i}] tcp_send payload_template must be a non-empty string")
            if st == "tcp_expect":
                cond = str(step.get("condition", "") or "").strip()
                if not cond:
                    raise ValueError(f"flow '{fname}' step[{i}] tcp_expect requires 'condition'")
                timeout_ms = int(step.get("timeout_ms", 0) or 0)
                if timeout_ms <= 0:
                    raise ValueError(f"flow '{fname}' step[{i}] tcp_expect timeout_ms must be > 0")

            if backend == "l4_tcp":
                if st == "request":
                    raise ValueError(f"flow '{fname}' step[{i}] request is not allowed for l4_tcp backend")
            elif st in {"tcp_connect", "tcp_send", "tcp_expect", "tcp_close"}:
                raise ValueError(f"flow '{fname}' step[{i}] {st} requires l4_tcp backend")

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
