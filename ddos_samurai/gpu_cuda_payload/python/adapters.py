from __future__ import annotations

from typing import Any, Dict


def normalize_vector_spec(spec: Dict[str, Any] | None) -> Dict[str, Any]:
    raw = dict(spec or {})
    schema_version = int(raw.get("schema_version", 1) or 1)
    if schema_version not in {1, 2}:
        raise ValueError("schema_version must be 1 or 2")
    mode = str(raw.get("mode", "program") or "program").strip().lower()
    if mode not in {"program", "pcap", "mixed"}:
        raise ValueError("mode must be one of: program|pcap|mixed")
    methods = [str(x or "").strip() for x in list(raw.get("methods") or ["GET"]) if str(x or "").strip()]
    paths = [str(x or "").strip() for x in list(raw.get("paths") or ["/"]) if str(x or "").strip()]
    header_profiles = [
        str(x or "").strip() for x in list(raw.get("header_profiles") or ["default"]) if str(x or "").strip()
    ]
    body_profiles = [
        str(x or "").strip() for x in list(raw.get("body_profiles") or ["none"]) if str(x or "").strip()
    ]
    max_steps = int(raw.get("max_steps", 4) or 4)
    if max_steps <= 0:
        raise ValueError("max_steps must be > 0")

    topology_raw = dict(raw.get("topology") or {})
    topology_enabled = bool(topology_raw.get("enabled", raw.get("topology_enabled", False)))
    topology_plan_id = str(topology_raw.get("plan_id", raw.get("topology_plan_id", "")) or "").strip()
    client_pool_size = int(topology_raw.get("client_pool_size", raw.get("client_pool_size", 1)) or 1)
    server_pool_size = int(topology_raw.get("server_pool_size", raw.get("server_pool_size", 1)) or 1)
    if client_pool_size <= 0 or server_pool_size <= 0:
        raise ValueError("client_pool_size and server_pool_size must be > 0")

    template_catalog_raw = dict(raw.get("template_catalog") or {})
    l4_templates = [
        str(x or "").strip()
        for x in list(template_catalog_raw.get("l4_templates", raw.get("l4_templates", [])) or [])
        if str(x or "").strip()
    ]
    l7_templates = [
        str(x or "").strip()
        for x in list(template_catalog_raw.get("l7_templates", raw.get("l7_templates", [])) or [])
        if str(x or "").strip()
    ]

    flow_raw = dict(raw.get("flow") or {})
    flow_count = int(flow_raw.get("flow_count", raw.get("flow_count", 0)) or 0)
    tuple_seed = int(flow_raw.get("tuple_seed", raw.get("tuple_seed", 0)) or 0)
    step_graph = [
        str(x or "").strip()
        for x in list(flow_raw.get("step_graph", raw.get("step_graph", ["open", "send", "expect", "close"])) or [])
        if str(x or "").strip()
    ]
    if not step_graph:
        raise ValueError("flow.step_graph must contain at least one step")
    transport = str(flow_raw.get("transport", raw.get("transport", "custom_tcp")) or "custom_tcp").strip().lower()

    pacing_raw = dict(raw.get("pacing") or {})
    base_tx_timestamp_ns = int(
        pacing_raw.get("base_tx_timestamp_ns", raw.get("base_tx_timestamp_ns", 0)) or 0
    )
    base_ipg_ns = int(pacing_raw.get("base_ipg_ns", raw.get("base_ipg_ns", 1000)) or 1000)
    inter_flow_gap_ns = int(
        pacing_raw.get("inter_flow_gap_ns", raw.get("inter_flow_gap_ns", 0)) or 0
    )
    if base_tx_timestamp_ns < 0:
        raise ValueError("base_tx_timestamp_ns must be >= 0")
    if base_ipg_ns < 0:
        raise ValueError("base_ipg_ns must be >= 0")
    if inter_flow_gap_ns < 0:
        raise ValueError("inter_flow_gap_ns must be >= 0")

    return {
        "schema_version": schema_version,
        "mode": mode,
        "methods": methods,
        "paths": paths,
        "header_profiles": header_profiles,
        "body_profiles": body_profiles,
        "max_steps": max_steps,
        "topology": {
            "enabled": topology_enabled,
            "plan_id": topology_plan_id,
            "client_pool_size": client_pool_size,
            "server_pool_size": server_pool_size,
        },
        "template_catalog": {
            "l4_templates": l4_templates,
            "l7_templates": l7_templates,
        },
        "flow": {
            "flow_count": flow_count,
            "tuple_seed": tuple_seed,
            "step_graph": step_graph,
            "transport": transport,
        },
        "pacing": {
            "base_tx_timestamp_ns": base_tx_timestamp_ns,
            "base_ipg_ns": base_ipg_ns,
            "inter_flow_gap_ns": inter_flow_gap_ns,
        },
    }
