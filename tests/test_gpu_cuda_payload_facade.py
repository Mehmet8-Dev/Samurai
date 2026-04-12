from __future__ import annotations

import pytest

from ddos_samurai.gpu_cuda_payload import (
    D2HTransferEngine,
    compile_vector_spec,
    evaluate_oracle,
    execute_plan_batch,
    plan_batch_to_h2_request_plan,
)
from ddos_samurai.gpu_cuda_payload.python.adapters import normalize_vector_spec

pytestmark = [pytest.mark.gpu]


def test_normalize_vector_spec_defaults():
    out = normalize_vector_spec({})
    assert out["mode"] == "program"
    assert out["methods"] == ["GET"]
    assert out["paths"] == ["/"]
    assert out["max_steps"] == 4


def test_compile_vector_spec_seed_is_deterministic():
    spec = {
        "mode": "program",
        "methods": ["GET", "POST"],
        "paths": ["/a", "/b"],
        "header_profiles": ["h0", "h1"],
        "body_profiles": ["none", "small"],
        "max_steps": 4,
    }
    a = compile_vector_spec(spec=spec, seed=42, batch_size=16)
    b = compile_vector_spec(spec=spec, seed=42, batch_size=16)
    assert a == b
    assert int(a["count"]) == 16
    assert len(a["method_idx"]) == 16
    assert len(a["flags"]) == 16
    assert a["metadata"]["planner_rng"] == "xoroshiro128plus"
    assert bool(a["metadata"]["planner_polymorphic_http"]) is True


def test_plan_batch_to_h2_request_plan_shapes_items():
    plan = compile_vector_spec(
        spec={"mode": "program", "methods": ["GET"], "paths": ["/x"], "header_profiles": ["d"], "body_profiles": ["n"]},
        seed=1,
        batch_size=3,
    )
    request_plan = plan_batch_to_h2_request_plan(plan)
    assert len(request_plan.items) == 3
    assert request_plan.items[0].method == "GET"
    assert request_plan.items[0].path == "/x"
    assert request_plan.items[0].headers.get("x-gpu-vector-source") == "gpu_cuda_payload_v1"


def test_normalize_vector_spec_v2_with_topology_and_flow():
    out = normalize_vector_spec(
        {
            "schema_version": 2,
            "mode": "program",
            "topology": {"enabled": True, "plan_id": "p1", "client_pool_size": 8, "server_pool_size": 4},
            "template_catalog": {"l4_templates": ["l4:syn"], "l7_templates": ["l7:get:/"]},
            "flow": {"flow_count": 32, "tuple_seed": 77, "step_graph": ["open", "send", "close"], "transport": "custom_tcp"},
        }
    )
    assert int(out["schema_version"]) == 2
    assert bool(out["topology"]["enabled"]) is True
    assert int(out["topology"]["client_pool_size"]) == 8
    assert out["template_catalog"]["l7_templates"] == ["l7:get:/"]
    assert int(out["flow"]["flow_count"]) == 32
    assert out["flow"]["step_graph"] == ["open", "send", "close"]


def test_plan_batch_to_h2_request_plan_emits_v2_headers():
    plan = compile_vector_spec(
        spec={
            "schema_version": 2,
            "mode": "program",
            "methods": ["GET"],
            "paths": ["/v2"],
            "header_profiles": ["d"],
            "body_profiles": ["n"],
            "topology": {"enabled": True, "client_pool_size": 2, "server_pool_size": 2},
            "template_catalog": {"l4_templates": ["l4:syn"], "l7_templates": ["l7:get:/v2"]},
            "flow": {"flow_count": 4, "step_graph": ["open", "send"], "transport": "custom_tcp"},
        },
        seed=11,
        batch_size=2,
    )
    request_plan = plan_batch_to_h2_request_plan(plan)
    headers = request_plan.items[0].headers
    assert headers.get("x-gpu-vector-source") == "gpu_cuda_payload_v2"
    assert "x-gpu-flow-id" in headers
    assert "x-gpu-template-id" in headers
    assert "x-gpu-state-op" in headers


def test_execute_plan_batch_strict_precheck_fail_visible():
    plan = compile_vector_spec(spec={"mode": "program"}, seed=7, batch_size=2)
    out = execute_plan_batch(
        plan_batch=plan,
        runtime_cfg={
            "stateful_runtime_strict": False,
            "legacy_mode": True,
            "transport_backend": "python",
            "stateful_runtime_backend": "none",
            "count": 2,
        },
    )
    assert int(out["sent"]) == 0
    assert int(out["errors"]) == 2
    assert str(out["stateful_runtime_reason"]) == "stateful_runtime_transport_unavailable"


def test_oracle_reports_strict_runtime_violation():
    plan = compile_vector_spec(spec={"mode": "program"}, seed=8, batch_size=1)
    out = evaluate_oracle(
        plan_batch=plan,
        run_result={"sent": 1, "errors": 0, "stateful_runtime_strict": 0},
        checks={"require_strict": True},
    )
    assert bool(out["pass"]) is False
    assert "strict_runtime_not_enforced" in list(out["reasons"])


def test_d2h_transfer_engine_sync_numpy_fallback():
    eng = D2HTransferEngine(max_pinned_mb=1)
    src = [1, 2, 3, 4]
    mv = eng.copy_to_host_sync(src, key="k0")
    assert isinstance(mv, memoryview)
    assert bytes(mv) != b""
    m = eng.metrics()
    assert int(m.copy_count) == 1
    assert int(m.copy_bytes) > 0
