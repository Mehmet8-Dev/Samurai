"""End-to-end stdio JSON-RPC 2.0 tests against the native C++17 `samurai_mcp` binary."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
MCP_BINARY = REPO_ROOT / "build" / "mcp" / "samurai_mcp"


def _send_rpc(messages: list[dict]) -> list[dict]:
    if not MCP_BINARY.is_file():
        pytest.skip(f"Native MCP binary not built at {MCP_BINARY}")
    payload = "\n".join(json.dumps(m) for m in messages) + "\n"
    proc = subprocess.run(
        [str(MCP_BINARY)],
        input=payload,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return [json.loads(line) for line in lines]


def test_cpp_mcp_initialize_and_tools_list() -> None:
    responses = _send_rpc(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ]
    )
    assert len(responses) == 2
    assert responses[0]["id"] == 1
    assert responses[0]["result"]["protocolVersion"] == "2024-11-05"
    assert responses[0]["result"]["serverInfo"]["name"] == "samurai-mcp"
    tool_names = {t["name"] for t in responses[1]["result"]["tools"]}
    assert {
        "samurai_list_profiles",
        "samurai_list_workers",
        "samurai_run_benchmark",
        "samurai_run_rfc_suite",
        "samurai_bench_tcp_flows",
        "samurai_bench_l7_userspace",
        "samurai_cluster_discover",
        "samurai_cluster_status",
        "samurai_cluster_provision_node",
        "samurai_cluster_reconfigure",
        "samurai_cluster_abort",
        "samurai_cluster_plan_shards",
        "samurai_cluster_local_mesh",
        "samurai_cluster_run_job",
        "samurai_autopilot_create",
        "samurai_autopilot_step",
        "samurai_autopilot_run_window",
        "samurai_autopilot_status",
        "samurai_autopilot_reset",
        "samurai_scenario_compile",
        "samurai_scenario_run",
        "samurai_scenario_evaluate_sla",
    }.issubset(tool_names)


def test_cpp_mcp_list_workers_and_profiles() -> None:
    responses = _send_rpc(
        [
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {"name": "samurai_list_workers", "arguments": {}},
            },
            {
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {"name": "samurai_list_profiles", "arguments": {}},
            },
        ]
    )
    workers_payload = json.loads(responses[0]["result"]["content"][0]["text"])
    assert workers_payload["host"]["runtime"] == "native-cpp17"
    assert "cpu" in workers_payload["workers"]

    profiles_payload = json.loads(responses[1]["result"]["content"][0]["text"])
    assert profiles_payload["exit_code"] == 0
    assert "web-stress" in profiles_payload["profiles_output"]


def test_cpp_mcp_blocks_public_targets_fail_closed() -> None:
    responses = _send_rpc(
        [
            {
                "jsonrpc": "2.0",
                "id": 20,
                "method": "tools/call",
                "params": {
                    "name": "samurai_run_benchmark",
                    "arguments": {
                        "worker": "cpu",
                        "target": "8.8.8.8",
                        "port": 53,
                        "count": 10,
                    },
                },
            }
        ]
    )
    assert responses[0]["result"]["isError"] is True
    err_payload = json.loads(responses[0]["result"]["content"][0]["text"])
    assert "safety gate" in err_payload["error"].lower()


def test_cpp_mcp_autopilot_rl_session_roundtrip() -> None:
    create_resp = _send_rpc(
        [
            {
                "jsonrpc": "2.0",
                "id": 30,
                "method": "tools/call",
                "params": {
                    "name": "samurai_autopilot_create",
                    "arguments": {
                        "strategy": "rl",
                        "min_rps": 100,
                        "max_rps": 5000,
                        "initial_rps": 250,
                        "slo_max_error_pct": 1.0,
                        "rl_max_jump_factor": 2.0,
                        "explore": True,
                    },
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 31,
                "method": "tools/call",
                "params": {
                    "name": "samurai_autopilot_step",
                    "arguments": {
                        "session_id": "ap-1",
                        "actual_rps": 250,
                        "attempted": 1000,
                        "errors": 0,
                        "rl_action_rps": 4000,
                    },
                },
            },
        ]
    )
    created = json.loads(create_resp[0]["result"]["content"][0]["text"])
    assert created["session_id"] == "ap-1"
    assert created["initial_setpoint_rps"] == 250.0

    stepped = json.loads(create_resp[1]["result"]["content"][0]["text"])
    assert stepped["decision"]["last_healthy"] is True
    assert stepped["decision"]["setpoint_rps"] == 500.0  # capped at 2x by native RL shield
    assert "rps" in stepped["shielded_action"]


def test_cpp_mcp_scenario_compile_and_sla() -> None:
    responses = _send_rpc(
        [
            {
                "jsonrpc": "2.0",
                "id": 40,
                "method": "tools/call",
                "params": {
                    "name": "samurai_scenario_compile",
                    "arguments": {
                        "scenario": {
                            "schema_version": 1,
                            "protocol": "http2",
                            "personas": {"web": {"device_profile": "web", "weight": 1.0}},
                            "flows": {
                                "browse": {
                                    "persona": "web",
                                    "steps": [
                                        {"type": "request", "method": "GET", "path": "/"},
                                        {"type": "end_session"},
                                    ],
                                }
                            },
                            "load_model": {"backend": "http2", "concurrent_vus": 4},
                        },
                        "workers": 2,
                        "sessions_per_worker": 2,
                    },
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 41,
                "method": "tools/call",
                "params": {
                    "name": "samurai_scenario_evaluate_sla",
                    "arguments": {
                        "sla": {"min_completion_rate": 0.95, "max_latency_p95_ms": 50.0},
                        "sessions_started": 50,
                        "sessions_completed": 50,
                        "step_attempted": 100,
                        "step_failed": 0,
                        "latency_p95_ms": 12.0,
                    },
                },
            },
        ]
    )
    compiled = json.loads(responses[0]["result"]["content"][0]["text"])
    assert compiled["valid"] is True
    assert compiled["summary"]["flow_count"] == 1
    assert compiled["summary"]["total_steps"] == 2

    sla = json.loads(responses[1]["result"]["content"][0]["text"])
    assert sla["passed"] is True


def test_cpp_mcp_skills_resources_and_cluster_planning() -> None:
    responses = _send_rpc(
        [
            {"jsonrpc": "2.0", "id": 50, "method": "resources/list", "params": {}},
            {"jsonrpc": "2.0", "id": 51, "method": "prompts/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 52,
                "method": "resources/read",
                "params": {"uri": "samurai://skills/samurai-hardware-dataplane"},
            },
            {
                "jsonrpc": "2.0",
                "id": 53,
                "method": "tools/call",
                "params": {
                    "name": "samurai_cluster_plan_shards",
                    "arguments": {
                        "mode": "packets",
                        "strategy": "capability",
                        "total_count": 50000,
                        "workers": [
                            {"worker_id": "w1", "gpu_available": True, "capacity_score": 3},
                            {"worker_id": "w2", "xdp_available": True, "capacity_score": 1},
                        ],
                    },
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 54,
                "method": "tools/call",
                "params": {
                    "name": "samurai_cluster_provision_node",
                    "arguments": {"host": "127.0.0.1", "node_hosts": "8.8.8.8"},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 55,
                "method": "tools/call",
                "params": {
                    "name": "samurai_cluster_run_job",
                    "arguments": {"worker": "telco", "target": "8.8.8.8", "port": 2152, "count": 100},
                },
            },
        ]
    )
    assert len(responses[0]["result"]["resources"]) == 5
    assert len(responses[1]["result"]["prompts"]) == 5
    skill_text = responses[2]["result"]["contents"][0]["text"]
    assert "samurai_afxdp_worker" in skill_text

    plan = json.loads(responses[3]["result"]["content"][0]["text"])
    assert len(plan["shards"]) == 2
    assert "autoscale_recommendation" in plan

    assert responses[4]["result"]["isError"] is True
    assert responses[5]["result"]["isError"] is True


def test_cpp_mcp_doctor_and_setup_cli(tmp_path: Path) -> None:
    if not MCP_BINARY.is_file():
        pytest.skip(f"Native MCP binary not built at {MCP_BINARY}")

    doc = subprocess.run(
        [str(MCP_BINARY), "doctor", "--client", "cursor", "--json"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    doc_json = json.loads(doc.stdout)
    assert "core_binaries" in doc_json
    assert doc_json["clients"][0]["client"] == "cursor"

    setup = subprocess.run(
        [
            str(MCP_BINARY),
            "setup",
            "--client",
            "cursor",
            "--scope",
            "project",
            "--json",
        ],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    setup_json = json.loads(setup.stdout)
    assert setup_json["ok"] is True
    assert setup_json["applied"] is False
    assert setup_json["config_path"] == str(tmp_path / ".cursor" / "mcp.json")
    assert not (tmp_path / ".cursor" / "mcp.json").exists()
