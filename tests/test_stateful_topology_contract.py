import unittest
from unittest.mock import patch

from ddos_samurai.stateful_runtime import evaluate_hot_path_contract
from ddos_samurai.topology_native import (
    compiled_topology_plan_from_dict,
    parse_compile_topology_spec,
    topology_tuple_for_index,
    topology_tuple_preview,
)


_VALID_SPEC = {
    "clients": [
        {
            "name": "c1",
            "ip_ranges": {"v4": ["10.0.0.0/30"]},
            "port_ranges": ["1024-1030"],
            "dist": "uniform",
        }
    ],
    "servers": [
        {
            "name": "s1",
            "ip_ranges": {"v4": ["192.0.2.10/32"]},
            "ports": [80, 443],
            "weight": 1,
        }
    ],
    "templates": [
        {
            "name": "t1",
            "protocol": "l7",
            "path": "/",
            "cps_weight": 1,
            "think_time": 0,
            "retries": 0,
        }
    ],
    "links": [
        {
            "client_group": "c1",
            "server_group": "s1",
            "template": "t1",
            "conn_rate": 100,
            "max_active": 200,
            "reuse_policy": "keepalive",
        }
    ],
    "constraints": {
        "max_flows": 10000,
        "max_new_conn_per_sec": 5000,
        "fail_policy": "hard_fail",
    },
    "tuple_gen": {
        "client_pool_strategy": "sequential",
        "server_pool_strategy": "sequential",
        "port_allocator": "hash",
        "flow_affinity_5tuple": True,
        "stickiness": True,
    },
}


class TestStatefulTopologyContract(unittest.TestCase):
    def test_topology_uses_native_parser_when_available(self):
        native_result = {
            "plan_id": "native_plan_1234",
            "seed": 99,
            "client_pool_size": 4,
            "server_pool_size": 2,
            "spec": _VALID_SPEC,
        }

        class _Native:
            @staticmethod
            def parse_compile_topology_json(_json, _seed, _strict):
                return native_result

            @staticmethod
            def topology_tuple_preview(_compiled, _sample):
                return [{"client_group": "c1", "server_group": "s1", "template": "t1"}]

        with patch("ddos_samurai.topology_native._native", _Native()):
            compiled = parse_compile_topology_spec(
                topo_spec_json=__import__("json").dumps(_VALID_SPEC),
                topo_seed=99,
                topo_strict=True,
            )
            self.assertEqual(compiled.plan_id, "native_plan_1234")
            preview = topology_tuple_preview(compiled, sample_size=1)
            self.assertEqual(preview[0]["client_group"], "c1")

    def test_topology_schema_missing_field_fails(self):
        bad = dict(_VALID_SPEC)
        bad.pop("links", None)
        class _Native:
            @staticmethod
            def parse_compile_topology_json(_json, _seed, _strict):
                raise ValueError("topology_spec_requires_clients_servers_templates_links")

            @staticmethod
            def topology_tuple_preview(_compiled, _sample):
                return []

        with patch("ddos_samurai.topology_native._native", _Native()):
            with self.assertRaises(ValueError):
                parse_compile_topology_spec(topo_spec_json=__import__("json").dumps(bad), topo_seed=7, topo_strict=True)

    def test_topology_deterministic_preview(self):
        import json

        class _Native:
            @staticmethod
            def parse_compile_topology_json(_json, _seed, _strict):
                return {
                    "plan_id": "p42",
                    "seed": 42,
                    "client_pool_size": 4,
                    "server_pool_size": 2,
                    "spec": _VALID_SPEC,
                }

            @staticmethod
            def topology_tuple_preview(_compiled, sample):
                return [
                    {
                        "client_group": "c1",
                        "server_group": "s1",
                        "template": "t1",
                        "client_ip": "10.0.0.1",
                        "server_ip": "192.0.2.10",
                        "client_port": 1024 + i,
                        "server_port": 80 if i % 2 == 0 else 443,
                    }
                    for i in range(int(sample))
                ]

        with patch("ddos_samurai.topology_native._native", _Native()):
            compiled_a = parse_compile_topology_spec(
                topo_spec_json=json.dumps(_VALID_SPEC),
                topo_seed=42,
                topo_strict=True,
            )
            compiled_b = parse_compile_topology_spec(
                topo_spec_json=json.dumps(_VALID_SPEC),
                topo_seed=42,
                topo_strict=True,
            )
            self.assertEqual(compiled_a.plan_id, compiled_b.plan_id)
            self.assertEqual(topology_tuple_preview(compiled_a, sample_size=8), topology_tuple_preview(compiled_b, sample_size=8))

    def test_topology_tuple_preview_resolves_real_ip_and_ports(self):
        import json

        class _Native:
            @staticmethod
            def parse_compile_topology_json(_json, _seed, _strict):
                return {
                    "plan_id": "p123",
                    "seed": 123,
                    "client_pool_size": 4,
                    "server_pool_size": 2,
                    "spec": _VALID_SPEC,
                }

            @staticmethod
            def topology_tuple_preview(_compiled, sample):
                return [
                    {
                        "client_group": "c1",
                        "server_group": "s1",
                        "template": "t1",
                        "client_ip": "10.0.0.2",
                        "server_ip": "192.0.2.10",
                        "client_port": 1027,
                        "server_port": 443,
                    }
                    for _ in range(int(sample))
                ]

        with patch("ddos_samurai.topology_native._native", _Native()):
            compiled = parse_compile_topology_spec(
                topo_spec_json=json.dumps(_VALID_SPEC),
                topo_seed=123,
                topo_strict=True,
            )
            row = topology_tuple_for_index(compiled, tuple_index=0)
            self.assertIn("client_ip", row)
            self.assertIn("server_ip", row)
            self.assertIn("client_port", row)
            self.assertIn("server_port", row)
            self.assertRegex(str(row["client_ip"]), r"^\d+\.\d+\.\d+\.\d+$")
            self.assertEqual(str(row["server_ip"]), "192.0.2.10")
            self.assertTrue(1024 <= int(row["client_port"]) <= 1030)
            self.assertIn(int(row["server_port"]), {80, 443})

    def test_compiled_plan_round_trip_from_dict(self):
        import json

        class _Native:
            @staticmethod
            def parse_compile_topology_json(_json, _seed, _strict):
                return {
                    "plan_id": "p7",
                    "seed": 7,
                    "client_pool_size": 4,
                    "server_pool_size": 2,
                    "spec": _VALID_SPEC,
                }

            @staticmethod
            def topology_tuple_preview(_compiled, sample):
                return [
                    {
                        "client_group": "c1",
                        "server_group": "s1",
                        "template": "t1",
                        "client_ip": "10.0.0.1",
                        "server_ip": "192.0.2.10",
                        "client_port": 1024 + i,
                        "server_port": 80,
                    }
                    for i in range(int(sample))
                ]

        with patch("ddos_samurai.topology_native._native", _Native()):
            compiled = parse_compile_topology_spec(
                topo_spec_json=json.dumps(_VALID_SPEC),
                topo_seed=7,
                topo_strict=True,
            )
            raw = compiled.as_dict()
            reconstructed = compiled_topology_plan_from_dict(raw)
            self.assertEqual(reconstructed.plan_id, compiled.plan_id)
            self.assertEqual(topology_tuple_for_index(reconstructed, tuple_index=3), topology_tuple_for_index(compiled, tuple_index=3))

    def test_topology_native_required_hard_fail(self):
        with patch("ddos_samurai.topology_native._native", None):
            with self.assertRaises(RuntimeError):
                parse_compile_topology_spec(
                    topo_spec_json=__import__("json").dumps(_VALID_SPEC),
                    topo_seed=1,
                    topo_strict=True,
                )

    def test_contract_engine_fails_for_fallback(self):
        result = evaluate_hot_path_contract(
            attack_vector="basic",
            sender_path="DP_TX_RING",
            sender_fallback_reason="fallback_used",
            fallback_count=1,
            runtime_transport_backend="",
            custom_tcp_bridge_backend_used="",
        )
        self.assertEqual(result.status, "failed")

    def test_contract_engine_requires_l7_custom_tcp_xdp(self):
        failed = evaluate_hot_path_contract(
            attack_vector="http",
            sender_path="L7_C_STATE_HTTP",
            sender_fallback_reason="none",
            fallback_count=0,
            runtime_transport_backend="kernel_socket",
            custom_tcp_bridge_backend_used="txring",
        )
        self.assertEqual(failed.status, "failed")
        passed = evaluate_hot_path_contract(
            attack_vector="http",
            sender_path="L7_C_STATE_HTTP",
            sender_fallback_reason="none",
            fallback_count=0,
            runtime_transport_backend="custom_tcp",
            custom_tcp_bridge_backend_used="xdp",
        )
        self.assertEqual(passed.status, "passed")


if __name__ == "__main__":
    unittest.main()
