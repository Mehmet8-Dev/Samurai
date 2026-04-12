import unittest

from ddos_samurai import kpi_gate


class TestKpiGateDynamicRequirements(unittest.TestCase):
    def _base_results(self):
        return {
            "run_quality": "valid",
            "send_success_ratio_pct": 99.9,
            "wire_loss_est_pct": 0.2,
            "rate_accuracy_pct": 99.0,
            "txring_flush_error_ratio_pct": 0.1,
            "txring_flush_eagain_ratio_pct": 0.2,
            "txring_hold_block_pressure_pct": 10.0,
            "sender_paths_used": {"C_EXT_L3": 1},
            "sender_fallback_reason": "none",
            "runtime_backend": "afxdp",
            "runtime_hot_path_level": "phase1_hybrid_afxdp_custom_tcp",
            "legacy_path_used": 0,
            "runtime_transport_backend": "custom_tcp",
            "stateful_runtime_status": "ready",
            "custom_tcp_bridge_xdp_enabled": 1,
            "custom_tcp_bridge_backend_match": 1,
            "stateful_runtime_preflight_status": "passed",
            "stateful_runtime_preflight_xdp_enabled": 1,
            "l7_conn_rate_cv_pct": 1.0,
        }

    def test_dedicated_non_quic_run_does_not_require_quic_metrics(self):
        results = self._base_results()
        out = kpi_gate.evaluate(results, profile="dedicated_lab", hard_fail=True)
        self.assertEqual(out.status, "pass")
        self.assertEqual(out.hard_fail, 0)
        self.assertEqual(out.score_eligible, 1)

    def test_dedicated_quic_run_requires_quic_native_metrics(self):
        results = self._base_results()
        results.update(
            {
                "by_vector": {"quic": {"attempted": 100, "sent": 99, "errors": 1}},
                "session_success_rate": 99.0,
                "retry_success_rate": 95.0,
                "l7_step_fail_ratio": 0.0,
                "l7_handshake_p99_ms": 50.0,
                "l7_fail_budget_pct": 1.0,
            }
        )
        out = kpi_gate.evaluate(results, profile="dedicated_lab", hard_fail=True)
        self.assertEqual(out.status, "fail")
        self.assertEqual(out.hard_fail, 1)
        self.assertTrue(any(v.startswith("quic_stream_fail_ratio:missing_metric") for v in out.violations))
        self.assertTrue(any(v.startswith("quic_stack_mode:missing_metric") for v in out.violations))

    def test_dedicated_quic_run_passes_with_native_metrics(self):
        results = self._base_results()
        results.update(
            {
                "by_vector": {"quic": {"attempted": 100, "sent": 99, "errors": 1}},
                "session_success_rate": 99.0,
                "retry_success_rate": 95.0,
                "l7_step_fail_ratio": 0.0,
                "l7_handshake_p99_ms": 50.0,
                "l7_fail_budget_pct": 1.0,
                "quic_stream_fail_ratio": 0.0,
                "quic_handshake_fail_ratio": 0.0,
                "quic_response_validation_fail_ratio": 0.0,
                "quic_stack_mode": "custom_native",
            }
        )
        out = kpi_gate.evaluate(results, profile="dedicated_lab", hard_fail=True)
        self.assertEqual(out.status, "pass")
        self.assertEqual(out.hard_fail, 0)
        self.assertEqual(out.score_eligible, 1)

    def test_dedicated_txring_scope_requires_afpacket_hugepage_effective(self):
        results = self._base_results()
        results.update(
            {
                "sender_paths_used": {"TX_RING_L2": 1},
                "afpacket_hugepage_mode": "required",
                "afpacket_hugepage_effective": 0,
            }
        )
        out = kpi_gate.evaluate(results, profile="dedicated_lab", hard_fail=True)
        self.assertEqual(out.status, "fail")
        self.assertEqual(out.hard_fail, 1)
        self.assertTrue(any(v.startswith("afpacket_hugepage_effective:") for v in out.violations))

    def test_dedicated_non_txring_scope_does_not_require_afpacket_hugepage(self):
        results = self._base_results()
        results.update({"sender_paths_used": {"PYTHON_SENDMMSG": 1}})
        out = kpi_gate.evaluate(results, profile="dedicated_lab", hard_fail=True)
        self.assertEqual(out.status, "pass")

    def test_dedicated_l7_run_requires_afxdp_runtime_backend(self):
        results = self._base_results()
        results.update(
            {
                "by_vector": {"http": {"attempted": 100, "sent": 100, "errors": 0}},
                "session_success_rate": 99.5,
                "retry_success_rate": 95.0,
                "l7_step_fail_ratio": 0.0,
                "l7_handshake_p99_ms": 20.0,
                "l7_fail_budget_pct": 0.0,
                "runtime_backend": "legacy",
            }
        )
        out = kpi_gate.evaluate(results, profile="dedicated_lab", hard_fail=True)
        self.assertEqual(out.status, "fail")
        self.assertTrue(any(v.startswith("runtime_backend:") for v in out.violations))

    def test_dedicated_l7_run_requires_native_runtime_hot_path_and_bridge(self):
        results = self._base_results()
        results.update(
            {
                "by_vector": {"http": {"attempted": 100, "sent": 100, "errors": 0}},
                "session_success_rate": 99.5,
                "retry_success_rate": 95.0,
                "l7_step_fail_ratio": 0.0,
                "l7_handshake_p99_ms": 20.0,
                "l7_fail_budget_pct": 0.0,
                "runtime_hot_path_level": "legacy_compat",
                "legacy_path_used": 1,
                "custom_tcp_bridge_xdp_enabled": 0,
                "custom_tcp_bridge_backend_match": 0,
                "stateful_runtime_preflight_status": "failed",
                "stateful_runtime_preflight_xdp_enabled": 0,
            }
        )
        out = kpi_gate.evaluate(results, profile="dedicated_lab", hard_fail=True)
        self.assertEqual(out.status, "fail")
        self.assertTrue(any(v.startswith("runtime_hot_path_level:") for v in out.violations))
        self.assertTrue(any(v.startswith("legacy_path_used:") for v in out.violations))
        self.assertTrue(any(v.startswith("custom_tcp_bridge_xdp_enabled:") for v in out.violations))
        self.assertTrue(any(v.startswith("custom_tcp_bridge_backend_match:") for v in out.violations))
        self.assertTrue(any(v.startswith("stateful_runtime_preflight_status:") for v in out.violations))
        self.assertTrue(any(v.startswith("stateful_runtime_preflight_xdp_enabled:") for v in out.violations))

    def test_dedicated_requires_rate_accuracy_metric(self):
        results = self._base_results()
        results.pop("rate_accuracy_pct", None)
        out = kpi_gate.evaluate(results, profile="dedicated_lab", hard_fail=True)
        self.assertEqual(out.status, "fail")
        self.assertTrue(any(v.startswith("rate_accuracy_pct:missing_metric") for v in out.violations))

    def test_dedicated_txring_scope_requires_flush_metrics(self):
        results = self._base_results()
        results.update({"sender_paths_used": {"TX_RING_L2": 1}})
        results.pop("txring_flush_error_ratio_pct", None)
        out = kpi_gate.evaluate(results, profile="dedicated_lab", hard_fail=True)
        self.assertEqual(out.status, "fail")
        self.assertTrue(any(v.startswith("txring_flush_error_ratio_pct:missing_metric") for v in out.violations))

    def test_dedicated_fails_when_sender_fallback_reason_not_none(self):
        results = self._base_results()
        results["sender_fallback_reason"] = "txring_unavailable"
        out = kpi_gate.evaluate(results, profile="dedicated_lab", hard_fail=True)
        self.assertEqual(out.status, "fail")
        self.assertTrue(any(v.startswith("sender_fallback_reason:") for v in out.violations))

    def test_dedicated_fails_when_sender_path_drift_detected(self):
        results = self._base_results()
        results["sender_paths_used"] = {"TX_RING_L2": 1, "C_EXT_L3": 1}
        out = kpi_gate.evaluate(results, profile="dedicated_lab", hard_fail=True)
        self.assertEqual(out.status, "fail")
        self.assertTrue(any(v.startswith("sender_paths_used:") for v in out.violations))

    def test_dev_profile_is_supported(self):
        results = self._base_results()
        out = kpi_gate.evaluate(results, profile="dev", hard_fail=False)
        self.assertEqual(out.profile, "dev")
        self.assertEqual(out.status, "pass")

    def test_ci_safe_profile_warns_without_hard_fail(self):
        results = self._base_results()
        results["send_success_ratio_pct"] = 90.0
        out = kpi_gate.evaluate(results, profile="ci_safe", hard_fail=True)
        self.assertEqual(out.profile, "ci_safe")
        self.assertEqual(out.status, "warn")
        self.assertEqual(out.hard_fail, 0)


if __name__ == "__main__":
    unittest.main()
