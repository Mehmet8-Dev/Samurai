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
                "quic_stack_mode": "h3_stateful",
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
