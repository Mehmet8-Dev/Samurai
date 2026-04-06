import unittest

from ddos_samurai.l7 import policy


class TestL7Policy(unittest.TestCase):
    def test_normalize_engine_aliases(self):
        self.assertEqual(policy.normalize_engine("c"), "c_state")
        self.assertEqual(policy.normalize_engine("cstate"), "c_state")
        self.assertEqual(policy.normalize_engine("python"), "python")
        self.assertEqual(policy.normalize_engine("weird"), "python")
        self.assertEqual(policy.normalize_engine("auto", allow_auto=True, default="auto"), "auto")

    def test_dedicated_profile_forces_capability_strict(self):
        self.assertTrue(
            policy.resolve_capability_strict(
                capability_strict=False,
                lab_profile="dedicated",
                kpi_gate_profile="off",
            )
        )
        self.assertTrue(
            policy.resolve_capability_strict(
                capability_strict=False,
                lab_profile="off",
                kpi_gate_profile="dedicated_lab",
            )
        )

    def test_allow_python_fallback_policy(self):
        self.assertTrue(
            policy.allow_python_fallback(
                fallback_policy="allow",
                capability_strict=False,
            )
        )
        self.assertFalse(
            policy.allow_python_fallback(
                fallback_policy="fail",
                capability_strict=False,
            )
        )
        self.assertFalse(
            policy.allow_python_fallback(
                fallback_policy="allow",
                capability_strict=True,
            )
        )
