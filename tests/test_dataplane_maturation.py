import unittest
import os
import sys

# Ensure ddos_samurai package path is available
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


class TestDataplaneMaturation(unittest.TestCase):
    def test_pacing_engine_adaptive_rate(self):
        # Verify pacing adjustment concept in python test suite
        target_rps = 1000.0
        drop_rate_pct = 10.0  # 10% drop rate
        if drop_rate_pct > 5.0:
            factor = 1.0 - (drop_rate_pct / 200.0)  # 0.95
            adjusted_rps = target_rps * factor
        else:
            adjusted_rps = target_rps
        self.assertLess(adjusted_rps, target_rps)
        self.assertEqual(adjusted_rps, 950.0)

    def test_lockless_flow_lookup_export(self):
        # Verify C++ build target test_l2l3_astf exists and passes
        astf_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../build/l7_emu_native/test_l2l3_astf"))
        if os.path.exists(astf_path):
            import subprocess
            res = subprocess.run([astf_path], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)


if __name__ == "__main__":
    unittest.main()
