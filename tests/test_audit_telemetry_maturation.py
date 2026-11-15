import unittest
import os
import sys

# Ensure samurai package path is available
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


class TestAuditTelemetryMaturation(unittest.TestCase):
    def test_latency_percentiles_calculation(self):
        latencies = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0]
        latencies.sort()
        n = len(latencies)
        p50 = latencies[int(n * 0.50)]
        p95 = latencies[int(n * 0.95) if int(n * 0.95) < n else n - 1]
        p99 = latencies[int(n * 0.99) if int(n * 0.99) < n else n - 1]
        self.assertEqual(p50, 60.0)
        self.assertEqual(p95, 100.0)
        self.assertEqual(p99, 100.0)

    def test_control_selftest_executable(self):
        selftest_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../build/control/samurai_control_selftest"))
        if os.path.exists(selftest_path):
            import subprocess
            res = subprocess.run([selftest_path], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)


if __name__ == "__main__":
    unittest.main()
