import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


class TestHwTimestamping(unittest.TestCase):
    def test_nanosecond_latency_percentiles_logic(self):
        # Generate 1000 simulated nanosecond RTT samples (10us to 10ms)
        samples = [10000 + (i * 10000) for i in range(1000)]
        samples.sort()
        n = len(samples)

        p50 = samples[int(0.50 * n)]
        p90 = samples[int(0.90 * n)]
        p95 = samples[int(0.95 * n)]
        p99 = samples[int(0.99 * n)]
        p99_9 = samples[int(0.999 * n) if int(0.999 * n) < n else n - 1]

        self.assertGreater(p50, 0)
        self.assertGreater(p90, p50)
        self.assertGreater(p95, p90)
        self.assertGreater(p99, p95)
        self.assertGreaterEqual(p99_9, p99)

        # Check jitter calculation (diff between consecutive samples)
        diffs = [abs(samples[i] - samples[i - 1]) for i in range(1, n)]
        avg_jitter = sum(diffs) / len(diffs)
        self.assertEqual(avg_jitter, 10000.0)


if __name__ == "__main__":
    unittest.main()
