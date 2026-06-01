"""Detailed GPU sender helper tests for ZMQ-only mode."""

import unittest

from ddos_samurai import gpu_packet


class TestGpuSenderDetailed(unittest.TestCase):
    def test_flow_affinity_determinism(self):
        a = gpu_packet.compute_flow_affinity(1, 256, 64, 4)
        b = gpu_packet.compute_flow_affinity(1, 256, 64, 4)
        self.assertEqual(a, b)

    def test_flow_affinity_lane_bounds(self):
        for tid in range(0, 256):
            aff = gpu_packet.compute_flow_affinity(0, 256, tid, 4)
            self.assertGreaterEqual(aff["lane"], 0)
            self.assertLess(aff["lane"], 32)

    def test_seqlock_progression(self):
        cur = 0
        for _ in range(10):
            wb, wc = gpu_packet.seqlock_next_versions(cur)
            self.assertEqual(wb % 2, 1)
            self.assertEqual(wc % 2, 0)
            self.assertEqual(wc, wb + 1)
            cur = wc


if __name__ == "__main__":
    unittest.main(verbosity=2)
