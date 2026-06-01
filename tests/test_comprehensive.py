"""Comprehensive smoke for current ZMQ-only architecture."""

import unittest

from ddos_samurai import gpu_packet


class TestComprehensiveSmoke(unittest.TestCase):
    def test_facade_contract(self):
        self.assertEqual(gpu_packet.get_active_backend_name(), "zmq")
        self.assertEqual(gpu_packet.get_kernel_mode(), "persistent")
        stats = gpu_packet.read_stream_stats()
        self.assertEqual(stats["transport"], "zmq")
        self.assertEqual(stats["python_cuda_bridge_active"], 0)

    def test_dataplane_helpers(self):
        self.assertTrue(gpu_packet.descriptor_transition_valid(0, 1))
        self.assertFalse(gpu_packet.descriptor_transition_valid(0, 3))
        aff = gpu_packet.compute_flow_affinity(0, 128, 17, 2)
        self.assertIn("flow_id", aff)


if __name__ == "__main__":
    unittest.main(verbosity=2)
