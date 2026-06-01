"""Legacy filename kept; now validates ZMQ-only GPU facade contracts."""

from __future__ import annotations

import unittest

from ddos_samurai import gpu_packet


class TestFacadeBasics(unittest.TestCase):
    def test_backend_flags(self):
        self.assertEqual(gpu_packet.get_active_backend_name(), "zmq")
        self.assertFalse(gpu_packet.is_native_path_enabled())
        self.assertFalse(gpu_packet.is_native_library_available())
        self.assertFalse(gpu_packet.is_native_path_active())

    def test_kernel_mode_is_persistent_only(self):
        self.assertEqual(gpu_packet.get_kernel_mode(), "persistent")
        self.assertEqual(gpu_packet.set_kernel_mode("persistent"), "persistent")
        with self.assertRaises(gpu_packet.GPUPacketError):
            gpu_packet.set_kernel_mode("legacy")

    def test_removed_bridge_calls_raise(self):
        with self.assertRaises(gpu_packet.GPUPacketError):
            gpu_packet.generate_packets()
        with self.assertRaises(gpu_packet.GPUPacketError):
            gpu_packet.generate_packets_from_template()
        with self.assertRaises(gpu_packet.GPUPacketError):
            gpu_packet.generate_packets_from_template_pool()


class TestStatefulHelpers(unittest.TestCase):
    def test_seqlock_versions(self):
        wb, wc = gpu_packet.seqlock_next_versions(8)
        self.assertEqual(wb, 9)
        self.assertEqual(wc, 10)

        wb2, wc2 = gpu_packet.seqlock_next_versions(9)
        self.assertEqual(wb2, 11)
        self.assertEqual(wc2, 12)

    def test_publication_budget(self):
        self.assertEqual(gpu_packet.publication_budget_us(0), 50)
        self.assertEqual(gpu_packet.publication_budget_us(500), 50)
        self.assertEqual(gpu_packet.publication_budget_us(5000), 500)
        self.assertEqual(gpu_packet.publication_budget_us(999999), 1000)

    def test_descriptor_transitions(self):
        ok_path = [(0, 1), (1, 2), (2, 3), (3, 4), (4, 0)]
        for s, t in ok_path:
            self.assertTrue(gpu_packet.descriptor_transition_valid(s, t))

        bad_path = [(0, 2), (1, 4), (4, 2), (3, 1)]
        for s, t in bad_path:
            self.assertFalse(gpu_packet.descriptor_transition_valid(s, t))

    def test_flow_affinity_shape(self):
        aff = gpu_packet.compute_flow_affinity(
            block_idx=2,
            block_dim=256,
            thread_idx=63,
            flows_per_warp=4,
            warp_size=32,
        )
        self.assertIn("global_tid", aff)
        self.assertIn("global_warp_id", aff)
        self.assertIn("lane", aff)
        self.assertIn("flow_id", aff)
        self.assertGreaterEqual(aff["lane"], 0)
        self.assertLess(aff["lane"], 32)


if __name__ == "__main__":
    unittest.main(verbosity=2)
