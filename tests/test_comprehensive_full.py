"""Full-profile smoke checks aligned with ZMQ-only GPU runtime."""

import unittest

from ddos_samurai import gpu_packet


class TestComprehensiveFull(unittest.TestCase):
    def test_removed_bridge_is_fail_closed(self):
        with self.assertRaises(gpu_packet.GPUPacketError):
            gpu_packet.generate_packets()

    def test_subnet_and_budget_helpers(self):
        net, prefix = gpu_packet.parse_subnet("203.0.113.0/24")
        self.assertEqual(prefix, 24)
        self.assertEqual(gpu_packet.int_to_ip(net), "203.0.113.0")
        self.assertEqual(gpu_packet.publication_budget_us(10), 50)


if __name__ == "__main__":
    unittest.main(verbosity=2)
