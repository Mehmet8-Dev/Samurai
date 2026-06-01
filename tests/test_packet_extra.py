import unittest

from ddos_samurai import gpu_packet


class TestPacketExtra(unittest.TestCase):
    def test_ip_int_roundtrip(self):
        ip = "203.0.113.7"
        self.assertEqual(gpu_packet.int_to_ip(gpu_packet.ip_to_int(ip)), ip)

    def test_parse_subnet(self):
        base, prefix = gpu_packet.parse_subnet("198.51.100.0/24")
        self.assertEqual(prefix, 24)
        self.assertEqual(gpu_packet.int_to_ip(base), "198.51.100.0")

    def test_http_line_contract_not_exposed_in_facade(self):
        with self.assertRaises(AttributeError):
            getattr(gpu_packet, "_randomize_http_headers")


if __name__ == "__main__":
    unittest.main(verbosity=2)
