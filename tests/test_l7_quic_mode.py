import unittest

from ddos_samurai.l7 import quic_mode


class TestL7QuicMode(unittest.TestCase):
    def test_normalize_aliases(self):
        self.assertEqual(quic_mode.normalize("h3"), "h3_stateful")
        self.assertEqual(quic_mode.normalize("h3_bridge"), "h3_stateful_py")
        self.assertEqual(quic_mode.normalize("probe"), "probe_udp")
        self.assertEqual(quic_mode.normalize("unknown-mode"), "unavailable")

    def test_mode_classification(self):
        self.assertTrue(quic_mode.is_h3_stateful("h3_stateful"))
        self.assertTrue(quic_mode.is_h3_stateful("h3_stateful_py"))
        self.assertFalse(quic_mode.is_h3_stateful("probe_udp"))
        self.assertTrue(quic_mode.is_native_h3_stateful("h3_stateful"))
        self.assertFalse(quic_mode.is_native_h3_stateful("h3_stateful_py"))
        self.assertTrue(quic_mode.is_bridge_h3_stateful("h3_stateful_py"))
        self.assertFalse(quic_mode.is_bridge_h3_stateful("h3_stateful"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
