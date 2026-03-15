import types
import unittest
from unittest.mock import Mock

from ddos_samurai.af_xdp_sender import XDPSender


class TestAFXDPZeroCopy(unittest.TestCase):
    def _mk_sender(self):
        sender = XDPSender(interface="lo", auto_fallback=True)
        sender._is_running = True
        sender._use_fallback = False
        return sender

    def test_send_udp_prefers_zero_copy_symbol(self):
        sender = self._mk_sender()
        xdp_mod = Mock()
        xdp_mod.xdp_send_udp_zc.return_value = 7
        xdp_mod.xdp_send_udp.return_value = 3
        sender._xdp = xdp_mod

        sent = sender.send_udp("127.0.0.1", 9999, [b"a", b"b"])
        self.assertEqual(sent, 7)
        xdp_mod.xdp_send_udp_zc.assert_called_once()
        xdp_mod.xdp_send_udp.assert_not_called()

    def test_send_udp_falls_back_to_legacy_symbol(self):
        sender = self._mk_sender()
        legacy = Mock(return_value=5)
        sender._xdp = types.SimpleNamespace(xdp_send_udp=legacy)

        sent = sender.send_udp("127.0.0.1", 9999, [b"x"])
        self.assertEqual(sent, 5)
        legacy.assert_called_once()

    def test_send_udp_returns_zero_when_api_missing(self):
        sender = self._mk_sender()
        sender._xdp = object()

        sent = sender.send_udp("127.0.0.1", 9999, [b"x"])
        self.assertEqual(sent, 0)


if __name__ == "__main__":
    unittest.main()
