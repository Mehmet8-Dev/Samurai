import types
import unittest
from unittest.mock import Mock, patch
import os

from ddos_samurai.af_xdp_sender import XDP_MODE_OFFLOAD, XDPStats, XDPSender


class TestAFXDPZeroCopy(unittest.TestCase):
    def _mk_sender(self):
        sender = XDPSender(interface="lo", auto_fallback=True)
        sender._is_running = True
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

    def test_acquire_submit_release_tx_frame_wrappers(self):
        sender = self._mk_sender()
        xdp_mod = Mock()
        xdp_mod.xdp_acquire_tx_frame.return_value = (12, memoryview(bytearray(64)))
        xdp_mod.xdp_submit_tx_frame.return_value = True
        xdp_mod.xdp_release_tx_frame.return_value = True
        sender._xdp = xdp_mod

        frame_id, view = sender.acquire_tx_frame()
        self.assertEqual(frame_id, 12)
        self.assertEqual(len(view), 64)
        self.assertTrue(sender.submit_tx_frame(frame_id, 32))
        self.assertTrue(sender.release_tx_frame(frame_id))

    def test_tx_frame_wrappers_fail_in_multi_context_mode(self):
        sender = self._mk_sender()
        sender._ctx_handle = 7
        sender._xdp = Mock()

        with self.assertRaises(RuntimeError):
            sender.acquire_tx_frame()
        with self.assertRaises(RuntimeError):
            sender.submit_tx_frame(1, 64)
        with self.assertRaises(RuntimeError):
            sender.release_tx_frame(1)

    def test_mode2_hard_policy_raises_when_probe_not_supported(self):
        sender = XDPSender(
            interface="lo",
            mode=XDP_MODE_OFFLOAD,
            auto_fallback=False,
            mode2_policy="hard",
            attach_bpf=False,
        )
        sender._check_requirements = Mock(return_value=(True, "ok"))
        sender._probe_mode2_capability = Mock(return_value=("unsupported", "no hw offload"))
        xdp_mod = Mock()
        xdp_mod.xdp_init.return_value = True

        with patch("ddos_samurai.af_xdp_sender._load_xdp_extension", return_value=xdp_mod):
            with self.assertRaises(RuntimeError):
                sender.start()

        xdp_mod.xdp_init.assert_not_called()

    def test_mode2_soft_policy_downgrades_to_native_mode(self):
        sender = XDPSender(
            interface="lo",
            mode=XDP_MODE_OFFLOAD,
            auto_fallback=False,
            mode2_policy="soft",
            attach_bpf=False,
        )
        sender._check_requirements = Mock(return_value=(True, "ok"))
        sender._probe_mode2_capability = Mock(return_value=("unsupported", "no hw offload"))
        xdp_mod = Mock()
        xdp_mod.xdp_init.return_value = True

        with patch("ddos_samurai.af_xdp_sender._load_xdp_extension", return_value=xdp_mod):
            started = sender.start()

        self.assertTrue(started)
        xdp_mod.xdp_init.assert_called_once_with("lo", 0, 1)

    def test_mode2_soft_policy_downgrades_to_native_mode_when_probe_unknown(self):
        sender = XDPSender(
            interface="lo",
            mode=XDP_MODE_OFFLOAD,
            auto_fallback=False,
            mode2_policy="soft",
            attach_bpf=False,
        )
        sender._check_requirements = Mock(return_value=(True, "ok"))
        sender._probe_mode2_capability = Mock(return_value=("unknown", "cannot verify hw offload"))
        xdp_mod = Mock()
        xdp_mod.xdp_init.return_value = True

        with patch("ddos_samurai.af_xdp_sender._load_xdp_extension", return_value=xdp_mod):
            started = sender.start()

        self.assertTrue(started)
        xdp_mod.xdp_init.assert_called_once_with("lo", 0, 1)

    def test_xdp_stats_parses_extended_telemetry(self):
        stats = XDPStats.from_dict(
            {
                "tx_packets": 10,
                "tx_desc_reserve_failures": 3,
                "tx_frame_alloc_failures": 4,
                "tx_partial_batches": 5,
                "tx_retry_loops": 6,
                "tx_completion_events": 7,
                "tx_completed_desc": 8,
                "tx_invalid_packets": 9,
                "tx_backpressure_events": 11,
                "tx_send_calls": 12,
                "tx_send_ns_total": 13000,
                "tx_send_ns_max": 2500,
                "tx_send_avg_us": 1.08,
                "tx_send_max_us": 2.50,
                "queue_id": 4,
            }
        )
        self.assertEqual(stats.tx_packets, 10)
        self.assertEqual(stats.tx_desc_reserve_failures, 3)
        self.assertEqual(stats.tx_frame_alloc_failures, 4)
        self.assertEqual(stats.tx_partial_batches, 5)
        self.assertEqual(stats.tx_retry_loops, 6)
        self.assertEqual(stats.tx_completion_events, 7)
        self.assertEqual(stats.tx_completed_desc, 8)
        self.assertEqual(stats.tx_invalid_packets, 9)
        self.assertEqual(stats.tx_backpressure_events, 11)
        self.assertEqual(stats.tx_send_calls, 12)
        self.assertEqual(stats.tx_send_ns_total, 13000)
        self.assertEqual(stats.tx_send_ns_max, 2500)
        self.assertAlmostEqual(stats.tx_send_avg_us, 1.08, places=2)
        self.assertAlmostEqual(stats.tx_send_max_us, 2.50, places=2)
        self.assertEqual(stats.queue_id, 4)

    def test_start_uses_multi_context_api_when_enabled(self):
        old = os.environ.get("SAMURAI_XDP_MULTI_CTX")
        os.environ["SAMURAI_XDP_MULTI_CTX"] = "1"
        try:
            sender = XDPSender(interface="lo", auto_fallback=False, attach_bpf=False)
            sender._check_requirements = Mock(return_value=(True, "ok"))

            class _Mod:
                def xdp_create(self, *_args):
                    return 7
                def xdp_destroy(self, *_args):
                    return None
                def xdp_send_ctx(self, *_args):
                    return 0

            mod = _Mod()
            with patch("ddos_samurai.af_xdp_sender._load_xdp_extension", return_value=mod):
                started = sender.start()

            self.assertTrue(started)
            self.assertEqual(sender._ctx_handle, 7)
        finally:
            if old is None:
                os.environ.pop("SAMURAI_XDP_MULTI_CTX", None)
            else:
                os.environ["SAMURAI_XDP_MULTI_CTX"] = old


if __name__ == "__main__":
    unittest.main()
