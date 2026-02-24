from __future__ import annotations

import os
import socket
import unittest

import pytest

pytestmark = [pytest.mark.privileged]


class TestFastSenderTxRingStats(unittest.TestCase):
    def test_send_ring_optimized_ex_returns_stats_schema(self):
        try:
            from ddos_samurai import fast_sender
        except Exception as exc:
            raise unittest.SkipTest(f"fast_sender extension unavailable: {exc}")

        if not hasattr(fast_sender, "send_ring_optimized_ex"):
            raise unittest.SkipTest("send_ring_optimized_ex is not available in this build")
        if os.geteuid() != 0:
            raise unittest.SkipTest("TX_RING stats test requires root")

        iface = str(os.environ.get("SAMURAI_LOSS_IFACE", "lo") or "lo").strip()
        try:
            socket.if_nametoindex(iface)
        except Exception:
            raise unittest.SkipTest(f"Interface not available: {iface}")

        count = 8
        packet_size = 64
        # Ethernet-like frame payload (test data only).
        frame = (b"\xff" * 6) + (b"\x00" * 6) + b"\x08\x00" + (b"\x00" * (packet_size - 14))
        buf = frame * count
        mac = b"\x00\x11\x22\x33\x44\x55"

        try:
            out = fast_sender.send_ring_optimized_ex(iface, buf, packet_size, count, mac)
        except OSError as exc:
            raise unittest.SkipTest(f"TX_RING unavailable in this environment: {exc}")
        finally:
            try:
                fast_sender.cleanup_ring()
            except Exception:
                pass

        self.assertIsInstance(out, dict)
        for key in (
            "attempted",
            "sent",
            "errors",
            "txring_flush_call_count",
            "txring_flush_error_count",
            "txring_flush_eagain_count",
            "txring_tp_packets",
            "txring_tp_drops",
            "txring_tp_freeze_q_cnt",
        ):
            self.assertIn(key, out)
            self.assertGreaterEqual(int(out.get(key, 0) or 0), 0)

        self.assertLessEqual(int(out["sent"]), int(out["attempted"]))


if __name__ == "__main__":
    unittest.main()

