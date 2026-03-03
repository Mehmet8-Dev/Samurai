import os
import tempfile
import unittest
from unittest.mock import patch

import pytest

from ddos_samurai import loss_telemetry

pytestmark = [pytest.mark.ci_safe]


class TestLossTelemetry(unittest.TestCase):
    def test_parse_proc_net_dev(self):
        sample = """
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
   lo: 1000 10 0 1 0 0 0 0 1000 12 0 2 0 0 0 0
 eth0: 2000 20 3 4 0 0 0 0 3000 30 5 6 0 0 0 0
"""
        out = loss_telemetry._parse_proc_net_dev_text(sample)
        self.assertIn("lo", out)
        self.assertIn("eth0", out)
        self.assertEqual(out["eth0"]["tx_packets"], 30)
        self.assertEqual(out["eth0"]["tx_errors"], 5)
        self.assertEqual(out["eth0"]["tx_dropped"], 6)

    def test_parse_softnet_stat(self):
        sample = """
00000010 00000002 00000003 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
00000020 00000004 00000005 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
"""
        out = loss_telemetry._parse_softnet_stat_text(sample)
        self.assertEqual(out["processed"], 0x30)
        self.assertEqual(out["dropped"], 0x06)
        self.assertEqual(out["time_squeeze"], 0x08)

    def test_delta_computation(self):
        before = {
            "enabled": 1,
            "iface": "eth0",
            "host_tx_packets": 100,
            "host_tx_dropped": 2,
            "host_tx_errors": 1,
            "softnet_dropped": 8,
            "softnet_time_squeeze": 5,
            "wire_counter_available": 1,
            "wire_counter_source": "sysfs_netdev_stats",
            "wire_counter_confidence": 1.0,
            "wire_tx_packets": 90,
            "wire_tx_dropped": 1,
            "wire_tx_errors": 0,
            "wire_tx_bytes": 9000,
        }
        after = {
            "enabled": 1,
            "iface": "eth0",
            "host_tx_packets": 120,
            "host_tx_dropped": 7,
            "host_tx_errors": 3,
            "softnet_dropped": 10,
            "softnet_time_squeeze": 9,
            "wire_counter_available": 1,
            "wire_counter_source": "sysfs_netdev_stats",
            "wire_counter_confidence": 1.0,
            "wire_tx_packets": 108,
            "wire_tx_dropped": 2,
            "wire_tx_errors": 1,
            "wire_tx_bytes": 10240,
        }
        d = loss_telemetry.delta(before, after)
        self.assertEqual(d["host_tx_packets_delta"], 20)
        self.assertEqual(d["host_tx_dropped_delta"], 5)
        self.assertEqual(d["host_tx_errors_delta"], 2)
        self.assertEqual(d["softnet_dropped_delta"], 2)
        self.assertEqual(d["softnet_time_squeeze_delta"], 4)
        self.assertEqual(d["wire_counter_available"], 1)
        self.assertEqual(d["wire_counter_source"], "sysfs_netdev_stats")
        self.assertEqual(d["wire_tx_packets_delta"], 18)
        self.assertEqual(d["wire_tx_dropped_delta"], 1)
        self.assertEqual(d["wire_tx_errors_delta"], 1)
        self.assertEqual(d["wire_tx_bytes_delta"], 1240)

    def test_snapshot_fallback_when_proc_missing(self):
        with patch.dict(os.environ, {"SAMURAI_LOSS_TELEMETRY": "1"}, clear=False):
            snap = loss_telemetry.snapshot(
                iface="samurai_missing_iface_1234",
                proc_net_dev_path="/tmp/definitely_missing_proc_net_dev",
                softnet_path="/tmp/definitely_missing_softnet_stat",
            )
        self.assertEqual(int(snap.get("enabled", 0)), 0)
        self.assertIn("proc_net_dev_unavailable", str(snap.get("reason", "")))

    def test_snapshot_and_resolve_iface_with_temp_proc_files(self):
        dev_text = """
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
   lo: 1000 10 0 1 0 0 0 0 1000 12 0 2 0 0 0 0
 eth9: 2000 20 3 4 0 0 0 0 3000 40 5 6 0 0 0 0
"""
        softnet_text = "00000010 00000002 00000003 0 0 0 0 0 0 0 0\n"

        with tempfile.TemporaryDirectory() as td:
            dev_path = os.path.join(td, "net_dev")
            softnet_path = os.path.join(td, "softnet_stat")
            sysfs_root = os.path.join(td, "sysfs")
            os.makedirs(os.path.join(sysfs_root, "eth9", "statistics"), exist_ok=True)
            with open(dev_path, "w", encoding="utf-8") as f:
                f.write(dev_text)
            with open(softnet_path, "w", encoding="utf-8") as f:
                f.write(softnet_text)
            with open(os.path.join(sysfs_root, "eth9", "statistics", "tx_packets"), "w", encoding="utf-8") as f:
                f.write("41\n")
            with open(os.path.join(sysfs_root, "eth9", "statistics", "tx_dropped"), "w", encoding="utf-8") as f:
                f.write("7\n")
            with open(os.path.join(sysfs_root, "eth9", "statistics", "tx_errors"), "w", encoding="utf-8") as f:
                f.write("2\n")
            with open(os.path.join(sysfs_root, "eth9", "statistics", "tx_bytes"), "w", encoding="utf-8") as f:
                f.write("4096\n")

            with patch.dict(os.environ, {"SAMURAI_LOSS_TELEMETRY": "1"}, clear=False):
                snap = loss_telemetry.snapshot(
                    proc_net_dev_path=dev_path,
                    softnet_path=softnet_path,
                    sysfs_root=sysfs_root,
                )
        self.assertEqual(int(snap.get("enabled", 0)), 1)
        self.assertEqual(str(snap.get("iface", "")), "eth9")
        self.assertEqual(int(snap.get("host_tx_packets", 0)), 40)
        self.assertEqual(int(snap.get("softnet_dropped", 0)), 2)
        self.assertEqual(int(snap.get("wire_counter_available", 0)), 1)
        self.assertEqual(str(snap.get("wire_counter_source", "")), "sysfs_netdev_stats")
        self.assertEqual(int(snap.get("wire_tx_packets", 0)), 41)


if __name__ == "__main__":
    unittest.main()
