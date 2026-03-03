"""Full-profile loss telemetry policy checks."""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

import pytest

pytestmark = [pytest.mark.privileged, pytest.mark.benchmark]


class TestLossTelemetryPolicy(unittest.TestCase):
    def _build_report(self, attempted: int, wire_loss_packets: int):
        from ddos_samurai import reporting

        events = [
            {
                "status": "ok",
                "attack_vector": "basic",
                "compute_backend": "cpu",
                "stats": {
                    "attempted": attempted,
                    "sent": max(0, attempted - wire_loss_packets),
                    "errors": wire_loss_packets,
                    "bytes_sent_est": max(0, attempted - wire_loss_packets) * 64,
                    "wire_counter_available": 1,
                    "wire_counter_source": "sysfs_netdev_stats",
                    "wire_counter_confidence": 1.0,
                    "wire_tx_packets_delta": max(0, attempted - wire_loss_packets),
                    "wire_loss_est_packets": wire_loss_packets,
                },
                "wire_counter_available": 1,
                "wire_counter_source": "sysfs_netdev_stats",
                "wire_counter_confidence": 1.0,
                "wire_tx_packets_delta": max(0, attempted - wire_loss_packets),
                "wire_loss_est_packets": wire_loss_packets,
            }
        ]
        return reporting.build_live_attack_report(
            args={"target": "127.0.0.1"},
            worker_events=events,
            duration_s=1.0,
            progress_total=attempted,
            total_count=attempted,
            metrics={},
            warnings=[],
        )

    def test_wire_loss_status_fail_warn_ok(self):
        with patch.dict(os.environ, {"SAMURAI_LOSS_FAIL_PCT": "5"}, clear=False):
            rep_fail = self._build_report(attempted=1000, wire_loss_packets=60)
            rep_warn = self._build_report(attempted=1000, wire_loss_packets=10)
            rep_ok = self._build_report(attempted=1000, wire_loss_packets=0)

        self.assertEqual(rep_fail.results["wire_loss_status"], "fail")
        self.assertGreater(rep_fail.results["wire_loss_est_pct"], 5.0)
        self.assertEqual(rep_warn.results["wire_loss_status"], "warn")
        self.assertGreater(rep_warn.results["wire_loss_est_pct"], 0.0)
        self.assertLessEqual(rep_warn.results["wire_loss_est_pct"], 5.0)
        self.assertEqual(rep_ok.results["wire_loss_status"], "ok")
        self.assertEqual(rep_ok.results["wire_loss_est_pct"], 0.0)


if __name__ == "__main__":
    unittest.main()
