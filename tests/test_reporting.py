import json
import os
import tempfile
import unittest


class TestReporting(unittest.TestCase):
    def test_write_json_and_md(self):
        from ddos_samurai import reporting

        rr = reporting.RunReport(
            run_id="unit-test",
            started_utc="2026-02-18T00:00:00+00:00",
            finished_utc="2026-02-18T00:00:01+00:00",
            duration_s=1.0,
            mode="unit",
            inputs={"a": 1},
            results={"ok": True},
            environment={"python": {"version": "3.x"}},
        )

        with tempfile.TemporaryDirectory() as td:
            out_json = os.path.join(td, "report.json")
            out_md = os.path.join(td, "report.md")

            reporting.write_json(rr, out_json)
            reporting.write_markdown(rr, out_md)

            self.assertTrue(os.path.exists(out_json))
            self.assertTrue(os.path.exists(out_md))

            with open(out_json, "r", encoding="utf-8") as f:
                data = json.loads(f.read())
            self.assertEqual(data["run_id"], "unit-test")
            self.assertEqual(data["mode"], "unit")

    def test_self_test_report_builder(self):
        from ddos_samurai import reporting

        summary = {"tests_run": 10, "failures": 0, "errors": 0, "skipped": 2, "successful": True}
        rr = reporting.build_self_test_report(summary=summary, log_path=None, duration_s=0.1, warnings=["w"])
        self.assertEqual(rr.mode, "self_test")
        self.assertEqual(rr.results["tests_run"], 10)
        self.assertEqual(rr.results["skipped"], 2)
        self.assertTrue(rr.results["successful"])

    def test_live_attack_report_aggregates_extended_sender_counters(self):
        from ddos_samurai import reporting

        events = [
            {
                "status": "ok",
                "attack_vector": "basic",
                "compute_backend": "cpu",
                "sender_path": "PYTHON_SENDMMSG",
                "fallback_count": 1,
                "permission_error_count": 0,
                "buffer_copy_count": 2,
                "buffer_copy_bytes": 1024,
                "eagain_retry_count": 3,
                "partial_send_retry_count": 4,
                "txring_flush_call_count": 11,
                "txring_flush_error_count": 1,
                "txring_flush_eagain_count": 1,
                "txring_tp_packets": 9,
                "txring_tp_drops": 1,
                "txring_tp_freeze_q_cnt": 0,
                "host_tx_packets_delta": 10,
                "host_tx_dropped_delta": 1,
                "host_tx_errors_delta": 0,
                "softnet_dropped_delta": 2,
                "softnet_time_squeeze_delta": 1,
                "wire_loss_est_packets": 1,
                "gpu_template_h2d_copy_count": 3,
                "gpu_template_h2d_copy_bytes": 2048,
                "gpu_rng_state_alloc_count": 1,
                "gpu_rng_state_reuse_count": 5,
                "stats": {
                    "attempted": 10,
                    "sent": 9,
                    "errors": 1,
                    "bytes_sent_est": 900,
                },
            },
            {
                "status": "degraded",
                "attack_vector": "basic",
                "compute_backend": "cpu",
                "sender_path": "C_EXT_L3",
                "fallback_count": 0,
                "permission_error_count": 1,
                "buffer_copy_count": 0,
                "buffer_copy_bytes": 0,
                "eagain_retry_count": 2,
                "partial_send_retry_count": 1,
                "txring_flush_call_count": 7,
                "txring_flush_error_count": 0,
                "txring_flush_eagain_count": 0,
                "txring_tp_packets": 8,
                "txring_tp_drops": 0,
                "txring_tp_freeze_q_cnt": 0,
                "host_tx_packets_delta": 9,
                "host_tx_dropped_delta": 0,
                "host_tx_errors_delta": 1,
                "softnet_dropped_delta": 0,
                "softnet_time_squeeze_delta": 0,
                "wire_loss_est_packets": 0,
                "gpu_template_h2d_copy_count": 1,
                "gpu_template_h2d_copy_bytes": 1024,
                "gpu_rng_state_alloc_count": 1,
                "gpu_rng_state_reuse_count": 3,
                "stats": {
                    "attempted": 10,
                    "sent": 8,
                    "errors": 2,
                    "bytes_sent_est": 800,
                },
            },
        ]

        rr = reporting.build_live_attack_report(
            args={"target": "127.0.0.1"},
            worker_events=events,
            duration_s=2.0,
            progress_total=20,
            total_count=20,
            metrics={},
            warnings=[],
        )

        self.assertEqual(rr.mode, "live_attack")
        self.assertEqual(rr.results["buffer_copy_count"], 2)
        self.assertEqual(rr.results["buffer_copy_bytes"], 1024)
        self.assertEqual(rr.results["eagain_retry_count"], 5)
        self.assertEqual(rr.results["partial_send_retry_count"], 5)
        self.assertEqual(rr.results["txring_flush_call_count"], 18)
        self.assertEqual(rr.results["txring_flush_error_count"], 1)
        self.assertEqual(rr.results["txring_tp_packets"], 17)
        self.assertEqual(rr.results["txring_tp_drops"], 1)
        self.assertEqual(rr.results["host_tx_packets_delta"], 19)
        self.assertEqual(rr.results["host_tx_dropped_delta"], 1)
        self.assertEqual(rr.results["softnet_dropped_delta"], 2)
        self.assertEqual(rr.results["wire_loss_est_packets"], 1)
        self.assertEqual(rr.results["wire_loss_status"], "warn")
        self.assertEqual(rr.results["gpu_template_h2d_copy_count"], 4)
        self.assertEqual(rr.results["gpu_rng_state_alloc_count"], 2)

    def test_live_attack_report_caps_wire_loss_pct_and_preserves_raw(self):
        from ddos_samurai import reporting

        events = [
            {
                "status": "ok",
                "attack_vector": "basic",
                "compute_backend": "cuda",
                "sender_path": "TX_RING_L2",
                "txring_tp_packets": 410,
                "txring_tp_drops": 400,
                "host_tx_dropped_delta": 0,
                "wire_loss_est_packets": 400,
                "stats": {
                    "attempted": 100,
                    "sent": 100,
                    "errors": 0,
                    "bytes_sent_est": 6400,
                },
            }
        ]

        rr = reporting.build_live_attack_report(
            args={"target": "127.0.0.1"},
            worker_events=events,
            duration_s=1.0,
            progress_total=100,
            total_count=100,
            metrics={},
            warnings=[],
        )

        self.assertEqual(rr.results["wire_loss_est_packets"], 100)
        self.assertEqual(rr.results["wire_loss_est_pct"], 100.0)
        self.assertEqual(rr.results["wire_loss_raw_packets"], 400)
        self.assertEqual(rr.results["wire_loss_estimation_capped"], 1)
