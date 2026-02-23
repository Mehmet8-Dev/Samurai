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
