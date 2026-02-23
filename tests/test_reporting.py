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
