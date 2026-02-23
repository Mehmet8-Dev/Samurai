import os
import tempfile
import unittest


class TestCliDryRunReporting(unittest.TestCase):
    def test_dry_run_writes_report_and_metrics(self):
        # Dry-run must be usable without root and must not trigger orchestrator/root checks.
        from ddos_samurai import cli
        from ddos_samurai import metrics

        metrics.reset_global_metrics()
        with tempfile.TemporaryDirectory() as td:
            out_base = os.path.join(td, "dryrun_unit")
            argv = [
                "--dry-run",
                "--target",
                "192.168.1.1",
                "--port",
                "80",
                "--protocol",
                "tcp",
                "--attack-vector",
                "basic",
                "--run-report",
                "--run-report-format",
                "json",
                "--run-report-dir",
                td,
                "--run-report-out",
                "dryrun_unit",
            ]
            with self.assertRaises(SystemExit) as cm:
                cli.main(argv)
            self.assertEqual(cm.exception.code, 0)

            self.assertTrue(os.path.exists(out_base + ".json"))
            self.assertTrue(os.path.exists(out_base + ".metrics.json"))
            self.assertTrue(os.path.exists(out_base + ".metrics.prom"))

