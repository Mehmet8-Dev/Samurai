import subprocess
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


class TestRfcSuiteEngine(unittest.TestCase):
    def test_samurai_cli_rfc_suite_run(self):
        cli_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../build/cli/samurai"))
        if os.path.exists(cli_path):
            with tempfile.TemporaryDirectory() as td:
                html_out = os.path.join(td, "benchmark_report.html")
                cmd = [cli_path, "--run-rfc-suite", "all", "--rfc-report-out", html_out]
                res = subprocess.run(cmd, capture_output=True, text=True)
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertIn("Samurai Executive RFC Benchmark Report", res.stdout)
                self.assertIn("RFC 2544 Maximum Zero-Loss Throughput", res.stdout)

                # Verify HTML Report file generation
                self.assertTrue(os.path.exists(html_out))
                with open(html_out, "r", encoding="utf-8") as f:
                    content = f.read()
                    self.assertIn("<title>Samurai RFC 2544 / 3511 / 8219 Benchmark Report</title>", content)
                    self.assertIn("PASSED (100%)", content)


if __name__ == "__main__":
    unittest.main()
