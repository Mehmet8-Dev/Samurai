import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path("tests/test_rfc_gate_ci.py")


class TestRfcGateScript(unittest.TestCase):
    def _run(self, report: dict, *extra: str) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "rfc_negative_report.json"
            p.write_text(json.dumps(report), encoding="utf-8")
            cmd = [sys.executable, str(SCRIPT), "--report", str(p), *extra]
            return subprocess.run(cmd, text=True, capture_output=True, check=False)

    def test_passes_on_perfect_report(self):
        cp = self._run(
            {
                "score": 100.0,
                "passed": 5,
                "total": 5,
                "checks": [
                    {"name": "checksum_invalid_detected", "passed": True},
                    {"name": "tcp_data_offset_invalid_detected", "passed": True},
                    {"name": "total_length_mismatch_detected", "passed": True},
                    {"name": "ttl_zero_detected", "passed": True},
                    {"name": "udp_length_mismatch_detected", "passed": True},
                ],
            }
        )
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn("[RFC-GATE] PASS", cp.stdout)

    def test_fails_on_missing_critical_check(self):
        cp = self._run(
            {
                "score": 100.0,
                "passed": 4,
                "total": 4,
                "checks": [
                    {"name": "checksum_invalid_detected", "passed": True},
                ],
            }
        )
        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("[RFC-GATE] FAIL", cp.stdout)


if __name__ == "__main__":
    unittest.main()
