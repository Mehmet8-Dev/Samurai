#!/usr/bin/env python3
"""
TASK-TEST-L3-02: HTTP/2 kTLS Socket-BIO vs OpenSSL Memory-BIO CPU Overhead Stress Test.

Validates:
1. Exactly 1 TLS connection established (concurrency = 1).
2. 100 concurrent multiplexed HTTP/2 streams active (active_streams_peak >= 100).
3. Zero HTTP/2 protocol errors / zero GOAWAY frames (goaway_count = 0, errors = 0).
4. 100% request completion with HTTP 200 responses across both kTLS and Memory-BIO engines.
5. Regression test suite passes 100% (run_kernel_threaded_h2_e2e.sh matrix 6/6).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path


class TestH2KtlsVsMemoryBio(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.build_dir = cls.repo_root / "build"
        cls.binary_path = cls.build_dir / "l7_emu_native" / "test_kernel_threaded_h2"
        cls.bench_script = cls.repo_root / "tests" / "bench_h2_ktls_vs_memory_bio.sh"
        cls.e2e_script = cls.repo_root / "ddos_samurai" / "l7_emu_native" / "run_kernel_threaded_h2_e2e.sh"

        cmake_bin = shutil.which("cmake")
        if not cmake_bin:
            raise unittest.SkipTest("cmake not found on system")

        cls.build_dir.mkdir(parents=True, exist_ok=True)
        cmake_src = cls.repo_root / "ddos_samurai"
        subprocess.run([cmake_bin, "-B", str(cls.build_dir), "-S", str(cmake_src)], check=True, capture_output=True, text=True)
        res = subprocess.run([cmake_bin, "--build", str(cls.build_dir), "--target", "test_kernel_threaded_h2", "-j4"], capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"CMake build failed:\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}")

        if not cls.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {cls.binary_path}")

    def test_h2_e2e_matrix(self):
        """Execute default integration regression test suite (6/6 matrix)."""
        env = os.environ.copy()
        env["H2_TEST_BIN"] = str(self.binary_path)
        res = subprocess.run(["bash", str(self.e2e_script)], env=env, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"H2 E2E matrix failed:\n{res.stdout}\n{res.stderr}")
        self.assertIn("H2 E2E MATRIX PASSED (6/6)", res.stdout)

    def test_benchmark_script_execution(self):
        """Execute bench_h2_ktls_vs_memory_bio.sh with 1,000 requests for fast CI validation."""
        env = os.environ.copy()
        env["REQUESTS"] = "1000"
        env["CONCURRENCY"] = "1"
        env["STREAMS"] = "100"
        env["BENCH_RUNS"] = "2"
        env["WARMUP_REQUESTS"] = "200"
        env["OUTPUT_DIR"] = str(self.repo_root / "reports" / "benchmarks" / "task_l3_02_ci")

        res = subprocess.run(["bash", str(self.bench_script)], env=env, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Benchmark script failed:\n{res.stdout}\n{res.stderr}")
        self.assertIn("Definition of Done (DoD) ALL CRITERIA SATISFIED!", res.stdout)

        out_dir = Path(env["OUTPUT_DIR"])
        summary_path = out_dir / "summary.json"
        self.assertTrue(summary_path.exists(), "summary.json not generated")

        with open(summary_path, "r", encoding="utf-8") as f:
            summary = json.load(f)

        dod = summary["dod_validation"]
        self.assertTrue(dod["zero_protocol_errors"], "Zero protocol errors check failed")
        self.assertTrue(dod["single_connection_verified"], "Single connection check failed")
        self.assertTrue(dod["streams_concurrency_verified"], "100 streams concurrency check failed")
        self.assertTrue(dod["status_200_parity"], "100% 200 OK parity check failed")


if __name__ == "__main__":
    unittest.main()
