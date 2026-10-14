#!/usr/bin/env python3
"""
TASK-TEST-L3-01: Multi-Reactor io_uring vs epoll 100K Request Syscall & Latency Benchmark.

Validates:
1. io_uring reactor zero socket syscalls: rx_syscalls=0, tx_syscalls=0.
2. Complete epoll bypass: epoll_wakeups=0 under io_uring.
3. System call reduction and context switch reduction (>= 50%).
4. Throughput performance parity and gain (>= 20% under traced workload).
5. 100% request completion with HTTP 200 responses.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path


class TestIoUringVsEpollSyscalls(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.build_dir = cls.repo_root / "build"
        cls.binary_path = cls.build_dir / "l7_emu_native" / "test_kernel_threaded_io_uring"
        cls.bench_script = cls.repo_root / "tests" / "bench_iouring_vs_epoll_syscalls.sh"

        cmake_bin = shutil.which("cmake")
        if not cmake_bin:
            raise unittest.SkipTest("cmake not found on system")

        cls.build_dir.mkdir(parents=True, exist_ok=True)
        cmake_src = cls.repo_root / "ddos_samurai"
        subprocess.run([cmake_bin, "-B", str(cls.build_dir), "-S", str(cmake_src)], check=True, capture_output=True, text=True)
        res = subprocess.run([cmake_bin, "--build", str(cls.build_dir), "--target", "test_kernel_threaded_io_uring", "-j4"], capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"CMake build failed:\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}")

        if not cls.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {cls.binary_path}")

    def test_native_regression_suite(self):
        """Execute default integration test suite inside test_kernel_threaded_io_uring."""
        res = subprocess.run([str(self.binary_path)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Regression test failed:\n{res.stdout}\n{res.stderr}")
        if "SKIP: kernel io_uring capability not supported on this host" in res.stdout:
            raise unittest.SkipTest("Kernel io_uring not supported on this host")
        self.assertIn("ALL KERNEL THREADED IO_URING TESTS PASSED", res.stdout)

    def test_benchmark_script_execution(self):
        """Execute bench_iouring_vs_epoll_syscalls.sh with 10,000 requests for fast CI validation."""
        env = os.environ.copy()
        env["REQUESTS"] = "10000"
        env["CONCURRENCY"] = "32"
        env["PORT"] = "18099"
        env["BENCH_RUNS"] = "2"
        env["OUTPUT_DIR"] = str(self.repo_root / "reports" / "benchmarks" / "task_l3_01_ci")

        res = subprocess.run(["bash", str(self.bench_script)], env=env, capture_output=True, text=True)
        if res.returncode == 77 or "[SKIP]" in res.stdout:
            raise unittest.SkipTest("Kernel io_uring not supported on this host")
        self.assertEqual(res.returncode, 0, f"Benchmark script failed:\n{res.stdout}\n{res.stderr}")
        self.assertIn("Definition of Done (DoD) ALL CRITERIA SATISFIED!", res.stdout)

        # Check generated JSON outputs
        out_dir = Path(env["OUTPUT_DIR"])
        uring_json_path = out_dir / "res_iouring_native.json"
        epoll_json_path = out_dir / "res_epoll_native.json"
        self.assertTrue(uring_json_path.exists())
        self.assertTrue(epoll_json_path.exists())

        with open(uring_json_path, "r", encoding="utf-8") as f:
            uring_data = json.load(f)
        with open(epoll_json_path, "r", encoding="utf-8") as f:
            epoll_data = json.load(f)

        self.assertEqual(uring_data["rx_syscalls"], 0)
        self.assertEqual(uring_data["tx_syscalls"], 0)
        self.assertEqual(uring_data["epoll_wakeups"], 0)
        self.assertEqual(uring_data["status_2xx"], 10000)
        self.assertEqual(epoll_data["status_2xx"], 10000)


if __name__ == "__main__":
    unittest.main()
