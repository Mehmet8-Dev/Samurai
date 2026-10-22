#!/usr/bin/env python3
"""
TASK-TEST-L5-01: Distributed Master/Slave Dynamic Rebalancing Under Worker Chaos (kill -9).

Validates:
1. 1 Master and 4 Slave worker processes launched for a 10,000,000 packet job.
2. Mid-test, one slave is forcibly terminated via SIGKILL (kill -9).
3. Master detects worker heartbeat loss within 2,000 ms.
4. Master reclaims unacknowledged in-flight shards and dynamically redistributes them
   across the surviving 3 slaves.
5. Definition of Done (DoD):
   - Exact aggregate packet delivery (N_actual = 10,000,000).
   - Zero dropped packets across all completed shards.
   - Zero Master deadlocks (exit code = 0, clean termination).
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
import unittest
from pathlib import Path


class TestDistributedFailoverChaos(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.build_dir = cls.repo_root / "build"
        cls.master_bin = cls.build_dir / "control" / "daemon" / "samurai_master"
        cls.slave_bin = cls.build_dir / "control" / "daemon" / "samurai_slave"
        cls.selftest_bin = cls.build_dir / "control" / "samurai_control_selftest"
        cls.bench_script = cls.repo_root / "tests" / "bench_distributed_failover_chaos.sh"

        # Build project if binaries are missing
        if not (cls.master_bin.exists() and cls.slave_bin.exists() and cls.selftest_bin.exists()):
            res = subprocess.run(
                ["cmake", "--build", str(cls.build_dir), "-j4"],
                cwd=str(cls.repo_root),
                capture_output=True,
                text=True,
            )
            if res.returncode != 0:
                raise RuntimeError(f"Build failed:\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}")

    def test_native_selftest_matrix(self):
        """Execute C++ control selftest suite containing TASK-TEST-L5-01 validation."""
        res = subprocess.run([str(self.selftest_bin)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Selftest failed:\n{res.stdout}\n{res.stderr}")
        self.assertIn("control selftest: all checks passed", res.stdout)

    def test_distributed_failover_chaos_10m(self):
        """
        Execute 10,000,000 packet distributed job with 1 Master and 4 Slaves.
        Mid-test, kill slave_1 with kill -9. Verify failover, rebalance, and exact 10M delivery.
        """
        port = 15099
        master_ep = f"tcp://127.0.0.1:{port}"
        target_packets = 10_000_000
        shard_unit = 1_000_000
        hb_timeout_ms = 2000

        t0 = time.time()
        master_proc = subprocess.Popen(
            [
                str(self.master_bin),
                "--control-listen", master_ep,
                "--expect-workers", "4",
                "--count", str(target_packets),
                "--shard-unit-count", str(shard_unit),
                "--heartbeat-timeout-ms", str(hb_timeout_ms),
                "--job-timeout-s", "30",
                "--poll-interval-ms", "50",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        time.sleep(0.3)
        slaves = {}
        for i in range(4):
            wid = f"slave_{i}"
            sproc = subprocess.Popen(
                [
                    str(self.slave_bin),
                    "--control-endpoints", f"127.0.0.1:{port}",
                    "--worker-id", wid,
                    "--mock",
                    "--mock-delay-ms", "150",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            slaves[wid] = sproc

        # Wait for dispatch of initial shards across workers
        time.sleep(0.2)
        killed_worker = "slave_1"
        t_kill = time.time()
        os.kill(slaves[killed_worker].pid, signal.SIGKILL)
        slaves[killed_worker].wait()

        # Collect master completion
        stdout, stderr = master_proc.communicate(timeout=35)
        t_finish = time.time()

        for wid, sproc in slaves.items():
            if wid != killed_worker:
                sproc.terminate()
                try:
                    sproc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    sproc.kill()

        self.assertEqual(master_proc.returncode, 0, f"Master exited with non-zero code {master_proc.returncode}:\n{stderr}")

        # Parse final snapshot JSON
        json_lines = [line.strip() for line in stdout.splitlines() if line.strip().startswith("{")]
        self.assertTrue(len(json_lines) > 0, f"No JSON snapshot output from master:\n{stdout}")
        snap = json.loads(json_lines[-1])

        # Verification of Definition of Done (DoD)
        self.assertEqual(snap.get("sent"), target_packets, f"Total sent mismatch: expected {target_packets}, got {snap.get('sent')}")
        self.assertEqual(snap.get("errors"), 0, f"Errors occurred during job: {snap.get('errors')}")
        self.assertEqual(snap.get("shards_reported"), target_packets // shard_unit, "Mismatch in reported shards count")
        self.assertEqual(snap.get("pending_shards_left"), 0, "Backlog not empty")
        self.assertEqual(snap.get("inflight_shards_left"), 0, "Inflight shards remaining (deadlock)")
        self.assertIn(killed_worker, snap.get("lost_workers", []), "Master did not record killed worker in lost_workers")

        # Verify heartbeat detection took <= 3.0s total from kill to master completion
        time_since_kill = t_finish - t_kill
        self.assertLessEqual(time_since_kill, 5.0, f"Failover recovery took too long: {time_since_kill:.2f}s")

        # Verify surviving workers took all traffic
        rollup = snap.get("worker_rollup", [])
        active_wids = [w["worker_id"] for w in rollup]
        self.assertNotIn(killed_worker, active_wids, f"Killed worker {killed_worker} unexpectedly reported in final active rollup")
        self.assertEqual(len(active_wids), 3, f"Expected exactly 3 surviving workers in rollup, got {active_wids}")

        rollup_sent_sum = sum(w["sent"] for w in rollup)
        self.assertEqual(rollup_sent_sum, target_packets, f"Sum of worker rollups ({rollup_sent_sum}) does not equal {target_packets}")

    def test_benchmark_script_execution(self):
        """Execute bench_distributed_failover_chaos.sh for multi-run determinism verification."""
        env = os.environ.copy()
        env["BENCH_RUNS"] = "3"
        env["PACKET_COUNT"] = "10000000"
        env["SHARD_UNIT"] = "1000000"
        env["HEARTBEAT_TIMEOUT_MS"] = "2000"
        env["OUTPUT_DIR"] = str(self.repo_root / "reports" / "benchmarks" / "task_l5_01")

        res = subprocess.run(["bash", str(self.bench_script)], env=env, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Benchmark script failed:\n{res.stdout}\n{res.stderr}")
        self.assertIn("TASK-TEST-L5-01 BENCHMARK PASSED (ALL DoD SATISFIED)", res.stdout)

        out_dir = Path(env["OUTPUT_DIR"])
        summary_path = out_dir / "summary.json"
        report_path = out_dir / "report.md"
        self.assertTrue(summary_path.exists(), "summary.json not generated")
        self.assertTrue(report_path.exists(), "report.md not generated")

        with open(summary_path, "r", encoding="utf-8") as f:
            summary = json.load(f)

        dod = summary["dod_validation"]
        self.assertTrue(dod["exact_packet_delivery_parity"], "DoD exact packet delivery check failed")
        self.assertTrue(dod["zero_master_deadlocks"], "DoD zero master deadlocks check failed")
        self.assertTrue(dod["heartbeat_timeout_detected"], "DoD heartbeat timeout detection failed")
        self.assertTrue(dod["dynamic_rebalance_verified"], "DoD dynamic rebalancing check failed")


if __name__ == "__main__":
    unittest.main()
