#!/usr/bin/env python3
"""
TASK-TEST-L2-02: RFC 6675 SACK Loss Recovery Verification and Stress Benchmark.

Validates:
1. RFC 6675 loss identification (IsLostSeg):
   - DupThresh packet threshold and (DupThresh - 1) * SMSS byte threshold.
2. Scoreboard pipe estimation (ComputePipe):
   - Segments in flight, excluding SACKed and lost holes, tracking retransmitted octets.
3. Loss recovery under 10% synthetic packet loss:
   - 50 MB data stream delivered byte-for-byte exact without corruption.
   - Spurious retransmission rate <= 2.0%.
   - Selective retransmission without head-of-line collapse.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path


class TestTcpSlidingWindowLossRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.build_dir = cls.repo_root / "build"
        cls.binary_path = cls.build_dir / "l4" / "test_tcp_sliding_window"

        # Build native binary if not yet built or stale
        cmake_bin = shutil.which("cmake")
        if not cmake_bin:
            raise unittest.SkipTest("cmake not found on system")

        cls.build_dir.mkdir(parents=True, exist_ok=True)
        cmake_src = cls.repo_root / "samurai"
        config_cmd = [cmake_bin, "-B", str(cls.build_dir), "-S", str(cmake_src)]
        subprocess.run(config_cmd, check=True, capture_output=True, text=True)

        build_cmd = [cmake_bin, "--build", str(cls.build_dir), "--target", "test_tcp_sliding_window", "-j4"]
        res = subprocess.run(build_cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"CMake build failed:\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}")

        if not cls.binary_path.exists():
            raise FileNotFoundError(f"Binary not found after build: {cls.binary_path}")

    def run_cpp_test(self, stream_mb: int = 50) -> tuple[int, str, dict[str, float]]:
        cmd = [str(self.binary_path), "--stream-mb", str(stream_mb)]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        output = proc.stdout + proc.stderr

        metrics: dict[str, float] = {}

        stream_match = re.search(r"Stream Size:\s+(\d+)\s+MB", output)
        if stream_match:
            metrics["stream_mb"] = float(stream_match.group(1))

        duration_match = re.search(r"Duration \(T\):\s+([\d\.]+)\s+s", output)
        if duration_match:
            metrics["duration_sec"] = float(duration_match.group(1))

        tput_match = re.search(r"Throughput:\s+([\d\.]+)\s+MB/s\s+\(([\d\.]+)\s+PPS\)", output)
        if tput_match:
            metrics["throughput_mb_s"] = float(tput_match.group(1))
            metrics["pps"] = float(tput_match.group(2))

        pkts_sent_match = re.search(r"Packets Sent \(N_sent\):\s+(\d+)", output)
        if pkts_sent_match:
            metrics["packets_sent"] = float(pkts_sent_match.group(1))

        pkts_dropped_match = re.search(r"Packets Dropped:\s+(\d+)\s+\(Drop Rate:\s+([\d\.]+)%\)", output)
        if pkts_dropped_match:
            metrics["packets_dropped"] = float(pkts_dropped_match.group(1))
            metrics["drop_rate_pct"] = float(pkts_dropped_match.group(2))

        total_rtx_match = re.search(r"Total Retransmissions:\s+(\d+)", output)
        if total_rtx_match:
            metrics["total_retransmissions"] = float(total_rtx_match.group(1))

        spurious_match = re.search(r"Spurious Retransmits:\s+(\d+)\s+\(Spurious Rate:\s+([\d\.]+)%\)", output)
        if spurious_match:
            metrics["spurious_retransmits"] = float(spurious_match.group(1))
            metrics["spurious_rate_pct"] = float(spurious_match.group(2))

        corruption_match = re.search(r"Data Corruption:\s+(\d+)\s+bytes", output)
        if corruption_match:
            metrics["data_corruption_bytes"] = float(corruption_match.group(1))

        return proc.returncode, output, metrics

    def test_rfc6675_loss_recovery_unit_invariants(self) -> None:
        """Runs the native unit test suite (Tests A-P) verifying RFC 6675 invariants."""
        # 1 MB stream executes all unit tests A through P as well as Test Q (1MB).
        retcode, output, metrics = self.run_cpp_test(stream_mb=1)
        self.assertEqual(retcode, 0, f"Native test failed:\n{output}")
        self.assertIn("ALL TCP SLIDING-WINDOW TESTS PASSED", output)
        self.assertEqual(metrics.get("data_corruption_bytes"), 0.0)
        self.assertLessEqual(metrics.get("spurious_rate_pct", 100.0), 2.0)

    def test_rfc6675_sack_loss_recovery_50mb_benchmark(self) -> None:
        """TASK-TEST-L2-02 DoD: 50 MB stream under 10% loss with spurious rate <= 2.0% and 0 corruption."""
        retcode, output, metrics = self.run_cpp_test(stream_mb=50)
        self.assertEqual(retcode, 0, f"50 MB stress run failed with output:\n{output}")
        self.assertIn("ALL TCP SLIDING-WINDOW TESTS PASSED", output)

        # DoD verifications
        self.assertIn("stream_mb", metrics)
        self.assertEqual(metrics["stream_mb"], 50.0)

        # 1. Zero data corruption
        self.assertIn("data_corruption_bytes", metrics)
        self.assertEqual(
            metrics["data_corruption_bytes"],
            0.0,
            f"Expected 0 corruption, found {metrics['data_corruption_bytes']} bytes corrupt",
        )

        # 2. Spurious retransmission rate <= 2.0%
        self.assertIn("spurious_rate_pct", metrics)
        spurious_rate = metrics["spurious_rate_pct"]
        self.assertLessEqual(
            spurious_rate,
            2.0,
            f"Spurious retransmission rate {spurious_rate:.2f}% exceeds 2.0% threshold",
        )

        # 3. Drop rate within expected 10% netem envelope (8.0% - 12.0%)
        self.assertIn("drop_rate_pct", metrics)
        drop_rate = metrics["drop_rate_pct"]
        self.assertGreaterEqual(drop_rate, 8.0, f"Drop rate {drop_rate:.2f}% unexpectedly low")
        self.assertLessEqual(drop_rate, 12.0, f"Drop rate {drop_rate:.2f}% unexpectedly high")

        # 4. Dimension & mathematical consistency checks (DoD rule)
        # N_sent > 0, T > 0, PPS == N_sent / T
        n_sent = metrics["packets_sent"]
        duration = metrics["duration_sec"]
        pps = metrics["pps"]
        self.assertGreater(n_sent, 0)
        self.assertGreater(duration, 0.0)
        self.assertAlmostEqual(pps, n_sent / duration, delta=500.0)

        print("\n" + "=" * 70)
        print("TASK-TEST-L2-02: RFC 6675 SACK LOSS RECOVERY VERIFICATION SUMMARY")
        print(f"  Stream Size:         {metrics['stream_mb']:.0f} MB")
        print(f"  Duration (T):        {duration:.4f} s")
        print(f"  Packets Sent:        {n_sent:.0f}")
        print(f"  Packets Dropped:     {metrics['packets_dropped']:.0f} ({drop_rate:.2f}%)")
        print(f"  Retransmissions:     {metrics['total_retransmissions']:.0f}")
        print(f"  Spurious Retransmits:{metrics['spurious_retransmits']:.0f} ({spurious_rate:.2f}%)")
        print(f"  Throughput:          {metrics['throughput_mb_s']:.2f} MB/s ({pps:.1f} PPS)")
        print(f"  Data Corruption:     {metrics['data_corruption_bytes']:.0f} bytes")
        print("  Definition of Done:  PASSED")
        print("=" * 70)


if __name__ == "__main__":
    unittest.main()
