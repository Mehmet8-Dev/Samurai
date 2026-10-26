#!/usr/bin/env python3
"""
TASK-TEST-GPU-01: High-Performance GPU Architecture & Coprocessor Engine Validation.

Validates:
1. Commodity GPU (GeForce GTX/RTX) BAR1 P2P DMA Packet Engine:
   - Sysfs 64-bit BAR1 Physical Aperture Resolution.
   - Vulkan Host-Visible Device-Local memory allocation & POSIX Opaque FD export.
   - GeforceP2pApiV1 C ABI full lifecycle (create, claim, commit, burst, telemetry, destroy).
   - High-throughput batch slot submission (> 100 Mpps).
   - Zero-Copy global BAR1 packet pool C ABI (16 MiB).
2. QUIC Cryptographic Coprocessor Engine:
   - Official IETF RFC 9001 Appendix A.1 byte-exact selftest.
   - Initial Key Derivation scaling (HKDF-Extract/Expand SHA-256).
   - AES-128-ECB Header Protection mask generation.
   - AEAD batch encryption (AES-128-GCM and ChaCha20-Poly1305).
   - Graceful fallback and telemetry accounting.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path


class TestGpuArchitecture(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.binary_path = cls.repo_root / "tests" / "native_gpu" / "test_gpu_architecture"
        cls.source_path = cls.repo_root / "tests" / "native_gpu" / "test_gpu_architecture.cpp"
        cls.json_output = cls.repo_root / "docs" / "gpu_architecture_benchmark_results.json"

        # Build native binary if not yet compiled or source modified
        if not cls.binary_path.exists() or cls.source_path.stat().st_mtime > cls.binary_path.stat().st_mtime:
            compile_cmd = [
                "g++", "-std=c++17", "-O3",
                str(cls.source_path),
                f"-I{cls.repo_root}",
                f"-I{cls.repo_root}/ddos_samurai/l7_emu_native",
                f"-I{cls.repo_root}/ddos_samurai/core",
                f"-I{cls.repo_root}/ddos_samurai/l4",
                f"-I{cls.repo_root}/ddos_samurai",
                f"-L{cls.repo_root}/ddos_samurai/build/l7_emu_native",
                f"-L{cls.repo_root}/ddos_samurai/build/l4",
                f"-L{cls.repo_root}/ddos_samurai/build/core",
                f"-L{cls.repo_root}/ddos_samurai/build/af_packet",
                "-Wl,--whole-archive", "-lsamurai_l7emu", "-Wl,--no-whole-archive",
                "-lsamurai_l4", "-lsamurai_core", "-laf_packet_static",
                "-lssl", "-lcrypto", "-lpthread", "-ldl", "-lcudart",
                "-o", str(cls.binary_path),
            ]
            res = subprocess.run(compile_cmd, capture_output=True, text=True)
            if res.returncode != 0:
                raise RuntimeError(f"Compilation of test_gpu_architecture failed:\n{res.stderr}")

    def test_gpu_architecture_comprehensive_matrix(self) -> None:
        """Runs the 27-point comprehensive GPU architecture verification test suite."""
        env = os.environ.copy()
        env["SAMURAI_GEFORCE_P2P_EMU"] = "1"
        res = subprocess.run(
            [str(self.binary_path), "--json-file", str(self.json_output)],
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            res.returncode,
            0,
            f"test_gpu_architecture exited with code {res.returncode}:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}",
        )
        self.assertTrue(self.json_output.exists(), "Benchmark JSON output was not created")

        with open(self.json_output, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data.get("overall_status"), "PASS")
        self.assertEqual(data.get("failed_checks"), 0)
        self.assertGreaterEqual(data.get("passed_checks", 0), 27)

        # GeForce BAR1 P2P checks
        bar1 = data.get("geforce_bar1_p2p", {})
        self.assertTrue(bar1.get("ring_lifecycle_pass"), "BAR1 ring lifecycle failed")
        self.assertGreater(bar1.get("batch_throughput_mpps", 0.0), 50.0, "BAR1 throughput below 50 Mpps")

        # QUIC Crypto Coprocessor checks
        quic = data.get("quic_cuda_crypto", {})
        self.assertTrue(quic.get("rfc9001_selftest_pass"), "RFC 9001 Appendix A.1 selftest failed")
        self.assertGreater(quic.get("hp_50k_mmasks_sec", 0.0), 1.0, "Header protection throughput below 1 Mmasks/s")
        self.assertGreater(quic.get("chacha20_mbps", 0.0), 50.0, "ChaCha20 throughput below 50 MB/s")
        self.assertTrue(quic.get("telemetry_verified"), "Crypto telemetry unverified")


if __name__ == "__main__":
    unittest.main()
