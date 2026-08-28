from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class TestCpuNativeCppSelftest(unittest.TestCase):
    def test_cpp_selftest_binary(self):
        compiler = shutil.which("c++") or shutil.which("g++")
        if not compiler:
            self.skipTest("No C++ compiler available")

        repo = Path(__file__).resolve().parents[1]
        build_dir = Path(tempfile.mkdtemp(prefix="cpu_native_cpp_"))
        binary = build_dir / "cpu_native_selftest"
        cmd = [
            compiler,
            "-std=c++20",
            "-O2",
            "-I",
            str(repo / "ddos_samurai" / "cpu_native"),
            str(repo / "ddos_samurai" / "cpu_native" / "native_selftest.cpp"),
            # engine.cpp refactor sonrası tek amalgamation TU'dur; spoofing/
            # packets/pool/amp tanımlarını da içerir, ayrı derlenmemelidir.
            str(repo / "ddos_samurai" / "cpu_native" / "engine.cpp"),
            "-o",
            str(binary),
        ]
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        proc = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
        self.assertIn("selftest ok", proc.stdout)
