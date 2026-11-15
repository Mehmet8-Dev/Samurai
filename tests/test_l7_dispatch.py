"""Faz 0: JobEnvelopeV2 / L7 dispatch contract selftest."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import pytest


@pytest.mark.ci_safe
class TestL7Dispatch(unittest.TestCase):
    def test_job_envelope_v2_selftest(self) -> None:
        compiler = shutil.which("c++") or shutil.which("g++")
        if not compiler:
            self.skipTest("No C++ compiler available")

        repo = Path(__file__).resolve().parents[1]
        build_dir = Path(tempfile.mkdtemp(prefix="l7_dispatch_"))
        binary = build_dir / "l7_dispatch_selftest"
        cmd = [
            compiler,
            "-std=c++17",
            "-O2",
            "-I",
            str(repo / "samurai" / "zmq" / "daemon"),
            "-I",
            str(repo / "samurai" / "orchestrator"),
            str(repo / "samurai" / "zmq" / "daemon" / "l7_dispatch_selftest.cpp"),
            "-o",
            str(binary),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            self.fail(f"compile failed:\n{proc.stdout}\n{proc.stderr}")
        run = subprocess.run([str(binary)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, msg=run.stderr)
        self.assertIn("l7_dispatch selftest ok", run.stdout)


if __name__ == "__main__":
    unittest.main()
