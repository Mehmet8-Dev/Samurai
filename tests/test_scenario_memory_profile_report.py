from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ddos_samurai.scenario_engine import (
    load_scenario_spec,
    run_compile_benchmark,
    write_memory_profile_report,
)


class TestScenarioMemoryProfileReport(unittest.TestCase):
    def test_write_memory_profile_report(self):
        spec = load_scenario_spec("docs/scenario_web_mobile.yaml")
        report = run_compile_benchmark(spec, scales=[100], workers=2, seed=1337)
        with tempfile.TemporaryDirectory() as td:
            out = write_memory_profile_report(report, Path(td) / "scenario_memory_profile.md")
            p = Path(out)
            self.assertTrue(p.exists())
            text = p.read_text(encoding="utf-8")
            self.assertIn("Scenario Compile Memory Profile", text)
            self.assertIn("Per-Session Peak (bytes)", text)

