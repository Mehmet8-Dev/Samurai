import os
import tempfile
import unittest
from pathlib import Path

from ddos_samurai.scenario_engine import load_scenario_spec, run_compile_benchmark, write_compile_benchmark_report


class TestScenarioEngine1MReport(unittest.TestCase):
    def test_generate_official_1m_report_when_enabled(self):
        if str(os.getenv("SAMURAI_RUN_SCENARIO_1M_REPORT", "0")).strip() != "1":
            self.skipTest("set SAMURAI_RUN_SCENARIO_1M_REPORT=1 to run official 1M report")
        spec = load_scenario_spec("docs/scenario_web_mobile.yaml")
        workers = int(os.getenv("SAMURAI_SCENARIO_1M_WORKERS", "16"))
        report = run_compile_benchmark(spec, scales=[10_000, 100_000, 300_000, 1_000_000], workers=workers, seed=1337)
        with tempfile.TemporaryDirectory() as td:
            out = write_compile_benchmark_report(report, Path(td) / "scenario_1m_benchmark_report.json")
            self.assertTrue(Path(out).exists())
        self.assertEqual(str(report.get("schema", "")), "samurai.scenario.benchmark.v1")
        self.assertEqual(len(list(report.get("rows", []) or [])), 4)

