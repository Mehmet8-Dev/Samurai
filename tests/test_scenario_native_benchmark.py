import os
import time
import unittest

from ddos_samurai.scenario_engine import load_scenario_spec, build_worker_session_plans
from ddos_samurai.scenario_engine.compiler import scenario_spec_from_dict, scenario_spec_to_dict


class TestScenarioNativeBenchmark(unittest.TestCase):
    def test_benchmark_large_vu_smoke(self):
        if str(os.getenv("SAMURAI_RUN_SCENARIO_BENCH", "0")).strip() != "1":
            self.skipTest("set SAMURAI_RUN_SCENARIO_BENCH=1 to run benchmark smoke")
        spec = load_scenario_spec("docs/scenario_web_mobile.yaml")
        raw = scenario_spec_to_dict(spec)
        raw["load_model"]["concurrent_vus"] = int(os.getenv("SAMURAI_BENCH_VUS", "100000"))
        bench_spec = scenario_spec_from_dict(raw)
        workers = max(1, int(os.getenv("SAMURAI_BENCH_WORKERS", "16")))
        per = raw["load_model"]["concurrent_vus"] // workers
        rem = raw["load_model"]["concurrent_vus"] % workers
        worker_counts = [per] * workers
        for i in range(rem):
            worker_counts[i] += 1
        t0 = time.perf_counter()
        plans, metrics = build_worker_session_plans(bench_spec, worker_counts, 1337)
        elapsed = time.perf_counter() - t0
        self.assertEqual(len(plans), workers)
        self.assertTrue(all(len(x) == 1 for x in plans))
        self.assertEqual(int(metrics.get("sessions_started", 0)), int(raw["load_model"]["concurrent_vus"]))
        self.assertGreaterEqual(float(elapsed), 0.0)
        self.assertIn("sessions_started", metrics)
