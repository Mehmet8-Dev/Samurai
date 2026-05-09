import json
import tempfile
import unittest
from pathlib import Path

from ddos_samurai.scenario_engine import (
    RampController,
    build_vu_lifecycle_batches,
    load_raw_scenario,
    run_compile_benchmark,
    write_compile_benchmark_report,
)
from ddos_samurai.scenario_engine import native as scenario_native


_BASE_YAML = """\
schema_version: 2
personas:
  web_user:
    device_profile: web
    headers: {User-Agent: UA}
    cookies: {}
    retry_policy: {max_retries: 1}
    timeout_policy: {request_timeout_ms: 4000, session_timeout_ms: 1500}
flows:
  browse:
    persona: web_user
    steps:
      - {type: request, method: GET, path: /, body_template: '{"x":1}', on_failure: retry}
      - {type: pause, think_time: {distribution: uniform, min_ms: 10, max_ms: 20}}
      - {type: request, method: GET, path: /x, on_failure: skip}
      - {type: end_session}
load_model:
  concurrent_vus: 100
  ramp_seconds: 10
  max_session_seconds: 30
  backend: http2
sla:
  min_completion_rate: 0.9
  max_step_fail_ratio: 0.1
"""


class TestScenarioEngineUpgrade(unittest.TestCase):
    def _load_spec(self) -> dict:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "spec.yaml"
            p.write_text(_BASE_YAML, encoding="utf-8")
            return load_raw_scenario(str(p))

    def test_compile_session_plan_is_packed(self):
        try:
            scenario_native.require_native()
        except RuntimeError:
            self.skipTest("scenario native unavailable")
        spec = self._load_spec()
        out = scenario_native.compile_session_plan(spec, "browse", 5)
        self.assertTrue(bool(out.get("packed", False)))
        self.assertIn("event_kind", out)
        self.assertNotIn("events", out)
        self.assertIn("body_template", out)
        self.assertIn("session_timeout_ms", out)

    def test_compile_session_plan_bulk_is_packed(self):
        try:
            scenario_native.require_native()
        except RuntimeError:
            self.skipTest("scenario native unavailable")
        spec = self._load_spec()
        rows = scenario_native.compile_session_plans_packed_bulk(
            spec,
            ["browse", "browse", "browse"],
            [11, 12, 13],
        )
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(bool(dict(r).get("packed", False)) for r in rows))
        self.assertTrue(all("event_kind" in dict(r) for r in rows))

    def test_compile_session_plan_bulk_raises_on_unknown_flow(self):
        try:
            scenario_native.require_native()
        except RuntimeError:
            self.skipTest("scenario native unavailable")
        spec = self._load_spec()
        with self.assertRaises(RuntimeError):
            _ = scenario_native.compile_session_plans_packed_bulk(spec, ["browse", "missing_flow"], [11, 12])

    def test_compile_session_plan_bulk_soa_shape(self):
        try:
            scenario_native.require_native()
        except RuntimeError:
            self.skipTest("scenario native unavailable")
        spec = self._load_spec()
        out = scenario_native.compile_session_plans_packed_bulk_soa(
            spec,
            ["browse", "browse", "browse"],
            [101, 102, 103],
        )
        self.assertTrue(bool(out.get("packed_soa", False)))
        offs = list(out.get("session_offsets", []) or [])
        self.assertEqual(len(offs), 4)
        self.assertGreaterEqual(int(offs[-1]), int(offs[0]))
        self.assertIn("event_kind", out)

    def test_compile_session_plan_bulk_soa_raises_on_unknown_flow(self):
        try:
            scenario_native.require_native()
        except RuntimeError:
            self.skipTest("scenario native unavailable")
        spec = self._load_spec()
        with self.assertRaises(RuntimeError):
            _ = scenario_native.compile_session_plans_packed_bulk_soa(spec, ["missing_flow"], [101])

    def test_ramp_should_spawn_linear(self):
        rc = RampController(target_vus=100, ramp_seconds=10, curve="linear")
        self.assertEqual(rc.should_spawn(0.0, 0), 0)
        self.assertGreaterEqual(rc.should_spawn(5.0, 30), 15)

    def test_ramp_should_spawn_step(self):
        rc = RampController(target_vus=100, ramp_seconds=10, curve="step", step_interval_s=2)
        self.assertEqual(rc.should_spawn(1.0, 0), 0)
        self.assertGreaterEqual(rc.should_spawn(2.0, 0), 15)

    def test_ramp_custom_dedup_points(self):
        rc = RampController(
            target_vus=100,
            ramp_seconds=10,
            curve="custom",
            custom_points=((0.0, 0), (3.0, 20), (3.0, 40), (10.0, 100)),
        )
        self.assertGreaterEqual(rc.active_vus_at(3.0), 39)

    def test_build_batches_custom_curve(self):
        sessions = [{"flow": "browse", "events": [{"event_type": "http_request", "method": "GET", "path": "/"}]} for _ in range(50)]
        batches, metrics = build_vu_lifecycle_batches(
            scenario_sessions=sessions,
            ramp_seconds=10,
            max_session_seconds=20,
            seed=7,
            ramp_curve="custom",
            ramp_custom_points=[(0.0, 0), (2.0, 20), (10.0, 50)],
        )
        self.assertTrue(len(batches) > 0)
        self.assertEqual(int(metrics.get("vus_spawned", 0)), 50)

    def test_compile_benchmark_report_schema(self):
        spec = self._load_spec()
        report = run_compile_benchmark(spec, scales=[100, 1000], workers=4, seed=1)
        self.assertEqual(str(report.get("schema", "")), "samurai.scenario.benchmark.v1")
        rows = list(report.get("rows", []) or [])
        self.assertEqual(len(rows), 2)
        self.assertIn("elapsed_s", rows[0])
        self.assertIn("peak_mem_bytes", rows[0])

    def test_compile_benchmark_report_write(self):
        spec = self._load_spec()
        report = run_compile_benchmark(spec, scales=[100], workers=2, seed=1)
        with tempfile.TemporaryDirectory() as td:
            out = write_compile_benchmark_report(report, Path(td) / "scenario_bench.json")
            payload = json.loads(Path(out).read_text(encoding="utf-8"))
        self.assertEqual(payload.get("schema"), "samurai.scenario.benchmark.v1")
        self.assertEqual(int(payload["rows"][0]["vus"]), 100)

    def test_fuzz_like_randomized_compile_smoke(self):
        try:
            scenario_native.require_native()
        except RuntimeError:
            self.skipTest("scenario native unavailable")
        base = self._load_spec()
        for i in range(16):
            raw = dict(base)
            lm = dict(raw.get("load_model") or {})
            lm["concurrent_vus"] = 50 + (i * 10)
            lm["ramp_seconds"] = i % 7
            raw["load_model"] = lm
            out = scenario_native.compile_session_plan_packed(raw, "browse", 1337 + i)
            self.assertTrue(bool(out.get("packed", False)))
            self.assertGreaterEqual(len(list(out.get("event_kind", []) or [])), 1)
