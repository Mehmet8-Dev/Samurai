import asyncio
import random
import tempfile
import unittest
from pathlib import Path

from ddos_samurai.scenario_engine import (
    RampController,
    VUPool,
    build_vu_lifecycle_batches,
    collect_per_flow_metrics,
    deserialize_batches,
    load_raw_scenario,
    load_scenario_spec,
    run_compile_benchmark,
    serialize_batches,
)
from ddos_samurai.scenario_engine import native as scenario_native


_BASE_YAML = """\
schema_version: 2
personas:
  web_user:
    device_profile: web
    headers: {User-Agent: UA}
    cookies: {}
    retry_policy: {max_retries: 2}
    timeout_policy: {request_timeout_ms: 4000}
flows:
  browse:
    persona: web_user
    steps:
      - {type: request, method: GET, path: /, on_failure: retry}
      - {type: pause, think_time: {distribution: uniform, min_ms: 5, max_ms: 10}}
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


class TestScenarioEngineFuzzIntegration(unittest.TestCase):
    def _yaml_to_raw(self, text: str) -> dict:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "scenario.yaml"
            p.write_text(text, encoding="utf-8")
            return load_raw_scenario(str(p))

    def test_load_spec_dataclass(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "scenario.yaml"
            p.write_text(_BASE_YAML, encoding="utf-8")
            spec = load_scenario_spec(str(p))
        self.assertEqual(spec.load_model.backend, "http2")

    def test_schema_reject_invalid_on_failure(self):
        bad = _BASE_YAML.replace("on_failure: skip", "on_failure: nonsense")
        with self.assertRaises(ValueError):
            _ = self._yaml_to_raw(bad)

    def test_schema_reject_invalid_distribution(self):
        bad = _BASE_YAML.replace("distribution: uniform", "distribution: broken")
        with self.assertRaises(ValueError):
            _ = self._yaml_to_raw(bad)

    def test_ramp_linear_monotonic(self):
        rc = RampController(target_vus=100, ramp_seconds=10, curve="linear")
        vals = [rc.active_vus_at(x) for x in (0.0, 2.5, 5.0, 7.5, 10.0)]
        self.assertTrue(all(vals[i] <= vals[i + 1] for i in range(len(vals) - 1)))

    def test_ramp_step_monotonic(self):
        rc = RampController(target_vus=100, ramp_seconds=10, curve="step", step_interval_s=2)
        vals = [rc.active_vus_at(x) for x in (0.0, 1.9, 2.0, 4.0, 10.0)]
        self.assertTrue(all(vals[i] <= vals[i + 1] for i in range(len(vals) - 1)))

    def test_ramp_spike_frontload(self):
        rc = RampController(target_vus=100, ramp_seconds=10, curve="spike")
        self.assertGreaterEqual(rc.active_vus_at(2.0), 60)

    def test_ramp_custom_points_dedup(self):
        rc = RampController(
            target_vus=100,
            ramp_seconds=10,
            curve="custom",
            custom_points=((0.0, 0), (3.0, 20), (3.0, 40), (10.0, 100)),
        )
        self.assertGreaterEqual(rc.active_vus_at(3.0), 39)

    def test_ramp_should_spawn_never_negative(self):
        rc = RampController(target_vus=100, ramp_seconds=10, curve="linear")
        self.assertEqual(rc.should_spawn(5.0, 99), 0)

    def test_spawn_schedule_count(self):
        rc = RampController(target_vus=37, ramp_seconds=5, curve="linear")
        sched = rc.spawn_schedule()
        self.assertEqual(len(sched), 37)

    def test_build_batches_empty(self):
        batches, metrics = build_vu_lifecycle_batches(
            scenario_sessions=[],
            ramp_seconds=1,
            max_session_seconds=5,
            seed=1,
        )
        self.assertEqual(batches, [])
        self.assertEqual(int(metrics.get("vus_spawned", 0)), 0)

    def test_batches_roundtrip_serialize(self):
        sessions = [{"events": [{"event_type": "http_request", "method": "GET", "path": "/"}]}]
        batches, _ = build_vu_lifecycle_batches(
            scenario_sessions=sessions,
            ramp_seconds=0,
            max_session_seconds=5,
            seed=1,
        )
        payload = serialize_batches(batches)
        back = deserialize_batches(payload)
        self.assertEqual(len(back), len(batches))

    def test_vu_pool_retry_path(self):
        sessions = [{"flow": "f1", "events": [{"event_type": "http_request"}]}]
        pool = VUPool(
            scenario_sessions=sessions,
            ramp_seconds=0,
            max_session_seconds=10,
            flow_policies={"f1": {"max_retries": 2, "backoff_base_ms": 1, "backoff_max_ms": 2}},
        )
        pool.spawn_until(0.0)
        pool.ingest_step_results([{"vu_id": "1", "flow": "f1", "success": False, "timeout": False, "on_failure": "retry"}])
        snap = pool.snapshots()[0]
        self.assertEqual(str(snap.state.value), "failed")
        self.assertEqual(int(snap.retries_used), 1)

    def test_vu_pool_skip_path(self):
        sessions = [{"flow": "f1", "events": [{"event_type": "http_request"}, {"event_type": "http_request"}]}]
        pool = VUPool(scenario_sessions=sessions, ramp_seconds=0, max_session_seconds=10)
        pool.spawn_until(0.0)
        pool.ingest_step_results([{"vu_id": "1", "flow": "f1", "success": False, "timeout": False, "on_failure": "skip"}])
        snap = pool.snapshots()[0]
        self.assertEqual(str(snap.state.value), "running")

    def test_vu_pool_abort_path(self):
        sessions = [{"flow": "f1", "events": [{"event_type": "http_request"}]}]
        pool = VUPool(scenario_sessions=sessions, ramp_seconds=0, max_session_seconds=10)
        pool.spawn_until(0.0)
        pool.ingest_step_results([{"vu_id": "1", "flow": "f1", "success": False, "timeout": False, "on_failure": "abort"}])
        snap = pool.snapshots()[0]
        self.assertEqual(str(snap.state.value), "failed")

    def test_vu_pool_tick_retries(self):
        sessions = [{"flow": "f1", "events": [{"event_type": "http_request"}, {"event_type": "http_request"}]}]
        pool = VUPool(
            scenario_sessions=sessions,
            ramp_seconds=0,
            max_session_seconds=10,
            flow_policies={"f1": {"max_retries": 2, "backoff_base_ms": 1, "backoff_max_ms": 2}},
        )
        pool.spawn_until(0.0)
        pool.ingest_step_results([{"vu_id": "1", "flow": "f1", "success": False, "timeout": False, "on_failure": "retry"}])
        moved = pool.tick_retries(1.0)
        self.assertGreaterEqual(moved, 0)

    def test_vu_pool_finalize_timeout(self):
        sessions = [{"flow": "f1", "events": [{"event_type": "http_request"}]}]
        pool = VUPool(scenario_sessions=sessions, ramp_seconds=0, max_session_seconds=1)
        pool.spawn_until(0.0)
        marked = pool.finalize_timeouts(2.0)
        self.assertEqual(marked, 1)

    def test_vu_pool_async_driver(self):
        sessions = [{"flow": "f1", "events": [{"event_type": "http_request"}, {"event_type": "http_request"}]}]
        pool = VUPool(scenario_sessions=sessions, ramp_seconds=0, max_session_seconds=5)

        calls = {"n": 0}

        async def provider(_elapsed_s):
            calls["n"] += 1
            if calls["n"] == 1:
                return [{"vu_id": "1", "flow": "f1", "success": True, "timeout": False}]
            if calls["n"] == 2:
                return [{"vu_id": "1", "flow": "f1", "success": True, "timeout": False}]
            return []

        snaps = asyncio.run(pool.drive_with_step_batches(duration_s=0.1, step_batch_provider=provider, tick_ms=10))
        self.assertEqual(len(snaps), 1)

    def test_collect_per_flow_metrics_has_failed(self):
        sessions = [{"flow": "a", "events": [{"event_type": "http_request"}]}]
        pool = VUPool(scenario_sessions=sessions, ramp_seconds=0, max_session_seconds=10)
        pool.spawn_until(0.0)
        pool.ingest_step_results([{"vu_id": "1", "flow": "a", "success": False, "timeout": False, "on_failure": "abort"}])
        metrics = collect_per_flow_metrics(pool.snapshots(), duration_s=1.0)
        self.assertIn("failed", metrics["a"])

    def test_native_build_worker_session_plans_counts(self):
        try:
            scenario_native.require_native()
        except RuntimeError:
            self.skipTest("scenario native unavailable")
        raw = self._yaml_to_raw(_BASE_YAML)
        plans, m = scenario_native.build_worker_session_plans(raw, [2, 3], 99)
        self.assertEqual(sum(len(x) for x in plans), 5)
        self.assertEqual(int(m.get("sessions_started", 0)), 5)

    def test_native_compile_packed_contains_required_columns(self):
        try:
            scenario_native.require_native()
        except RuntimeError:
            self.skipTest("scenario native unavailable")
        raw = self._yaml_to_raw(_BASE_YAML)
        out = scenario_native.compile_session_plan(raw, "browse", 7)
        for key in ("event_kind", "request_kind", "method", "path", "headers_idx", "headers_pool"):
            self.assertIn(key, out)

    def test_fuzz_randomized_small_compile(self):
        try:
            scenario_native.require_native()
        except RuntimeError:
            self.skipTest("scenario native unavailable")
        base = self._yaml_to_raw(_BASE_YAML)
        rng = random.Random(1337)
        for i in range(12):
            raw = dict(base)
            lm = dict(raw.get("load_model") or {})
            lm["concurrent_vus"] = 10 + rng.randint(0, 200)
            lm["ramp_seconds"] = rng.randint(0, 20)
            raw["load_model"] = lm
            out = scenario_native.compile_session_plan_packed(raw, "browse", i + 100)
            self.assertTrue(bool(out.get("packed", False)))
            self.assertGreaterEqual(len(list(out.get("event_kind", []) or [])), 1)

    def test_compile_benchmark_smoke_small(self):
        raw = self._yaml_to_raw(_BASE_YAML)
        report = run_compile_benchmark(raw, scales=[100, 500], workers=4, seed=1)
        rows = list(report.get("rows", []) or [])
        self.assertEqual(len(rows), 2)
        self.assertGreaterEqual(float(rows[0].get("elapsed_s", 0.0)), 0.0)

