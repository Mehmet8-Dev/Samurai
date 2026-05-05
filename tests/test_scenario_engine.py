import tempfile
import unittest
from pathlib import Path
import asyncio

from ddos_samurai.scenario_engine import load_raw_scenario, load_scenario_spec
from ddos_samurai.scenario_engine import native as scenario_native
from ddos_samurai.scenario_engine.runtime import (
    RampController,
    VUPool,
    build_vu_lifecycle_batches,
    collect_per_flow_metrics,
    deserialize_batches,
    simulate_vu_state_machine,
    serialize_batches,
)
from ddos_samurai.scenario_engine.sla import evaluate_scenario_sla
from ddos_samurai.scenario_engine.types import ScenarioSpec


_VALID_YAML = """\
schema_version: 1
personas:
  web_user:
    device_profile: web
    headers: {User-Agent: UA}
    cookies: {}
    retry_policy: {max_retries: 1}
    timeout_policy: {request_timeout_ms: 4000}
flows:
  browse:
    persona: web_user
    steps:
      - {type: request, method: GET, path: /}
      - {type: end_session}
load_model:
  concurrent_vus: 100
  ramp_seconds: 10
  max_session_seconds: 30
  backend: http
sla:
  min_completion_rate: 0.9
  max_step_fail_ratio: 0.1
"""

_WITH_PAUSE_YAML = """\
schema_version: 1
personas:
  web_user:
    device_profile: web
    headers: {User-Agent: UA}
    cookies: {}
    retry_policy: {max_retries: 1}
    timeout_policy: {request_timeout_ms: 4000}
flows:
  browse:
    persona: web_user
    steps:
      - {type: request, method: GET, path: /}
      - type: pause
        think_time: {min_ms: 10, max_ms: 20}
      - {type: request, method: GET, path: /x}
      - {type: end_session}
load_model:
  concurrent_vus: 10
  ramp_seconds: 1
  max_session_seconds: 30
  backend: http
sla:
  min_completion_rate: 0.9
  max_step_fail_ratio: 0.1
"""

_V2_YAML = """\
schema_version: 2
variables:
  base_url: "https://example.test"
personas:
  web_user:
    device_profile: web
    headers: {User-Agent: UA, X-Base: "${base_url}"}
    cookies: {}
    retry_policy: {max_retries: 1}
    timeout_policy: {request_timeout_ms: 4000}
flows:
  browse:
    persona: web_user
    steps:
      - {type: request, method: GET, path: "${base_url}/"}
      - type: request
        method: GET
        path: /checkout
        extract: {order_id: "$.order_id"}
      - {type: assert, condition: "order_id != null"}
      - {type: end_session}
load_model:
  concurrent_vus: 10
  ramp_seconds: 1
  max_session_seconds: 30
  backend: http
sla:
  min_completion_rate: 0.9
  max_step_fail_ratio: 0.1
"""

_V2_POLICY_GAUSS_YAML = """\
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
      - type: request
        method: GET
        path: /
        on_failure: abort
      - type: pause
        think_time:
          distribution: gaussian
          min_ms: 0
          max_ms: 1000
          mean_ms: 500
          stddev_ms: 1
      - type: request
        method: GET
        path: /x
        on_failure: skip
      - {type: end_session}
load_model:
  concurrent_vus: 10
  ramp_seconds: 1
  max_session_seconds: 30
  backend: http
sla:
  min_completion_rate: 0.9
  max_step_fail_ratio: 0.1
"""


class TestScenarioEngineParser(unittest.TestCase):
    def test_load_valid_yaml(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "ok.yaml"
            p.write_text(_VALID_YAML, encoding="utf-8")
            out = load_raw_scenario(str(p))
        self.assertEqual(int(out["schema_version"]), 1)
        self.assertIn("web_user", out["personas"])
        self.assertIn("browse", out["flows"])

    def test_load_scenario_spec_returns_dataclass(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "ok.yaml"
            p.write_text(_VALID_YAML, encoding="utf-8")
            spec = load_scenario_spec(str(p))
        self.assertIsInstance(spec, ScenarioSpec)
        self.assertEqual(spec.load_model.backend, "http")

    def test_reject_unknown_backend(self):
        bad = _VALID_YAML.replace("backend: http", "backend: quic")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.yaml"
            p.write_text(bad, encoding="utf-8")
            with self.assertRaises(ValueError):
                _ = load_raw_scenario(str(p))

    def test_reject_missing_persona_ref(self):
        bad = _VALID_YAML.replace("persona: web_user", "persona: no_such_persona")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad2.yaml"
            p.write_text(bad, encoding="utf-8")
            with self.assertRaises(ValueError):
                _ = load_raw_scenario(str(p))

    def test_reject_non_progress_cycle(self):
        cyc = """\
schema_version: 1
personas:
  p1:
    device_profile: web
    headers: {}
    cookies: {}
    retry_policy: {}
    timeout_policy: {}
flows:
  a:
    persona: p1
    steps:
      - {type: loop, flow: b, repeat: 1}
  b:
    persona: p1
    steps:
      - {type: loop, flow: a, repeat: 1}
load_model: {concurrent_vus: 10, ramp_seconds: 1, max_session_seconds: 10, backend: http}
sla: {min_completion_rate: 0.9, max_step_fail_ratio: 0.1}
"""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad3.yaml"
            p.write_text(cyc, encoding="utf-8")
            with self.assertRaises(ValueError):
                _ = load_raw_scenario(str(p))

    def test_native_scheduler_is_deterministic(self):
        try:
            scenario_native.require_native()
        except RuntimeError:
            self.skipTest("scenario native module unavailable")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "ok.yaml"
            p.write_text(_VALID_YAML, encoding="utf-8")
            spec = load_raw_scenario(str(p))
        plans1, m1 = scenario_native.build_worker_session_plans(spec, [3, 2], 42)
        plans2, m2 = scenario_native.build_worker_session_plans(spec, [3, 2], 42)
        self.assertEqual(m1, m2)
        self.assertEqual(plans1, plans2)

    def test_native_compiler_emits_think_time_event(self):
        try:
            scenario_native.require_native()
        except RuntimeError:
            self.skipTest("scenario native module unavailable")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "pause.yaml"
            p.write_text(_WITH_PAUSE_YAML, encoding="utf-8")
            spec = load_raw_scenario(str(p))
        out = scenario_native.compile_session_plan(spec, "browse", 7)
        self.assertTrue(bool(out.get("packed", False)))
        event_kind = list(out.get("event_kind", []) or [])
        self.assertTrue(any(int(x) == 1 for x in event_kind))

    def test_native_compiler_packed_mode(self):
        try:
            scenario_native.require_native()
        except RuntimeError:
            self.skipTest("scenario native module unavailable")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "pause.yaml"
            p.write_text(_WITH_PAUSE_YAML, encoding="utf-8")
            spec = load_raw_scenario(str(p))
        out = scenario_native.compile_session_plan_packed(spec, "browse", 7)
        self.assertTrue(bool(out.get("packed", False)))
        self.assertIn("event_kind", out)
        self.assertIn("headers_idx", out)
        self.assertIn("headers_pool", out)
        self.assertIn("on_failure", out)
        self.assertIn("think_distribution", out)
        self.assertIn("think_mean_ms", out)
        self.assertIn("think_stddev_ms", out)
        self.assertGreaterEqual(len(list(out.get("event_kind", []) or [])), 1)
        batches, metrics = build_vu_lifecycle_batches(
            scenario_sessions=[out],
            ramp_seconds=0,
            max_session_seconds=30,
            seed=7,
        )
        self.assertTrue(len(batches) > 0)
        self.assertGreaterEqual(int(metrics.get("step_attempted", 0) or 0), 1)

    def test_vu_lifecycle_batches_apply_ramp_and_think_time(self):
        sessions = [
            {
                "events": [
                    {"event_type": "http_request", "method": "GET", "path": "/"},
                    {"event_type": "think_time", "min_ms": 100, "max_ms": 100},
                    {"event_type": "http_request", "method": "GET", "path": "/x"},
                ]
            },
            {
                "events": [
                    {"event_type": "http_request", "method": "GET", "path": "/y"},
                ]
            },
        ]
        batches, metrics = build_vu_lifecycle_batches(
            scenario_sessions=sessions,
            ramp_seconds=2,
            max_session_seconds=10,
            seed=123,
            bucket_ms=50,
        )
        self.assertGreaterEqual(len(batches), 2)
        delays = [float(b.delay_s) for b in batches]
        self.assertTrue(any(d >= 1.0 for d in delays))
        self.assertEqual(int(metrics["vus_spawned"]), 2)

    def test_vu_lifecycle_batches_inject_body_template(self):
        sessions = [
            {
                "events": [
                    {"event_type": "http_request", "method": "POST", "path": "/submit", "body_template": '{"ok":true}'},
                ]
            }
        ]
        batches, _ = build_vu_lifecycle_batches(
            scenario_sessions=sessions,
            ramp_seconds=0,
            max_session_seconds=10,
            seed=3,
            bucket_ms=50,
        )
        self.assertTrue(batches)
        item = batches[0].request_plan.items[0]
        self.assertEqual(item.method, "POST")
        self.assertEqual(bytes(item.body or b""), b'{"ok":true}')
        self.assertEqual(str(item.content_type or ""), "application/json")

    def test_serialize_deserialize_batches_keep_body(self):
        sessions = [
            {
                "events": [
                    {"event_type": "http_request", "method": "POST", "path": "/x", "body_template": "hello"},
                ]
            }
        ]
        batches, _ = build_vu_lifecycle_batches(
            scenario_sessions=sessions,
            ramp_seconds=0,
            max_session_seconds=10,
            seed=5,
        )
        encoded = serialize_batches(batches)
        restored = deserialize_batches(encoded)
        item = restored[0].request_plan.items[0]
        self.assertEqual(bytes(item.body or b""), b"hello")
        self.assertEqual(str(item.content_type or ""), "text/plain; charset=utf-8")

    def test_state_machine_feedback_and_per_flow_metrics(self):
        sessions = [
            {"flow": "a", "events": [{"event_type": "http_request"}, {"event_type": "think_time", "min_ms": 10, "max_ms": 10}]},
            {"flow": "a", "events": [{"event_type": "http_request"}]},
            {"flow": "b", "events": [{"event_type": "http2_headers"}]},
        ]
        vus = simulate_vu_state_machine(
            scenario_sessions=sessions,
            observed_error_ratio=0.2,
            observed_timeout_ratio=0.1,
            seed=42,
        )
        self.assertEqual(len(vus), 3)
        per_flow = collect_per_flow_metrics(vus, duration_s=2.0)
        self.assertIn("a", per_flow)
        self.assertIn("b", per_flow)
        self.assertIn("session_completion_rate", per_flow["a"])

    def test_schema_v2_variables_and_extract_assert(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "v2.yaml"
            p.write_text(_V2_YAML, encoding="utf-8")
            out = load_raw_scenario(str(p))
        self.assertEqual(int(out["schema_version"]), 2)
        self.assertEqual(out["flows"]["browse"]["steps"][0]["path"], "https://example.test/")
        self.assertEqual(out["personas"]["web_user"]["headers"]["X-Base"], "https://example.test")

    def test_sla_module_evaluation(self):
        ev = evaluate_scenario_sla(
            sessions_started=100,
            sessions_completed=96,
            step_attempted=1000,
            step_failed=30,
            sla={"min_completion_rate": 0.95, "max_step_fail_ratio": 0.05},
            latency_p95_ms=100.0,
        )
        self.assertTrue(ev.passed)
        self.assertEqual(ev.reasons, [])

    def test_sla_module_per_flow_rules(self):
        ev = evaluate_scenario_sla(
            sessions_started=100,
            sessions_completed=99,
            step_attempted=1000,
            step_failed=5,
            sla={
                "min_completion_rate": 0.95,
                "max_step_fail_ratio": 0.05,
                "per_flow": {
                    "checkout": {
                        "min_completion_rate": 0.99,
                        "max_step_fail_ratio": 0.02,
                    }
                },
            },
            per_flow_metrics={
                "checkout": {
                    "session_completion_rate": 0.98,
                    "step_fail_ratio": 0.01,
                    "latency_p95_ms": 100.0,
                }
            },
            latency_p95_ms=120.0,
        )
        self.assertFalse(ev.passed)
        self.assertTrue(any(str(x).startswith("per_flow_completion_below:checkout") for x in ev.reasons))

    def test_ramp_controller_curves(self):
        linear = RampController(target_vus=100, ramp_seconds=10, curve="linear")
        step = RampController(target_vus=100, ramp_seconds=10, curve="step", step_interval_s=2)
        spike = RampController(target_vus=100, ramp_seconds=10, curve="spike")
        custom = RampController(target_vus=100, ramp_seconds=10, curve="custom", custom_points=((0.0, 0), (3.0, 30), (10.0, 100)))
        self.assertGreaterEqual(linear.active_vus_at(5.0), 45)
        self.assertLessEqual(step.active_vus_at(1.0), 5)
        self.assertGreaterEqual(spike.active_vus_at(2.0), 65)
        self.assertGreaterEqual(custom.active_vus_at(3.0), 30)

    def test_lifecycle_batches_with_step_curve(self):
        sessions = [{"events": [{"event_type": "http_request", "method": "GET", "path": "/"}]} for _ in range(20)]
        batches, _ = build_vu_lifecycle_batches(
            scenario_sessions=sessions,
            ramp_seconds=10,
            max_session_seconds=30,
            seed=7,
            ramp_curve="step",
            ramp_step_interval_s=2,
        )
        self.assertTrue(len(batches) > 0)

    def test_vu_pool_live_transitions(self):
        sessions = [
            {
                "flow": "f1",
                "events": [
                    {"event_type": "http_request"},
                    {"event_type": "http_request"},
                ],
            },
            {
                "flow": "f2",
                "events": [
                    {"event_type": "http_request"},
                ],
            },
        ]
        pool = VUPool(
            scenario_sessions=sessions,
            ramp_seconds=1,
            max_session_seconds=5,
            ramp_curve="linear",
        )
        pool.spawn_until(0.0)
        pool.ingest_step_results(
            [
                {"vu_id": "1", "flow": "f1", "success": True, "timeout": False},
                {"vu_id": "2", "flow": "f2", "success": False, "timeout": True},
            ]
        )
        pool.ingest_step_results(
            [
                {"vu_id": "1", "flow": "f1", "success": True, "timeout": False},
            ]
        )
        snaps = pool.snapshots()
        s1 = [x for x in snaps if x.vu_id == 1][0]
        s2 = [x for x in snaps if x.vu_id == 2][0]
        self.assertEqual(str(s1.state.value), "completed")
        self.assertEqual(str(s2.state.value), "failed")
        summary = pool.summary_metrics()
        self.assertEqual(int(summary["sessions_completed"]), 1)
        self.assertEqual(int(summary["sessions_failed"]), 1)

    def test_vu_pool_timeout_finalize(self):
        sessions = [{"flow": "f1", "events": [{"event_type": "http_request"}]}]
        pool = VUPool(
            scenario_sessions=sessions,
            ramp_seconds=0,
            max_session_seconds=1,
        )
        pool.spawn_until(0.0)
        marked = pool.finalize_timeouts(2.0)
        self.assertEqual(marked, 1)
        snaps = pool.snapshots()
        self.assertEqual(str(snaps[0].state.value), "failed")

    def test_vu_pool_drive_with_observed_ratios(self):
        sessions = [
            {"flow": "f1", "events": [{"event_type": "http_request"}, {"event_type": "http_request"}]},
            {"flow": "f2", "events": [{"event_type": "http_request"}]},
        ]
        pool = VUPool(
            scenario_sessions=sessions,
            ramp_seconds=0,
            max_session_seconds=30,
            retry_backoff_base_ms=10,
            retry_backoff_max_ms=20,
        )
        snaps = pool.drive_with_observed_ratios(
            observed_error_ratio=0.2,
            observed_timeout_ratio=0.1,
            seed=123,
            duration_s=1.0,
        )
        self.assertEqual(len(snaps), 2)
        self.assertTrue(all(str(s.state.value) in {"completed", "failed"} for s in snaps))

    def test_vu_pool_policy_max_retries_abort(self):
        sessions = [{"flow": "f1", "events": [{"event_type": "http_request"}]}]
        pool = VUPool(
            scenario_sessions=sessions,
            ramp_seconds=0,
            max_session_seconds=10,
            flow_policies={"f1": {"max_retries": 0, "timeout_action": "abort"}},
        )
        pool.spawn_until(0.0)
        pool.ingest_step_results([{"vu_id": "1", "flow": "f1", "success": False, "timeout": True}])
        snap = pool.snapshots()[0]
        self.assertEqual(str(snap.state.value), "failed")
        self.assertEqual(int(snap.retries_used), 0)

    def test_vu_pool_on_failure_skip_and_abort(self):
        sessions = [{"flow": "f1", "events": [{"event_type": "http_request"}, {"event_type": "http_request"}]}]
        pool = VUPool(
            scenario_sessions=sessions,
            ramp_seconds=0,
            max_session_seconds=10,
            flow_policies={"f1": {"max_retries": 3}},
        )
        pool.spawn_until(0.0)
        pool.ingest_step_results([{"vu_id": "1", "flow": "f1", "success": False, "timeout": False, "on_failure": "skip"}])
        snap = pool.snapshots()[0]
        self.assertEqual(str(snap.state.value), "running")
        self.assertEqual(int(snap.retries_used), 0)
        pool.ingest_step_results([{"vu_id": "1", "flow": "f1", "success": False, "timeout": False, "on_failure": "abort"}])
        snap2 = pool.snapshots()[0]
        self.assertEqual(str(snap2.state.value), "failed")
        self.assertEqual(int(snap2.retries_used), 0)

    def test_schema_v2_on_failure_and_gaussian_runtime(self):
        try:
            scenario_native.require_native()
        except RuntimeError:
            self.skipTest("scenario native module unavailable")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "v2_policy_gauss.yaml"
            p.write_text(_V2_POLICY_GAUSS_YAML, encoding="utf-8")
            spec = load_raw_scenario(str(p))
        packed = scenario_native.compile_session_plan_packed(spec, "browse", 77)
        batches, _ = build_vu_lifecycle_batches(
            scenario_sessions=[packed],
            ramp_seconds=0,
            max_session_seconds=30,
            seed=77,
            bucket_ms=10,
        )
        self.assertGreaterEqual(len(batches), 2)
        first_headers = dict((batches[0].request_plan.items[0].headers or {}))
        self.assertEqual(str(first_headers.get("x-scenario-on-failure", "")), "abort")
        delays = [float(b.delay_s) for b in batches]
        self.assertTrue(any(d >= 0.45 for d in delays))

    def test_vu_pool_async_step_batches(self):
        sessions = [{"flow": "f1", "events": [{"event_type": "http_request"}, {"event_type": "http_request"}]}]
        pool = VUPool(
            scenario_sessions=sessions,
            ramp_seconds=0,
            max_session_seconds=5,
            flow_policies={"f1": {"max_retries": 2, "backoff_base_ms": 1, "backoff_max_ms": 2}},
        )

        calls = {"n": 0}

        async def provider(elapsed_s):
            calls["n"] += 1
            if calls["n"] == 1:
                return [{"vu_id": "1", "flow": "f1", "success": False, "timeout": False}]
            if calls["n"] == 2:
                return [{"vu_id": "1", "flow": "f1", "success": True, "timeout": False}]
            return []

        snaps = asyncio.run(
            pool.drive_with_step_batches(duration_s=0.1, step_batch_provider=provider, tick_ms=10)
        )
        self.assertEqual(len(snaps), 1)
        self.assertIn(str(snaps[0].state.value), {"completed", "failed"})
