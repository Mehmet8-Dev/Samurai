import tempfile
import unittest
from pathlib import Path

from ddos_samurai.scenario_engine import load_raw_scenario, load_scenario_spec
from ddos_samurai.scenario_engine import native as scenario_native
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
        events = list(out.get("events", []) or [])
        self.assertTrue(any(dict(ev or {}).get("event_type") == "think_time" for ev in events))
