import tempfile
import unittest

from ddos_samurai.gpu_payload import build_request_plan_from_session_plan
from ddos_samurai.ml.fallback_profiles import generate_deterministic_plan
from ddos_samurai.ml.feature_codec import FeatureCodec
from ddos_samurai.ml.plan_validator import validate
from ddos_samurai.ml.planner import MambaPlanner, PlannerError
from ddos_samurai.ml.types import PlanRequest, SessionEvent


class TestMLPlanner(unittest.TestCase):
    def test_feature_codec_encode_decode_parity(self):
        codec = FeatureCodec.default()
        event = SessionEvent(step_index=3, event_type="http_request", delay_ms=12, method="GET")
        encoded = codec.encode_event(event)
        decoded = codec.decode_event(encoded)
        self.assertEqual(decoded.step_index, 3)
        self.assertEqual(decoded.event_type, "http_request")
        self.assertEqual(decoded.method, "GET")

    def test_fallback_plan_is_deterministic(self):
        req = PlanRequest(
            session_count=5,
            session_len=8,
            seed=42,
            protocols=["http1"],
            label_mix={"benign": 1.0},
        )
        p1 = generate_deterministic_plan(req)
        p2 = generate_deterministic_plan(req)
        self.assertEqual(p1.to_dict(), p2.to_dict())

    def test_plan_validator_rejects_invalid_sequence(self):
        req = PlanRequest(session_count=1, session_len=6, seed=7, protocols=["http1"], label_mix={})
        plan = generate_deterministic_plan(req)
        sp = plan.session_plans[0]
        bad_event = SessionEvent(step_index=99, event_type="http_request", delay_ms=1, method="GET", path="/x")
        plan_bad = plan.__class__(
            plan_id=plan.plan_id,
            model_name=plan.model_name,
            checkpoint_id=plan.checkpoint_id,
            seed=plan.seed,
            session_plans=[sp.__class__(session_id=sp.session_id, protocol=sp.protocol, label=sp.label, events=[bad_event])],
        )
        vr = validate(plan_bad)
        self.assertFalse(vr.valid)
        self.assertTrue(vr.errors)

    def test_request_plan_builder_from_session_plan(self):
        session_plan = {
            "session_id": "s1",
            "protocol": "http2",
            "label": "benign",
            "events": [
                {"step_index": 0, "event_type": "connect_open", "delay_ms": 1},
                {
                    "step_index": 1,
                    "event_type": "http2_headers",
                    "delay_ms": 2,
                    "method": "GET",
                    "path": "/api/x",
                    "header_profile": "h",
                    "payload_class": "p",
                },
            ],
        }
        rp = build_request_plan_from_session_plan(session_plan)
        self.assertEqual(len(rp.items), 1)
        self.assertEqual(rp.items[0].method, "GET")
        self.assertEqual(rp.items[0].path, "/api/x")

    def test_mamba_planner_requires_existing_checkpoint(self):
        with self.assertRaises(PlannerError):
            MambaPlanner.load("/tmp/this-file-does-not-exist.ckpt", device="cpu")

    def test_mamba_planner_load_and_generate(self):
        with tempfile.NamedTemporaryFile(suffix=".ckpt") as tmp:
            planner = MambaPlanner.load(tmp.name, device="cpu")
            plan = planner.generate(
                PlanRequest(
                    session_count=2,
                    session_len=6,
                    seed=11,
                    protocols=["http1"],
                    label_mix={"benign": 1.0},
                )
            )
            self.assertEqual(plan.model_name, "mamba2")
            self.assertEqual(len(plan.session_plans), 2)

