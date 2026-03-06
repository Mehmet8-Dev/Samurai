import unittest
from unittest.mock import AsyncMock, patch

from ddos_samurai import l7_engine


class _FakeL7Core:
    def __init__(self):
        self.open_calls = 0
        self.run_calls = []
        self.handle = object()

    def open(self, _cfg):
        self.open_calls += 1
        return self.handle

    def snapshot(self, _handle):
        return {
            "runs_total": len(self.run_calls),
            "sessions_total": 100 + len(self.run_calls),
        }

    def run_http1_stateful(self, handle, payload=None):
        if payload is None:
            payload = handle
            handle = None
        self.run_calls.append((handle, dict(payload)))
        count = int(payload.get("count", 0) or 0)
        return {
            "attempted": count,
            "sent": 0,
            "errors": count,
            "sender_path": "C_STATE_HTTP1",
            "sender_fallback_reason": "tls_not_supported",
        }


class TestL7EngineAdapter(unittest.IsolatedAsyncioTestCase):
    async def test_core_handle_is_reused_and_snapshot_is_attached(self):
        fake_core = _FakeL7Core()
        with patch.object(l7_engine, "_l7_core", fake_core), patch.object(l7_engine, "_CORE_HANDLE", None):
            cfg = l7_engine.L7EngineConfig(
                engine="c_state",
                target_ip="127.0.0.1",
                target_port=80,
                count=3,
                concurrency=1,
                mode="http1_stateful",
            )
            r1 = await l7_engine.run_http1_stateful(cfg)
            r2 = await l7_engine.run_http1_stateful(cfg)

        self.assertIsNotNone(r1)
        self.assertIsNotNone(r2)
        self.assertEqual(fake_core.open_calls, 1)
        self.assertEqual(len(fake_core.run_calls), 2)
        self.assertTrue(bool(r1.allow_legacy_fallback))
        self.assertIn("l7_handle_runs_total", r1.extra)
        self.assertIn("l7_handle_sessions_total", r1.extra)

    def test_from_core_result_marks_unsupported_reasons_as_legacy_fallback(self):
        unsupported = l7_engine._from_core_result(
            {"attempted": 5, "sent": 0, "errors": 5, "sender_fallback_reason": "ws_scenario_unsupported"},
            default_count=5,
            sender_path="C_STATE_WS",
        )
        quic_connect = l7_engine._from_core_result(
            {"attempted": 5, "sent": 0, "errors": 5, "sender_fallback_reason": "connect_fail"},
            default_count=5,
            sender_path="C_STATE_QUIC",
        )
        normal = l7_engine._from_core_result(
            {"attempted": 5, "sent": 0, "errors": 5, "sender_fallback_reason": "none"},
            default_count=5,
            sender_path="C_STATE_WS",
        )
        self.assertTrue(bool(unsupported.allow_legacy_fallback))
        self.assertTrue(bool(quic_connect.allow_legacy_fallback))
        self.assertFalse(bool(normal.allow_legacy_fallback))

    async def test_http2_and_quic_return_capability_unavailable_when_runner_is_missing(self):
        fake_core = _FakeL7Core()
        with patch.object(l7_engine, "_l7_core", fake_core), patch.object(l7_engine, "_CORE_HANDLE", None):
            cfg_h2 = l7_engine.L7EngineConfig(
                engine="c_state",
                target_ip="127.0.0.1",
                target_port=443,
                count=2,
                concurrency=1,
                mode="http2_stateful",
            )
            cfg_quic = l7_engine.L7EngineConfig(
                engine="c_state",
                target_ip="127.0.0.1",
                target_port=443,
                count=2,
                concurrency=1,
                mode="quic_stateful",
            )
            h2_out = await l7_engine.run_http2_stateful(cfg_h2)
            quic_out = await l7_engine.run_quic_stateful(cfg_quic)

        self.assertIsNotNone(h2_out)
        self.assertIsNotNone(quic_out)
        self.assertEqual(h2_out.sender_fallback_reason, "h2_capability_unavailable")
        self.assertEqual(quic_out.sender_fallback_reason, "quic_capability_unavailable")
        self.assertTrue(h2_out.allow_legacy_fallback)
        self.assertTrue(quic_out.allow_legacy_fallback)

    async def test_quic_uses_h3_bridge_when_enabled(self):
        fake_core = _FakeL7Core()
        with patch.object(l7_engine, "_l7_core", fake_core), patch.object(l7_engine, "_CORE_HANDLE", None), patch.object(
            l7_engine.quic_h3_bridge, "supported", return_value=True
        ), patch.object(
            l7_engine.quic_h3_bridge,
            "run_stateful",
            new=AsyncMock(
                return_value={
                    "attempted": 2,
                    "sent": 2,
                    "errors": 0,
                    "sender_path": "C_STATE_QUIC_H3PY",
                    "sender_fallback_reason": "none",
                    "quic_stack_mode": "h3_stateful_py",
                }
            ),
        ):
            cfg_quic = l7_engine.L7EngineConfig(
                engine="c_state",
                target_ip="127.0.0.1",
                target_port=443,
                count=2,
                concurrency=1,
                mode="quic_stateful",
                extra={"enable_quic_py_bridge": 1},
            )
            quic_out = await l7_engine.run_quic_stateful(cfg_quic)

        self.assertIsNotNone(quic_out)
        self.assertEqual(quic_out.sender_path, "C_STATE_QUIC_H3PY")
        self.assertEqual(quic_out.sender_fallback_reason, "none")
        self.assertEqual(quic_out.sent, 2)
        self.assertFalse(quic_out.allow_legacy_fallback)
