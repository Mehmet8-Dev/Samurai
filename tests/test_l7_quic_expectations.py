from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from ddos_samurai import senders
from ddos_samurai._senders import l7_quic


class _DummyRunOut:
    def __init__(self, payload):
        self._payload = dict(payload or {})

    def as_dict(self):
        return dict(self._payload)


class TestL7QuicExpectations(unittest.TestCase):
    def test_compile_profile_injects_quic_expectations(self):
        profile = senders.compile_l7_profile(
            protocol="quic",
            target_ip="127.0.0.1",
            target_port=443,
            scheme="https",
            http_method="GET",
            http_path="/health",
            payloads=[],
            concurrency=1,
            timeout_s=1.0,
            quic_expect_status_min=200,
            quic_expect_status_max=299,
            quic_expect_header_name="server",
            quic_expect_header_value_contains="nginx",
            quic_expect_body_substring="ok",
            quic_require_response_body=True,
            quic_min_response_body_bytes=32,
        )
        ops = list(profile.flow_program.ops)
        expect_ops = [op for op in ops if str(op.opcode.value) in {"EXPECT_STATUS", "EXPECT_HEADER", "EXPECT_BODY_SUBSTRING"}]
        self.assertTrue(expect_ops)

        status = [op for op in expect_ops if str(op.opcode.value) == "EXPECT_STATUS"][-1]
        self.assertIsNotNone(status.expect)
        self.assertEqual(int(status.expect.status_min), 200)
        self.assertEqual(int(status.expect.status_max), 299)

        header = [op for op in expect_ops if str(op.opcode.value) == "EXPECT_HEADER"][-1]
        self.assertIsNotNone(header.expect)
        self.assertEqual(str(header.expect.name), "server")
        self.assertEqual(str(header.expect.value), "nginx")

        body_ops = [op for op in expect_ops if str(op.opcode.value) == "EXPECT_BODY_SUBSTRING"]
        body_kinds = {str(op.expect.kind) for op in body_ops if op.expect is not None}
        self.assertIn("body_substring", body_kinds)
        self.assertIn("body_required", body_kinds)
        self.assertIn("body_min_bytes", body_kinds)

    def test_sender_passes_quic_expectations_to_compiler(self):
        captured = {}

        def _fake_compile(**kwargs):
            captured.update(kwargs)
            return object()

        async def _fake_run(profile, cfg):
            _ = (profile, cfg)
            return _DummyRunOut(
                {
                    "attempted": 1,
                    "sent": 0,
                    "errors": 1,
                    "quic_capability_available": 1,
                }
            )

        with (
            mock.patch("ddos_samurai._senders.l7_quic._sender_runtime.has_l7_native_quic", return_value=True),
            mock.patch("ddos_samurai._senders.l7_quic._compile_l7_profile", side_effect=_fake_compile),
            mock.patch("ddos_samurai._senders.l7_quic._run_l7_profile", side_effect=_fake_run),
        ):
            out = asyncio.run(
                l7_quic.quic_sender(
                    target_ip="127.0.0.1",
                    target_port=443,
                    count=1,
                    concurrency=1,
                    quic_path="/",
                    quic_method="GET",
                    verbose=False,
                    timeout_s=0.3,
                    l7_quic_engine="auto",
                    quic_expect_status_min=201,
                    quic_expect_status_max=204,
                    quic_expect_header_name="x-test",
                    quic_expect_header_value_contains="abc",
                    quic_expect_body_substring="hello",
                    quic_require_response_body=True,
                    quic_min_response_body_bytes=64,
                    stats_fn=lambda **kwargs: kwargs,
                    normalize_l7_output_fn=lambda d, **_: d,
                    update_live_fn=lambda *_: None,
                )
            )

        self.assertEqual(int(captured.get("quic_expect_status_min", 0)), 201)
        self.assertEqual(int(captured.get("quic_expect_status_max", 0)), 204)
        self.assertEqual(str(captured.get("quic_expect_header_name", "")), "x-test")
        self.assertEqual(str(captured.get("quic_expect_header_value_contains", "")), "abc")
        self.assertEqual(str(captured.get("quic_expect_body_substring", "")), "hello")
        self.assertEqual(bool(captured.get("quic_require_response_body", False)), True)
        self.assertEqual(int(captured.get("quic_min_response_body_bytes", 0)), 64)
        self.assertIn("quic_stack_mode", out)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
