from __future__ import annotations

import asyncio
import unittest

from ddos_samurai import senders
from ddos_samurai.l7_emu.runtime import run_l7_profile
from ddos_samurai.l7_emu.types import RuntimeConfig

try:
    from ddos_samurai import _l7_emu_native as _native
except Exception:  # pragma: no cover
    _native = None


@unittest.skipIf(_native is None, "native l7 module unavailable")
class TestL7QuicNativeStack(unittest.TestCase):
    def test_minimal_h3_request_builder_and_response_parser(self):
        packet = _native.quic_build_minimal_h3_request("GET", "/health", b"hello")
        self.assertIsInstance(packet, (bytes, bytearray))
        self.assertGreater(len(packet), 8)
        self.assertTrue(bytes(packet).startswith(b"H3Q1"))

        # Synthetic minimal H3 response wire format consumed by native parser.
        # Magic + HEADERS frame(type=1,len=11,":status=200") + DATA(type=0,len=2,"ok")
        response = b"H3R1" + bytes([1, 0, 11]) + b":status=200" + bytes([0, 0, 2]) + b"ok"
        parsed = _native.quic_parse_minimal_h3_response(response)
        self.assertEqual(int(parsed.get("valid", 0) or 0), 1)
        self.assertEqual(int(parsed.get("headers_ok", 0) or 0), 1)
        self.assertEqual(int(parsed.get("body_ok", 0) or 0), 1)
        self.assertEqual(int(parsed.get("expected_header_ok", 0) or 0), 1)
        self.assertEqual(int(parsed.get("expected_body_match_ok", 0) or 0), 1)

    def test_quic_native_metrics_surface_contains_validation_and_recovery_keys(self):
        profile = senders.compile_l7_profile(
            protocol="quic",
            target_ip="127.0.0.1",
            target_port=65531,
            scheme="https",
            http_method="GET",
            http_path=["/"],
            payloads=[],
            concurrency=1,
            timeout_s=0.1,
        )
        out = asyncio.run(run_l7_profile(profile, RuntimeConfig(concurrency=1))).as_dict()

        expected = {
            "quic_pto_count",
            "quic_retransmission_count",
            "quic_response_headers_ok_count",
            "quic_response_body_ok_count",
            "quic_response_expected_header_ok_count",
            "quic_response_expected_body_match_ok_count",
            "quic_response_validation_fail_count",
            "quic_stream_fail_ratio",
            "quic_handshake_fail_ratio",
            "quic_response_validation_fail_ratio",
            "quic_stack_mode",
        }
        self.assertTrue(expected.issubset(set(out.keys())))
        self.assertIn(str(out.get("quic_stack_mode", "")), {"custom_native", "unavailable"})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
