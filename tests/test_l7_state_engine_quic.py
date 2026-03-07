import unittest


try:
    from ddos_samurai import l7_state_engine as l7_core
except Exception:  # pragma: no cover
    l7_core = None


@unittest.skipIf(l7_core is None, "l7_state_engine extension unavailable")
class TestL7StateEngineQuic(unittest.TestCase):
    def test_quic_stack_mode_contract(self):
        mode = str(l7_core.quic_stack_mode() or "")
        self.assertIn(mode, {"h3_stateful", "h3_stateful_py", "unavailable"})

    def test_quic_supported_matches_mode(self):
        mode = str(l7_core.quic_stack_mode() or "")
        supported = bool(l7_core.quic_supported())
        self.assertEqual(supported, mode in {"h3_stateful", "h3_stateful_py"})

    def test_quic_h3_native_batch_contract(self):
        mode = str(l7_core.quic_stack_mode() or "")
        if mode != "h3_stateful":
            self.skipTest("requires native h3_stateful mode")

        handle = l7_core.open({})
        try:
            out = l7_core.run_quic_stateful(
                handle,
                {
                    "target_ip": "127.0.0.1",
                    "target_port": 65530,
                    "count": 6,
                    "concurrency": 4,
                    "retries": 1,
                    "timeout_s": 0.3,
                    "scheme": "https",
                    "verify": False,
                    "quic_method": "GET",
                    "quic_path": "/",
                    "quic_streams_per_conn": 2,
                    "quic_requests_per_conn": 3,
                    "quic_expect_header_name": "Server",
                    "quic_expect_header_value_contains": "nginx",
                    "quic_expect_body_substring": "ok",
                    "enable_quic_py_bridge": 0,
                },
            )
        finally:
            l7_core.close(handle)

        self.assertEqual(str(out.get("quic_stack_mode", "")), "h3_stateful")
        self.assertEqual(int(out.get("attempted", -1)), 6)
        self.assertEqual(int(out.get("quic_streams_per_conn", -1)), 2)
        self.assertEqual(int(out.get("quic_requests_per_conn", -1)), 3)
        self.assertGreaterEqual(int(out.get("quic_connection_attempts", -1)), 1)
        self.assertEqual(int(out.get("retry_attempts", -1)), 6)
        self.assertEqual(str(out.get("quic_expect_header_name", "")), "server")
        self.assertEqual(str(out.get("quic_expect_header_value_contains", "")), "nginx")
        self.assertEqual(str(out.get("quic_expect_body_substring", "")), "ok")

    def test_quic_unavailable_result_contract(self):
        mode = str(l7_core.quic_stack_mode() or "")
        if mode != "unavailable":
            self.skipTest("requires unavailable mode")

        handle = l7_core.open({})
        try:
            out = l7_core.run_quic_stateful(
                handle,
                {
                    "target_ip": "127.0.0.1",
                    "target_port": 443,
                    "count": 2,
                    "concurrency": 1,
                    "retries": 1,
                    "timeout_s": 0.3,
                    "scheme": "https",
                    "verify": False,
                    "quic_method": "GET",
                    "quic_path": "/",
                },
            )
        finally:
            l7_core.close(handle)

        reason = str(out.get("sender_fallback_reason", ""))
        self.assertIn(reason, {"quic_capability_unavailable", "capability_unavailable"})
        self.assertEqual(int(out.get("attempted", -1)), 2)
        self.assertEqual(int(out.get("sent", -1)), 0)
        self.assertEqual(int(out.get("errors", -1)), 2)
        self.assertEqual(str(out.get("quic_stack_mode", "")), "unavailable")
        self.assertAlmostEqual(float(out.get("quic_stream_fail_ratio", -1.0)), 1.0, places=6)
        self.assertAlmostEqual(float(out.get("quic_handshake_fail_ratio", -1.0)), 0.0, places=6)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
