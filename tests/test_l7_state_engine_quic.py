import unittest


try:
    from ddos_samurai import l7_state_engine as l7_core
except Exception:  # pragma: no cover
    l7_core = None


@unittest.skipIf(l7_core is None, "l7_state_engine extension unavailable")
class TestL7StateEngineQuic(unittest.TestCase):
    def test_quic_stack_mode_contract(self):
        mode = str(l7_core.quic_stack_mode() or "")
        self.assertIn(mode, {"h3_stateful", "unavailable"})

    def test_quic_supported_matches_mode(self):
        mode = str(l7_core.quic_stack_mode() or "")
        supported = bool(l7_core.quic_supported())
        self.assertEqual(supported, mode == "h3_stateful")

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
