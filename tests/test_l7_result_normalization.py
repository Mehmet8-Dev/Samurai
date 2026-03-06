import unittest

from ddos_samurai.l7.telemetry import aggregate_l7_stats, normalize_l7_stats


class TestL7ResultNormalization(unittest.TestCase):
    def test_normalize_fills_common_fields(self):
        out = normalize_l7_stats(
            {"attempted": 10, "sent": 9, "errors": 1, "sender_path": "PY_HTTP2"},
            attempted_default=10,
            sender_path="PY_HTTP2",
            engine_path_used="PY_HTTP2",
            fallback_reason="none",
        )
        self.assertEqual(out["attempted"], 10)
        self.assertEqual(out["sent"], 9)
        self.assertEqual(out["errors"], 1)
        self.assertEqual(out["l7_engine_path_used"], "PY_HTTP2")
        self.assertEqual(out["l7_fallback_reason"], "none")
        self.assertEqual(out["l7_capability_status"], "ok")
        self.assertIn("h2_goaway_count", out)
        self.assertIn("quic_stream_fail_ratio", out)

    def test_aggregate_uses_weighted_ratios(self):
        out = aggregate_l7_stats(
            [
                {"attempted": 10, "sent": 9, "errors": 1, "h2_stream_reset_ratio": 0.1},
                {"attempted": 30, "sent": 24, "errors": 6, "h2_stream_reset_ratio": 0.5},
            ]
        )
        self.assertEqual(out["attempted"], 40)
        self.assertEqual(out["sent"], 33)
        self.assertEqual(out["errors"], 7)
        self.assertAlmostEqual(out["h2_stream_reset_ratio"], 0.4, places=6)
        self.assertEqual(out["l7_capability_status"], "ok")

    def test_capability_status_inference_and_aggregate(self):
        missing = normalize_l7_stats(
            {"attempted": 4, "sent": 0, "errors": 4, "sender_path": "C_STATE_QUIC_UNAVAILABLE", "sender_fallback_reason": "quic_capability_unavailable"},
            attempted_default=4,
        )
        partial = normalize_l7_stats(
            {"attempted": 3, "sent": 0, "errors": 3, "sender_path": "C_STATE_QUIC", "sender_fallback_reason": "connect_fail"},
            attempted_default=3,
        )
        self.assertEqual(missing["l7_capability_status"], "missing")
        self.assertEqual(partial["l7_capability_status"], "partial")

        agg = aggregate_l7_stats([partial, {"attempted": 2, "sent": 2, "errors": 0}])
        self.assertEqual(agg["l7_capability_status"], "partial")

        agg_missing = aggregate_l7_stats([missing, {"attempted": 2, "sent": 2, "errors": 0}])
        self.assertEqual(agg_missing["l7_capability_status"], "missing")
