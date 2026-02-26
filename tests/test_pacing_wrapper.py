import unittest

from ddos_samurai import pacing


class TestPacingWrapper(unittest.TestCase):
    def test_normalize_stats_fills_defaults_and_types(self):
        out = pacing.normalize_stats(
            {
                "actual_rps": 123.4,
                "so_txtime_active": True,
                "txring_flush_last_errno_name": None,
                "ipg_histogram": (1, 2, 3),
            }
        )
        self.assertEqual(out["actual_rps"], 123.4)
        self.assertEqual(out["so_txtime_active"], 1)
        self.assertEqual(out["txring_flush_last_errno_name"], "NONE")
        self.assertEqual(out["ipg_histogram"], [1, 2, 3])
        self.assertIn("jitter_p99_ns", out)
        self.assertIn("txring_flush_enobufs_count", out)
        self.assertIn("txring_frame_wait_ns", out)

    def test_pacing_config_validate_enforces_mode_constraints(self):
        cfg = pacing.PacingConfig(
            pacing_mode=pacing.PacingMode.RPS,
            target_rps=0.0,
        )
        with self.assertRaises(ValueError):
            cfg.validate()

        cfg = pacing.PacingConfig(
            pacing_mode=pacing.PacingMode.IPG,
            ipg_ns=0,
        )
        with self.assertRaises(ValueError):
            cfg.as_kwargs()

    def test_pacing_config_validate_enforces_common_constraints(self):
        cfg = pacing.PacingConfig(jitter_pct=1.5)
        with self.assertRaises(ValueError):
            cfg.validate()

        cfg = pacing.PacingConfig(burst_size=0)
        with self.assertRaises(ValueError):
            cfg.validate()

        cfg = pacing.PacingConfig(burst_gap_ns=-1)
        with self.assertRaises(ValueError):
            cfg.validate()
