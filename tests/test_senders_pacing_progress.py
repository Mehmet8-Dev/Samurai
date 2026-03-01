import unittest

from ddos_samurai import senders
from ddos_samurai.pacing import PacingConfig, PacingMode


class TestPacingProgressEstimate(unittest.TestCase):
    def test_estimate_rps_respects_budget(self):
        cfg = PacingConfig(pacing_mode=PacingMode.RPS, target_rps=1000.0)
        self.assertEqual(
            senders._estimate_paced_packets(cfg, elapsed_s=0.5, progress_budget=1000),
            500,
        )
        self.assertEqual(
            senders._estimate_paced_packets(cfg, elapsed_s=3.0, progress_budget=1000),
            1000,
        )

    def test_estimate_ipg_respects_budget(self):
        cfg = PacingConfig(pacing_mode=PacingMode.IPG, ipg_ns=1_000_000)  # 1ms
        self.assertEqual(
            senders._estimate_paced_packets(cfg, elapsed_s=0.25, progress_budget=1000),
            250,
        )
        self.assertEqual(
            senders._estimate_paced_packets(cfg, elapsed_s=2.0, progress_budget=300),
            300,
        )


if __name__ == "__main__":
    unittest.main()
