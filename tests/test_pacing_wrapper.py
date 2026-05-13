import unittest
from unittest.mock import patch

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
        self.assertIn("afpacket_hugepage_mode", out)
        self.assertIn("afpacket_hugepage_effective", out)
        self.assertIn("afpacket_ring_size_bytes", out)
        self.assertIn("xdp_mode_requested", out)
        self.assertIn("xdp_mode_effective", out)
        self.assertIn("xdp_mode2_probe_status", out)

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

    def test_get_stats_contract_when_engine_available(self):
        if not pacing.PACING_ENGINE_AVAILABLE:
            self.skipTest("pacing engine extension unavailable")
        pacing.reset_stats()
        out = pacing.get_stats()
        self.assertIsInstance(out, dict)
        self.assertIn("spin_threshold_ns", out)
        self.assertIn("afpacket_hugepage_mode", out)
        self.assertIn("afpacket_hugepage_effective", out)
        self.assertIn("afpacket_ring_size_bytes", out)

    def test_check_capabilities_etf_probe_contract(self):
        with patch.object(pacing, "_find_tool") as m_find, patch.object(pacing, "_run_cmd_capture") as m_run:
            def _fake_find(name):
                if name == "tc":
                    return "/usr/sbin/tc"
                if name == "ethtool":
                    return "/usr/sbin/ethtool"
                return None

            m_find.side_effect = _fake_find
            m_run.side_effect = [
                (
                    0,
                    "qdisc etf 8001: dev eth0 root refcnt 2 clockid CLOCK_TAI delta 200000 offload\n",
                    "",
                ),
                (
                    0,
                    "Time stamping parameters for eth0\n"
                    "Capabilities:\n"
                    "hardware-transmit\n"
                    "SOF_TIMESTAMPING_TX_SCHED\n"
                    "Hardware Transmit Timestamp Modes:\n"
                    "off\n"
                    "on\n",
                    "",
                ),
            ]
            caps = pacing.check_capabilities(iface="eth0")

        self.assertEqual(int(caps.get("tc_available", 0)), 1)
        self.assertEqual(int(caps.get("etf_qdisc_present", 0)), 1)
        self.assertEqual(str(caps.get("etf_clockid", "")), "CLOCK_TAI")
        self.assertEqual(int(caps.get("etf_delta_ns", 0)), 200000)
        self.assertEqual(int(caps.get("etf_offload", 0)), 1)
        self.assertEqual(int(caps.get("ethtool_available", 0)), 1)
        self.assertEqual(int(caps.get("ethtool_tx_sched_timestamp", 0)), 1)
        self.assertIn("etf_ready", caps)

    def test_check_capabilities_accepts_tai_clockid_alias(self):
        with patch.object(pacing, "_find_tool") as m_find, patch.object(pacing, "_run_cmd_capture") as m_run:
            def _fake_find(name):
                if name == "tc":
                    return "/usr/sbin/tc"
                if name == "ethtool":
                    return "/usr/sbin/ethtool"
                return None

            m_find.side_effect = _fake_find
            m_run.side_effect = [
                (
                    0,
                    "qdisc etf 8001: dev eth0 root refcnt 2 clockid TAI delta 200000\n",
                    "",
                ),
                (0, "Time stamping parameters for eth0\nCapabilities:\n", ""),
            ]
            caps = pacing.check_capabilities(iface="eth0")

        self.assertEqual(int(caps.get("etf_qdisc_present", 0)), 1)
        self.assertEqual(str(caps.get("etf_clockid", "")), "TAI")
        self.assertIn("etf_ready", caps)

    def test_ensure_etf_qdisc_dry_run(self):
        with patch.object(pacing, "_find_tool", return_value="/usr/sbin/tc"):
            out = pacing.ensure_etf_qdisc(
                "eth0",
                delta_ns=300000,
                offload=True,
                parent="root",
                replace=True,
                strict=True,
                dry_run=True,
            )
        self.assertEqual(int(out.get("ok", 0)), 1)
        self.assertEqual(int(out.get("dry_run", 0)), 1)
        self.assertIn("qdisc replace dev eth0 root etf", str(out.get("cmd", "")))
