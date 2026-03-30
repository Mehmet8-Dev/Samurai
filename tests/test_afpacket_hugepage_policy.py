import unittest

from ddos_samurai import dataplane
from ddos_samurai import senders


class TestAfpacketHugepagePolicy(unittest.TestCase):
    def test_dataplane_config_dedicated_txring_forces_required(self):
        cfg = dataplane.build_dataplane_config(
            {
                "sender_backend": "txring",
                "lab_profile": "dedicated",
                "afpacket_hugepage_mode": "off",
            }
        )
        self.assertEqual(cfg.afpacket_hugepage_mode, "required")

    def test_apply_pacing_stats_propagates_afpacket_fields(self):
        out = senders._apply_pacing_stats(
            {"attempted": 10, "sent": 10, "errors": 0},
            {
                "afpacket_hugepage_mode": "required",
                "afpacket_hugepage_effective": 1,
                "afpacket_hugepage_reason": "effective",
                "afpacket_hugepage_size_kb": 2048,
                "afpacket_madvise_hugepage_ok": 1,
                "afpacket_mlock_ok": 0,
                "afpacket_prefault_pages": 12,
                "afpacket_smaps_kernel_page_kb": 2048,
                "afpacket_smaps_anon_hugepages_kb": 4096,
                "afpacket_ring_block_size": 4096,
                "afpacket_ring_block_nr": 64,
                "afpacket_ring_size_bytes": 262144,
            },
        )
        self.assertEqual(out["afpacket_hugepage_mode"], "required")
        self.assertEqual(out["afpacket_hugepage_effective"], 1)
        self.assertEqual(out["afpacket_hugepage_reason"], "effective")
        self.assertEqual(out["afpacket_ring_block_nr"], 64)

    def test_apply_pacing_stats_required_not_met_sets_fallback_reason(self):
        out = senders._apply_pacing_stats(
            {"attempted": 10, "sent": 0, "errors": 10, "sender_fallback_reason": "none", "fallback_count": 0},
            {
                "afpacket_hugepage_mode": "required",
                "afpacket_hugepage_effective": 0,
                "afpacket_hugepage_reason": "hinted_not_realized",
            },
        )
        self.assertEqual(out["sender_fallback_reason"], "afpacket_hugepage_required_not_met")
        self.assertGreaterEqual(int(out.get("fallback_count", 0) or 0), 1)

    def test_dataplane_config_maps_mode2_policy_from_fallback_policy(self):
        cfg_fail = dataplane.build_dataplane_config(
            {
                "sender_backend": "xdp",
                "sender_fallback_policy": "fail",
                "xdp_mode": 2,
            }
        )
        self.assertEqual(cfg_fail.xdp_mode2_policy, "hard")

        cfg_allow = dataplane.build_dataplane_config(
            {
                "sender_backend": "xdp",
                "sender_fallback_policy": "allow",
                "xdp_mode": 2,
            }
        )
        self.assertEqual(cfg_allow.xdp_mode2_policy, "soft")

    def test_dataplane_config_mode2_policy_invalid_value_is_normalized(self):
        cfg = dataplane.build_dataplane_config(
            {
                "sender_backend": "xdp",
                "sender_fallback_policy": "fail",
                "xdp_mode": 2,
                "xdp_mode2_policy": "invalid",
            }
        )
        self.assertEqual(cfg.xdp_mode2_policy, "hard")


if __name__ == "__main__":
    unittest.main()
