import unittest

from ddos_samurai import h2_mimic


class TestH2Mimic(unittest.TestCase):
    def test_resolve_none_profile(self):
        self.assertIsNone(h2_mimic.resolve_h2_profile("none"))

    def test_resolve_empty_uses_default_profile(self):
        profile = h2_mimic.resolve_h2_profile("")
        self.assertIsNotNone(profile)
        self.assertEqual(profile.name, "chrome_120")

    def test_resolve_unknown_profile_raises(self):
        with self.assertRaises(ValueError):
            h2_mimic.resolve_h2_profile("unknown_profile")

    def test_apply_disabled_profile_is_fail_visible(self):
        cfg = h2_mimic.apply_h2_profile(client=None, profile_name="none")
        self.assertFalse(cfg.applied)
        self.assertEqual(cfg.reason, "profile_disabled")

    def test_apply_known_profile_without_supported_transport_is_fail_visible(self):
        cfg = h2_mimic.apply_h2_profile(client=object(), profile_name="chrome_120")
        self.assertFalse(cfg.applied)
        self.assertEqual(cfg.resolved, "chrome_120")
        self.assertIn(cfg.reason, {"unsupported_client", "transport_does_not_expose_h2_settings"})
