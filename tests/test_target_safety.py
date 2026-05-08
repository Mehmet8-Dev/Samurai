import unittest

from ddos_samurai import utils


class TestTargetSafety(unittest.TestCase):
    def test_default_policy(self):
        cases = [
            ("127.0.0.1", True),
            ("10.0.0.1", True),
            ("192.168.1.10", True),
            ("8.8.8.8", False),
        ]
        for ip, expected_ok in cases:
            with self.subTest(ip=ip):
                ok, _msg = utils.validate_target_safety(ip)
                self.assertEqual(ok, expected_ok)

    def test_allows_public_with_flag(self):
        ok, _msg = utils.validate_target_safety("8.8.8.8", allow_public=True)
        self.assertTrue(ok)

    def test_rejects_invalid_ip(self):
        ok, msg = utils.validate_target_safety("not-an-ip")
        self.assertFalse(ok)
        self.assertIn("Geçersiz", msg)

    def test_rejects_ipv6_targets(self):
        ok, msg = utils.validate_target_safety("::1")
        self.assertFalse(ok)
        self.assertIn("IPv4", msg)

    def test_rejects_multicast(self):
        ok, msg = utils.validate_target_safety("224.0.0.1")
        self.assertFalse(ok)
        self.assertIn("multicast", msg.lower())

    def test_rejects_unspecified(self):
        ok, msg = utils.validate_target_safety("0.0.0.0")
        self.assertFalse(ok)
        self.assertIn("geçersiz", msg.lower())

    def test_allowlist_cidr_match(self):
        ok, _msg = utils.validate_target_safety("10.123.45.6", allow_targets=["10.0.0.0/8"])
        self.assertTrue(ok)

    def test_allowlist_ip_match(self):
        ok, _msg = utils.validate_target_safety("192.168.1.10", allow_targets=["192.168.1.10"])
        self.assertTrue(ok)

    def test_allowlist_mismatch_blocks(self):
        ok, msg = utils.validate_target_safety("192.168.1.10", allow_targets=["10.0.0.0/8"])
        self.assertFalse(ok)
        self.assertIn("allowlist", msg.lower())

    def test_invalid_allowlist_entry_blocks(self):
        ok, msg = utils.validate_target_safety("10.0.0.1", allow_targets=["bad/cidr"])
        self.assertFalse(ok)
        self.assertIn("allowlist", msg.lower())

    def test_global_denylist_cidr_blocks_even_when_public_allowed(self):
        ok, msg = utils.validate_target_safety(
            "8.8.8.8",
            allow_public=True,
            deny_targets=["8.8.0.0/16"],
        )
        self.assertFalse(ok)
        self.assertIn("denylist", msg.lower())

    def test_invalid_denylist_entry_blocks(self):
        ok, msg = utils.validate_target_safety("10.0.0.1", deny_targets=["bad/cidr"])
        self.assertFalse(ok)
        self.assertIn("denylist", msg.lower())
