import argparse
import unittest

from ddos_samurai.cli.profile_resolver import apply_profile


class TestProfileResolver(unittest.TestCase):
    def test_profile_does_not_override_explicit_cli_arg(self):
        args = argparse.Namespace(
            profile="web-stress",
            count=123,
            attack_vector="basic",
            protocol="tcp",
            port=80,
            workers=1,
            http_method="GET",
            http_path=["/"],
            stealth_mode=False,
            payload_mutation=False,
        )
        apply_profile(args, ["--profile", "web-stress", "--count", "123"])
        self.assertEqual(args.count, 123)
        self.assertEqual(args.attack_vector, "http")
