import unittest

from ddos_samurai import cli


def _all_option_strings(parser):
    opts = set()
    for a in parser._actions:
        for s in getattr(a, "option_strings", []) or []:
            opts.add(s)
    return opts


class TestCliParser(unittest.TestCase):
    def test_parser_does_not_expose_removed_metrics_flags(self):
        parser = cli.build_parser()
        opts = _all_option_strings(parser)
        self.assertNotIn("--metrics-log", opts)
        self.assertNotIn("--metrics-port", opts)
        self.assertNotIn("--no-metrics", opts)
        self.assertNotIn("--adaptive", opts)
        self.assertNotIn("--feedback", opts)

    def test_attack_vector_choices_are_aligned_with_orchestrator(self):
        parser = cli.build_parser()
        action = next(a for a in parser._actions if a.dest == "attack_vector")
        self.assertEqual(
            set(action.choices),
            {
                "basic",
                "http",
                "http2",
                "dns",
                "websocket",
                "quic",
                "slowloris",
                "slow-post",
                "slow-read",
                "ntp-amp",
                "ssdp-amp",
                "dns-amp",
                "memcached-amp",
                "ldap-amp",
                "anomaly",
                "pcap-replay",
            },
        )

    def test_parser_has_expected_flags(self):
        parser = cli.build_parser()
        opts = _all_option_strings(parser)

        # core
        self.assertIn("--compute-backend", opts)
        self.assertIn("--workers", opts)
        self.assertIn("--attack-vector", opts)

        # packet shaping
        self.assertIn("--fragment", opts)
        self.assertIn("--fragment-size", opts)

        # safety
        self.assertIn("--allow-target", opts)
        self.assertIn("--allow-public-target", opts)

        # L7 / extra
        self.assertIn("--ninja-mode", opts)
        self.assertIn("--ws-path", opts)
        self.assertIn("--quic-path", opts)
        self.assertIn("--tls-profile", opts)
        self.assertIn("--h2-profile", opts)
        self.assertIn("--ja3-profile", opts)

    def test_ja3_profile_alias_sets_tls_profile(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--ja3-profile", "firefox_120"])
        cli._resolve_profile_args(parser, args, ["--ja3-profile", "firefox_120"])
        self.assertEqual(args.tls_profile, "firefox_120")
        self.assertEqual(args.ja3_profile, "firefox_120")

    def test_ja3_profile_alias_conflict_errors(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--tls-profile", "chrome_120", "--ja3-profile", "firefox_120"])
        with self.assertRaises(SystemExit):
            cli._resolve_profile_args(
                parser,
                args,
                ["--tls-profile", "chrome_120", "--ja3-profile", "firefox_120"],
            )


class TestRootGateRegression(unittest.TestCase):
    """Regression tests for the vector-based root privilege check (trex_path Görev #5).

    The root requirement should only apply to vectors that ACTUALLY use raw
    sockets. HTTP-layer vectors (http, http2, websocket, quic) use userspace
    sockets and must be runnable without root.
    """

    # This must match the set defined in cli.py main()
    EXPECTED_RAW_VECTORS = {
        "basic", "dns", "anomaly",
        "ntp-amp", "ssdp-amp", "dns-amp", "memcached-amp", "ldap-amp",
        "pcap-replay",
        "slowloris", "slow-post", "slow-read",
    }

    def test_root_required_vectors_match(self):
        """The set of raw-socket vectors in the test should match those in cli.py."""
        import inspect
        src = inspect.getsource(cli.main)
        # Verify the set is defined in main()
        self.assertIn("_RAW_SOCKET_VECTORS", src)
        for v in self.EXPECTED_RAW_VECTORS:
            self.assertIn(f'"{v}"', src, f"Vector '{v}' should be in _RAW_SOCKET_VECTORS")

    def test_http_vectors_not_in_root_gate(self):
        """HTTP-layer vectors should NOT require root."""
        import inspect
        src = inspect.getsource(cli.main)
        for v in ("http", "http2", "websocket", "quic"):
            # These should NOT appear in the raw socket vectors set
            # (but they might appear elsewhere in main, so check specifically)
            self.assertNotIn(
                f'"{v}"', src.split("_RAW_SOCKET_VECTORS")[1].split("}")[0],
                f"Vector '{v}' should NOT be in _RAW_SOCKET_VECTORS",
            )


class TestBuildTestCommandRegression(unittest.TestCase):
    """Regression tests for _build_test_command API->CLI mapping (trex_path Görev #3)."""

    def test_tls_profile_uses_ja3_field_not_user_agent(self):
        """--tls-profile should map from ja3_profile, not user_agent."""
        from ddos_samurai.saas_schemas import TestStartRequest
        from ddos_samurai.api import _build_test_command

        payload = TestStartRequest(
            target="127.0.0.1",
            port=80,
            user_agent="chrome_120",
            ja3_profile="firefox_120",
        )
        cmd = _build_test_command(payload)
        # Find --tls-profile value
        idx = cmd.index("--tls-profile")
        tls_val = cmd[idx + 1]
        self.assertEqual(tls_val, "firefox_120",
                         "Should use ja3_profile field, not user_agent")

    def test_h2_profile_uses_dedicated_field(self):
        """--h2-profile should map from h2_profile field for http2 vector."""
        from ddos_samurai.saas_schemas import TestStartRequest
        from ddos_samurai.api import _build_test_command

        payload = TestStartRequest(
            target="127.0.0.1",
            port=443,
            attack_vector="http2",
            user_agent="chrome_120",
            h2_profile="edge_120",
        )
        cmd = _build_test_command(payload)
        idx = cmd.index("--h2-profile")
        h2_val = cmd[idx + 1]
        self.assertEqual(h2_val, "edge_120",
                         "Should use h2_profile field, not user_agent")

    def test_tls_profile_falls_back_to_user_agent_when_none(self):
        """When ja3_profile is 'none', --tls-profile should fallback to user_agent."""
        from ddos_samurai.saas_schemas import TestStartRequest
        from ddos_samurai.api import _build_test_command

        payload = TestStartRequest(
            target="127.0.0.1",
            port=80,
            user_agent="chrome_120",
            ja3_profile="none",
        )
        cmd = _build_test_command(payload)
        idx = cmd.index("--tls-profile")
        tls_val = cmd[idx + 1]
        self.assertEqual(tls_val, "chrome_120",
                         "Should fallback to user_agent when ja3_profile is 'none'")
