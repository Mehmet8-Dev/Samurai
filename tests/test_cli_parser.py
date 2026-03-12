import importlib.util
import unittest
import io
import os
from contextlib import redirect_stderr
from unittest.mock import patch

from ddos_samurai import cli

_SAAS_MODULES_AVAILABLE = (
    importlib.util.find_spec("ddos_samurai.saas_schemas") is not None
    and importlib.util.find_spec("ddos_samurai.api") is not None
)


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
        self.assertIn("--quic-streams-per-conn", opts)
        self.assertIn("--quic-requests-per-conn", opts)
        self.assertIn("--quic-conn-pool-size", opts)
        self.assertIn("--quic-expect-status-min", opts)
        self.assertIn("--quic-expect-status-max", opts)
        self.assertIn("--quic-require-response-headers", opts)
        self.assertIn("--quic-require-response-body", opts)
        self.assertIn("--quic-min-response-body-bytes", opts)
        self.assertIn("--tls-profile", opts)
        self.assertIn("--h2-profile", opts)
        self.assertIn("--ja3-profile", opts)
        self.assertIn("--loss-telemetry", opts)
        self.assertIn("--loss-iface", opts)
        self.assertIn("--loss-fail-pct", opts)
        self.assertIn("--loss-report-out", opts)
        self.assertIn("--gpu-template-pool-size-l4", opts)
        self.assertIn("--gpu-template-pool-size-l7", opts)
        self.assertIn("--gpu-ring-capacity", opts)
        self.assertIn("--gpu-batch-size", opts)
        self.assertIn("--gpu-stream-count", opts)
        self.assertIn("--gpu-pipeline-depth", opts)
        self.assertIn("--gpu-full-variation", opts)
        self.assertIn("--no-gpu-full-variation", opts)
        self.assertIn("--gpu-pinned-max-mb", opts)
        self.assertIn("--gpu-rng-seed", opts)
        self.assertIn("--state-table-size", opts)
        self.assertIn("--state-lock-count", opts)
        self.assertIn("--state-timeout-sec", opts)
        self.assertIn("--state-sweep-interval-ms", opts)
        self.assertIn("--sender-backend", opts)
        self.assertIn("--sender-fallback-policy", opts)
        self.assertIn("--dataplane-core-mode", opts)
        self.assertIn("--afpacket-hugepage-mode", opts)
        self.assertIn("--afpacket-hugepage-size-kb", opts)
        self.assertIn("--afpacket-ring-target-mb", opts)
        self.assertIn("--afpacket-block-size-kb", opts)
        self.assertIn("--afpacket-frame-size", opts)
        self.assertIn("--afpacket-frames-per-block", opts)
        self.assertIn("--afpacket-poll-timeout-ms", opts)
        self.assertIn("--afpacket-spin-limit", opts)
        self.assertIn("--afpacket-busy-poll-us", opts)
        self.assertIn("--afpacket-qdisc-bypass", opts)
        self.assertIn("--no-afpacket-qdisc-bypass", opts)
        self.assertIn("--afpacket-mlock-ring", opts)
        self.assertIn("--no-afpacket-mlock-ring", opts)
        self.assertIn("--afpacket-prefault-ring", opts)
        self.assertIn("--no-afpacket-prefault-ring", opts)
        self.assertIn("--lab-profile", opts)
        self.assertIn("--dp-queue-strategy", opts)
        self.assertIn("--dp-queues", opts)
        self.assertIn("--dp-queue-map", opts)
        self.assertIn("--xdp-enable", opts)
        self.assertIn("--xdp-interface", opts)
        self.assertIn("--xdp-queue-id", opts)
        self.assertIn("--kpi-gate-profile", opts)
        self.assertIn("--kpi-hard-fail", opts)
        self.assertIn("--l7-engine", opts)
        self.assertIn("--l7-http2-engine", opts)
        self.assertIn("--l7-quic-engine", opts)
        self.assertIn("--l7-quic-require-native", opts)
        self.assertIn("--l7-quic-auto-bridge", opts)
        self.assertIn("--l7-quic-bridge-autopromote", opts)
        self.assertIn("--l7-fallback-policy", opts)
        self.assertIn("--l7-capability-strict", opts)
        self.assertIn("--legacy-path-enable", opts)
        self.assertIn("--http2-connections", opts)
        self.assertIn("--http2-streams-per-conn", opts)
        self.assertIn("--l7-session-repeats", opts)
        self.assertIn("--l7-max-active-sessions", opts)
        self.assertIn("--quic-expect-header-name", opts)
        self.assertIn("--quic-expect-header-value-contains", opts)
        self.assertIn("--quic-expect-body-substring", opts)

    def test_sender_route_defaults(self):
        parser = cli.build_parser()
        args = parser.parse_args([])
        self.assertEqual(args.sender_backend, "auto")
        self.assertEqual(args.sender_fallback_policy, "allow")
        self.assertEqual(args.dataplane_core_mode, "off")
        self.assertEqual(args.afpacket_hugepage_mode, "off")
        self.assertEqual(args.afpacket_hugepage_size_kb, 2048)
        self.assertEqual(args.afpacket_ring_target_mb, 64)
        self.assertEqual(args.afpacket_block_size_kb, 0)
        self.assertEqual(args.afpacket_frame_size, 0)
        self.assertEqual(args.afpacket_frames_per_block, 64)
        self.assertEqual(args.afpacket_poll_timeout_ms, 1)
        self.assertEqual(args.afpacket_spin_limit, 2000)
        self.assertEqual(args.afpacket_busy_poll_us, 0)
        self.assertTrue(args.afpacket_qdisc_bypass)
        self.assertFalse(args.afpacket_mlock_ring)
        self.assertTrue(args.afpacket_prefault_ring)
        self.assertEqual(args.lab_profile, "off")
        self.assertEqual(args.dp_queue_strategy, "rr")
        self.assertEqual(args.dp_queues, 1)
        self.assertEqual(args.dp_queue_map, "")
        self.assertFalse(args.xdp_enable)
        self.assertEqual(args.xdp_interface, "")
        self.assertEqual(args.xdp_queue_id, 0)
        self.assertEqual(args.kpi_gate_profile, "off")
        self.assertFalse(args.kpi_hard_fail)
        self.assertEqual(args.l7_engine, "python")
        self.assertEqual(args.l7_http2_engine, "auto")
        self.assertEqual(args.l7_quic_engine, "auto")
        self.assertFalse(args.l7_quic_require_native)
        self.assertFalse(args.l7_quic_auto_bridge)
        self.assertFalse(args.l7_quic_bridge_autopromote)
        self.assertEqual(args.quic_streams_per_conn, 0)
        self.assertEqual(args.quic_requests_per_conn, 0)
        self.assertEqual(args.quic_conn_pool_size, 1)
        self.assertEqual(args.quic_expect_status_min, 200)
        self.assertEqual(args.quic_expect_status_max, 399)
        self.assertTrue(args.quic_require_response_headers)
        self.assertFalse(args.quic_require_response_body)
        self.assertEqual(args.quic_min_response_body_bytes, 0)
        self.assertEqual(args.quic_expect_header_name, "")
        self.assertEqual(args.quic_expect_header_value_contains, "")
        self.assertEqual(args.quic_expect_body_substring, "")
        self.assertEqual(args.l7_fallback_policy, "allow")
        self.assertFalse(args.l7_capability_strict)
        self.assertFalse(args.legacy_path_enable)
        self.assertEqual(args.gpu_batch_size, 100000)
        self.assertEqual(args.gpu_stream_count, 3)
        self.assertEqual(args.gpu_pipeline_depth, 2)
        self.assertTrue(args.gpu_full_variation)
        self.assertEqual(args.http2_connections, 1)
        self.assertEqual(args.http2_streams_per_conn, 100)
        self.assertEqual(args.l7_session_repeats, 1)
        self.assertEqual(args.l7_max_active_sessions, 0)

    def test_loss_telemetry_flags_defaults(self):
        parser = cli.build_parser()
        args = parser.parse_args([])
        self.assertEqual(args.loss_telemetry, "auto")
        self.assertEqual(args.loss_iface, "")
        self.assertEqual(args.loss_fail_pct, 5.0)
        self.assertEqual(args.loss_report_out, "")

    def test_loss_telemetry_flags_parse(self):
        parser = cli.build_parser()
        args = parser.parse_args(
            [
                "--loss-telemetry", "1",
                "--loss-iface", "eth0",
                "--loss-fail-pct", "7.5",
                "--loss-report-out", "artifacts/loss.json",
            ]
        )
        self.assertEqual(args.loss_telemetry, "1")
        self.assertEqual(args.loss_iface, "eth0")
        self.assertEqual(args.loss_fail_pct, 7.5)
        self.assertEqual(args.loss_report_out, "artifacts/loss.json")

    def test_hybrid_flags_read_env_defaults(self):
        with patch.dict(
            os.environ,
            {
                "SAMURAI_GPU_TEMPLATE_POOL_SIZE_L4": "11",
                "SAMURAI_GPU_TEMPLATE_POOL_SIZE_L7": "55",
                "SAMURAI_GPU_RING_CAPACITY": "4",
                "SAMURAI_GPU_BATCH": "131072",
                "SAMURAI_GPU_STREAMS": "5",
                "SAMURAI_GPU_PIPELINE_DEPTH": "3",
                "SAMURAI_GPU_FULL_VARIATION": "0",
                "SAMURAI_GPU_PINNED_MAX_MB": "256",
                "SAMURAI_GPU_RNG_SEED": "987654",
                "SAMURAI_STATE_TABLE_SIZE": "32768",
                "SAMURAI_STATE_LOCK_COUNT": "128",
                "SAMURAI_STATE_TIMEOUT_SEC": "45",
                "SAMURAI_STATE_SWEEP_INTERVAL_MS": "1500",
            },
            clear=False,
        ):
            parser = cli.build_parser()
            args = parser.parse_args([])
            self.assertEqual(args.gpu_template_pool_size_l4, 11)
            self.assertEqual(args.gpu_template_pool_size_l7, 55)
            self.assertEqual(args.gpu_ring_capacity, 4)
            self.assertEqual(args.gpu_batch_size, 131072)
            self.assertEqual(args.gpu_stream_count, 5)
            self.assertEqual(args.gpu_pipeline_depth, 3)
            self.assertFalse(args.gpu_full_variation)
            self.assertEqual(args.gpu_pinned_max_mb, 256)
            self.assertEqual(args.gpu_rng_seed, 987654)
            self.assertEqual(args.state_table_size, 32768)
            self.assertEqual(args.state_lock_count, 128)
            self.assertEqual(args.state_timeout_sec, 45)
            self.assertEqual(args.state_sweep_interval_ms, 1500)

    def test_ja3_profile_alias_sets_tls_profile(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--ja3-profile", "firefox_120"])
        cli._resolve_profile_args(parser, args, ["--ja3-profile", "firefox_120"])
        self.assertEqual(args.tls_profile, "firefox_120")
        self.assertEqual(args.ja3_profile, "firefox_120")

    def test_ja3_profile_alias_conflict_errors(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--tls-profile", "chrome_120", "--ja3-profile", "firefox_120"])
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                cli._resolve_profile_args(
                    parser,
                    args,
                    ["--tls-profile", "chrome_120", "--ja3-profile", "firefox_120"],
                )


class TestPacingArgValidation(unittest.TestCase):
    def _assert_validation_fails(self, parser, args):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                cli._validate_pacing_args(parser, args)

    def test_validate_pacing_args_requires_positive_rps_in_rps_mode(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--pacing-mode", "rps", "--rps", "0"])
        self._assert_validation_fails(parser, args)

    def test_validate_pacing_args_requires_positive_ipg_in_ipg_mode(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--pacing-mode", "ipg", "--ipg", "0"])
        self._assert_validation_fails(parser, args)

    def test_validate_pacing_args_requires_burst_size_in_burst_mode(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--pacing-mode", "burst", "--burst-size", "0"])
        self._assert_validation_fails(parser, args)

    def test_validate_pacing_args_rejects_out_of_range_jitter(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--jitter-pct", "1.2"])
        self._assert_validation_fails(parser, args)

    def test_validate_pacing_args_rejects_negative_burst_gap(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--burst-gap", "-1"])
        self._assert_validation_fails(parser, args)

    def test_validate_pacing_args_logs_auto_promote_hint(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--rps", "1000", "--pacing-mode", "none"])
        with patch.object(cli.utils, "log_info") as mock_log:
            cli._validate_pacing_args(parser, args)
            mock_log.assert_called_once()


class TestHybridArgValidation(unittest.TestCase):
    def _assert_validation_fails(self, parser, args):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                cli._validate_hybrid_cuda_args(parser, args)

    def test_rejects_non_divisible_state_table_config(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--state-table-size", "1000", "--state-lock-count", "256"])
        self._assert_validation_fails(parser, args)

    def test_accepts_valid_state_table_config(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--state-table-size", "65536", "--state-lock-count", "256"])
        cli._validate_hybrid_cuda_args(parser, args)


class TestSenderRouteValidation(unittest.TestCase):
    def _assert_validation_fails(self, parser, args):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                cli._validate_sender_route_args(parser, args)

    def test_sender_backend_xdp_requires_interface(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--sender-backend", "xdp"])
        self._assert_validation_fails(parser, args)

    def test_xdp_enable_requires_interface(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--xdp-enable"])
        self._assert_validation_fails(parser, args)

    def test_sender_fallback_fail_forbids_auto_backend(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--sender-backend", "auto", "--sender-fallback-policy", "fail"])
        self._assert_validation_fails(parser, args)

    def test_afpacket_required_requires_txring_backend(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--afpacket-hugepage-mode", "required", "--sender-backend", "python"])
        self._assert_validation_fails(parser, args)

    def test_afpacket_hugepage_size_validation(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--afpacket-hugepage-size-kb", "0", "--sender-backend", "txring"])
        self._assert_validation_fails(parser, args)

    def test_afpacket_block_size_validation(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--afpacket-block-size-kb", "-1", "--sender-backend", "txring"])
        self._assert_validation_fails(parser, args)

    def test_afpacket_frame_size_validation(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--afpacket-frame-size", "-1", "--sender-backend", "txring"])
        self._assert_validation_fails(parser, args)

    def test_afpacket_frames_per_block_validation(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--afpacket-frames-per-block", "0", "--sender-backend", "txring"])
        self._assert_validation_fails(parser, args)

    def test_afpacket_poll_timeout_validation(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--afpacket-poll-timeout-ms", "-1", "--sender-backend", "txring"])
        self._assert_validation_fails(parser, args)

    def test_afpacket_spin_limit_validation(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--afpacket-spin-limit", "-1", "--sender-backend", "txring"])
        self._assert_validation_fails(parser, args)

    def test_afpacket_busy_poll_validation(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--afpacket-busy-poll-us", "-1", "--sender-backend", "txring"])
        self._assert_validation_fails(parser, args)

    def test_dataplane_required_requires_fail_policy(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--dataplane-core-mode", "required"])
        self._assert_validation_fails(parser, args)

    def test_dp_queue_map_requires_map_spec(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--dp-queue-strategy", "map"])
        self._assert_validation_fails(parser, args)

    def test_dp_queue_map_rejects_invalid_format(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--dp-queue-strategy", "map", "--dp-queue-map", "1=0"])
        self._assert_validation_fails(parser, args)

    def test_kpi_hard_fail_requires_profile(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--kpi-hard-fail"])
        self._assert_validation_fails(parser, args)

    def test_kpi_gate_profile_accepts_dev_and_ci_safe(self):
        parser = cli.build_parser()
        args_dev = parser.parse_args(["--kpi-gate-profile", "dev"])
        args_ci = parser.parse_args(["--kpi-gate-profile", "ci_safe"])
        cli._validate_sender_route_args(parser, args_dev)
        cli._validate_sender_route_args(parser, args_ci)

    def test_l7_quic_require_native_requires_capability_strict(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--l7-quic-require-native"])
        self._assert_validation_fails(parser, args)

    def test_l7_quic_require_native_rejects_python_engine(self):
        parser = cli.build_parser()
        args = parser.parse_args(
            ["--l7-quic-require-native", "--l7-capability-strict", "--l7-quic-engine", "python"]
        )
        self._assert_validation_fails(parser, args)

    def test_l7_quic_require_native_rejects_auto_bridge(self):
        parser = cli.build_parser()
        args = parser.parse_args(
            ["--l7-quic-require-native", "--l7-capability-strict", "--l7-quic-auto-bridge"]
        )
        self._assert_validation_fails(parser, args)

    def test_l7_quic_require_native_rejects_bridge_autopromote(self):
        parser = cli.build_parser()
        args = parser.parse_args(
            ["--l7-quic-require-native", "--l7-capability-strict", "--l7-quic-bridge-autopromote"]
        )
        self._assert_validation_fails(parser, args)

    def test_quic_expect_status_range_validation(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--quic-expect-status-min", "500", "--quic-expect-status-max", "399"])
        self._assert_validation_fails(parser, args)

    def test_quic_conn_pool_size_must_be_positive(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--quic-conn-pool-size", "0"])
        self._assert_validation_fails(parser, args)

    def test_quic_expect_header_name_length_validation(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--quic-expect-header-name", "x" * 64])
        self._assert_validation_fails(parser, args)

    def test_quic_expect_header_value_contains_length_validation(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--quic-expect-header-value-contains", "x" * 160])
        self._assert_validation_fails(parser, args)

    def test_quic_expect_body_substring_length_validation(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--quic-expect-body-substring", "x" * 160])
        self._assert_validation_fails(parser, args)

    def test_sender_route_accepts_explicit_xdp_config(self):
        parser = cli.build_parser()
        args = parser.parse_args(
            [
                "--sender-backend",
                "xdp",
                "--sender-fallback-policy",
                "fail",
                "--xdp-interface",
                "eth0",
                "--xdp-queue-id",
                "1",
            ]
        )
        cli._validate_sender_route_args(parser, args)

    def test_dedicated_profile_autopromotes_afpacket_required_for_txring(self):
        parser = cli.build_parser()
        args = parser.parse_args(
            [
                "--lab-profile",
                "dedicated",
                "--sender-backend",
                "txring",
                "--sender-fallback-policy",
                "fail",
                "--xdp-interface",
                "eth0",
            ]
        )
        with patch("ddos_samurai.af_xdp_sender.get_interface_queue_count", return_value=8):
            cli._preflight_lab_profile(parser, args)
        self.assertEqual(args.afpacket_hugepage_mode, "required")


class TestL7CapabilityPreflight(unittest.TestCase):
    def _assert_preflight_fails(self, parser, args):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                cli._preflight_l7_capabilities(parser, args)

    def test_capability_strict_http2_fails_when_c_capability_missing(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--attack-vector", "http2", "--l7-capability-strict", "--l7-http2-engine", "c_state"])
        with patch("ddos_samurai.l7.c_adapter.capability_map", return_value={"core_available": True, "http1": True, "ws": True, "http2": False, "quic": True}):
            self._assert_preflight_fails(parser, args)

    def test_capability_strict_http2_passes_when_capability_present(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--attack-vector", "http2", "--l7-capability-strict", "--l7-http2-engine", "c_state"])
        with patch("ddos_samurai.l7.c_adapter.capability_map", return_value={"core_available": True, "http1": True, "ws": True, "http2": True, "quic": True}):
            cli._preflight_l7_capabilities(parser, args)

    def test_dedicated_profile_rejects_python_engine_for_http2(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--attack-vector", "http2", "--lab-profile", "dedicated", "--l7-capability-strict", "--l7-http2-engine", "python"])
        with patch("ddos_samurai.l7.c_adapter.capability_map", return_value={"core_available": True, "http1": True, "ws": True, "http2": True, "quic": True}):
            self._assert_preflight_fails(parser, args)

    def test_capability_strict_quic_rejects_probe_only_mode(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--attack-vector", "quic", "--l7-capability-strict", "--l7-quic-engine", "c_state"])
        with patch(
            "ddos_samurai.l7.c_adapter.capability_map",
            return_value={
                "core_available": True,
                "http1": True,
                "ws": True,
                "http2": True,
                "quic": True,
                "quic_stack_mode": "probe_udp",
                "quic_h3_stateful": False,
            },
        ):
            self._assert_preflight_fails(parser, args)

    def test_capability_strict_quic_accepts_h3_stateful_mode(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--attack-vector", "quic", "--l7-capability-strict", "--l7-quic-engine", "c_state"])
        with patch(
            "ddos_samurai.l7.c_adapter.capability_map",
            return_value={
                "core_available": True,
                "http1": True,
                "ws": True,
                "http2": True,
                "quic": True,
                "quic_stack_mode": "h3_stateful",
                "quic_h3_stateful": True,
            },
        ):
            cli._preflight_l7_capabilities(parser, args)

    def test_capability_strict_quic_accepts_h3_stateful_py_mode(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--attack-vector", "quic", "--l7-capability-strict", "--l7-quic-engine", "c_state"])
        with patch(
            "ddos_samurai.l7.c_adapter.capability_map",
            return_value={
                "core_available": True,
                "http1": True,
                "ws": True,
                "http2": True,
                "quic": True,
                "quic_stack_mode": "h3_stateful_py",
                "quic_h3_stateful": True,
            },
        ):
            cli._preflight_l7_capabilities(parser, args)

    def test_dedicated_strict_quic_rejects_h3_stateful_py_without_explicit_flag(self):
        parser = cli.build_parser()
        args = parser.parse_args(
            ["--attack-vector", "quic", "--lab-profile", "dedicated", "--l7-capability-strict", "--l7-quic-engine", "c_state"]
        )
        with patch(
            "ddos_samurai.l7.c_adapter.capability_map",
            return_value={
                "core_available": True,
                "http1": True,
                "ws": True,
                "http2": True,
                "quic": True,
                "quic_stack_mode": "h3_stateful_py",
                "quic_h3_stateful": True,
            },
        ):
            self._assert_preflight_fails(parser, args)

    def test_capability_strict_quic_require_native_rejects_h3_stateful_py_mode(self):
        parser = cli.build_parser()
        args = parser.parse_args(
            [
                "--attack-vector",
                "quic",
                "--l7-capability-strict",
                "--l7-quic-engine",
                "c_state",
                "--l7-quic-require-native",
            ]
        )
        with patch(
            "ddos_samurai.l7.c_adapter.capability_map",
            return_value={
                "core_available": True,
                "http1": True,
                "ws": True,
                "http2": True,
                "quic": True,
                "quic_stack_mode": "h3_stateful_py",
                "quic_h3_stateful": True,
            },
        ):
            self._assert_preflight_fails(parser, args)

    def test_capability_strict_quic_require_native_accepts_native_mode(self):
        parser = cli.build_parser()
        args = parser.parse_args(
            [
                "--attack-vector",
                "quic",
                "--l7-capability-strict",
                "--l7-quic-engine",
                "c_state",
                "--l7-quic-require-native",
            ]
        )
        with patch(
            "ddos_samurai.l7.c_adapter.capability_map",
            return_value={
                "core_available": True,
                "http1": True,
                "ws": True,
                "http2": True,
                "quic": True,
                "quic_stack_mode": "h3_stateful",
                "quic_h3_stateful": True,
            },
        ):
            cli._preflight_l7_capabilities(parser, args)


class TestRootGateRegression(unittest.TestCase):
    """Regression tests for the vector-based root privilege check (trex_path Görev #5).

    The root requirement should only apply to vectors that ACTUALLY use raw
    sockets. HTTP-layer vectors (http, http2, websocket, quic) use userspace
    sockets and must be runnable without root.
    """

    # This must match _CPU_RAW_SOCKET_VECTORS defined in cli.py main().
    EXPECTED_CPU_RAW_VECTORS = {
        "basic", "dns", "anomaly",
        "ntp-amp", "ssdp-amp", "dns-amp", "memcached-amp", "ldap-amp",
        "pcap-replay",
    }

    def test_root_required_vectors_match(self):
        """The CPU raw-socket vector set should match those in cli.py."""
        import inspect
        src = inspect.getsource(cli.main)
        self.assertIn("_CPU_RAW_SOCKET_VECTORS", src)
        for v in self.EXPECTED_CPU_RAW_VECTORS:
            self.assertIn(f'"{v}"', src, f"Vector '{v}' should be in _CPU_RAW_SOCKET_VECTORS")

    def test_http_vectors_not_in_root_gate(self):
        """HTTP-layer vectors should not be considered raw on CPU backend."""
        parser = cli.build_parser()
        for v in ("http", "http2", "websocket", "quic"):
            args = parser.parse_args(["--attack-vector", v, "--compute-backend", "cpu"])
            self.assertFalse(cli._is_cuda_raw_vector(args))

    def test_cuda_http_vectors_are_marked_raw(self):
        """CUDA HTTP path uses raw sender and remains root-gated."""
        parser = cli.build_parser()
        for v in ("http",):
            args = parser.parse_args(["--attack-vector", v, "--compute-backend", "cuda"])
            self.assertTrue(cli._is_cuda_raw_vector(args))

    def test_cuda_http2_vector_not_marked_raw_after_hybrid_integration(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--attack-vector", "http2", "--compute-backend", "cuda"])
        self.assertFalse(cli._is_cuda_raw_vector(args))


@unittest.skipUnless(
    _SAAS_MODULES_AVAILABLE,
    "SaaS modules removed from this profile; skipping SaaS command mapping tests",
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

    def test_quic_require_native_flag_is_forwarded(self):
        from ddos_samurai.saas_schemas import TestStartRequest
        from ddos_samurai.api import _build_test_command

        payload = TestStartRequest(
            target="127.0.0.1",
            port=443,
            attack_vector="quic",
            l7_quic_require_native=True,
        )
        cmd = _build_test_command(payload)
        self.assertIn("--l7-quic-require-native", cmd)

    def test_quic_response_match_flags_are_forwarded(self):
        from ddos_samurai.saas_schemas import TestStartRequest
        from ddos_samurai.api import _build_test_command

        payload = TestStartRequest(
            target="127.0.0.1",
            port=443,
            attack_vector="quic",
            quic_expect_header_name="server",
            quic_expect_header_value_contains="nginx",
            quic_expect_body_substring="ok",
        )
        cmd = _build_test_command(payload)
        self.assertIn("--quic-expect-header-name", cmd)
        self.assertIn("--quic-expect-header-value-contains", cmd)
        self.assertIn("--quic-expect-body-substring", cmd)
