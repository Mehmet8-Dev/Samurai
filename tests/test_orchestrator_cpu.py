import unittest
from unittest.mock import AsyncMock
from unittest.mock import patch
import os

from ddos_samurai import orchestrator


def _base_args():
    return {
        "target": "127.0.0.1",
        "port": 80,
        "count": 5,
        "verbose": False,
        "compute_backend": "cpu",
        "attack_vector": "basic",
        "protocol": "tcp",
        "spoof": False,
        "spoof_mode": "realistic",
        "spoof_subnet": None,
        "spoof_list_file": None,
        "payloads": [],
        "tcp_flags": "PA",
        "ttl": None,
        "tos": None,
        "window": None,
        "fragment": False,
        "fragment_size": 800,
        "pad": 0,
        "dns_name": "example.com",
        "dns_qtype": ["A"],
        "dns_edns": False,
        "dns_nord": False,
        "delay": 0.0,
        "rps": 0.0,
        "jitter": 0.0,
        "ramp": 0.0,
        # HTTP knobs
        "http_verify": "true",
        "http_concurrency": 10,
        "http_method": "GET",
        "http_path": ["/"],
        "http_scheme": "http",
        "http_timeout": 2.0,
        "http_retries": 0,
        "http2_concurrency": 10,
        "h2_transport": "auto",
        "ws_path": "/ws",
        "ws_message": "ping",
        "ws_concurrency": 10,
        "ws_scenario": False,
        "ws_auth_message": "",
        "ws_subscribe_message": None,
        "ws_ping_count": 1,
        "ws_await_response": False,
        "pcap_use_l2": False,
        "pcap_no_flow_aware": False,
        "evasion_techniques": None,
        "cookies": None,
        "user_agent": None,
        # amplification
        "reflector_file": "does-not-matter.txt",
        # misc
        "ja3_profile": "none",
        "tls_profile": "none",
        "h2_profile": "none",
        "stateful": False,
        "source_port": 0,
    }

class TestOrchestratorCpu(unittest.IsolatedAsyncioTestCase):
    async def test_worker_process_http_path_calls_http_sender(self):
        args = _base_args()
        args["attack_vector"] = "http"

        mock_http = AsyncMock()
        with patch.object(orchestrator.senders, "http_app_sender", mock_http):
            await orchestrator.worker_process(worker_id=1, args=args, ssl_context=None)
            mock_http.assert_awaited_once()

    async def test_worker_process_http_stateful_calls_stateful_sender(self):
        args = _base_args()
        args["attack_vector"] = "http"
        args["stateful"] = True
        args["count"] = 3

        mock_http = AsyncMock()
        mock_stateful = AsyncMock(return_value={"attempted": 3, "sent": 3, "errors": 0})
        with patch.object(orchestrator.senders, "http_app_sender", mock_http):
            with patch.object(orchestrator.senders, "http_stateful_sender", mock_stateful):
                await orchestrator.worker_process(worker_id=1, args=args, ssl_context=None)
                mock_stateful.assert_awaited_once()
                mock_http.assert_not_awaited()

    async def test_worker_process_websocket_scenario_calls_scenario_sender(self):
        args = _base_args()
        args["attack_vector"] = "websocket"
        args["ws_scenario"] = True
        args["count"] = 3

        mock_ws = AsyncMock()
        mock_ws_scenario = AsyncMock(return_value={"attempted": 3, "sent": 3, "errors": 0})
        with patch.object(orchestrator.senders, "websocket_sender", mock_ws):
            with patch.object(orchestrator.senders, "websocket_scenario_sender", mock_ws_scenario):
                await orchestrator.worker_process(worker_id=1, args=args, ssl_context=None)
                mock_ws_scenario.assert_awaited_once()
                mock_ws.assert_not_awaited()

    async def test_worker_process_http2_path_calls_http2_sender(self):
        args = _base_args()
        args["attack_vector"] = "http2"
        args["h2_profile"] = "none"

        mock_h2 = AsyncMock()
        with patch.object(orchestrator.senders, "http2_sender", mock_h2):
            await orchestrator.worker_process(worker_id=1, args=args, ssl_context=None)
            mock_h2.assert_awaited_once()
            _call_args, call_kwargs = mock_h2.call_args
            self.assertEqual(call_kwargs["h2_profile_name"], "none")
            self.assertTrue(bool(call_kwargs["verify"]))

    async def test_worker_process_http2_respects_http_verify_false(self):
        args = _base_args()
        args["attack_vector"] = "http2"
        args["http_verify"] = "false"

        mock_h2 = AsyncMock()
        with patch.object(orchestrator.senders, "http2_sender", mock_h2):
            await orchestrator.worker_process(worker_id=1, args=args, ssl_context=None)
            mock_h2.assert_awaited_once()
            _call_args, call_kwargs = mock_h2.call_args
            self.assertFalse(bool(call_kwargs["verify"]))

    async def test_worker_process_slow_post_calls_slow_sender(self):
        args = _base_args()
        args["attack_vector"] = "slow-post"

        mock_slow = AsyncMock()
        with patch.object(orchestrator.senders, "slow_attack_sender", mock_slow):
            await orchestrator.worker_process(worker_id=1, args=args, ssl_context=None)
            mock_slow.assert_awaited_once()

    async def test_worker_process_amp_calls_amplification_sender(self):
        args = _base_args()
        args["attack_vector"] = "dns-amp"

        mock_amp = AsyncMock()
        with patch.object(orchestrator.senders, "amplification_sender", mock_amp):
            await orchestrator.worker_process(worker_id=1, args=args, ssl_context=None)
            mock_amp.assert_awaited_once()

    async def test_worker_process_basic_calls_packet_sender_and_passes_fragment_size(self):
        args = _base_args()
        args["attack_vector"] = "basic"
        args["fragment"] = True
        args["fragment_size"] = 256

        mock_pkt = AsyncMock()
        with patch.object(orchestrator.senders, "packet_sender", mock_pkt):
            await orchestrator.worker_process(worker_id=1, args=args, ssl_context=None)
            mock_pkt.assert_awaited_once()

            _call_args, call_kwargs = mock_pkt.call_args
            cfg = call_kwargs["packet_config"]
            self.assertTrue(getattr(cfg, "fragment_enabled") is True)
            self.assertEqual(getattr(cfg, "fragment_size"), 256)

    async def test_worker_process_basic_with_pacing_routes_to_paced_sender(self):
        args = _base_args()
        args["attack_vector"] = "basic"
        args["pacing_mode"] = "rps"
        args["rps"] = 1000.0

        mock_pkt = AsyncMock()
        mock_paced = AsyncMock(return_value={"attempted": 5, "sent": 5, "errors": 0})
        with patch.object(orchestrator, "PACING_ENGINE_AVAILABLE", True):
            with patch.object(orchestrator.cpu_packet_engine, "generate_packet_pool", return_value=(b"x" * 320, 64)):
                with patch.object(orchestrator.senders, "packet_sender", mock_pkt):
                    with patch.object(orchestrator.senders, "paced_raw_socket_sender", mock_paced):
                        await orchestrator.worker_process(worker_id=1, args=args, ssl_context=None)

        mock_paced.assert_awaited_once()
        _call_args, call_kwargs = mock_paced.call_args
        self.assertEqual(call_kwargs["count"], 5)
        mock_pkt.assert_not_awaited()

    async def test_worker_process_basic_with_pacing_and_fragment_falls_back(self):
        args = _base_args()
        args["attack_vector"] = "basic"
        args["pacing_mode"] = "rps"
        args["rps"] = 1000.0
        args["fragment"] = True
        args["fragment_size"] = 256

        mock_pkt = AsyncMock(return_value={"attempted": 5, "sent": 5, "errors": 0})
        mock_paced = AsyncMock(return_value={"attempted": 5, "sent": 5, "errors": 0})
        with patch.object(orchestrator, "PACING_ENGINE_AVAILABLE", True):
            with patch.object(orchestrator.senders, "packet_sender", mock_pkt):
                with patch.object(orchestrator.senders, "paced_raw_socket_sender", mock_paced):
                    await orchestrator.worker_process(worker_id=1, args=args, ssl_context=None)

        mock_pkt.assert_awaited_once()
        mock_paced.assert_not_awaited()


class TestWorkerStatusSemantics(unittest.IsolatedAsyncioTestCase):
    """Tests for the worker_status derivation logic (trex_path Görev #6).

    The orchestrator must derive worker_status from actual sent/errors
    rather than blindly reporting "ok".
    """

    async def test_worker_status_failed_when_zero_sent(self):
        """Worker should have status='failed' when sender reports 0 sent."""
        args = _base_args()
        args["attack_vector"] = "http"
        args["count"] = 100

        events = []
        # Sender returns 0 sent, all errors
        mock_http = AsyncMock(return_value={
            "attempted": 100, "sent": 0, "errors": 100, "bytes_sent_est": 0,
        })
        with patch.object(orchestrator.senders, "http_app_sender", mock_http):
            await orchestrator.worker_process(
                worker_id=1, args=args, ssl_context=None, run_events=events,
            )

        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["status"], "failed")
        self.assertIn("0/100", ev["error"])

    async def test_worker_status_degraded_when_high_error_rate(self):
        """Worker should be 'degraded' when errors exceed sent count."""
        args = _base_args()
        args["attack_vector"] = "http"
        args["count"] = 100

        events = []
        # Sender: 30 sent, 70 errors → error rate > 50%
        mock_http = AsyncMock(return_value={
            "attempted": 100, "sent": 30, "errors": 70, "bytes_sent_est": 0,
        })
        with patch.object(orchestrator.senders, "http_app_sender", mock_http):
            await orchestrator.worker_process(
                worker_id=1, args=args, ssl_context=None, run_events=events,
            )

        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["status"], "degraded")

    async def test_worker_status_ok_when_fully_sent(self):
        """Worker should remain 'ok' when all packets are sent successfully."""
        args = _base_args()
        args["attack_vector"] = "http"
        args["count"] = 100

        events = []
        mock_http = AsyncMock(return_value={
            "attempted": 100, "sent": 100, "errors": 0, "bytes_sent_est": 5000,
        })
        with patch.object(orchestrator.senders, "http_app_sender", mock_http):
            await orchestrator.worker_process(
                worker_id=1, args=args, ssl_context=None, run_events=events,
            )

        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["status"], "ok")

    async def test_worker_event_contains_sender_path_metadata(self):
        """Worker events should carry sender_path and fallback_count."""
        args = _base_args()
        args["attack_vector"] = "http"
        args["count"] = 10

        events = []
        mock_http = AsyncMock(return_value={
            "attempted": 10, "sent": 10, "errors": 0, "bytes_sent_est": 500,
            "sender_path": "HTTPX_H1", "fallback_count": 0,
            "permission_error_count": 0,
        })
        with patch.object(orchestrator.senders, "http_app_sender", mock_http):
            await orchestrator.worker_process(
                worker_id=1, args=args, ssl_context=None, run_events=events,
            )

        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertIn("sender_path", ev)
        self.assertEqual(ev["sender_path"], "HTTPX_H1")
        self.assertIn("fallback_count", ev)
        self.assertIn("permission_error_count", ev)

    async def test_worker_event_contains_extended_sender_counters(self):
        """Extended sender counters should propagate into worker events."""
        args = _base_args()
        args["attack_vector"] = "http"
        args["count"] = 10

        events = []
        mock_http = AsyncMock(return_value={
            "attempted": 10,
            "sent": 10,
            "errors": 0,
            "bytes_sent_est": 640,
            "sender_path": "PYTHON_SENDMMSG",
            "fallback_count": 1,
            "permission_error_count": 0,
            "buffer_copy_count": 2,
            "buffer_copy_bytes": 4096,
            "eagain_retry_count": 3,
            "partial_send_retry_count": 4,
            "actual_rps": 9500.0,
            "rate_accuracy_pct": 95.0,
            "jitter_p99_ns": 1200.0,
            "ipg_mean_ns": 104000.0,
            "sleep_calls": 12,
            "busywait_cycles": 34,
            "so_txtime_active": 1,
            "txtime_errors": 2,
            "txring_flush_call_count": 5,
            "txring_flush_error_count": 1,
            "txring_flush_eagain_count": 1,
            "txring_flush_enobufs_count": 2,
            "txring_flush_ebusy_count": 1,
            "txring_flush_other_errno_count": 0,
            "txring_flush_last_errno": 105,
            "txring_flush_last_errno_name": "ENOBUFS",
            "txring_tp_packets": 9,
            "txring_tp_drops": 2,
            "txring_tp_freeze_q_cnt": 0,
            "txring_packet_version": 1,
            "txring_packet_version_name": "TPACKET_V2",
            "host_tx_packets_delta": 10,
            "host_tx_dropped_delta": 2,
            "host_tx_errors_delta": 1,
            "softnet_dropped_delta": 0,
            "softnet_time_squeeze_delta": 0,
            "nicq_counter_available": 1,
            "nicq_counter_source": "ethtool_stats",
            "nicq_counter_confidence": 0.8,
            "nicq_pressure_delta": 3,
            "nicq_drop_delta": 2,
            "nicq_fifo_delta": 1,
            "nicq_timeout_delta": 0,
            "nicq_restart_delta": 0,
            "nicq_busy_delta": 0,
            "nicq_pressure_status": "warn",
            "wire_loss_est_packets": 2,
        })
        with patch.object(orchestrator.senders, "http_app_sender", mock_http):
            await orchestrator.worker_process(
                worker_id=1, args=args, ssl_context=None, run_events=events,
            )

        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["buffer_copy_count"], 2)
        self.assertEqual(ev["buffer_copy_bytes"], 4096)
        self.assertEqual(ev["eagain_retry_count"], 3)
        self.assertEqual(ev["partial_send_retry_count"], 4)
        self.assertAlmostEqual(ev["actual_rps"], 9500.0)
        self.assertAlmostEqual(ev["rate_accuracy_pct"], 95.0)
        self.assertAlmostEqual(ev["jitter_p99_ns"], 1200.0)
        self.assertAlmostEqual(ev["ipg_mean_ns"], 104000.0)
        self.assertEqual(ev["sleep_calls"], 12)
        self.assertEqual(ev["busywait_cycles"], 34)
        self.assertEqual(ev["so_txtime_active"], 1)
        self.assertEqual(ev["txtime_errors"], 2)
        self.assertEqual(ev["txring_flush_call_count"], 5)
        self.assertEqual(ev["txring_flush_error_count"], 1)
        self.assertEqual(ev["txring_flush_enobufs_count"], 2)
        self.assertEqual(ev["txring_flush_ebusy_count"], 1)
        self.assertEqual(ev["txring_flush_last_errno"], 105)
        self.assertEqual(ev["txring_flush_last_errno_name"], "ENOBUFS")
        self.assertEqual(ev["txring_tp_packets"], 9)
        self.assertEqual(ev["txring_tp_drops"], 2)
        self.assertEqual(ev["txring_packet_version"], 1)
        self.assertEqual(ev["txring_packet_version_name"], "TPACKET_V2")
        self.assertEqual(ev["host_tx_packets_delta"], 10)
        self.assertEqual(ev["host_tx_dropped_delta"], 2)
        self.assertEqual(ev["nicq_counter_available"], 1)
        self.assertEqual(ev["nicq_counter_source"], "ethtool_stats")
        self.assertEqual(ev["nicq_pressure_delta"], 3)
        self.assertEqual(ev["nicq_drop_delta"], 2)
        self.assertEqual(ev["nicq_fifo_delta"], 1)
        self.assertEqual(ev["nicq_pressure_status"], "warn")
        self.assertEqual(ev["wire_loss_est_packets"], 2)
        self.assertGreater(ev["wire_loss_est_pct"], 0.0)
        self.assertEqual(ev["stats"]["sleep_calls"], 12)
        self.assertEqual(ev["stats"]["busywait_cycles"], 34)
        self.assertEqual(ev["stats"]["buffer_copy_count"], 2)
        self.assertEqual(ev["stats"]["eagain_retry_count"], 3)
        self.assertEqual(ev["stats"]["nicq_pressure_delta"], 3)

    async def test_worker_status_interrupted_on_keyboard_interrupt(self):
        """Worker should report 'interrupted' on KeyboardInterrupt."""
        args = _base_args()
        args["attack_vector"] = "http"
        args["count"] = 10

        events = []
        mock_http = AsyncMock(side_effect=KeyboardInterrupt)
        with patch.object(orchestrator.senders, "http_app_sender", mock_http):
            await orchestrator.worker_process(
                worker_id=1, args=args, ssl_context=None, run_events=events,
            )

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["status"], "interrupted")

    async def test_dedicated_required_fails_when_sender_fallback_detected(self):
        args = _base_args()
        args["attack_vector"] = "basic"
        args["count"] = 10
        args["lab_profile"] = "dedicated"
        args["dataplane_core_mode"] = "required"

        events = []
        mock_sender = AsyncMock(
            return_value={
                "attempted": 10,
                "sent": 10,
                "errors": 0,
                "bytes_sent_est": 640,
                "sender_path": "DP_TX_RING",
                "fallback_count": 1,
                "sender_fallback_reason": "txring_unavailable",
            }
        )
        with patch.object(orchestrator.senders, "packet_sender", mock_sender):
            await orchestrator.worker_process(
                worker_id=1, args=args, ssl_context=None, run_events=events,
            )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["status"], "failed")
        self.assertIn("hot_path_policy_violation", str(events[0].get("error", "")))

    async def test_dedicated_required_fails_when_sender_path_drift_detected(self):
        args = _base_args()
        args["attack_vector"] = "basic"
        args["count"] = 10
        args["lab_profile"] = "dedicated"
        args["dataplane_core_mode"] = "required"

        events = []
        mock_sender = AsyncMock(
            return_value={
                "attempted": 10,
                "sent": 10,
                "errors": 0,
                "bytes_sent_est": 640,
                "sender_path": "MIXED",
                "fallback_count": 0,
                "sender_fallback_reason": "none",
            }
        )
        with patch.object(orchestrator.senders, "packet_sender", mock_sender):
            await orchestrator.worker_process(
                worker_id=1, args=args, ssl_context=None, run_events=events,
            )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["status"], "failed")
        self.assertIn("hot_path_policy_violation", str(events[0].get("error", "")))


class TestStatsAggregateHelpers(unittest.TestCase):
    def test_add_stats_aggregates_pacing_fields(self):
        acc = orchestrator._empty_stats()
        acc = orchestrator._add_stats(
            acc,
            {
                "attempted": 5,
                "sent": 5,
                "errors": 0,
                "actual_rps": 1000.0,
                "rate_accuracy_pct": 95.0,
                "jitter_p99_ns": 100.0,
                "ipg_mean_ns": 1000.0,
                "sleep_calls": 2,
                "busywait_cycles": 4,
                "so_txtime_active": 1,
                "txtime_errors": 1,
            },
        )
        acc = orchestrator._add_stats(
            acc,
            {
                "attempted": 5,
                "sent": 5,
                "errors": 0,
                "actual_rps": 2000.0,
                "rate_accuracy_pct": 96.0,
                "jitter_p99_ns": 120.0,
                "ipg_mean_ns": 900.0,
                "sleep_calls": 3,
                "busywait_cycles": 5,
                "so_txtime_active": 0,
                "txtime_errors": 2,
            },
        )

        self.assertEqual(acc["attempted"], 10)
        self.assertEqual(acc["sleep_calls"], 5)
        self.assertEqual(acc["busywait_cycles"], 9)
        self.assertEqual(acc["so_txtime_active"], 1)
        self.assertEqual(acc["txtime_errors"], 3)
        self.assertAlmostEqual(acc["actual_rps"], 2000.0)
        self.assertAlmostEqual(acc["rate_accuracy_pct"], 96.0)

    def test_add_stats_preserves_l7_protocol_specific_fields(self):
        acc = orchestrator._empty_stats()
        acc = orchestrator._add_stats(
            acc,
            {
                "attempted": 4,
                "sent": 4,
                "errors": 0,
                "l7_engine_path_used": "C_STATE_H2",
                "l7_fallback_reason": "none",
                "l7_capability_status": "ok",
                "h2_goaway_count": 2,
                "h2_stream_resets": 1,
                "h2_connections_used": 1,
                "h2_request_plan_used": 1,
                "h2_request_plan_items": 4,
                "h2_stream_reset_ratio": 0.25,
            },
        )
        acc = orchestrator._add_stats(
            acc,
            {
                "attempted": 2,
                "sent": 1,
                "errors": 1,
                "l7_engine_path_used": "C_STATE_QUIC",
                "l7_fallback_reason": "connect_fail",
                "l7_capability_status": "partial",
                "quic_connect_fail_count": 1,
                "quic_connect_timeout_count": 1,
                "quic_tls_fail_count": 2,
                "quic_handshake_timeout_count": 1,
                "quic_stream_fail_count": 3,
                "quic_stream_fail_ratio": 0.5,
                "quic_handshake_fail_ratio": 0.3,
            },
        )

        self.assertEqual(acc["l7_engine_path_used"], "mixed")
        self.assertEqual(acc["l7_fallback_reason"], "connect_fail")
        self.assertEqual(acc["l7_capability_status"], "partial")
        self.assertEqual(acc["h2_goaway_count"], 2)
        self.assertEqual(acc["h2_stream_resets"], 1)
        self.assertEqual(acc["h2_connections_used"], 1)
        self.assertEqual(acc["h2_request_plan_used"], 1)
        self.assertEqual(acc["h2_request_plan_items"], 4)
        self.assertAlmostEqual(float(acc["h2_stream_reset_ratio"]), 0.25, places=6)
        self.assertEqual(acc["quic_connect_fail_count"], 1)
        self.assertEqual(acc["quic_connect_timeout_count"], 1)
        self.assertEqual(acc["quic_tls_fail_count"], 2)
        self.assertEqual(acc["quic_handshake_timeout_count"], 1)
        self.assertEqual(acc["quic_stream_fail_count"], 3)
        self.assertAlmostEqual(float(acc["quic_stream_fail_ratio"]), 0.5, places=6)
        self.assertAlmostEqual(float(acc["quic_handshake_fail_ratio"]), 0.3, places=6)


class TestPacingConfigBuilder(unittest.TestCase):
    def test_build_pacing_config_auto_pin_from_affinity(self):
        args = _base_args()
        args.update({"pacing_mode": "rps", "rps": 1000.0, "pin_cpu": -1})

        with patch.object(orchestrator.os, "sched_getaffinity", return_value={7}):
            cfg = orchestrator._build_pacing_config(args)
        self.assertEqual(int(cfg.pin_cpu), 7)

    def test_build_pacing_config_auto_pin_can_be_disabled(self):
        args = _base_args()
        args.update({"pacing_mode": "rps", "rps": 1000.0, "pin_cpu": -1})

        with patch.dict(os.environ, {"SAMURAI_PACING_AUTO_PIN": "0"}, clear=False):
            with patch.object(orchestrator.os, "sched_getaffinity", return_value={9}):
                cfg = orchestrator._build_pacing_config(args)
        self.assertEqual(int(cfg.pin_cpu), -1)
