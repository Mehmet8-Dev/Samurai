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
        self.assertEqual(ev["wire_loss_est_packets"], 2)
        self.assertGreater(ev["wire_loss_est_pct"], 0.0)
        self.assertEqual(ev["stats"]["sleep_calls"], 12)
        self.assertEqual(ev["stats"]["busywait_cycles"], 34)
        self.assertEqual(ev["stats"]["buffer_copy_count"], 2)
        self.assertEqual(ev["stats"]["eagain_retry_count"], 3)

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
