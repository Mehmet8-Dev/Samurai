import json
import os
import tempfile
import unittest
from unittest.mock import patch


class TestReporting(unittest.TestCase):
    def test_write_json_and_md(self):
        from ddos_samurai import reporting

        rr = reporting.RunReport(
            run_id="unit-test",
            started_utc="2026-02-18T00:00:00+00:00",
            finished_utc="2026-02-18T00:00:01+00:00",
            duration_s=1.0,
            mode="unit",
            inputs={"a": 1},
            results={
                "ok": True,
                "txring_drop_ratio_pct": 99.0,
                "txring_packet_version": 2,
                "txring_packet_version_name": "TPACKET_V3",
                "flush_mode": "adaptive",
            },
            environment={"python": {"version": "3.x"}},
        )

        with tempfile.TemporaryDirectory() as td:
            out_json = os.path.join(td, "report.json")
            out_md = os.path.join(td, "report.md")

            reporting.write_json(rr, out_json)
            reporting.write_markdown(rr, out_md)

            self.assertTrue(os.path.exists(out_json))
            self.assertTrue(os.path.exists(out_md))

            with open(out_json, "r", encoding="utf-8") as f:
                data = json.loads(f.read())
            self.assertEqual(data["run_id"], "unit-test")
            self.assertEqual(data["mode"], "unit")
            self.assertIn("ok", data["results"])
            self.assertNotIn("txring_drop_ratio_pct", data["results"])
            self.assertNotIn("flush_mode", data["results"])
            self.assertEqual(int(data["results"].get("txring_packet_version", 0)), 2)
            self.assertEqual(str(data["results"].get("txring_packet_version_name", "")), "TPACKET_V3")

            with open(out_md, "r", encoding="utf-8") as f:
                md = f.read()
            self.assertNotIn("txring_drop_ratio_pct", md)
            self.assertNotIn("flush_mode", md)
            self.assertIn("`txring_packet_version`", md)
            self.assertIn("`txring_packet_version_name`", md)

    def test_self_test_report_builder(self):
        from ddos_samurai import reporting

        summary = {"tests_run": 10, "failures": 0, "errors": 0, "skipped": 2, "successful": True}
        rr = reporting.build_self_test_report(summary=summary, log_path=None, duration_s=0.1, warnings=["w"])
        self.assertEqual(rr.mode, "self_test")
        self.assertEqual(rr.results["tests_run"], 10)
        self.assertEqual(rr.results["skipped"], 2)
        self.assertTrue(rr.results["successful"])

    def test_live_attack_report_aggregates_extended_sender_counters(self):
        from ddos_samurai import reporting

        events = [
            {
                "status": "ok",
                "attack_vector": "basic",
                "compute_backend": "cpu",
                "sender_path": "PYTHON_SENDMMSG",
                "fallback_count": 1,
                "permission_error_count": 0,
                "buffer_copy_count": 2,
                "buffer_copy_bytes": 1024,
                "eagain_retry_count": 3,
                "partial_send_retry_count": 4,
                "actual_rps": 9000.0,
                "rate_accuracy_pct": 90.0,
                "jitter_p99_ns": 1000.0,
                "ipg_mean_ns": 100000.0,
                "sleep_calls": 10,
                "busywait_cycles": 100,
                "so_txtime_active": 1,
                "txtime_errors": 1,
                "txring_flush_call_count": 11,
                "txring_flush_error_count": 1,
                "txring_flush_eagain_count": 1,
                "txring_flush_enobufs_count": 0,
                "txring_flush_ebusy_count": 0,
                "txring_flush_other_errno_count": 0,
                "txring_flush_last_errno": 11,
                "txring_flush_last_errno_name": "EAGAIN",
                "txring_tp_packets": 9,
                "txring_tp_drops": 1,
                "txring_tp_freeze_q_cnt": 0,
                "txring_packet_version": 1,
                "txring_packet_version_name": "TPACKET_V2",
                "host_tx_packets_delta": 10,
                "host_tx_dropped_delta": 1,
                "host_tx_errors_delta": 0,
                "softnet_dropped_delta": 2,
                "softnet_time_squeeze_delta": 1,
                "wire_counter_available": 1,
                "wire_counter_source": "sysfs_netdev_stats",
                "wire_counter_confidence": 1.0,
                "wire_tx_packets_delta": 10,
                "wire_tx_dropped_delta": 1,
                "wire_tx_errors_delta": 0,
                "wire_tx_bytes_delta": 900,
                "nicq_counter_available": 1,
                "nicq_counter_source": "ethtool_stats",
                "nicq_counter_confidence": 0.8,
                "nicq_pressure_delta": 2,
                "nicq_drop_delta": 1,
                "nicq_fifo_delta": 1,
                "nicq_timeout_delta": 0,
                "nicq_restart_delta": 0,
                "nicq_busy_delta": 0,
                "nicq_pressure_status": "warn",
                "wire_loss_est_packets": 1,
                "gpu_template_h2d_copy_count": 3,
                "gpu_template_h2d_copy_bytes": 2048,
                "gpu_rng_state_alloc_count": 1,
                "gpu_rng_state_reuse_count": 5,
                "gpu_ring_depth_peak": 3,
                "gpu_ring_block_wait_ns": 1200,
                "state_active_entries": 100,
                "state_timeout_evictions": 4,
                "state_overwrites": 2,
                "stats": {
                    "attempted": 10,
                    "sent": 9,
                    "errors": 1,
                    "bytes_sent_est": 900,
                },
            },
            {
                "status": "degraded",
                "attack_vector": "basic",
                "compute_backend": "cpu",
                "sender_path": "C_EXT_L3",
                "fallback_count": 0,
                "permission_error_count": 1,
                "buffer_copy_count": 0,
                "buffer_copy_bytes": 0,
                "eagain_retry_count": 2,
                "partial_send_retry_count": 1,
                "actual_rps": 7000.0,
                "rate_accuracy_pct": 70.0,
                "jitter_p99_ns": 2000.0,
                "ipg_mean_ns": 120000.0,
                "sleep_calls": 20,
                "busywait_cycles": 200,
                "so_txtime_active": 0,
                "txtime_errors": 2,
                "txring_flush_call_count": 7,
                "txring_flush_error_count": 0,
                "txring_flush_eagain_count": 0,
                "txring_flush_enobufs_count": 2,
                "txring_flush_ebusy_count": 1,
                "txring_flush_other_errno_count": 3,
                "txring_flush_last_errno": 105,
                "txring_flush_last_errno_name": "ENOBUFS",
                "txring_tp_packets": 8,
                "txring_tp_drops": 0,
                "txring_tp_freeze_q_cnt": 0,
                "txring_packet_version": 1,
                "txring_packet_version_name": "TPACKET_V2",
                "host_tx_packets_delta": 9,
                "host_tx_dropped_delta": 0,
                "host_tx_errors_delta": 1,
                "softnet_dropped_delta": 0,
                "softnet_time_squeeze_delta": 0,
                "wire_counter_available": 1,
                "wire_counter_source": "sysfs_netdev_stats",
                "wire_counter_confidence": 1.0,
                "wire_tx_packets_delta": 9,
                "wire_tx_dropped_delta": 0,
                "wire_tx_errors_delta": 1,
                "wire_tx_bytes_delta": 800,
                "nicq_counter_available": 1,
                "nicq_counter_source": "ethtool_stats",
                "nicq_counter_confidence": 0.9,
                "nicq_pressure_delta": 0,
                "nicq_drop_delta": 0,
                "nicq_fifo_delta": 0,
                "nicq_timeout_delta": 0,
                "nicq_restart_delta": 0,
                "nicq_busy_delta": 0,
                "nicq_pressure_status": "ok",
                "wire_loss_est_packets": 0,
                "gpu_template_h2d_copy_count": 1,
                "gpu_template_h2d_copy_bytes": 1024,
                "gpu_rng_state_alloc_count": 1,
                "gpu_rng_state_reuse_count": 3,
                "gpu_ring_depth_peak": 2,
                "gpu_ring_block_wait_ns": 800,
                "state_active_entries": 120,
                "state_timeout_evictions": 1,
                "state_overwrites": 1,
                "stats": {
                    "attempted": 10,
                    "sent": 8,
                    "errors": 2,
                    "bytes_sent_est": 800,
                },
            },
        ]

        rr = reporting.build_live_attack_report(
            args={"target": "127.0.0.1"},
            worker_events=events,
            duration_s=2.0,
            progress_total=20,
            total_count=20,
            metrics={},
            warnings=[],
        )

        self.assertEqual(rr.mode, "live_attack")
        self.assertEqual(rr.results["buffer_copy_count"], 2)
        self.assertEqual(rr.results["buffer_copy_bytes"], 1024)
        self.assertEqual(rr.results["eagain_retry_count"], 5)
        self.assertEqual(rr.results["partial_send_retry_count"], 5)
        self.assertAlmostEqual(rr.results["actual_rps"], 8000.0, places=4)
        self.assertAlmostEqual(rr.results["rate_accuracy_pct"], 80.0, places=4)
        self.assertAlmostEqual(rr.results["jitter_p99_ns"], 1500.0, places=4)
        self.assertAlmostEqual(rr.results["ipg_mean_ns"], 110000.0, places=4)
        self.assertEqual(rr.results["sleep_calls"], 30)
        self.assertEqual(rr.results["busywait_cycles"], 300)
        self.assertEqual(rr.results["so_txtime_active"], 1)
        self.assertEqual(rr.results["txtime_errors"], 3)
        self.assertEqual(rr.results["txring_flush_call_count"], 18)
        self.assertEqual(rr.results["txring_flush_error_count"], 1)
        self.assertEqual(rr.results["txring_flush_enobufs_count"], 2)
        self.assertEqual(rr.results["txring_flush_ebusy_count"], 1)
        self.assertEqual(rr.results["txring_flush_other_errno_count"], 3)
        self.assertEqual(rr.results["txring_flush_last_errno"], 105)
        self.assertEqual(rr.results["txring_flush_last_errno_name"], "ENOBUFS")
        self.assertEqual(rr.results["txring_tp_packets"], 17)
        self.assertEqual(rr.results["txring_tp_drops"], 1)
        self.assertEqual(rr.results["txring_kernel_raw_tp_drops"], 1)
        self.assertEqual(rr.results["txring_packet_version"], 1)
        self.assertEqual(rr.results["txring_packet_version_name"], "TPACKET_V2")
        self.assertAlmostEqual(rr.results["txring_hold_block_pressure_pct"], 0.0, places=4)
        self.assertEqual(rr.results["host_tx_packets_delta"], 19)
        self.assertEqual(rr.results["host_tx_dropped_delta"], 1)
        self.assertEqual(rr.results["softnet_dropped_delta"], 2)
        self.assertEqual(rr.results["wire_loss_est_packets"], 1)
        self.assertEqual(rr.results["wire_loss_raw_uncapped_packets"], 1)
        self.assertEqual(rr.results["wire_loss_raw_over_attempted_packets"], 0)
        self.assertEqual(rr.results["wire_loss_raw_gt_attempted"], 0)
        self.assertEqual(rr.results["wire_loss_status"], "warn")
        self.assertEqual(rr.results["nicq_counter_available"], 1)
        self.assertEqual(rr.results["nicq_counter_partial"], 0)
        self.assertEqual(rr.results["nicq_counter_available_workers"], 2)
        self.assertEqual(rr.results["nicq_counter_missing_workers"], 0)
        self.assertEqual(rr.results["nicq_counter_source"], "ethtool_stats")
        self.assertEqual(rr.results["nicq_pressure_delta"], 2)
        self.assertEqual(rr.results["nicq_drop_delta"], 1)
        self.assertEqual(rr.results["nicq_fifo_delta"], 1)
        self.assertEqual(rr.results["nicq_pressure_status"], "warn")
        self.assertAlmostEqual(rr.results["txring_flush_enobufs_ratio_pct"], 11.1111, places=4)
        self.assertAlmostEqual(rr.results["txring_flush_ebusy_ratio_pct"], 5.5556, places=4)
        self.assertAlmostEqual(rr.results["txring_flush_other_errno_ratio_pct"], 16.6667, places=4)
        self.assertEqual(rr.results["gpu_template_h2d_copy_count"], 4)
        self.assertEqual(rr.results["gpu_rng_state_alloc_count"], 2)
        self.assertEqual(rr.results["gpu_ring_depth_peak"], 3)
        self.assertEqual(rr.results["gpu_ring_block_wait_ns"], 2000)
        self.assertEqual(rr.results["state_active_entries"], 120)
        self.assertEqual(rr.results["state_timeout_evictions"], 5)
        self.assertEqual(rr.results["state_overwrites"], 3)

    def test_live_attack_report_ignores_txring_drops_for_wire_loss(self):
        from ddos_samurai import reporting

        events = [
            {
                "status": "ok",
                "attack_vector": "basic",
                "compute_backend": "cuda",
                "sender_path": "TX_RING_L2",
                "txring_tp_packets": 410,
                "txring_tp_drops": 400,
                "host_tx_dropped_delta": 0,
                "wire_loss_est_packets": 400,
                "stats": {
                    "attempted": 100,
                    "sent": 100,
                    "errors": 0,
                    "bytes_sent_est": 6400,
                },
            }
        ]

        rr = reporting.build_live_attack_report(
            args={"target": "127.0.0.1"},
            worker_events=events,
            duration_s=1.0,
            progress_total=100,
            total_count=100,
            metrics={},
            warnings=[],
        )

        self.assertEqual(rr.results["wire_loss_est_packets"], 100)
        self.assertEqual(rr.results["wire_loss_est_pct"], 100.0)
        self.assertEqual(rr.results["wire_loss_raw_packets"], 0)
        self.assertEqual(rr.results["wire_loss_raw_uncapped_packets"], 0)
        self.assertEqual(rr.results["wire_loss_raw_over_attempted_packets"], 0)
        self.assertEqual(rr.results["wire_loss_raw_over_attempted_pct"], 0.0)
        self.assertEqual(rr.results["wire_loss_raw_gt_attempted"], 0)
        self.assertEqual(rr.results["wire_loss_estimation_capped"], 0)

    def test_live_attack_report_txring_drops_do_not_fail_wire_status(self):
        from ddos_samurai import reporting

        events = [
            {
                "status": "ok",
                "attack_vector": "basic",
                "compute_backend": "cuda",
                "sender_path": "PACED_L2",
                "txring_tp_packets": 500,
                "txring_tp_drops": 400,
                "host_tx_dropped_delta": 0,
                "stats": {
                    "attempted": 100,
                    "sent": 100,
                    "errors": 0,
                    "bytes_sent_est": 6400,
                },
            }
        ]

        rr = reporting.build_live_attack_report(
            args={"target": "127.0.0.1"},
            worker_events=events,
            duration_s=1.0,
            progress_total=100,
            total_count=100,
            metrics={},
            warnings=[],
        )

        self.assertEqual(rr.results["wire_loss_est_packets"], 0)
        self.assertEqual(rr.results["wire_loss_status"], "unknown")
        self.assertEqual(rr.results["nicq_pressure_status"], "unknown")
        self.assertEqual(rr.results["wire_loss_raw_packets"], 0)
        self.assertEqual(rr.results["wire_loss_raw_uncapped_packets"], 0)
        self.assertEqual(rr.results["wire_loss_raw_over_attempted_packets"], 0)
        self.assertEqual(rr.results["wire_loss_raw_gt_attempted"], 0)
        self.assertEqual(rr.results["txring_kernel_raw_tp_drops"], 400)

    def test_live_attack_report_derives_wire_loss_once_for_shared_interface_counters(self):
        from ddos_samurai import reporting

        events = [
            {
                "status": "ok",
                "attack_vector": "basic",
                "compute_backend": "cuda",
                "sender_path": "PACED_L2",
                "wire_counter_available": 1,
                "wire_counter_source": "sysfs_netdev_stats",
                "wire_counter_confidence": 1.0,
                "wire_tx_packets_delta": 45,
                "wire_loss_est_packets": 10,
                "wire_loss_raw_packets": 10,
                "stats": {
                    "attempted": 50,
                    "sent": 50,
                    "errors": 0,
                    "bytes_sent_est": 3200,
                },
            },
            {
                "status": "ok",
                "attack_vector": "basic",
                "compute_backend": "cuda",
                "sender_path": "PACED_L2",
                "wire_counter_available": 1,
                "wire_counter_source": "sysfs_netdev_stats",
                "wire_counter_confidence": 1.0,
                "wire_tx_packets_delta": 45,
                "wire_loss_est_packets": 10,
                "wire_loss_raw_packets": 10,
                "stats": {
                    "attempted": 50,
                    "sent": 50,
                    "errors": 0,
                    "bytes_sent_est": 3200,
                },
            },
        ]

        rr = reporting.build_live_attack_report(
            args={"target": "127.0.0.1"},
            worker_events=events,
            duration_s=1.0,
            progress_total=100,
            total_count=100,
            metrics={},
            warnings=[],
        )

        self.assertEqual(rr.results["wire_tx_packets_delta"], 90)
        self.assertEqual(rr.results["wire_tx_accounted_packets"], 90)
        self.assertEqual(rr.results["wire_loss_raw_packets"], 10)
        self.assertEqual(rr.results["wire_loss_est_packets"], 10)
        self.assertAlmostEqual(rr.results["wire_loss_est_pct"], 10.0, places=4)
        self.assertEqual(rr.results["wire_loss_status"], "fail")

    def test_live_attack_report_computes_hold_block_pressure(self):
        from ddos_samurai import reporting

        events = [
            {
                "status": "ok",
                "attack_vector": "basic",
                "compute_backend": "cuda",
                "sender_path": "PACED_L2",
                "txring_tp_packets": 10,
                "txring_tp_drops": 0,
                "txring_tp_freeze_q_cnt": 1,
                "txring_poll_count": 2,
                "txring_frame_wait_ns": 200_000_000,
                "stats": {
                    "attempted": 10,
                    "sent": 10,
                    "errors": 0,
                    "bytes_sent_est": 640,
                },
            }
        ]

        rr = reporting.build_live_attack_report(
            args={"target": "127.0.0.1"},
            worker_events=events,
            duration_s=1.0,
            progress_total=10,
            total_count=10,
            metrics={},
            warnings=[],
        )

        # frame_wait=20% + poll=20% + freeze=10% => 50%
        self.assertAlmostEqual(rr.results["txring_hold_block_pressure_pct"], 50.0, places=4)
        self.assertAlmostEqual(rr.results["txring_hold_block_frame_wait_ratio_pct"], 20.0, places=4)
        self.assertAlmostEqual(rr.results["txring_hold_block_poll_ratio_pct"], 20.0, places=4)
        self.assertAlmostEqual(rr.results["txring_hold_block_freeze_ratio_pct"], 10.0, places=4)

    def test_live_attack_report_run_quality_interrupted(self):
        from ddos_samurai import reporting

        rr = reporting.build_live_attack_report(
            args={"target": "127.0.0.1"},
            worker_events=[
                {
                    "status": "ok",
                    "attack_vector": "basic",
                    "compute_backend": "cpu",
                    "sender_path": "PYTHON_SENDMMSG",
                    "stats": {"attempted": 10, "sent": 10, "errors": 0, "bytes_sent_est": 640},
                }
            ],
            duration_s=1.0,
            progress_total=10,
            total_count=10,
            metrics={},
            warnings=["run_interrupted_by_user"],
        )
        self.assertEqual(rr.results["run_quality"], "interrupted")

    def test_live_attack_report_run_quality_invalid_metrics(self):
        from ddos_samurai import reporting

        rr = reporting.build_live_attack_report(
            args={"target": "127.0.0.1"},
            worker_events=[],
            duration_s=1.0,
            progress_total=0,
            total_count=0,
            metrics={},
            warnings=[],
        )
        self.assertEqual(rr.results["run_quality"], "invalid_metrics")

    def test_live_attack_report_includes_new_sender_and_l7_fields(self):
        from ddos_samurai import reporting

        rr = reporting.build_live_attack_report(
            args={"target": "127.0.0.1"},
            worker_events=[
                {
                    "status": "ok",
                    "attack_vector": "http",
                    "compute_backend": "cpu",
                    "sender_path": "C_EXT_L3",
                    "sender_fallback_reason": "none",
                    "l7_engine_path_used": "C_STATE_H2",
                    "l7_fallback_reason": "none",
                    "l7_capability_status": "ok",
                    "txring_batch_target": 128,
                    "txring_backoff_ns": 2000,
                    "afpacket_hugepage_mode": "required",
                    "afpacket_hugepage_effective": 1,
                    "afpacket_hugepage_reason": "effective",
                    "afpacket_hugepage_size_kb": 2048,
                    "afpacket_madvise_hugepage_ok": 1,
                    "afpacket_mlock_ok": 0,
                    "afpacket_prefault_pages": 8,
                    "afpacket_smaps_kernel_page_kb": 2048,
                    "afpacket_smaps_anon_hugepages_kb": 2048,
                    "afpacket_ring_block_size": 4096,
                    "afpacket_ring_block_nr": 64,
                    "afpacket_ring_size_bytes": 262144,
                    "l7_active_sessions_peak": 50,
                    "l7_conn_rate": 1234.5,
                    "l7_handshake_p99_ms": 44.0,
                    "l7_step_fail_ratio": 0.01,
                    "session_success_rate": 0.995,
                    "retry_success_rate": 0.91,
                    "h2_goaway_count": 2,
                    "h2_stream_resets": 1,
                    "h2_connections_used": 2,
                    "h2_request_plan_used": 1,
                    "h2_request_plan_items": 200,
                    "h2_stream_reset_ratio": 0.10,
                    "quic_connect_fail_count": 0,
                    "quic_connect_timeout_count": 0,
                    "quic_tls_fail_count": 0,
                    "quic_handshake_timeout_count": 0,
                    "quic_stream_fail_count": 0,
                    "quic_stream_fail_ratio": 0.0,
                    "quic_handshake_fail_ratio": 0.0,
                    "stats": {"attempted": 200, "sent": 198, "errors": 2, "bytes_sent_est": 19800},
                },
                {
                    "status": "degraded",
                    "attack_vector": "http",
                    "compute_backend": "cpu",
                    "sender_path": "PYTHON_SENDMMSG",
                    "sender_fallback_reason": "txring_unavailable",
                    "l7_engine_path_used": "C_STATE_QUIC",
                    "l7_fallback_reason": "connect_fail",
                    "l7_capability_status": "partial",
                    "txring_batch_target": 256,
                    "txring_backoff_ns": 4000,
                    "afpacket_hugepage_mode": "required",
                    "afpacket_hugepage_effective": 1,
                    "afpacket_hugepage_reason": "effective",
                    "afpacket_hugepage_size_kb": 2048,
                    "afpacket_madvise_hugepage_ok": 1,
                    "afpacket_mlock_ok": 0,
                    "afpacket_prefault_pages": 8,
                    "afpacket_smaps_kernel_page_kb": 2048,
                    "afpacket_smaps_anon_hugepages_kb": 4096,
                    "afpacket_ring_block_size": 4096,
                    "afpacket_ring_block_nr": 128,
                    "afpacket_ring_size_bytes": 524288,
                    "l7_active_sessions_peak": 60,
                    "l7_conn_rate": 1000.0,
                    "l7_handshake_p99_ms": 50.0,
                    "l7_step_fail_ratio": 0.03,
                    "session_success_rate": 0.98,
                    "retry_success_rate": 0.85,
                    "h2_goaway_count": 1,
                    "h2_stream_resets": 2,
                    "h2_connections_used": 1,
                    "h2_request_plan_used": 0,
                    "h2_request_plan_items": 0,
                    "h2_stream_reset_ratio": 0.30,
                    "quic_connect_fail_count": 1,
                    "quic_connect_timeout_count": 1,
                    "quic_tls_fail_count": 2,
                    "quic_handshake_timeout_count": 1,
                    "quic_stream_fail_count": 4,
                    "quic_stream_fail_ratio": 0.40,
                    "quic_handshake_fail_ratio": 0.20,
                    "stats": {"attempted": 100, "sent": 95, "errors": 5, "bytes_sent_est": 9500},
                },
            ],
            duration_s=2.0,
            progress_total=300,
            total_count=300,
            metrics={},
            warnings=[],
        )

        self.assertEqual(rr.results["run_quality"], "valid")
        self.assertEqual(rr.results["sender_fallback_reason"], "txring_unavailable")
        self.assertEqual(rr.results["txring_batch_target"], 256)
        self.assertEqual(rr.results["txring_backoff_ns"], 6000)
        self.assertEqual(rr.results["afpacket_hugepage_mode"], "required")
        self.assertEqual(rr.results["afpacket_hugepage_effective"], 1)
        self.assertEqual(rr.results["afpacket_hugepage_reason"], "effective")
        self.assertEqual(rr.results["afpacket_hugepage_size_kb"], 2048)
        self.assertEqual(rr.results["afpacket_ring_block_size"], 4096)
        self.assertEqual(rr.results["afpacket_ring_block_nr"], 128)
        self.assertEqual(rr.results["afpacket_ring_size_bytes"], 524288)
        self.assertEqual(rr.results["l7_active_sessions_peak"], 60)
        self.assertAlmostEqual(rr.results["l7_handshake_p99_ms"], 50.0, places=4)
        self.assertGreater(rr.results["session_success_rate"], 0.0)
        self.assertGreater(rr.results["retry_success_rate"], 0.0)
        self.assertEqual(rr.results["l7_engine_path_used"], "mixed")
        self.assertEqual(rr.results["l7_fallback_reason"], "connect_fail")
        self.assertEqual(rr.results["l7_capability_status"], "partial")
        self.assertEqual(rr.results["h2_goaway_count"], 3)
        self.assertEqual(rr.results["h2_stream_resets"], 3)
        self.assertEqual(rr.results["h2_connections_used"], 3)
        self.assertEqual(rr.results["h2_request_plan_used"], 1)
        self.assertEqual(rr.results["h2_request_plan_items"], 200)
        self.assertAlmostEqual(rr.results["h2_stream_reset_ratio"], 0.166667, places=6)
        self.assertEqual(rr.results["quic_connect_fail_count"], 1)
        self.assertEqual(rr.results["quic_connect_timeout_count"], 1)
        self.assertEqual(rr.results["quic_tls_fail_count"], 2)
        self.assertEqual(rr.results["quic_handshake_timeout_count"], 1)
        self.assertEqual(rr.results["quic_stream_fail_count"], 4)
        self.assertAlmostEqual(rr.results["quic_stream_fail_ratio"], 0.133333, places=6)
        self.assertAlmostEqual(rr.results["quic_handshake_fail_ratio"], 0.066667, places=6)
        self.assertEqual(rr.results["kpi_gate_profile"], "off")
        self.assertEqual(rr.results["kpi_gate_status"], "pass")
        self.assertEqual(rr.results["score_eligible"], 1)

    def test_live_attack_report_kpi_gate_dedicated_hard_fail(self):
        from ddos_samurai import reporting

        rr = reporting.build_live_attack_report(
            args={"target": "127.0.0.1", "kpi_gate_profile": "dedicated_lab", "kpi_hard_fail": True},
            worker_events=[
                {
                    "status": "ok",
                    "attack_vector": "basic",
                    "compute_backend": "cpu",
                    "sender_path": "C_EXT_L3",
                    "stats": {"attempted": 100, "sent": 50, "errors": 50, "bytes_sent_est": 3200},
                }
            ],
            duration_s=1.0,
            progress_total=100,
            total_count=100,
            metrics={},
            warnings=[],
        )
        self.assertEqual(rr.results["kpi_gate_profile"], "dedicated_lab")
        self.assertEqual(rr.results["kpi_gate_status"], "fail")
        self.assertEqual(rr.results["kpi_gate_hard_fail"], 1)
        self.assertEqual(rr.results["score_eligible"], 0)

    def test_live_attack_report_kpi_gate_dedicated_fails_on_afpacket_hugepage(self):
        from ddos_samurai import reporting

        rr = reporting.build_live_attack_report(
            args={"target": "127.0.0.1", "kpi_gate_profile": "dedicated_lab", "kpi_hard_fail": True},
            worker_events=[
                {
                    "status": "ok",
                    "attack_vector": "basic",
                    "compute_backend": "cpu",
                    "sender_path": "TX_RING_L2",
                    "afpacket_hugepage_mode": "required",
                    "afpacket_hugepage_effective": 0,
                    "afpacket_hugepage_reason": "hinted_not_realized",
                    "txring_tp_packets": 100,
                    "stats": {"attempted": 100, "sent": 100, "errors": 0, "bytes_sent_est": 6400},
                }
            ],
            duration_s=1.0,
            progress_total=100,
            total_count=100,
            metrics={},
            warnings=[],
        )
        self.assertEqual(rr.results["kpi_gate_status"], "fail")
        self.assertEqual(rr.results["kpi_gate_hard_fail"], 1)
        self.assertTrue(
            any(str(v).startswith("afpacket_hugepage_effective:") for v in rr.results.get("kpi_violations", []))
        )

    def test_live_attack_report_kpi_gate_exception_is_fail_closed(self):
        from ddos_samurai import reporting

        with patch("ddos_samurai.kpi_gate.evaluate", side_effect=RuntimeError("gate_boom")):
            rr = reporting.build_live_attack_report(
                args={"target": "127.0.0.1", "kpi_gate_profile": "dedicated_lab", "kpi_hard_fail": True},
                worker_events=[
                    {
                        "status": "ok",
                        "attack_vector": "basic",
                        "compute_backend": "cpu",
                        "sender_path": "C_EXT_L3",
                        "stats": {"attempted": 10, "sent": 10, "errors": 0, "bytes_sent_est": 640},
                    }
                ],
                duration_s=1.0,
                progress_total=10,
                total_count=10,
                metrics={},
                warnings=[],
            )
        self.assertEqual(rr.results["kpi_gate_profile"], "dedicated_lab")
        self.assertEqual(rr.results["kpi_gate_status"], "fail")
        self.assertEqual(rr.results["kpi_gate_hard_fail"], 1)
        self.assertEqual(rr.results["score_eligible"], 0)
        self.assertIn("kpi_gate_exception:RuntimeError", rr.results.get("kpi_violations", []))

    def test_live_attack_report_kpi_gate_dedicated_fails_on_runtime_hot_path_drift(self):
        from ddos_samurai import reporting

        rr = reporting.build_live_attack_report(
            args={"target": "127.0.0.1", "kpi_gate_profile": "dedicated_lab", "kpi_hard_fail": True},
            worker_events=[
                {
                    "status": "ok",
                    "attack_vector": "http",
                    "compute_backend": "cpu",
                    "sender_path": "C_STATE_HTTP",
                    "runtime_backend": "legacy",
                    "runtime_hot_path_level": "legacy_compat",
                    "legacy_path_used": 1,
                    "custom_tcp_bridge_xdp_enabled": 0,
                    "custom_tcp_bridge_backend_match": 0,
                    "sender_fallback_reason": "none",
                    "stats": {"attempted": 100, "sent": 100, "errors": 0, "bytes_sent_est": 6400},
                    "session_success_rate": 100.0,
                    "retry_success_rate": 100.0,
                    "l7_step_fail_ratio": 0.0,
                    "l7_handshake_p99_ms": 10.0,
                    "l7_fail_budget_pct": 0.0,
                }
            ],
            duration_s=1.0,
            progress_total=100,
            total_count=100,
            metrics={},
            warnings=[],
        )
        self.assertEqual(rr.results["kpi_gate_status"], "fail")
        self.assertEqual(rr.results["kpi_gate_hard_fail"], 1)
        self.assertTrue(any(str(v).startswith("runtime_backend:") for v in rr.results.get("kpi_violations", [])))
        self.assertTrue(any(str(v).startswith("runtime_hot_path_level:") for v in rr.results.get("kpi_violations", [])))
        self.assertTrue(any(str(v).startswith("legacy_path_used:") for v in rr.results.get("kpi_violations", [])))

    def test_live_attack_report_surfaces_stateful_runtime_preflight_and_transport_fields(self):
        from ddos_samurai import reporting

        rr = reporting.build_live_attack_report(
            args={"target": "127.0.0.1"},
            worker_events=[
                {
                    "status": "ok",
                    "attack_vector": "http",
                    "compute_backend": "cpu",
                    "sender_path": "C_STATE_HTTP",
                    "runtime_backend": "afxdp",
                    "runtime_hot_path_level": "phase1_hybrid_afxdp_custom_tcp",
                    "legacy_path_used": 0,
                    "stateful_runtime_status": "ready",
                    "stateful_runtime_reason": "none",
                    "stateful_runtime_detail": "",
                    "stateful_runtime_preflight_status": "passed",
                    "stateful_runtime_preflight_reason": "none",
                    "stateful_runtime_preflight_detail": "AF_XDP strict runtime preflight passed",
                    "stateful_runtime_preflight_backend_requested": "af_xdp",
                    "stateful_runtime_preflight_backend_used": "xdp",
                    "stateful_runtime_preflight_backend_match": 1,
                    "stateful_runtime_preflight_xdp_interface": "eth0",
                    "stateful_runtime_preflight_xdp_queue_id": 2,
                    "stateful_runtime_preflight_xdp_available": 1,
                    "stateful_runtime_preflight_xdp_enabled": 1,
                    "runtime_transport_service": "native_custom_tcp_runtime_service",
                    "runtime_transport_contract": "custom_tcp_runtime_bridge",
                    "runtime_transport_poll_calls": 3,
                    "runtime_transport_poll_actions": 7,
                    "runtime_transport_rx_poll_enabled": 1,
                    "runtime_transport_snapshot_available": 1,
                    "runtime_transport_service_loops": 4,
                    "stats": {"attempted": 10, "sent": 10, "errors": 0, "bytes_sent_est": 640},
                }
            ],
            duration_s=1.0,
            progress_total=10,
            total_count=10,
            metrics={},
            warnings=[],
        )
        self.assertEqual(rr.results["stateful_runtime_preflight_status"], "passed")
        self.assertEqual(rr.results["stateful_runtime_preflight_backend_used"], "xdp")
        self.assertEqual(rr.results["stateful_runtime_preflight_xdp_enabled"], 1)
        self.assertEqual(rr.results["runtime_transport_service"], "native_custom_tcp_runtime_service")
        self.assertEqual(rr.results["runtime_transport_contract"], "custom_tcp_runtime_bridge")
        self.assertEqual(rr.results["runtime_transport_poll_calls"], 3)
