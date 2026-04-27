import os
import tempfile
import unittest


class TestCliDryRunReporting(unittest.TestCase):
    def test_dry_run_writes_report_and_metrics(self):
        # Dry-run must be usable without root and must not trigger orchestrator/root checks.
        from ddos_samurai import cli
        from ddos_samurai import metrics

        metrics.reset_global_metrics()
        with tempfile.TemporaryDirectory() as td:
            out_base = os.path.join(td, "dryrun_unit")
            env = os.environ.copy()
            # Geliştirme/test ortamı için kullanmak amacıyla örnek bir lisans anahtarı "dev" olarak atanıyor
            env["SAMURAI_LICENSE_DEV_MODE"] = "1"
            os.environ.update(env)
            argv = [
                "--dry-run",
                "--target",
                "192.168.1.1",
                "--port",
                "80",
                "--protocol",
                "tcp",
                "--attack-vector",
                "basic",
                "--run-report",
                "--run-report-format",
                "json",
                "--run-report-dir",
                td,
                "--run-report-out",
                "dryrun_unit",
            ]
            with self.assertRaises(SystemExit) as cm:
                cli.main(argv)
            self.assertEqual(cm.exception.code, 0)

            self.assertTrue(os.path.exists(out_base + ".json"))
            self.assertTrue(os.path.exists(out_base + ".metrics.json"))
            self.assertTrue(os.path.exists(out_base + ".metrics.prom"))

    def test_build_loss_summary_includes_txring_and_sender_context(self):
        from ddos_samurai import cli

        payload = cli._build_loss_summary(
            {
                "attempted_total": 4000000,
                "sent_total": 3999980,
                "errors_total": 20,
                "sender_paths_used": {"TX_RING": 2},
                "sender_fallback_reason": "none",
                "txring_flush_call_count": 1024,
                "txring_flush_error_count": 8,
                "txring_flush_eagain_count": 6,
                "txring_flush_enobufs_count": 1,
                "txring_flush_ebusy_count": 1,
                "txring_flush_other_errno_count": 0,
                "txring_flush_last_errno": 11,
                "txring_flush_last_errno_name": "EAGAIN",
                "txring_tp_packets": 4000000,
                "txring_tp_drops": 0,
                "txring_tp_freeze_q_cnt": 0,
                "afpacket_ring_block_size": 1048576,
                "afpacket_ring_block_nr": 64,
                "afpacket_ring_size_bytes": 67108864,
                "wire_tx_accounted_packets": 4000000,
                "wire_tx_over_attempted_packets": 234,
            },
            "2026-03-13T12:00:00+00:00",
        )

        self.assertEqual(payload["attempted_total"], 4000000)
        self.assertEqual(payload["sent_total"], 3999980)
        self.assertEqual(payload["errors_total"], 20)
        self.assertEqual(payload["sender_paths_used"], {"TX_RING": 2})
        self.assertEqual(payload["sender_fallback_reason"], "none")
        self.assertEqual(payload["txring_flush_call_count"], 1024)
        self.assertEqual(payload["txring_flush_error_count"], 8)
        self.assertEqual(payload["txring_flush_eagain_count"], 6)
        self.assertEqual(payload["txring_flush_enobufs_count"], 1)
        self.assertEqual(payload["txring_flush_ebusy_count"], 1)
        self.assertEqual(payload["txring_flush_other_errno_count"], 0)
        self.assertEqual(payload["txring_flush_last_errno"], 11)
        self.assertEqual(payload["txring_flush_last_errno_name"], "EAGAIN")
        self.assertEqual(payload["txring_tp_packets"], 4000000)
        self.assertEqual(payload["txring_tp_drops"], 0)
        self.assertEqual(payload["txring_tp_freeze_q_cnt"], 0)
        self.assertEqual(payload["afpacket_ring_block_size"], 1048576)
        self.assertEqual(payload["afpacket_ring_block_nr"], 64)
        self.assertEqual(payload["afpacket_ring_size_bytes"], 67108864)
        self.assertEqual(payload["wire_tx_accounted_packets"], 4000000)
        self.assertEqual(payload["wire_tx_over_attempted_packets"], 234)
