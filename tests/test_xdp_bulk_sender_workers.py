import time
import unittest
from unittest.mock import patch

from ddos_samurai.af_xdp_sender import XDPBulkSender, XDPStats


class _FakeXDPSender:
    sent_calls = 0
    sent_packets = 0
    created_queue_ids = []
    created_multi_ctx_flags = []

    def __init__(self, **kwargs):
        self._running = False
        _FakeXDPSender.created_queue_ids.append(kwargs.get("queue_id"))
        _FakeXDPSender.created_multi_ctx_flags.append(kwargs.get("use_multi_ctx"))

    def start(self):
        self._running = True
        return True

    def stop(self):
        self._running = False

    def send(self, packets):
        _FakeXDPSender.sent_calls += 1
        _FakeXDPSender.sent_packets += len(packets or [])
        return len(packets or [])

    def get_stats(self):
        qid = _FakeXDPSender.created_queue_ids[-1]
        if qid is None:
            qid = 0
        return XDPStats(
            tx_packets=_FakeXDPSender.sent_packets,
            queue_id=int(qid),
            tx_backpressure_events=1,
            tx_send_calls=1,
            tx_send_ns_total=1000,
            tx_send_ns_max=1000,
            tx_send_avg_us=1.0,
            tx_send_max_us=1.0,
        )


class TestXDPBulkSenderWorkers(unittest.TestCase):
    def setUp(self):
        _FakeXDPSender.sent_calls = 0
        _FakeXDPSender.sent_packets = 0
        _FakeXDPSender.created_queue_ids = []
        _FakeXDPSender.created_multi_ctx_flags = []

    def test_start_creates_worker_threads(self):
        with patch("ddos_samurai.af_xdp_sender.XDPSender", _FakeXDPSender):
            bulk = XDPBulkSender(
                interface="lo",
                threads=3,
                batch_size=8,
                queue_id_base=2,
                queue_count=8,
                use_multi_ctx=True,
            )
            bulk.start()
            try:
                self.assertEqual(len(bulk._workers), 3)
                self.assertEqual(len(bulk._senders), 3)
                self.assertEqual(_FakeXDPSender.created_queue_ids, [2, 3, 4])
                self.assertEqual(_FakeXDPSender.created_multi_ctx_flags, [True, True, True])
                bulk._sender_queues[0].put([b"x" * 32], timeout=0.2)
                time.sleep(0.1)
                self.assertGreaterEqual(_FakeXDPSender.sent_calls, 1)
            finally:
                bulk.stop()

    def test_send_continuous_feeds_worker_queue(self):
        with patch("ddos_samurai.af_xdp_sender.XDPSender", _FakeXDPSender):
            bulk = XDPBulkSender(interface="lo", threads=2, batch_size=8, queue_count=1)
            stats = bulk.send_continuous(
                packet_generator=lambda: [b"x" * 32],
                duration=0.2,
            )
            try:
                self.assertIsInstance(stats, XDPStats)
                self.assertGreater(_FakeXDPSender.sent_packets, 0)
                self.assertEqual(len(bulk._senders), 2)
                self.assertEqual(_FakeXDPSender.created_queue_ids, [0, 0])
                self.assertEqual(_FakeXDPSender.created_multi_ctx_flags, [True, True])
                queue_stats = bulk.get_queue_stats()
                self.assertEqual(len(queue_stats), 2)
                self.assertEqual(queue_stats[0]["queue_id"], 0)
            finally:
                bulk.stop()


if __name__ == "__main__":
    unittest.main()
