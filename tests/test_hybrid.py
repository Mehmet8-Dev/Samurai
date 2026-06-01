import unittest

from ddos_samurai import gpu_packet
from ddos_samurai.zmq.dispatcher import DispatchResult
from ddos_samurai.zmq.wire import WorkerKind


class _FakeDispatcher:
    def __init__(self):
        self.calls = []

    def dispatch_start_job(self, **kwargs):
        self.calls.append(("start", kwargs))
        return DispatchResult(endpoint=str(kwargs.get("endpoint") or "ipc:///tmp/fake"), bytes_sent=64)

    def dispatch_stop_job(self, **kwargs):
        self.calls.append(("stop", kwargs))
        return DispatchResult(endpoint=str(kwargs.get("endpoint") or "ipc:///tmp/fake"), bytes_sent=32)

    def dispatch_shutdown_worker(self, **kwargs):
        self.calls.append(("shutdown", kwargs))
        return DispatchResult(endpoint=str(kwargs.get("endpoint") or "ipc:///tmp/fake"), bytes_sent=16)


class TestHybridFacade(unittest.TestCase):
    def test_stream_lifecycle_uses_gpu_worker_kind(self):
        fake = _FakeDispatcher()
        start = gpu_packet.start_stream({"job_id": "s1", "target_ip": "1.1.1.1"}, dispatcher=fake)
        upd = gpu_packet.update_stream("s1", {"target_rps": 1000}, dispatcher=fake)
        stop = gpu_packet.stop_stream("s1", dispatcher=fake)
        shut = gpu_packet.shutdown_persistent_runtime(dispatcher=fake)

        self.assertGreater(start.bytes_sent, 0)
        self.assertGreater(upd.bytes_sent, 0)
        self.assertGreater(stop.bytes_sent, 0)
        self.assertGreater(shut.bytes_sent, 0)

        for _kind, call in fake.calls:
            self.assertEqual(call["worker_kind"], WorkerKind.GPU)


if __name__ == "__main__":
    unittest.main(verbosity=2)
