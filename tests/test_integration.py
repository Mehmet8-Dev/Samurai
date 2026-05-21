import unittest

from ddos_samurai import orchestrator


def _base_args():
    return {
        "target": "192.168.1.1",
        "port": 80,
        "count": 100,
        "attack_vector": "basic",
        "protocol": "udp",
        "compute_backend": "cpu",
    }


class TestWorkerProcessIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_worker_process_removed_in_zmq_migration(self):
        with self.assertRaises(RuntimeError):
            await orchestrator.worker_process(worker_id=1, args=_base_args(), ssl_context=None)


if __name__ == "__main__":
    unittest.main()
