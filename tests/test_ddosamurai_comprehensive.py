"""Project-level compatibility smoke for ZMQ control-plane APIs."""

import unittest

import ddos_samurai
from ddos_samurai import gpu_packet


class TestProjectComprehensive(unittest.TestCase):
    def test_capabilities_shape(self):
        caps = ddos_samurai.get_capabilities()
        self.assertIn("version", caps)
        self.assertIn("gpu_acceleration", caps)
        self.assertIn("af_xdp", caps)

    def test_gpu_stats_snapshot(self):
        snap = gpu_packet.read_stream_stats_snapshot()
        self.assertEqual(snap["backend"], "zmq")
        self.assertEqual(snap["transport"], "zmq")


if __name__ == "__main__":
    unittest.main(verbosity=2)
