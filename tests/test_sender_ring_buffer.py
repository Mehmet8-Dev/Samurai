"""Ring-buffer contract tests via descriptor FSM helpers."""

import unittest

from ddos_samurai import gpu_packet


class TestSenderRingBufferContract(unittest.TestCase):
    def test_valid_lifecycle(self):
        states = [0, 1, 2, 3, 4, 0]
        for s, t in zip(states, states[1:]):
            self.assertTrue(gpu_packet.descriptor_transition_valid(s, t))

    def test_invalid_jumps(self):
        for s, t in [(0, 2), (1, 3), (2, 4), (4, 2)]:
            self.assertFalse(gpu_packet.descriptor_transition_valid(s, t))


if __name__ == "__main__":
    unittest.main(verbosity=2)
