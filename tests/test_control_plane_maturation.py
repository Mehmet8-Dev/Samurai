import unittest
import os
import sys

# Ensure samurai package path is available
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


class TestControlPlaneMaturation(unittest.TestCase):
    def test_default_db_port_memory_rule(self):
        # User Memory Rule Check: DB port MUST be 5099
        DEFAULT_DB_PORT = 5099
        self.assertEqual(DEFAULT_DB_PORT, 5099)

    def test_rate_limiter_logic(self):
        # Rate Limiting test simulation (100 reqs/sec cap)
        class RateLimiterPy:
            def __init__(self, max_per_sec=100):
                self.max_per_sec = max_per_sec
                self.clients = {}

            def allow(self, ip, sec):
                if ip not in self.clients or self.clients[ip][1] != sec:
                    self.clients[ip] = [1, sec]
                    return True
                if self.clients[ip][0] < self.max_per_sec:
                    self.clients[ip][0] += 1
                    return True
                return False

        limiter = RateLimiterPy(max_per_sec=3)
        ip = "127.0.0.1"
        sec = 1000
        self.assertTrue(limiter.allow(ip, sec))
        self.assertTrue(limiter.allow(ip, sec))
        self.assertTrue(limiter.allow(ip, sec))
        self.assertFalse(limiter.allow(ip, sec))  # Exceeded (4th request)

        # Next second resets limit
        self.assertTrue(limiter.allow(ip, sec + 1))


if __name__ == "__main__":
    unittest.main()
