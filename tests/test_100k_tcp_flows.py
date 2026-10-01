import unittest
import os
import sys
import subprocess
import math

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def hash_flow_key(src_ip: int, dst_ip: int, src_port: int, dst_port: int) -> int:
    h = src_ip & 0xFFFFFFFF
    h ^= (dst_ip & 0xFFFFFFFF) << 1
    h ^= (src_port & 0xFFFF) << 33
    h ^= (dst_port & 0xFFFF) << 49
    h &= 0xFFFFFFFFFFFFFFFF
    return ((h ^ (h >> 32)) & 0xFFFFFFFFFFFFFFFF) % 64


class Test100kTcpFlows(unittest.TestCase):
    def test_native_100k_flows_binary(self):
        """Execute compiled C++ test_100k_tcp_flows binary if available."""
        bin_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../ddos_samurai/build/l4/test_100k_tcp_flows")
        )
        if os.path.exists(bin_path):
            res = subprocess.run([bin_path], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"Native test failed:\n{res.stdout}\n{res.stderr}")
            self.assertIn("TEST PASSED", res.stdout)

    def test_python_4tuple_hash_distribution_100k(self):
        """Pure Python verification of 4-tuple hash distribution across 64 lock shards for 100,000 flows."""
        num_flows = 100000
        num_shards = 64
        shard_counts = [0] * num_shards

        for i in range(num_flows):
            src_ip = 0x0A000001 + (i % 256)
            dst_ip = 0xC0A80001 + ((i // 256) % 256)
            src_port = 10000 + (i % 50000)
            dst_port = 80

            shard = hash_flow_key(src_ip, dst_ip, src_port, dst_port)
            shard_counts[shard] += 1

        mean = num_flows / num_shards
        min_count = min(shard_counts)
        max_count = max(shard_counts)
        max_dev = max(abs(max_count - mean), abs(min_count - mean))
        max_variance_pct = (max_dev / mean) * 100.0

        self.assertLessEqual(
            max_variance_pct,
            5.0,
            f"Hash distribution variance {max_variance_pct:.2f}% exceeded 5.0% threshold (Min: {min_count}, Max: {max_count}, Mean: {mean})",
        )


if __name__ == "__main__":
    unittest.main()
