import unittest
import os
import sys
import subprocess
import json
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


class Test1mTcpFlows(unittest.TestCase):
    def test_native_1m_flows_binary(self):
        """Execute compiled C++ test_1m_tcp_flows binary if available and verify full 1M metrics."""
        candidate_paths = [
            os.path.abspath(os.path.join(os.path.dirname(__file__), "../build/l4/test_1m_tcp_flows")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "../samurai/build/l4/test_1m_tcp_flows")),
        ]
        bin_path = next((p for p in candidate_paths if os.path.exists(p)), None)
        if bin_path:
            json_report_path = "/tmp/samurai_1m_tcp_report.json"
            if os.path.exists(json_report_path):
                os.remove(json_report_path)

            res = subprocess.run([bin_path, "--flows", "1000000", "--runs", "1", "--json", json_report_path],
                                 capture_output=True, text=True, timeout=120)
            self.assertEqual(res.returncode, 0, f"Native 1M test failed:\n{res.stdout}\n{res.stderr}")
            self.assertIn("TEST PASSED", res.stdout)

            self.assertTrue(os.path.exists(json_report_path), "JSON benchmark report was not generated")
            with open(json_report_path, "r") as f:
                report = json.load(f)

            self.assertEqual(report.get("status"), "PASSED")
            self.assertEqual(report.get("num_flows"), 1000000)
            self.assertEqual(report.get("tx_syn_drained"), 1000000)
            self.assertEqual(report.get("handshakes_completed"), 1000000)
            self.assertEqual(report.get("tx_ack_drained"), 1000000)
            self.assertEqual(report.get("completions_collected"), 1000000)
            self.assertEqual(report.get("single_total_packets"), 3000000)
            self.assertEqual(report.get("shared_nothing_total_packets"), 3000000)
            self.assertLessEqual(report.get("shard_max_variance_pct", 100.0), 5.0)
            self.assertGreater(report.get("cps", 0), 100000)
            self.assertGreater(report.get("shared_nothing_cps", 0), 500000)
            self.assertGreater(report.get("sizeof_flow_entry_bytes", 0), 0)
            self.assertGreater(report.get("established_rss_delta_per_flow_bytes", 0), 0)
            self.assertGreater(report.get("bytes_per_flow", 0), 0)
            self.assertTrue(report.get("shared_nothing_affinity_verified", False))

    def test_python_4tuple_hash_distribution_1m(self):
        """Pure Python verification of 4-tuple hash distribution across 64 lock shards for 1,000,000 flows."""
        num_flows = 1000000
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
            f"Hash distribution variance {max_variance_pct:.4f}% exceeded 5.0% threshold (Min: {min_count}, Max: {max_count}, Mean: {mean})",
        )


if __name__ == "__main__":
    unittest.main()
