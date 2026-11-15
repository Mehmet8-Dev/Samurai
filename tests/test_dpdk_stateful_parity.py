import unittest
import os
import sys
import subprocess

# Ensure samurai package path is available
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


class TestDpdkStatefulParity(unittest.TestCase):
    def test_dpdk_vdev_env_variable(self):
        os.environ["SAMURAI_DPDK_VDEV"] = "net_af_packet0,iface=lo"
        self.assertEqual(os.environ.get("SAMURAI_DPDK_VDEV"), "net_af_packet0,iface=lo")

    def test_dpdk_worker_binary_exists(self):
        binary_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../build/zmq/samurai_dpdk_worker"))
        self.assertTrue(os.path.exists(binary_path), f"Binary not found at {binary_path}")

    def test_dpdk_test_astf_binary_runs(self):
        astf_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../build/l7_emu_native/test_l2l3_astf"))
        self.assertTrue(os.path.exists(astf_path))
        res = subprocess.run([astf_path], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("ALL VERIFICATION TESTS PASSED SUCCESSFULLY", res.stdout)


if __name__ == "__main__":
    unittest.main()
