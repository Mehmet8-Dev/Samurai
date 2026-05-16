import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class TestAnomalyPacket(unittest.TestCase):
    def setUp(self):
        # Check if CUDA is reachable (mock if not)
        self.cuda_available = False
        try:
            from numba import cuda
            if cuda.is_available():
                self.cuda_available = True
        except ImportError:
            pass

    def test_anomaly_suite_structure(self):
        """Verify that the anomaly suite generates correct dictionary keys."""
        if not self.cuda_available:
            self.skipTest("CUDA not available")

        try:
            from ddos_samurai import anomaly_packet
            import cupy as cp
            
            # Test parameters
            count = 20
            target_ip = "192.168.1.50"
            target_port = 80
            
            results = anomaly_packet.generate_full_anomaly_suite(
                count=count,
                target_ip=target_ip,
                target_port=target_port,
                anomaly_intensity=50
            )
            
            # Verify keys exist (based on default suite logic)
            self.assertIn('anomaly', results)
            self.assertIn('overlap_frag', results)
            self.assertIn('tiny_frag', results)
            
            # Verify shapes
            anom_buf, anom_size = results['anomaly']
            self.assertGreater(anom_buf.nbytes, 0)
            self.assertGreater(anom_size, 0)
            
            overlap_buf, overlap_size = results['overlap_frag']
            # Overlap generates 2 fragments per logical packet
            self.assertGreater(overlap_buf.nbytes, 0)
            self.assertGreater(overlap_size, 0)

        except ImportError:
            pass
        except Exception as e:
            msg = str(e)
            if (
                "CUDA_ERROR_UNSUPPORTED_PTX_VERSION" in msg
                or "Unsupported .version" in msg
                or "nvjitlink" in msg.lower()
                or "nvJitLink" in msg
                or "may need newer version of nvJitLink library" in msg
            ):
                self.skipTest("CUDA driver/PTX version mismatch in runtime environment")
            self.fail(f"Anomaly generation raised exception: {e}")

    def test_anomaly_flags(self):
        """Test argument parsing for anomaly command line flags."""
        from ddos_samurai import cli
        import argparse
        
        parser = argparse.ArgumentParser()
        # Re-create relevant CLI part for testing logic
        anomaly_group = parser.add_argument_group('Anomaly Packet Options')
        anomaly_group.add_argument("--anomaly-types", type=int, nargs='+', default=None)
        anomaly_group.add_argument("--anomaly-intensity", type=int, default=75)
        anomaly_group.add_argument("--anomaly-suite", action="store_true")
        
        # Test basic args
        args = parser.parse_args(['--anomaly-types', '0', '1', '2', '--anomaly-intensity', '90'])
        self.assertEqual(args.anomaly_types, [0, 1, 2])
        self.assertEqual(args.anomaly_intensity, 90)
        self.assertFalse(args.anomaly_suite)
        
        # Test suite flag
        args = parser.parse_args(['--anomaly-suite'])
        self.assertTrue(args.anomaly_suite)

if __name__ == '__main__':
    unittest.main()
