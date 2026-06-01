import unittest
import sys
import os
import random
import numpy as np

try:
    import pytest
    pytestmark = [pytest.mark.gpu]
except Exception:  # pragma: no cover - unittest-only environments
    pytestmark = []

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

GPU_AVAILABLE = False
try:
    import cupy as cp
    from numba import cuda
    if cuda.is_available():
        GPU_AVAILABLE = True
except ImportError:
    pass
except Exception:
    # Handle other init errors
    pass

# We still try to import the modules to check for syntax errors or non-GPU dependency issues
try:
    from ddos_samurai import gpu_packet
    MODULES_IMPORTABLE = True
except ImportError as e:
    print(f"[WARNING] Could not import GPU modules: {e}")
    MODULES_IMPORTABLE = False
except Exception as e:
    print(f"[WARNING] Error importing GPU modules: {e}")
    MODULES_IMPORTABLE = False

class TestGPUModules(unittest.TestCase):

    def setUp(self):
        if not MODULES_IMPORTABLE:
            self.skipTest("GPU modules could not be imported (missing dependencies?)")

    def test_gpu_packet_structure(self):
        """Verify gpu_packet module structure."""
        self.assertTrue(hasattr(gpu_packet, 'generate_packets'), "Missing generate_packets")
        self.assertTrue(hasattr(gpu_packet, 'generate_packets_from_template'), "Missing generate_packets_from_template")
        self.assertTrue(hasattr(gpu_packet, 'get_generation_telemetry'), "Missing get_generation_telemetry")
        self.assertTrue(hasattr(gpu_packet, 'reset_generation_telemetry'), "Missing reset_generation_telemetry")
        self.assertTrue(hasattr(gpu_packet, 'clear_generation_caches'), "Missing clear_generation_caches")
        self.assertTrue(hasattr(gpu_packet, 'init_gpu'), "Missing init_gpu")

    def test_basic_kernel_call(self):
        """Synchronous Python GPU generation is intentionally removed."""
        with self.assertRaises(gpu_packet.GPUPacketError):
            gpu_packet.generate_packets(
                count=10,
                target_ip="127.0.0.1",
                target_port=80,
                protocol="tcp",
                has_ethernet=False,
            )

if __name__ == '__main__':
    unittest.main()
