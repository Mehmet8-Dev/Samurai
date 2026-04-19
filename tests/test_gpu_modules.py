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
    from ddos_samurai import gpu_payload
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

    def test_gpu_payload_structure(self):
        """Verify gpu_payload module structure."""
        self.assertTrue(hasattr(gpu_payload, 'GPUPayloadEngine'), "Missing GPUPayloadEngine class")
        
        # Test class instantiation if possible (might require GPU)
        if GPU_AVAILABLE:
            try:
                engine = gpu_payload.GPUPayloadEngine(count=10)
                self.assertIsNotNone(engine.packets_gpu)
            except Exception as e:
                self.fail(f"GPUPayloadEngine init failed on GPU: {e}")

    def test_basic_kernel_call(self):
        """Attempt to call a basic generation function if GPU is available."""
        if not GPU_AVAILABLE:
            self.skipTest("No CUDA-capable GPU detected, skipping kernel execution test.")
            return

        try:
            # Try to generate a small batch of packets
            count = 10
            target_ip = "127.0.0.1"
            target_port = 80
            
            packets, size = gpu_packet.generate_packets(
                count=count,
                target_ip=target_ip,
                target_port=target_port,
                protocol="tcp",
                has_ethernet=False # Simpler for test
            )
            
            self.assertIsNotNone(packets)
            self.assertGreater(size, 0)
            
            # New default is host-ready; accept both host ndarray and device ndarray.
            self.assertTrue(isinstance(packets, (cp.ndarray, np.ndarray)))

            # Basic sanity check on CPU copy (supports both backends).
            cpu_packets = packets.get() if hasattr(packets, "get") else np.asarray(packets, dtype=np.uint8)
            self.assertEqual(len(cpu_packets), count * size)
            
        except Exception as e:
            self.fail(f"GPU Kernel execution failed: {e}")

if __name__ == '__main__':
    unittest.main()
