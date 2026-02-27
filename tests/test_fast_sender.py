import unittest
import sys
import os
import struct

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from ddos_samurai import fast_sender
    FAST_SENDER_AVAILABLE = True
except ImportError:
    FAST_SENDER_AVAILABLE = False

class TestFastSender(unittest.TestCase):
    
    def setUp(self):
        if not FAST_SENDER_AVAILABLE:
            self.skipTest("fast_sender C extension not available/compiled")

    def test_module_structure(self):
        """Verify that fast_sender module has expected functions."""
        self.assertTrue(hasattr(fast_sender, 'send_optimized'), "Missing send_optimized")
        self.assertTrue(hasattr(fast_sender, 'send_ring_optimized'), "Missing send_ring_optimized")
        self.assertTrue(hasattr(fast_sender, 'cleanup_ring'), "Missing cleanup_ring")
        self.assertTrue(hasattr(fast_sender, 'get_ring_info'), "Missing get_ring_info")
        self.assertTrue(hasattr(fast_sender, 'configure_state_engine'), "Missing configure_state_engine")
        self.assertTrue(hasattr(fast_sender, 'get_state_engine_stats'), "Missing get_state_engine_stats")
        self.assertTrue(hasattr(fast_sender, 'ingest_tx_packets'), "Missing ingest_tx_packets")
        self.assertTrue(hasattr(fast_sender, 'sweep_state_table'), "Missing sweep_state_table")

    def test_send_optimized_signature(self):
        """
        Verify send_optimized can be called (argument validation).
        We expect it to fail with specific errors if args are wrong, 
        or return 0 if socket is invalid but args parse correctly.
        """
        # Signature: send_optimized(sockfd, view, target_ip, target_port, packet_size, count)
        # We pass a dummy socket fd (e.g. -1 or 0)
        
        # Create a dummy packet buffer
        dummy_packet = b'A' * 64
        count = 1
        
        try:
            # We expect this might raise an OSError because fd 0 is stdin, or -1 is invalid
            # But we want to ensure the C extension *parsed* the args correctly before hitting OS logic
            fast_sender.send_optimized(-1, dummy_packet, "127.0.0.1", 80, len(dummy_packet), count)
        except OSError:
            # Expected behavior for invalid socket
            pass
        except TypeError as e:
            self.fail(f"send_optimized argument mismatch: {e}")
        except Exception as e:
            # If it's another error, it might still be fine (e.g. value error for IP)
            pass

    def test_mimicry_settings(self):
        """Test set_mimicry_settings if available."""
        if hasattr(fast_sender, 'set_mimicry_settings'):
            try:
                # Window, MSS, TTL
                fast_sender.set_mimicry_settings(65535, 1460, 64)
            except Exception as e:
                self.fail(f"set_mimicry_settings failed: {e}")

    def test_get_ring_info_schema(self):
        """get_ring_info should return a dict with stable introspection keys."""
        info = fast_sender.get_ring_info()
        self.assertIsInstance(info, dict)
        expected_keys = {
            "is_setup",
            "packet_version",
            "packet_version_name",
            "iface",
            "tp_block_size",
            "tp_frame_size",
            "tp_block_nr",
            "tp_frame_nr",
            "ring_size",
            "frame_header_size",
        }
        self.assertTrue(expected_keys.issubset(set(info.keys())))

    def test_configure_state_engine_and_stats(self):
        """State-engine runtime configuration APIs should be callable."""
        out = fast_sender.configure_state_engine(65536, 256, 60)
        self.assertIsInstance(out, dict)
        self.assertEqual(int(out.get("table_size", 0)), 65536)
        self.assertEqual(int(out.get("lock_count", 0)), 256)
        self.assertEqual(int(out.get("timeout_sec", 0)), 60)

        stats = fast_sender.get_state_engine_stats()
        self.assertIsInstance(stats, dict)
        self.assertIn("active_entries", stats)
        self.assertIn("timeout_evictions", stats)
        self.assertIn("overwrites", stats)

    def test_ingest_and_sweep_state_engine(self):
        """Ingest/sweep APIs should return integer counts."""
        dummy_packet = b"A" * 64
        ingested = fast_sender.ingest_tx_packets(dummy_packet, len(dummy_packet), 1)
        self.assertIsInstance(ingested, int)
        swept = fast_sender.sweep_state_table(1024)
        self.assertIsInstance(swept, int)

if __name__ == '__main__':
    unittest.main()
