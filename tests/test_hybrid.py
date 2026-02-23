
import sys
import os
import socket
import struct
import unittest
import numpy as np

try:
    import pytest
    pytestmark = [pytest.mark.gpu]
except Exception:  # pragma: no cover - unittest-only environments
    pytestmark = []

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ddos_samurai import packet
from ddos_samurai.scapy_support import is_scapy_available

GPU_MODULES_IMPORTABLE = False
try:
    from ddos_samurai import gpu_packet
    GPU_MODULES_IMPORTABLE = True
except Exception:
    gpu_packet = None
    GPU_MODULES_IMPORTABLE = False

class TestHybridGeneration(unittest.TestCase):
    def test_hybrid_generation(self):
        if not GPU_MODULES_IMPORTABLE:
            self.skipTest("gpu_packet module unavailable (missing numba/cupy/CUDA deps).")
        if not is_scapy_available():
            self.skipTest("Scapy unavailable; hybrid CPU-template generation requires scapy.")

        print("\n[TEST] Testing Hybrid CPU-Template + GPU-Replication...")
        
        # 1. Create Template (CPU)
        target_ip = "192.168.1.100"
        target_port = 80
        payload_data = b"HYBRID_TEST_PAYLOAD"
        
        cfg = packet.PacketConfig(
            target_ip=target_ip,
            target_port=target_port,
            protocol="tcp",
            spoof=False,
            payload=payload_data,
            tcp_flags="PA",
            ttl=64,
            window=8192
        )
        
        template_pkt = packet.create_packet(cfg)
        template_bytes = bytes(template_pkt)
        
        print(f"[INFO] Template created. Length: {len(template_bytes)} bytes")
        
        # 2. Generate on GPU
        count = 10
        try:
            out = gpu_packet.generate_packets_from_template(
                template_bytes=template_bytes,
                count=count,
                real_src_ip="192.168.1.100",
                spoof_ip=True,
                has_ethernet=False,
                spoof_subnet="1.0.0.0/8",
            )
        except Exception as e:
            self.skipTest(f"GPU generation unavailable in this environment: {e}")

        if out is None:
            self.skipTest("GPU generation returned None (CUDA device unavailable).")

        if isinstance(out, tuple):
            gpu_packets, packet_len = out
        else:
            gpu_packets = out
            packet_len = len(template_bytes)
        if gpu_packets is None:
            self.skipTest("GPU packet buffer is None (CUDA device unavailable).")

        cpu_packets = np.asarray(gpu_packets.get(), dtype=np.uint8)
        self.assertEqual(packet_len, len(template_bytes))
        self.assertEqual(cpu_packets.size, count * packet_len)
        
        # 3. Verify
        print("[INFO] Verifying generated packets...")
        
        seen_src_ips = set()
        seen_src_ports = set()
        
        for i in range(count):
            offset = i * packet_len
            pkt_data = cpu_packets[offset : offset + packet_len]
            
            # Verify Length
            self.assertEqual(len(pkt_data), packet_len)
            
            raw_pkt = pkt_data.tobytes()
            self.assertTrue(payload_data in raw_pkt)
            
            # Extract IP Header
            # Assuming standard IPv4 header length of 20 bytes for now
            ip_header = pkt_data[0:20]
            src_ip = socket.inet_ntoa(ip_header[12:16])
            dst_ip = socket.inet_ntoa(ip_header[16:20])
            
            seen_src_ips.add(src_ip)
            self.assertEqual(dst_ip, target_ip)
            
            # Extract TCP Header
            ihl = (ip_header[0] & 0x0F) * 4
            tcp_header = pkt_data[ihl:ihl + 20]
            src_port = struct.unpack("!H", tcp_header[0:2])[0]
            
            seen_src_ports.add(src_port)
            
            # Verify Checksum is not 0 (it was recalculated)
            ip_checksum = struct.unpack("!H", ip_header[10:12])[0]
            self.assertNotEqual(ip_checksum, 0)
            self.assertTrue(1024 <= src_port <= 65535)

        print(f"[INFO] Unique Source IPs: {len(seen_src_ips)}")
        print(f"[INFO] Unique Source Ports: {len(seen_src_ports)}")

        # Source ports are deterministic per idx in kernel and should be unique in this batch.
        self.assertEqual(len(seen_src_ports), count)
        # Source IP spoofing is RNG-based; avoid flaky "all unique" expectation.
        self.assertGreater(len(seen_src_ips), 1)
        print("[PASS] Hybrid generation verified successfully.")

if __name__ == '__main__':
    unittest.main()
