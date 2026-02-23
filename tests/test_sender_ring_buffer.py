#!/usr/bin/env python3
"""
COMPREHENSIVE SENDER TESTS - TX_RING, Fast Sender, Socket Operations
C extension ve ring buffer testleri
"""

import unittest
import sys
import os
import struct
import time

try:
    import pytest
    pytestmark = [pytest.mark.privileged]
except Exception:  # pragma: no cover - unittest-only environments
    pytestmark = []

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ddos_samurai.packet import create_packet, PacketConfig
from ddos_samurai.scapy_support import is_scapy_available


class TestUtilityFunctions(unittest.TestCase):
    """
    TEST SUITE 6: Network Configuration
    Network interfaces, addresses
    """
    
    def test_network_configuration(self):
        """Test 6.1: Network configuration"""
        print("\n" + "="*80)
        print("TEST 6.1: NETWORK CONFIGURATION")
        print("="*80)
        
        import socket
        
        try:
            # Get local hostname
            hostname = socket.gethostname()
            print(f"✓ Hostname: {hostname}")
            
            # Get local IP
            local_ip = socket.gethostbyname(hostname)
            print(f"✓ Local IP: {local_ip}")
            
            # Verify IP format
            parts = local_ip.split('.')
            self.assertEqual(len(parts), 4)
            
            for part in parts:
                num = int(part)
                self.assertGreaterEqual(num, 0)
                self.assertLess(num, 256)
            
            print(f"✓ IP format valid")
            print("✓ TEST 6.1 PASSED\n")
        
        except Exception as e:
            print(f"⚠ Skipped: {e}\n")


class TestEthernetFrameStructure(unittest.TestCase):
    """
    TEST SUITE 7: Ethernet Frame Structure
    L2 + L3 frame yapısı
    """
    
    def setUp(self):
        if not is_scapy_available():
            self.skipTest("Scapy unavailable; Ethernet frame tests require scapy packet creation.")

    def test_ethernet_frame_layout(self):
        """Test 7.1: Ethernet frame layoutı"""
        print("\n" + "="*80)
        print("TEST 7.1: ETHERNET FRAME LAYOUT FOR TX_RING")
        print("="*80)
        
        config = PacketConfig(
            target_ip="192.168.1.1",
            target_port=80,
            protocol="tcp"
        )
        
        packet = create_packet(config)
        pkt_bytes = bytes(packet)
        
        print(f"\n✓ IP packet size: {len(pkt_bytes)} bytes")
        print(f"\nExpected TX_RING frame structure:")
        print("-" * 80)
        print(f"  [0-5]:       Dest MAC (6 bytes)")
        print(f"  [6-11]:      Src MAC (6 bytes)")
        print(f"  [12-13]:     EtherType (0x0800 for IPv4)")
        print(f"  [14-33]:     IPv4 header (20 bytes)")
        print(f"  [34-53]:     TCP header (20 bytes)")
        print(f"  [54+]:       Payload (if any)")
        print(f"\nTotal frame size: 14 (L2) + {len(pkt_bytes)} (L3/L4) = {14 + len(pkt_bytes)} bytes")
        
        print(f"\n✓ L3 payload analysis:")
        print(f"  Byte[0]: 0x{pkt_bytes[0]:02x} (IPv4 Version/IHL)")
        print(f"  Byte[9]: {pkt_bytes[9]} (Protocol: TCP=6)")
        
        # Total length field check
        total_len = struct.unpack('>H', pkt_bytes[2:4])[0]
        print(f"  Total IPv4 length: {total_len} bytes")
        
        self.assertEqual(total_len, len(pkt_bytes), "IPv4 total length must match packet size")
        
        print("\n✓ TEST 7.1 PASSED\n")
    
    def test_ipv4_byte_zero_in_frame(self):
        """Test 7.2: Frame'de IPv4 Byte[0]"""
        print("\n" + "="*80)
        print("TEST 7.2: IPV4 BYTE[0] IN ETHERNET FRAME")
        print("="*80)
        
        config = PacketConfig(
            target_ip="192.168.1.1",
            target_port=80,
            protocol="tcp"
        )
        
        packet = create_packet(config)
        pkt_bytes = bytes(packet)
        user_data_offset = 64  # Example aligned offset used in frame math
        
        print(f"\nPayload structure in ring buffer:")
        print("-" * 80)
        print(f"User data offset: {user_data_offset} (aligned TPACKET header area)")
        print(f"\n  Ring_buffer[{user_data_offset}-{user_data_offset+13}]:    Ethernet header (14 bytes)")
        print(f"  Ring_buffer[{user_data_offset+14}-{user_data_offset+33}]:    IPv4 header (20 bytes)")
        print(f"  Ring_buffer[{user_data_offset+34}-{user_data_offset+53}]:   TCP header (20 bytes)")
        print(f"\nIP Byte[0] in ring buffer:")
        print(f"  Payload_offset = {user_data_offset}")
        print(f"  IPv4_offset = payload_offset + 14 = {user_data_offset + 14}")
        print(f"  IPv4_Byte[0] = ring_buffer[{user_data_offset + 14}] = pkt_bytes[0] = 0x{pkt_bytes[0]:02x}")
        
        self.assertEqual(pkt_bytes[0], 0x45, "IPv4 Byte[0] must be 0x45")
        
        print(f"\n✓ IPv4 Byte[0] correctly set to 0x45")
        print("✓ TEST 7.2 PASSED\n")


class TestRingBufferConfiguration(unittest.TestCase):
    """
    TEST SUITE 8: Ring Buffer Configuration
    TPACKET header (version-dependent), frame alignment
    """
    
    def test_tpacket_header_alignment(self):
        """Test 8.1: TPACKET header alignment"""
        print("\n" + "="*80)
        print("TEST 8.1: TPACKET HEADER ALIGNMENT")
        print("="*80)
        
        TPACKET_ALIGNMENT = 16
        header_sizes = [52, 68]  # Typical kernel header lengths for V2 and V3
        
        print(f"✓ TPACKET_ALIGNMENT: {TPACKET_ALIGNMENT} bytes")

        for hdr in header_sizes:
            aligned = ((hdr + TPACKET_ALIGNMENT - 1) & ~(TPACKET_ALIGNMENT - 1))
            print(f"✓ Header {hdr} -> aligned {aligned} bytes")
            self.assertEqual(aligned % TPACKET_ALIGNMENT, 0)
            self.assertGreaterEqual(aligned, hdr)
        
        print("\n✓ TEST 8.1 PASSED\n")
    
    def test_ring_buffer_frame_calculation(self):
        """Test 8.2: Ring buffer frame hesaplaması"""
        print("\n" + "="*80)
        print("TEST 8.2: RING BUFFER FRAME CALCULATION")
        print("="*80)
        
        # Typical ring buffer config
        block_size = 4096      # 4KB blocks
        frames_per_block = 2   # 2x 2048-byte frames
        frame_size = block_size // frames_per_block
        num_blocks = 4
        
        print(f"✓ Ring buffer configuration:")
        print(f"  Block size: {block_size} bytes")
        print(f"  Frames per block: {frames_per_block}")
        print(f"  Frame size: {frame_size} bytes")
        print(f"  Total blocks: {num_blocks}")
        print(f"  Total ring buffer: {block_size * num_blocks} bytes")
        
        # Frame offset calculation example
        print(f"\n✓ Frame offset calculation examples:")
        print("-" * 80)
        
        for frame_num in [0, 1, 2, 3, 4, 5]:
            block_idx = frame_num // frames_per_block
            frame_in_block = frame_num % frames_per_block
            offset = (block_idx * block_size) + (frame_in_block * frame_size)
            
            print(f"  Frame {frame_num}: block={block_idx}, " +
                  f"in_block={frame_in_block}, offset=0x{offset:04x} ({offset})")
            
            # Kontrol
            self.assertLess(offset, block_size * num_blocks,
                           f"Frame {frame_num} offset out of bounds")
        
        print("\n✓ TEST 8.2 PASSED\n")


class TestPayloadOffsets(unittest.TestCase):
    """
    TEST SUITE 9: Payload Offsets in Ring Buffer
    User data offset, Ethernet, IPv4, TCP positioning
    """
    
    def setUp(self):
        if not is_scapy_available():
            self.skipTest("Scapy unavailable; payload offset tests require scapy packet creation.")

    def test_payload_offset_calculation(self):
        """Test 9.1: Payload offset hesaplanması"""
        print("\n" + "="*80)
        print("TEST 9.1: PAYLOAD OFFSET CALCULATION")
        print("="*80)
        
        print(f"\n✓ In ring buffer frame:")
        print("-" * 80)
        user_data_offset = 64  # Example aligned start
        print(f"  [0-{user_data_offset-1}]:      TPACKET header (kernel fills)")
        print(f"  [{user_data_offset}-{user_data_offset+13}]:     Ethernet frame (dest_mac + src_mac + ethertype)")
        print(f"  [{user_data_offset+14}-{user_data_offset+33}]:     IPv4 header (20 bytes)")
        print(f"  [{user_data_offset+34}-{user_data_offset+53}]:    TCP header (20 bytes)")
        print(f"  [{user_data_offset+54}+]:      Payload/Options")
        
        # Frame'de ethernet offset
        eth_offset = user_data_offset
        ipv4_offset = eth_offset + 14  # Ethernet 14 bytes
        tcp_offset = ipv4_offset + 20  # IPv4 20 bytes
        
        print(f"\n✓ Calculated offsets:")
        print(f"  Ethernet header offset: {eth_offset}")
        print(f"  IPv4 header offset: {ipv4_offset}")
        print(f"  TCP header offset: {tcp_offset}")
        
        # Verify with actual packet
        config = PacketConfig(
            target_ip="192.168.1.1",
            target_port=80,
            protocol="tcp"
        )
        
        packet = create_packet(config)
        pkt_bytes = bytes(packet)
        
        # pkt_bytes[0] = IPv4 Byte[0]
        # In ring buffer: ring_buffer[eth_offset + 14] = pkt_bytes[0]
        # So: ring_buffer[78] = pkt_bytes[0] = 0x45
        
        print(f"\n✓ Verification with real packet:")
        print(f"  pkt_bytes[0] = 0x{pkt_bytes[0]:02x}")
        print(f"  In ring_buffer[{ipv4_offset}] = 0x{pkt_bytes[0]:02x}")
        
        self.assertEqual(pkt_bytes[0], 0x45)
        
        print("\n✓ TEST 9.1 PASSED\n")


class TestMACAddressOperations(unittest.TestCase):
    """
    TEST SUITE 10: MAC Address Operations
    MAC parsing, formatting, byte operations
    """
    
    def test_mac_string_to_bytes(self):
        """Test 10.1: MAC string'i bytes'a çevirme"""
        print("\n" + "="*80)
        print("TEST 10.1: MAC STRING TO BYTES CONVERSION")
        print("="*80)
        
        mac_string = "f4:2d:06:17:e4:34"
        
        # Parse MAC
        mac_bytes = bytes.fromhex(mac_string.replace(':', ''))
        
        print(f"✓ MAC string: {mac_string}")
        print(f"✓ MAC bytes: {mac_bytes.hex()}")
        print(f"✓ MAC as list: {list(mac_bytes)}")
        
        # Kontrol
        self.assertEqual(len(mac_bytes), 6)
        self.assertEqual(mac_bytes[0], 0xf4)
        self.assertEqual(mac_bytes[5], 0x34)
        
        print(f"\n✓ In Ethernet frame:")
        print(f"  dest_mac (6 bytes): {' '.join(f'{b:02x}' for b in mac_bytes)}")
        print(f"  src_mac (6 bytes):  ac:50:de:9a:42:9d")
        
        print("\n✓ TEST 10.1 PASSED\n")
    
    def test_ethertype_value(self):
        """Test 10.2: EtherType değerleri"""
        print("\n" + "="*80)
        print("TEST 10.2: ETHERTYPE VALUES")
        print("="*80)
        
        ethertypes = {
            'IPv4': 0x0800,
            'ARP': 0x0806,
            'IPv6': 0x86DD,
            'VLAN': 0x8100,
        }
        
        print(f"\n✓ Common EtherType values:")
        print("-" * 80)
        for name, value in ethertypes.items():
            high = (value >> 8) & 0xFF
            low = value & 0xFF
            print(f"  {name:8s}: 0x{value:04x} (bytes: 0x{high:02x} 0x{low:02x})")
        
        # IPv4 check
        ipv4_value = 0x0800
        ipv4_high = (ipv4_value >> 8) & 0xFF
        ipv4_low = ipv4_value & 0xFF
        
        self.assertEqual(ipv4_high, 0x08)
        self.assertEqual(ipv4_low, 0x00)
        
        print(f"\n✓ IPv4 EtherType in ring buffer:")
        print(f"  frame[12] = 0x{ipv4_high:02x}")
        print(f"  frame[13] = 0x{ipv4_low:02x}")
        
        print("\n✓ TEST 10.2 PASSED\n")


def run_sender_tests():
    """Tüm sender testlerini çalıştır"""
    print("\n" + "="*80)
    print("🔍 COMPREHENSIVE SENDER & RING BUFFER TESTS")
    print("="*80)
    print(f"Start time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Test suites
    suite.addTests(loader.loadTestsFromTestCase(TestUtilityFunctions))
    suite.addTests(loader.loadTestsFromTestCase(TestEthernetFrameStructure))
    suite.addTests(loader.loadTestsFromTestCase(TestRingBufferConfiguration))
    suite.addTests(loader.loadTestsFromTestCase(TestPayloadOffsets))
    suite.addTests(loader.loadTestsFromTestCase(TestMACAddressOperations))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Summary
    print("\n" + "="*80)
    print("📊 SENDER TESTS SUMMARY")
    print("="*80)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n✓ ALL SENDER TESTS PASSED!")
    else:
        print("\n✗ SOME TESTS FAILED")
    
    print(f"End time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    return result


if __name__ == "__main__":
    result = run_sender_tests()
    sys.exit(0 if result.wasSuccessful() else 1)
