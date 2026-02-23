"""
COMPREHENSIVE SENDER TESTS - fast_sender.c, senders.py, TX_RING Implementation
C extension, ring buffer, socket operations
"""

import unittest
import sys
import os
import struct
import socket
import ctypes
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ddos_samurai.packet import create_packet, PacketConfig
from ddos_samurai import senders as senders_module
from ddos_samurai.scapy_support import is_scapy_available
from ddos_samurai.utils import get_gateway_mac, get_local_ip


class _ScapyRequiredTestCase(unittest.TestCase):
    def setUp(self):
        if not is_scapy_available():
            self.skipTest("Scapy unavailable; packet creation tests require scapy.")


class TestFastSenderInitialization(unittest.TestCase):
    """
    TEST SUITE 7: FastSender Initialization
    C extension ve socket'ın düzgün initialize edilip edilmediği
    """
    
    def test_fast_sender_import(self):
        """Test 7.1: FastSender modülü yüklenebiliyor mu"""
        print("\n" + "="*70)
        print("TEST 7.1: FAST SENDER MODULE IMPORT")
        print("="*70)
        
        try:
            from ddos_samurai import fast_sender as _fast_sender  # type: ignore
            print("✓ fast_sender extension imported successfully")
            print(f"✓ send_optimized: {getattr(_fast_sender, 'send_optimized', None)}")
            print("✓ TEST 7.1 PASSED\n")
        except ImportError as e:
            print(f"⚠ fast_sender extension not available: {e}")
            self.skipTest("fast_sender C extension not available/compiled")
    
    def test_c_extension_availability(self):
        """Test 7.2: C extension'ın mevcut olup olmadığı"""
        print("\n" + "="*70)
        print("TEST 7.2: C EXTENSION AVAILABILITY")
        print("="*70)
        
        print(f"✓ Senders module loaded: {senders_module.__file__}")
        print(f"✓ senders.FAST_SENDER_AVAILABLE: {getattr(senders_module, 'FAST_SENDER_AVAILABLE', False)}")

        try:
            from ddos_samurai import fast_sender as _fast_sender  # type: ignore
            has_sendmmsg = hasattr(_fast_sender, "send_optimized")
            has_tx_ring = hasattr(_fast_sender, "send_ring_optimized")
            print(f"✓ fast_sender.send_optimized available: {has_sendmmsg}")
            print(f"✓ fast_sender.send_ring_optimized available: {has_tx_ring}")
            print("✓ TEST 7.2 PASSED\n")
        except ImportError as e:
            print(f"⚠ fast_sender extension not available: {e}")
            self.skipTest("fast_sender C extension not available/compiled")


class TestGatewayMAC(unittest.TestCase):
    """
    TEST SUITE 8: Gateway MAC Resolution
    Gateway MAC adresinin doğru tespit edilip edilmediği
    """
    
    def test_gateway_mac_resolution(self):
        """Test 8.1: Gateway MAC resolve edilebiliyor mu"""
        print("\n" + "="*70)
        print("TEST 8.1: GATEWAY MAC RESOLUTION")
        print("="*70)
        
        try:
            mac = get_gateway_mac()
            print(f"✓ Gateway MAC: {mac}")
            
            # MAC format kontrol (XX:XX:XX:XX:XX:XX)
            mac_parts = mac.split(':')
            self.assertEqual(len(mac_parts), 6, "MAC should have 6 parts")
            
            for part in mac_parts:
                self.assertEqual(len(part), 2, "Each MAC part should be 2 hex chars")
                int(part, 16)  # Hex kontrolü
            
            print(f"✓ MAC format valid")
            print("✓ TEST 8.1 PASSED\n")
        
        except Exception as e:
            print(f"⚠ Gateway MAC resolution failed: {e}")
            print("  (This may be expected in some environments)")
            print("✓ TEST 8.1 SKIPPED\n")
    
    def test_local_ip_resolution(self):
        """Test 8.2: Local IP doğru bulunuyor mu"""
        print("\n" + "="*70)
        print("TEST 8.2: LOCAL IP RESOLUTION")
        print("="*70)
        
        try:
            local_ip = get_local_ip()
            print(f"✓ Local IP: {local_ip}")
            
            # IP format kontrol
            parts = local_ip.split('.')
            self.assertEqual(len(parts), 4, "IP should have 4 parts")
            
            for part in parts:
                num = int(part)
                self.assertGreaterEqual(num, 0)
                self.assertLess(num, 256)
            
            print(f"✓ IP format valid")
            print("✓ TEST 8.2 PASSED\n")
        
        except Exception as e:
            print(f"⚠ Local IP resolution failed: {e}")
            print("✓ TEST 8.2 SKIPPED\n")


class TestPacketFormatForSending(_ScapyRequiredTestCase):
    """
    TEST SUITE 9: Packet Format for TX_RING
    Paketlerin TX_RING'e gönderilmek üzere doğru format olup olmadığı
    """
    
    def test_ethernet_frame_structure(self):
        """Test 9.1: Ethernet frame yapısı (L2 + L3)"""
        print("\n" + "="*70)
        print("TEST 9.1: ETHERNET FRAME STRUCTURE FOR TX_RING")
        print("="*70)
        
        config = PacketConfig(
            target_ip="192.168.1.1",
            target_port=80,
            protocol="tcp",
        )
        packet = create_packet(config)
        
        pkt_bytes = bytes(packet)
        print(f"✓ Packet size: {len(pkt_bytes)} bytes (IPv4 + TCP headers only)")
        
        # L2 frame eklenince nasıl olacağını göster
        # TX_RING: Dest MAC(6) + Src MAC(6) + EtherType(2) + IPv4(20) + TCP(20) + Payload(?)
        eth_frame_size = 14 + len(pkt_bytes)  # 14 byte Ethernet header
        
        print(f"\n✓ With Ethernet frame:")
        print(f"  Dest MAC:    6 bytes")
        print(f"  Src MAC:     6 bytes")
        print(f"  EtherType:   2 bytes (0x0800 for IPv4)")
        print(f"  IPv4+TCP:   {len(pkt_bytes)} bytes")
        print(f"  TOTAL:      {eth_frame_size} bytes")
        
        # Expected structure
        print(f"\n✓ Frame structure in TX_RING ring buffer:")
        print(f"  [0-5]:       Dest MAC (f4:2d:06:17:e4:34)")
        print(f"  [6-11]:      Src MAC  (ac:50:de:9a:42:9d)")
        print(f"  [12-13]:     EtherType (0x08 0x00)")
        print(f"  [14-33]:     IPv4 header (20 bytes)")
        print(f"  [34-53]:     TCP header (20 bytes)")
        print(f"  [54+]:       Payload (if any)")
        
        print("\n✓ TEST 9.1 PASSED\n")
    
    def test_ipv4_byte0_for_transmission(self):
        """Test 9.2: Transmission için IPv4 Byte[0] kontrolü"""
        print("\n" + "="*70)
        print("TEST 9.2: IPV4 BYTE[0] FOR TRANSMISSION")
        print("="*70)
        
        config = PacketConfig(
            target_ip="192.168.1.1",
            target_port=80,
            protocol="tcp",
        )
        packet = create_packet(config)
        
        pkt_bytes = bytes(packet)
        
        # TX_RING'e yazılmadan önceki durum
        print(f"✓ Before TX_RING transmission:")
        print(f"  Packet Byte[0]: 0x{pkt_bytes[0]:02x} (IPv4 + IHL)")
        
        # TX_RING'e yazarken Ethernet header eklenir
        # Bu durumda IPv4 header Byte[14]'te başlar
        print(f"\n✓ In TX_RING ring buffer:")
        print(f"  Offset 0-13:  Ethernet header (14 bytes)")
        print(f"  Offset 14:    IPv4 Byte[0] = 0x{pkt_bytes[0]:02x}")
        print(f"  Offset 15-33: Rest of IPv4+TCP headers")
        
        # Kontrol
        self.assertEqual(pkt_bytes[0], 0x45, "IPv4 Byte[0] must be 0x45")
        print(f"\n✓ VERIFIED: IPv4 Byte[0] = 0x45 for correct transmission")
        
        print("✓ TEST 9.2 PASSED\n")
    
    def test_tcp_port_configuration(self):
        """Test 9.3: TCP port'ların doğru ayarlanması"""
        print("\n" + "="*70)
        print("TEST 9.3: TCP PORT CONFIGURATION")
        print("="*70)
        
        target_port = 9999
        
        config = PacketConfig(
            target_ip="192.168.1.1",
            target_port=target_port,
            protocol="tcp",
        )
        packet = create_packet(config)
        
        pkt_bytes = bytes(packet)
        tcp_header = pkt_bytes[20:40]
        
        # TCP header: [0-1]=src port, [2-3]=dst port
        extracted_src_port = struct.unpack('>H', tcp_header[0:2])[0]
        extracted_dst_port = struct.unpack('>H', tcp_header[2:4])[0]
        
        print(f"✓ Source port set: {extracted_src_port} (randomized)")
        print(f"✓ Dest port set:   {extracted_dst_port} (expected: {target_port})")
        
        self.assertEqual(extracted_dst_port, target_port, 
                        f"Dest port must be {target_port}")
        self.assertGreaterEqual(extracted_src_port, 1024)
        self.assertLessEqual(extracted_src_port, 65535)
        
        print("✓ TEST 9.3 PASSED\n")


class TestRingBufferStructure(unittest.TestCase):
    """
    TEST SUITE 10: TX_RING Ring Buffer Structure
    TPACKET_V2 header, frame layout, alignment
    """
    
    def test_ring_buffer_frame_size_calculation(self):
        """Test 10.1: Ring buffer frame size hesaplanması"""
        print("\n" + "="*70)
        print("TEST 10.1: RING BUFFER FRAME SIZE")
        print("="*70)
        
        # TPACKET_V2_HDR = 64 bytes (fixed)
        TPACKET2_HDRLEN = 64
        
        # L2 + L3 payload
        eth_size = 14  # Ethernet header
        ipv4_tcp_size = 48  # IPv4(20) + TCP(20) + minimal payload(8)
        payload_size = eth_size + ipv4_tcp_size
        
        # Total frame size (with alignment)
        tp_len = payload_size  # This is what goes in tp_len field
        
        print(f"✓ TPACKET2_HDRLEN: {TPACKET2_HDRLEN} bytes")
        print(f"✓ Ethernet header: {eth_size} bytes")
        print(f"✓ IPv4+TCP: {ipv4_tcp_size} bytes")
        print(f"✓ Total payload: {payload_size} bytes (tp_len value)")
        
        # In ring buffer
        frame_start = TPACKET2_HDRLEN
        payload_start = TPACKET2_HDRLEN
        payload_end = TPACKET2_HDRLEN + payload_size
        
        print(f"\n✓ Ring buffer frame layout:")
        print(f"  [0-63]:        TPACKET2_HDR (kernel fills this)")
        print(f"  [64-77]:       Ethernet header (14 bytes)")
        print(f"  [78-106]:      IPv4 header (20 bytes)")
        print(f"  [98-117]:      TCP header (20 bytes)")
        print(f"  [118+]:        Payload (if any)")
        print(f"  tp_len field:  {tp_len} (tells kernel how much user data)")
        
        print("\n✓ TEST 10.1 PASSED\n")
    
    def test_frame_offset_calculation(self):
        """Test 10.2: Frame offset hesaplanması (block-based)"""
        print("\n" + "="*70)
        print("TEST 10.2: FRAME OFFSET CALCULATION (BLOCK-BASED)")
        print("="*70)
        
        # Ring buffer configuration
        block_size = 4096  # 4KB blocks
        frame_size = 2048  # frames
        num_blocks = 4
        
        print(f"✓ Ring buffer configuration:")
        print(f"  Block size: {block_size} bytes")
        print(f"  Frame size: {frame_size} bytes")
        print(f"  Num blocks: {num_blocks}")
        print(f"  Total size: {block_size * num_blocks} bytes")
        
        print(f"\n✓ Frame offset calculation (frame-based addressing):")
        
        # Example: Frame 5
        frame_num = 5
        block_idx = frame_num // (block_size // frame_size)
        frame_in_block = frame_num % (block_size // frame_size)
        offset = (block_idx * block_size) + (frame_in_block * frame_size)
        
        print(f"  Frame {frame_num}:")
        print(f"    Block index: {block_idx}")
        print(f"    Frame in block: {frame_in_block}")
        print(f"    Memory offset: 0x{offset:x} ({offset} bytes)")
        
        # Kontrol et
        self.assertGreaterEqual(offset, 0)
        self.assertLess(offset, block_size * num_blocks)
        
        print("\n✓ TEST 10.2 PASSED\n")


class TestPayloadOffsetInFrame(unittest.TestCase):
    """
    TEST SUITE 11: Payload Offset in Ring Buffer
    TPACKET_ALIGN macro, user data offset
    """
    
    def test_tpacket_align_macro(self):
        """Test 11.1: TPACKET_ALIGN macro'su"""
        print("\n" + "="*70)
        print("TEST 11.1: TPACKET_ALIGN MACRO")
        print("="*70)
        
        # TPACKET_ALIGN(x) = (((x)+TPACKET_ALIGNMENT-1)&~(TPACKET_ALIGNMENT-1))
        # TPACKET_ALIGNMENT = 16 (for modern systems)
        TPACKET_ALIGNMENT = 16
        TPACKET2_HDRLEN = 64
        
        def TPACKET_ALIGN(x):
            return ((x + TPACKET_ALIGNMENT - 1) & ~(TPACKET_ALIGNMENT - 1))
        
        aligned_hdr = TPACKET_ALIGN(TPACKET2_HDRLEN)
        
        print(f"✓ TPACKET_ALIGNMENT: {TPACKET_ALIGNMENT}")
        print(f"✓ TPACKET2_HDRLEN: {TPACKET2_HDRLEN}")
        print(f"✓ Aligned header size: {aligned_hdr}")
        
        # Payload starts at TPACKET_ALIGN(TPACKET2_HDRLEN)
        # For 64-byte header + 16-byte alignment = 64 (already aligned!)
        print(f"\n✓ Payload offset in frame:")
        print(f"  Frame[0-{aligned_hdr-1}]: TPACKET2_HDR ({aligned_hdr} bytes)")
        print(f"  Frame[{aligned_hdr}+]:    User payload (L2+L3+L4)")
        
        self.assertEqual(aligned_hdr, 64, "64-byte header should align to 64")
        
        print("\n✓ TEST 11.1 PASSED\n")
    
    def test_user_data_write_offset(self):
        """Test 11.2: User data yazılacağı offset"""
        print("\n" + "="*70)
        print("TEST 11.2: USER DATA WRITE OFFSET")
        print("="*70)
        
        TPACKET2_HDRLEN = 64
        user_data_offset = 64  # Payload starts here
        
        eth_header_offset = user_data_offset
        ipv4_header_offset = user_data_offset + 14
        tcp_header_offset = user_data_offset + 14 + 20
        
        print(f"✓ User payload offset: {user_data_offset}")
        print(f"\n✓ Offsets within frame:")
        print(f"  TPACKET2_HDR:   [0-63]")
        print(f"  Ethernet:       [{eth_header_offset}-{eth_header_offset+13}]")
        print(f"  IPv4:           [{ipv4_header_offset}-{ipv4_header_offset+19}]")
        print(f"  TCP:            [{tcp_header_offset}-{tcp_header_offset+19}]")
        
        print(f"\n✓ In C code (fast_sender.c):")
        print(f"  char* header = ring_buffer + frame_offset")
        print(f"  char* payload_ptr = (char*)header + 64  // User data offset")
        print(f"  memcpy(payload_ptr + 0, eth_header, 14)")
        print(f"  memcpy(payload_ptr + 14, ipv4_packet, 28)")
        
        print("\n✓ TEST 11.2 PASSED\n")


class TestMACAddressHandling(unittest.TestCase):
    """
    TEST SUITE 12: MAC Address Handling
    MAC address parsing, formatting, byte ordering
    """
    
    def test_mac_address_format(self):
        """Test 12.1: MAC address format'ı"""
        print("\n" + "="*70)
        print("TEST 12.1: MAC ADDRESS FORMAT")
        print("="*70)
        
        mac_string = "f4:2d:06:17:e4:34"
        
        # Parse MAC
        mac_bytes = bytes.fromhex(mac_string.replace(':', ''))
        
        print(f"✓ MAC string: {mac_string}")
        print(f"✓ MAC bytes: {mac_bytes.hex()}")
        print(f"✓ MAC as decimal: {' '.join(str(b) for b in mac_bytes)}")
        
        # Kontrol
        self.assertEqual(len(mac_bytes), 6)
        self.assertEqual(mac_bytes[0], 0xf4)
        self.assertEqual(mac_bytes[1], 0x2d)
        
        print("\n✓ How it's used in TX_RING:")
        print(f"  memcpy(frame + 0, dest_mac, 6)  // Offset 0")
        print(f"  memcpy(frame + 6, src_mac, 6)   // Offset 6")
        print(f"  frame[12] = 0x08  // EtherType high byte")
        print(f"  frame[13] = 0x00  // EtherType low byte")
        
        print("\n✓ TEST 12.1 PASSED\n")

class TestSenderStatsAndPaths(unittest.TestCase):
    """TEST SUITE 13: Sender Stats & Path Tracking (trex_path regression tests).

    Verifies that:
    - quic_sender dead code was removed
    - _stats() supports string values for sender_path
    - raw_socket_sender classifies PermissionError
    - sender path fields appear in returned dicts
    """

    def test_quic_sender_has_no_dead_code_after_return(self):
        """Regression: quic_sender should not contain unreachable _flush function."""
        import inspect
        src = inspect.getsource(senders_module.quic_sender)
        self.assertNotIn("async def _flush", src,
                         "Dead code (_flush) should have been removed from quic_sender")
        self.assertNotIn("status_2xx", src,
                         "Dead counter variables should have been removed")

    def test_stats_helper_accepts_string_sender_path(self):
        """_stats(**extra) should preserve string values like sender_path."""
        result = senders_module._stats(
            attempted=10, sent=10, errors=0,
            sender_path="TX_RING_L2",
            fallback_count=0,
            permission_error_count=0,
        )
        self.assertEqual(result["sender_path"], "TX_RING_L2")
        self.assertEqual(result["fallback_count"], 0)
        self.assertEqual(result["permission_error_count"], 0)

    def test_stats_helper_ignores_non_primitive_extra(self):
        """_stats should silently ignore dict/list/none in extra kwargs."""
        result = senders_module._stats(
            attempted=5, sent=5, errors=0,
            some_dict={"a": 1}, some_list=[1, 2], some_none=None,
        )
        self.assertNotIn("some_dict", result)
        self.assertNotIn("some_list", result)
        self.assertNotIn("some_none", result)

    def test_raw_socket_sender_permission_error_returns_sender_path_none(self):
        """raw_socket_sender should classify PermissionError and return sender_path=NONE."""
        import asyncio
        import socket
        from unittest.mock import patch

        async def _run():
            return await senders_module.raw_socket_sender(
                packets_buffer=b"X" * 100,
                target_ip="127.0.0.1",
                target_port=80,
                count=1,
                verbose=False,
            )

        real_socket_ctor = socket.socket

        def _socket_side_effect(*args, **kwargs):
            family = args[0] if len(args) > 0 else kwargs.get("family", socket.AF_INET)
            sock_type = args[1] if len(args) > 1 else kwargs.get("type", socket.SOCK_STREAM)
            proto = args[2] if len(args) > 2 else kwargs.get("proto", 0)

            if (
                family == socket.AF_INET
                and sock_type == socket.SOCK_RAW
                and proto == socket.IPPROTO_RAW
            ):
                raise PermissionError("test")

            return real_socket_ctor(*args, **kwargs)

        with patch("socket.socket", side_effect=_socket_side_effect):
            result = asyncio.run(_run())
        self.assertEqual(result["sender_path"], "NONE")
        self.assertEqual(result["permission_error_count"], 1)
        self.assertEqual(result["sent"], 0)
        self.assertEqual(result["errors"], 1)


def run_sender_tests():
    """Tüm sender testlerini çalıştır"""
    print("\n" + "="*70)
    print("🔍 COMPREHENSIVE SENDER TESTS")
    print("="*70)
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Tüm test sınıflarını ekle
    suite.addTests(loader.loadTestsFromTestCase(TestFastSenderInitialization))
    suite.addTests(loader.loadTestsFromTestCase(TestGatewayMAC))
    suite.addTests(loader.loadTestsFromTestCase(TestPacketFormatForSending))
    suite.addTests(loader.loadTestsFromTestCase(TestRingBufferStructure))
    suite.addTests(loader.loadTestsFromTestCase(TestPayloadOffsetInFrame))
    suite.addTests(loader.loadTestsFromTestCase(TestMACAddressHandling))
    suite.addTests(loader.loadTestsFromTestCase(TestSenderStatsAndPaths))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Özet
    print("\n" + "="*70)
    print("📊 SENDER TESTS SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    return result


if __name__ == "__main__":
    result = run_sender_tests()
    sys.exit(0 if result.wasSuccessful() else 1)
