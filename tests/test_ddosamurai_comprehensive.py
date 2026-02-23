#!/usr/bin/env python3
"""
SIMPLIFIED COMPREHENSIVE UNIT TESTS - DDoSamurai Full Stack
Gerçek codebase ile uyumlu, her bir parçayı detaylı kontrol eden testler
"""

import unittest
import sys
import os
import struct
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ddos_samurai.packet import create_packet, PacketConfig
from ddos_samurai.scapy_support import is_scapy_available


class _ScapyRequiredTestCase(unittest.TestCase):
    def setUp(self):
        if not is_scapy_available():
            self.skipTest("Scapy unavailable; packet creation tests require scapy.")


class TestBasicPacketGeneration(_ScapyRequiredTestCase):
    """
    TEST SUITE 1: Packet Generation Basics
    Temel paket oluşturma testleri
    """
    
    def test_tcp_packet_creation(self):
        """Test 1.1: TCP paketinin oluşturulması"""
        print("\n" + "="*80)
        print("TEST 1.1: TCP PACKET CREATION")
        print("="*80)
        
        config = PacketConfig(
            target_ip="192.168.1.1",
            target_port=80,
            protocol="tcp"
        )
        
        packet = create_packet(config)
        packet_bytes = bytes(packet)
        
        print(f"✓ TCP Packet created: {len(packet_bytes)} bytes")
        print(f"  Hex (first 30 bytes): {packet_bytes[:30].hex()}")
        
        # IPv4 version ve IHL kontrolü
        ip_version = (packet_bytes[0] >> 4) & 0xF
        ip_ihl = packet_bytes[0] & 0xF
        
        print(f"✓ Byte[0]: 0x{packet_bytes[0]:02x}")
        print(f"  IPv4 Version: {ip_version} (expected: 4)")
        print(f"  IPv4 IHL: {ip_ihl} (expected: 5)")
        
        self.assertEqual(ip_version, 4, "IPv4 version must be 4")
        self.assertEqual(ip_ihl, 5, "IPv4 IHL must be 5")
        self.assertEqual(packet_bytes[0], 0x45, "Byte[0] must be 0x45")
        
        # Protocol kontrolü (TCP = 6)
        protocol = packet_bytes[9]
        print(f"✓ Protocol field: {protocol} (expected: 6 for TCP)")
        self.assertEqual(protocol, 6, "Protocol must be 6 for TCP")
        
        print("✓ TEST 1.1 PASSED\n")
    
    def test_udp_packet_creation(self):
        """Test 1.2: UDP paketinin oluşturulması"""
        print("\n" + "="*80)
        print("TEST 1.2: UDP PACKET CREATION")
        print("="*80)
        
        config = PacketConfig(
            target_ip="192.168.1.1",
            target_port=9999,
            protocol="udp"
        )
        
        packet = create_packet(config)
        packet_bytes = bytes(packet)
        
        print(f"✓ UDP Packet created: {len(packet_bytes)} bytes")
        print(f"  Byte[0]: 0x{packet_bytes[0]:02x}")
        
        # Byte[0] kontrolü
        self.assertEqual(packet_bytes[0], 0x45, "Byte[0] must be 0x45")
        
        # Protocol kontrolü (UDP = 17)
        protocol = packet_bytes[9]
        print(f"✓ Protocol field: {protocol} (expected: 17 for UDP)")
        self.assertEqual(protocol, 17, "Protocol must be 17 for UDP")
        
        print("✓ TEST 1.2 PASSED\n")
    
    def test_multiple_packets(self):
        """Test 1.3: Birden fazla paket oluşturma"""
        print("\n" + "="*80)
        print("TEST 1.3: MULTIPLE PACKET GENERATION")
        print("="*80)
        
        packets = []
        for i in range(100):
            config = PacketConfig(
                target_ip="192.168.1.1",
                target_port=80 + (i % 100),
                protocol="tcp"
            )
            packet = create_packet(config)
            packets.append(bytes(packet))
        
        print(f"✓ Generated {len(packets)} packets")
        
        # Tüm paketlerin Byte[0] = 0x45 olduğunu kontrol et
        all_valid = all(pkt[0] == 0x45 for pkt in packets)
        print(f"✓ All packets have Byte[0] = 0x45: {all_valid}")
        self.assertTrue(all_valid)
        
        # Version kontrolü
        all_v4 = all((pkt[0] >> 4) & 0xF == 4 for pkt in packets)
        print(f"✓ All packets have IPv4 version 4: {all_v4}")
        self.assertTrue(all_v4)
        
        print("✓ TEST 1.3 PASSED\n")


class TestIPv4HeaderStructure(_ScapyRequiredTestCase):
    """
    TEST SUITE 2: IPv4 Header Structure
    IPv4 header'ındaki her byte'ı kontrol et
    """
    
    def test_ipv4_header_fields(self):
        """Test 2.1: IPv4 header alanları"""
        print("\n" + "="*80)
        print("TEST 2.1: IPV4 HEADER FIELDS")
        print("="*80)
        
        config = PacketConfig(
            target_ip="192.168.1.1",
            target_port=80,
            protocol="tcp"
        )
        
        packet = create_packet(config)
        pkt_bytes = bytes(packet)
        
        print("\nIPv4 Header Analysis:")
        print("-" * 80)
        
        # Byte 0: Version + IHL
        version = (pkt_bytes[0] >> 4) & 0xF
        ihl = pkt_bytes[0] & 0xF
        print(f"Byte[0] = 0x{pkt_bytes[0]:02x}:")
        print(f"  Version: {version}")
        print(f"  IHL: {ihl}")
        self.assertEqual(pkt_bytes[0], 0x45)
        
        # Byte 1: ToS
        tos = pkt_bytes[1]
        print(f"Byte[1] (ToS): 0x{tos:02x}")
        
        # Bytes 2-3: Total Length
        total_len = struct.unpack('>H', pkt_bytes[2:4])[0]
        print(f"Bytes[2-3] (Total Len): {total_len}")
        self.assertGreater(total_len, 20, "Packet must be at least 20 bytes")
        
        # Bytes 4-5: ID
        packet_id = struct.unpack('>H', pkt_bytes[4:6])[0]
        print(f"Bytes[4-5] (ID): 0x{packet_id:04x}")
        
        # Byte 8: TTL
        ttl = pkt_bytes[8]
        print(f"Byte[8] (TTL): {ttl}")
        self.assertGreater(ttl, 0)
        
        # Byte 9: Protocol
        protocol = pkt_bytes[9]
        print(f"Byte[9] (Protocol): {protocol} (TCP=6)")
        self.assertEqual(protocol, 6)
        
        # Bytes 10-11: Header Checksum
        hdr_checksum = struct.unpack('>H', pkt_bytes[10:12])[0]
        print(f"Bytes[10-11] (Checksum): 0x{hdr_checksum:04x}")
        self.assertNotEqual(hdr_checksum, 0, "Checksum should not be zero")
        
        # Bytes 12-15: Source IP
        src_ip = '.'.join(str(b) for b in pkt_bytes[12:16])
        print(f"Bytes[12-15] (Source IP): {src_ip}")
        
        # Bytes 16-19: Destination IP
        dst_ip = '.'.join(str(b) for b in pkt_bytes[16:20])
        print(f"Bytes[16-19] (Dest IP): {dst_ip}")
        self.assertEqual(dst_ip, "192.168.1.1")
        
        print("\n✓ TEST 2.1 PASSED\n")


class TestTCPHeaderStructure(_ScapyRequiredTestCase):
    """
    TEST SUITE 3: TCP Header Structure
    TCP header'ındaki alanlar
    """
    
    def test_tcp_header_fields(self):
        """Test 3.1: TCP header alanları"""
        print("\n" + "="*80)
        print("TEST 3.1: TCP HEADER FIELDS")
        print("="*80)
        
        config = PacketConfig(
            target_ip="192.168.1.1",
            target_port=80,
            protocol="tcp"
        )
        
        packet = create_packet(config)
        pkt_bytes = bytes(packet)
        tcp_header = pkt_bytes[20:40]  # TCP header starts at byte 20
        
        print("\nTCP Header Analysis:")
        print("-" * 80)
        
        # Bytes 0-1: Source Port
        src_port = struct.unpack('>H', tcp_header[0:2])[0]
        print(f"Bytes[0-1] (Source Port): {src_port}")
        self.assertGreater(src_port, 1024, "Source port should be >1024")
        
        # Bytes 2-3: Destination Port
        dst_port = struct.unpack('>H', tcp_header[2:4])[0]
        print(f"Bytes[2-3] (Dest Port): {dst_port}")
        self.assertEqual(dst_port, 80)
        
        # Bytes 4-7: Sequence Number
        seq_num = struct.unpack('>I', tcp_header[4:8])[0]
        print(f"Bytes[4-7] (Seq Num): 0x{seq_num:08x}")
        
        # Bytes 8-11: Acknowledgment Number
        ack_num = struct.unpack('>I', tcp_header[8:12])[0]
        print(f"Bytes[8-11] (Ack Num): 0x{ack_num:08x}")
        
        # Byte 12: Data Offset
        data_offset = (tcp_header[12] >> 4) & 0xF
        print(f"Byte[12] (Data Offset): {data_offset} ({data_offset*4} bytes)")
        self.assertGreaterEqual(data_offset, 5, "Data offset must be >=5")
        
        # Byte 13: Flags
        flags_byte = tcp_header[13]
        print(f"Byte[13] (Flags): 0x{flags_byte:02x}")
        
        flags = {
            'FIN': bool(flags_byte & 0x01),
            'SYN': bool((flags_byte >> 1) & 0x01),
            'RST': bool((flags_byte >> 2) & 0x01),
            'PSH': bool((flags_byte >> 3) & 0x01),
            'ACK': bool((flags_byte >> 4) & 0x01),
            'URG': bool((flags_byte >> 5) & 0x01),
        }
        active_flags = [k for k, v in flags.items() if v]
        print(f"  Active Flags: {', '.join(active_flags) if active_flags else 'None'}")
        
        # Bytes 14-15: Window Size
        window = struct.unpack('>H', tcp_header[14:16])[0]
        print(f"Bytes[14-15] (Window): {window}")
        
        # Bytes 16-17: Checksum
        checksum = struct.unpack('>H', tcp_header[16:18])[0]
        print(f"Bytes[16-17] (Checksum): 0x{checksum:04x}")
        self.assertNotEqual(checksum, 0)
        
        print("\n✓ TEST 3.1 PASSED\n")


class TestPacketIntegrity(_ScapyRequiredTestCase):
    """
    TEST SUITE 4: Packet Integrity
    Paket bütünlüğü ve tutarlılığı
    """
    
    def test_repeated_generation_consistency(self):
        """Test 4.1: Tekrar tekrar paket üretme tutarlılığı"""
        print("\n" + "="*80)
        print("TEST 4.1: REPEATED GENERATION CONSISTENCY")
        print("="*80)
        
        config = PacketConfig(
            target_ip="10.0.0.1",
            target_port=443,
            protocol="tcp"
        )
        
        # Aynı config ile 5 paket üret
        packets = []
        for i in range(5):
            packet = create_packet(config)
            packets.append(bytes(packet))
        
        print(f"✓ Generated {len(packets)} packets with same config")
        
        # Tüm paketlerin ilk 20 byte'ı (IPv4 header) aynı olmalı
        first_header = packets[0][:20]
        
        all_same = all(pkt[:20] == first_header for pkt in packets)
        print(f"✓ All IPv4 headers identical: {all_same}")
        
        # IPv4 headers aynı olmalı (destination ve başka sabit alanlar)
        for i, pkt in enumerate(packets):
            dst_ip = '.'.join(str(b) for b in pkt[16:20])
            self.assertEqual(dst_ip, "10.0.0.1", f"Packet {i} has wrong destination")
        
        print("✓ All packets have correct destination IP")
        
        print("✓ TEST 4.1 PASSED\n")
    
    def test_packet_size_consistency(self):
        """Test 4.2: Paket boyutlarının tutarlılığı"""
        print("\n" + "="*80)
        print("TEST 4.2: PACKET SIZE CONSISTENCY")
        print("="*80)
        
        configs = [
            PacketConfig(target_ip="192.168.1.1", target_port=80, protocol="tcp"),
            PacketConfig(target_ip="192.168.1.1", target_port=443, protocol="tcp"),
            PacketConfig(target_ip="192.168.1.1", target_port=9999, protocol="udp"),
        ]
        
        sizes = {}
        for config in configs:
            packet = create_packet(config)
            size = len(bytes(packet))
            proto = config.protocol.upper()
            
            if proto not in sizes:
                sizes[proto] = []
            sizes[proto].append(size)
            
            print(f"✓ {proto:4s} packet to port {config.target_port:5d}: {size} bytes")
        
        # UDP paketleri aynı boyutta olmalı
        if 'UDP' in sizes:
            udp_same = len(set(sizes['UDP'])) == 1
            print(f"✓ All UDP packets same size: {udp_same}")
            self.assertTrue(udp_same, "UDP packets should have consistent size")
        
        # TCP paketleri ≥40 bytes olmalı (minimum)
        if 'TCP' in sizes:
            all_valid = all(s >= 40 for s in sizes['TCP'])
            print(f"✓ All TCP packets ≥40 bytes: {all_valid}")
            self.assertTrue(all_valid, "TCP packets should be >= 40 bytes")
        
        print("✓ TEST 4.2 PASSED\n")


class TestPacketValidity(_ScapyRequiredTestCase):
    """
    TEST SUITE 5: Packet Validity
    Paketlerin geçerliliği
    """
    
    def test_minimum_packet_size(self):
        """Test 5.1: Minimum paket boyutu"""
        print("\n" + "="*80)
        print("TEST 5.1: MINIMUM PACKET SIZE")
        print("="*80)
        
        config = PacketConfig(
            target_ip="192.168.1.1",
            target_port=80,
            protocol="tcp"
        )
        
        packet = create_packet(config)
        size = len(bytes(packet))
        
        min_size = 20 + 20  # IPv4(20) + TCP(20) minimum
        
        print(f"✓ Packet size: {size} bytes")
        print(f"✓ Minimum required: {min_size} bytes")
        
        self.assertGreaterEqual(size, min_size, 
                               "Packet must have at least IPv4(20) + TCP(20) headers")
        
        print("✓ TEST 5.1 PASSED\n")
    
    def test_byte_zero_always_0x45(self):
        """Test 5.2: Byte[0] her zaman 0x45 olmalı"""
        print("\n" + "="*80)
        print("TEST 5.2: BYTE[0] ALWAYS 0x45")
        print("="*80)
        
        test_cases = [
            ("TCP port 80", PacketConfig(target_ip="192.168.1.1", target_port=80, protocol="tcp")),
            ("TCP port 443", PacketConfig(target_ip="192.168.1.1", target_port=443, protocol="tcp")),
            ("UDP port 53", PacketConfig(target_ip="8.8.8.8", target_port=53, protocol="udp")),
            ("TCP port 9999", PacketConfig(target_ip="10.0.0.1", target_port=9999, protocol="tcp")),
        ]
        
        print("\nTesting various packet configurations:")
        print("-" * 80)
        
        for name, config in test_cases:
            packet = create_packet(config)
            byte0 = bytes(packet)[0]
            
            status = "✓" if byte0 == 0x45 else "✗"
            print(f"{status} {name:20s}: Byte[0] = 0x{byte0:02x}")
            
            self.assertEqual(byte0, 0x45, f"{name} has invalid Byte[0]")
        
        print("\n✓ TEST 5.2 PASSED\n")


def run_comprehensive_tests():
    """Tüm testleri çalıştır"""
    print("\n" + "="*80)
    print("🔍 DDOSAMURAI COMPREHENSIVE UNIT TESTS")
    print("="*80)
    print(f"Start time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Test suite oluştur
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Tüm test sınıflarını ekle
    suite.addTests(loader.loadTestsFromTestCase(TestBasicPacketGeneration))
    suite.addTests(loader.loadTestsFromTestCase(TestIPv4HeaderStructure))
    suite.addTests(loader.loadTestsFromTestCase(TestTCPHeaderStructure))
    suite.addTests(loader.loadTestsFromTestCase(TestPacketIntegrity))
    suite.addTests(loader.loadTestsFromTestCase(TestPacketValidity))
    
    # Testleri çalıştır
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Özet
    print("\n" + "="*80)
    print("📊 TEST SUMMARY")
    print("="*80)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n✓ ALL TESTS PASSED!")
    else:
        print("\n✗ SOME TESTS FAILED")
        if result.failures:
            print("\nFailures:")
            for test, traceback in result.failures:
                print(f"  - {test}")
        if result.errors:
            print("\nErrors:")
            for test, traceback in result.errors:
                print(f"  - {test}")
    
    print(f"End time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    return result


if __name__ == "__main__":
    result = run_comprehensive_tests()
    sys.exit(0 if result.wasSuccessful() else 1)
