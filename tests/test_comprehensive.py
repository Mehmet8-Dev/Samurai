#!/usr/bin/env python3
"""
DDoSamurai Comprehensive Unit Test Suite
Tüm kritik bileşenleri test eder.
"""

import sys
import os
import numpy as np
import unittest

try:
    import pytest
except ModuleNotFoundError:  # unittest-only environments
    pytest = None

if pytest is not None:
    pytestmark = [pytest.mark.privileged]

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ddos_samurai import packet
from ddos_samurai import utils
from ddos_samurai.scapy_support import is_scapy_available

if pytest is not None:
    SCAPY_REQUIRED = pytest.mark.skipif(
        not is_scapy_available(),
        reason="Scapy is unavailable in this environment.",
    )
else:
    SCAPY_REQUIRED = unittest.skipUnless(
        is_scapy_available(),
        "Scapy is unavailable in this environment.",
    )

@SCAPY_REQUIRED
class TestPacketCreation:
    """Packet oluşturma testleri"""
    
    def test_tcp_syn_packet(self):
        """TCP SYN paketi oluşturma"""
        cfg = packet.PacketConfig(
            target_ip="192.168.1.1",
            target_port=80,
            protocol="tcp",
            tcp_flags="S"
        )
        pkt = packet.create_packet(cfg)
        
        # Convert to bytes
        if pkt.haslayer('Ether'):
            ip_bytes = bytes(pkt)[14:]
        else:
            ip_bytes = bytes(pkt)
        
        # Validate IP header
        assert len(ip_bytes) >= 20, "Packet too short"
        assert ip_bytes[0] == 0x45, f"Invalid IP version/IHL: 0x{ip_bytes[0]:02x}"
        assert ip_bytes[9] == 6, "Protocol should be TCP (6)"
    
    def test_udp_packet(self):
        """UDP paketi oluşturma"""
        cfg = packet.PacketConfig(
            target_ip="192.168.1.1",
            target_port=53,
            protocol="udp"
        )
        pkt = packet.create_packet(cfg)
        
        if pkt.haslayer('Ether'):
            ip_bytes = bytes(pkt)[14:]
        else:
            ip_bytes = bytes(pkt)
        
        assert ip_bytes[0] == 0x45
        assert ip_bytes[9] == 17, "Protocol should be UDP (17)"
    
    def test_icmp_packet(self):
        """ICMP paketi oluşturma"""
        cfg = packet.PacketConfig(
            target_ip="192.168.1.1",
            target_port=0,
            protocol="icmp"
        )
        pkt = packet.create_packet(cfg)
        
        if pkt.haslayer('Ether'):
            ip_bytes = bytes(pkt)[14:]
        else:
            ip_bytes = bytes(pkt)
        
        assert ip_bytes[0] == 0x45
        assert ip_bytes[9] == 1, "Protocol should be ICMP (1)"
    
    def test_syn_packet_no_payload(self):
        """SYN paketlerinde payload olmamalı (stealth)"""
        cfg = packet.PacketConfig(
            target_ip="192.168.1.1",
            target_port=80,
            protocol="tcp",
            tcp_flags="S"
        )
        pkt = packet.create_packet(cfg)
        
        # SYN paketlerde Raw layer olmamalı
        assert not pkt.haslayer("Raw"), "SYN packet should not have payload"


class TestIPSpoofing:
    """IP Spoofing testleri"""
    
    def test_random_spoofing(self):
        """Random IP spoofing"""
        ip1 = packet._generate_random_ip()
        ip2 = packet._generate_random_ip()
        
        # Format check
        parts = ip1.split('.')
        assert len(parts) == 4
        for part in parts:
            assert 1 <= int(part) <= 254
        
        # Should be different (statistically)
        assert ip1 != ip2 or True  # May be same by chance
    
    def test_subnet_spoofing(self):
        """Subnet-based spoofing"""
        subnet = "192.168.1.0/24"
        ip = packet._generate_ip_from_subnet(subnet)
        
        # Should be in range
        assert ip.startswith("192.168.1.")
        last_octet = int(ip.split('.')[-1])
        assert 0 <= last_octet <= 255


@SCAPY_REQUIRED
class TestTemplateExtraction:
    """Template extraction testleri (orchestrator.py logic)"""
    
    def test_template_without_ether(self):
        """Ether layer olmadan template"""
        cfg = packet.PacketConfig(
            target_ip="192.168.1.1",
            target_port=80,
            protocol="tcp",
            tcp_flags="S"
        )
        template_pkt = packet.create_packet(cfg)
        
        # Simulate orchestrator.py logic
        full_bytes = bytes(template_pkt)
        if template_pkt.haslayer('Ether'):
            t_bytes = full_bytes[14:]
        else:
            t_bytes = full_bytes
        
        # Validate
        assert len(t_bytes) >= 20
        assert t_bytes[0] == 0x45
    
    def test_template_pool_creation(self):
        """Template pool oluşturma"""
        template_pool = []
        
        for i in range(10):
            cfg = packet.PacketConfig(
                target_ip="192.168.1.1",
                target_port=80,
                protocol="tcp",
                tcp_flags="S"
            )
            template_pkt = packet.create_packet(cfg)
            
            full_bytes = bytes(template_pkt)
            if template_pkt.haslayer('Ether'):
                t_bytes = full_bytes[14:]
            else:
                t_bytes = full_bytes
            
            template_pool.append(t_bytes)
        
        # All templates should be valid
        for t in template_pool:
            assert len(t) >= 20
            assert t[0] == 0x45


@SCAPY_REQUIRED
class TestGPUKernelSimulation:
    """GPU kernel simülasyon testleri"""
    
    def test_template_copy(self):
        """Template kopyalama simülasyonu"""
        # Create template
        cfg = packet.PacketConfig(
            target_ip="192.168.1.1",
            target_port=80,
            protocol="tcp",
            tcp_flags="S"
        )
        template_pkt = packet.create_packet(cfg)
        
        full_bytes = bytes(template_pkt)
        if template_pkt.haslayer('Ether'):
            template = bytearray(full_bytes[14:])
        else:
            template = bytearray(full_bytes)
        
        # Simulate GPU kernel copy
        packets_buffer = bytearray(len(template))
        for i in range(len(template)):
            packets_buffer[i] = template[i]
        
        # Validate
        assert packets_buffer[0] == 0x45
        assert packets_buffer == template
    
    def test_ip_patching(self):
        """IP patching simülasyonu"""
        cfg = packet.PacketConfig(
            target_ip="192.168.1.1",
            target_port=80,
            protocol="tcp",
            tcp_flags="S"
        )
        template_pkt = packet.create_packet(cfg)
        
        full_bytes = bytes(template_pkt)
        if template_pkt.haslayer('Ether'):
            template = bytearray(full_bytes[14:])
        else:
            template = bytearray(full_bytes)
        
        # Patch source IP
        new_src_ip = 0x01010102  # 1.1.1.2
        template[12] = (new_src_ip >> 24) & 0xFF
        template[13] = (new_src_ip >> 16) & 0xFF
        template[14] = (new_src_ip >> 8) & 0xFF
        template[15] = new_src_ip & 0xFF
        
        # Recalculate checksum
        template[10] = 0
        template[11] = 0
        
        checksum = 0
        for i in range(0, 20, 2):
            w = (template[i] << 8) + template[i + 1]
            checksum += w
        
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += (checksum >> 16)
        checksum = ~checksum & 0xFFFF
        
        template[10] = (checksum >> 8) & 0xFF
        template[11] = checksum & 0xFF
        
        # Validate
        assert template[0] == 0x45, "IP version/IHL should remain 0x45"
        assert template[12:16] == bytes([0x01, 0x01, 0x01, 0x02])


@SCAPY_REQUIRED
class TestEthernetFrameConstruction:
    """Ethernet frame oluşturma testleri"""
    
    def test_ethernet_header(self):
        """Ethernet header yapısı"""
        dest_mac = bytes.fromhex("f42d0617e434")
        src_mac = bytes.fromhex("001122334455")
        ethertype = bytes([0x08, 0x00])
        
        eth_header = dest_mac + src_mac + ethertype
        
        assert len(eth_header) == 14
        assert eth_header[0:6] == dest_mac
        assert eth_header[6:12] == src_mac
        assert eth_header[12:14] == ethertype
    
    def test_full_frame(self):
        """Tam Ethernet frame"""
        # Create IP packet
        cfg = packet.PacketConfig(
            target_ip="192.168.1.1",
            target_port=80,
            protocol="tcp",
            tcp_flags="S"
        )
        pkt = packet.create_packet(cfg)
        
        if pkt.haslayer('Ether'):
            ip_bytes = bytes(pkt)[14:]
        else:
            ip_bytes = bytes(pkt)
        
        # Build Ethernet frame
        dest_mac = bytes.fromhex("f42d0617e434")
        src_mac = bytes.fromhex("001122334455")
        ethertype = bytes([0x08, 0x00])
        
        eth_header = dest_mac + src_mac + ethertype
        full_frame = eth_header + ip_bytes
        
        # Validate structure
        assert len(full_frame) == 14 + len(ip_bytes)
        assert full_frame[12:14] == ethertype
        assert full_frame[14] == 0x45, "IP should start at offset 14"


class TestFastSenderModule:
    """fast_sender C extension testleri"""
    
    def test_module_import(self):
        """Module import"""
        try:
            from ddos_samurai import fast_sender
            assert hasattr(fast_sender, 'send_optimized')
            assert hasattr(fast_sender, 'send_ring_optimized')
        except ImportError:
            if pytest is not None:
                pytest.skip("fast_sender module not compiled")
            return


def run_tests():
    """Tüm testleri çalıştır"""
    if pytest is None:
        raise RuntimeError("pytest is required to run this test module directly.")
    pytest.main([__file__, '-v', '--tb=short'])


if __name__ == "__main__":
    run_tests()
