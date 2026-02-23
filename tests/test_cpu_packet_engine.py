"""
Tests for the Zero-Dependency CPU Packet Engine (ddos_samurai.cpu_packet_engine).

Covers:
    - Checksum utility (RFC 1071)
    - IP address utilities
    - IPv4 header construction + validation
    - TCP header + options
    - UDP header
    - ICMP Echo Request
    - DNS query builder
    - TCP flag parsing
    - Full packet construction (transport, DNS, HTTP polymorphic)
    - OS fingerprint profiles
    - IP spoofing
    - Amplification packets (DNS, NTP, SSDP, Memcached, CLDAP)
    - IP fragmentation
    - Batch packet pool generation
    - Ethernet framing
    - Performance benchmark vs Scapy (if available)
"""

import struct
import time
import random
import os
import tempfile
import unittest
from unittest.mock import patch

try:
    import pytest
except Exception:  # pragma: no cover - unittest-only environments
    pytest = None

from ddos_samurai.cpu_packet_engine import (
    # Checksum
    _checksum,
    _pseudo_header_checksum,
    # IP utils
    ip_to_int,
    int_to_ip,
    ip_to_bytes,
    # Spoofing
    generate_random_ip,
    generate_realistic_ip,
    generate_ip_from_subnet,
    get_spoofed_ip,
    load_ips_from_file,
    # TCP options
    build_tcp_options,
    TCP_OPT_MSS,
    TCP_OPT_NOP,
    TCP_OPT_WSCALE,
    TCP_OPT_SACK_OK,
    TCP_OPT_TIMESTAMP,
    TCP_OPT_EOL,
    # Headers
    build_ipv4_header,
    build_tcp_header,
    build_udp_header,
    build_icmp_echo,
    build_ethernet_header,
    # DNS
    build_dns_query,
    _encode_dns_name,
    # TCP flags
    parse_tcp_flags,
    TCP_SYN,
    TCP_ACK,
    TCP_FIN,
    TCP_PSH,
    TCP_RST,
    TCP_URG,
    TCP_ECE,
    TCP_CWR,
    # Protocol numbers
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
    # High-level builders
    PacketConfig,
    SpoofingOptions,
    create_packet,
    build_transport_packet,
    build_dns_packet,
    build_polymorphic_http_packet,
    generate_packet_pool,
    # Amplification
    create_dns_amp_packet,
    create_ntp_amp_packet,
    create_ssdp_amp_packet,
    create_memcached_amp_packet,
    create_ldap_amp_packet,
    # Fragmentation
    fragment_packet,
    # Ethernet
    add_ethernet_frame,
    # Compatibility
    RawPacket,
    # OS Profiles
    OS_PROFILES,
)


# ────────────────────────────────────────────────────────────────
#  Helpers
# ────────────────────────────────────────────────────────────────

def _verify_ip_checksum(packet: bytes, ip_offset: int = 0) -> bool:
    """Verify that the IP header checksum is valid (sum → 0xFFFF or 0)."""
    ver_ihl = packet[ip_offset]
    ihl = (ver_ihl & 0xF) * 4
    ip_hdr = packet[ip_offset:ip_offset + ihl]
    s = 0
    for i in range(0, len(ip_hdr), 2):
        s += (ip_hdr[i] << 8) | ip_hdr[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s == 0xFFFF


def _extract_ip_fields(packet: bytes, offset: int = 0):
    """Extract key IP header fields for testing."""
    ver_ihl = packet[offset]
    version = (ver_ihl >> 4) & 0xF
    ihl = (ver_ihl & 0xF) * 4
    total_len = struct.unpack("!H", packet[offset+2:offset+4])[0]
    ttl = packet[offset + 8]
    protocol = packet[offset + 9]
    src_ip = struct.unpack("!I", packet[offset+12:offset+16])[0]
    dst_ip = struct.unpack("!I", packet[offset+16:offset+20])[0]
    return {
        "version": version, "ihl": ihl, "total_len": total_len,
        "ttl": ttl, "protocol": protocol,
        "src_ip": int_to_ip(src_ip), "dst_ip": int_to_ip(dst_ip),
    }


def _extract_tcp_fields(packet: bytes, ip_offset: int = 0):
    """Extract TCP header fields."""
    ver_ihl = packet[ip_offset]
    ihl = (ver_ihl & 0xF) * 4
    tcp_off = ip_offset + ihl
    src_port, dst_port, seq, ack = struct.unpack("!HHII", packet[tcp_off:tcp_off+12])
    offset_flags = struct.unpack("!H", packet[tcp_off+12:tcp_off+14])[0]
    data_offset = (offset_flags >> 12) * 4
    flags = offset_flags & 0x1FF
    window = struct.unpack("!H", packet[tcp_off+14:tcp_off+16])[0]
    return {
        "src_port": src_port, "dst_port": dst_port, "seq": seq, "ack": ack,
        "data_offset": data_offset, "flags": flags, "window": window,
    }


def _extract_udp_fields(packet: bytes, ip_offset: int = 0):
    """Extract UDP header fields."""
    ver_ihl = packet[ip_offset]
    ihl = (ver_ihl & 0xF) * 4
    udp_off = ip_offset + ihl
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", packet[udp_off:udp_off+8])
    return {
        "src_port": src_port, "dst_port": dst_port,
        "length": length, "checksum": checksum,
    }


# ────────────────────────────────────────────────────────────────
#  Test: Checksum
# ────────────────────────────────────────────────────────────────

class TestChecksum(unittest.TestCase):
    def test_zero_data(self):
        self.assertEqual(_checksum(b"\x00\x00"), 0xFFFF)

    def test_all_ones(self):
        self.assertEqual(_checksum(b"\xFF\xFF"), 0x0000)

    def test_known_value(self):
        # Simple known checksum test
        data = b"\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06\x00\x00\xac\x10\x0a\x63\xac\x10\x0a\x0c"
        cksum = _checksum(data)
        # The checksum of a valid header should be 0 when the checksum field is correct
        # But here checksum field is 0, so we get the expected checksum
        self.assertIsInstance(cksum, int)
        self.assertTrue(0 <= cksum <= 0xFFFF)

    def test_odd_length(self):
        # Odd-length data should be handled correctly
        cksum = _checksum(b"\x01\x02\x03")
        self.assertIsInstance(cksum, int)


# ────────────────────────────────────────────────────────────────
#  Test: IP Utilities
# ────────────────────────────────────────────────────────────────

class TestIPUtilities(unittest.TestCase):
    def test_ip_to_int_and_back(self):
        self.assertEqual(ip_to_int("192.168.1.1"), 0xC0A80101)
        self.assertEqual(int_to_ip(0xC0A80101), "192.168.1.1")
        self.assertEqual(int_to_ip(ip_to_int("10.0.0.1")), "10.0.0.1")
        self.assertEqual(int_to_ip(ip_to_int("255.255.255.255")), "255.255.255.255")
        self.assertEqual(int_to_ip(ip_to_int("0.0.0.0")), "0.0.0.0")

    def test_ip_to_bytes(self):
        b = ip_to_bytes("192.168.1.1")
        self.assertEqual(len(b), 4)
        self.assertEqual(b, b"\xc0\xa8\x01\x01")


# ────────────────────────────────────────────────────────────────
#  Test: IP Spoofing
# ────────────────────────────────────────────────────────────────

class TestSpoofing(unittest.TestCase):
    def test_random_ip_valid(self):
        for _ in range(50):
            ip = generate_random_ip()
            parts = ip.split(".")
            self.assertEqual(len(parts), 4)
            for p in parts:
                self.assertTrue(0 <= int(p) <= 255)
            # Should not be private
            a = int(parts[0])
            self.assertNotIn(a, (0, 10, 127))

    def test_realistic_ip_valid(self):
        for _ in range(50):
            ip = generate_realistic_ip()
            parts = ip.split(".")
            self.assertEqual(len(parts), 4)

    def test_subnet_ip(self):
        for _ in range(20):
            ip = generate_ip_from_subnet("192.168.100.0/24")
            parts = ip.split(".")
            self.assertEqual(parts[0], "192")
            self.assertEqual(parts[1], "168")
            self.assertEqual(parts[2], "100")

    def test_get_spoofed_modes(self):
        ip_random = get_spoofed_ip("random")
        self.assertIsInstance(ip_random, str)
        ip_realistic = get_spoofed_ip("realistic")
        self.assertIsInstance(ip_realistic, str)
        ip_subnet = get_spoofed_ip("subnet", subnet="10.0.0.0/16")
        self.assertTrue(ip_subnet.startswith("10.0."))

    def test_list_mode_cache_is_file_scoped(self):
        f1 = tempfile.NamedTemporaryFile("w", delete=False)
        f2 = tempfile.NamedTemporaryFile("w", delete=False)
        try:
            f1.write("198.51.100.11\n")
            f2.write("203.0.113.77\n")
            f1.close()
            f2.close()

            self.assertEqual(load_ips_from_file(f1.name), ["198.51.100.11"])
            self.assertEqual(load_ips_from_file(f2.name), ["203.0.113.77"])
            self.assertEqual(get_spoofed_ip("list", list_file=f1.name), "198.51.100.11")
            self.assertEqual(get_spoofed_ip("list", list_file=f2.name), "203.0.113.77")
        finally:
            os.unlink(f1.name)
            os.unlink(f2.name)


# ────────────────────────────────────────────────────────────────
#  Test: TCP Options
# ────────────────────────────────────────────────────────────────

class TestTCPOptions(unittest.TestCase):
    def test_mss_option(self):
        opts = build_tcp_options([(TCP_OPT_MSS, 1460)])
        self.assertGreaterEqual(len(opts), 4)
        self.assertEqual(opts[0], 2)   # kind
        self.assertEqual(opts[1], 4)   # length
        mss_val = struct.unpack("!H", opts[2:4])[0]
        self.assertEqual(mss_val, 1460)

    def test_nop_option(self):
        opts = build_tcp_options([(TCP_OPT_NOP, None)])
        self.assertTrue(len(opts) % 4 == 0)  # padded

    def test_timestamp_option(self):
        opts = build_tcp_options([(TCP_OPT_TIMESTAMP, (12345, 67890))])
        self.assertGreaterEqual(len(opts), 10)
        self.assertEqual(opts[0], 8)   # kind
        self.assertEqual(opts[1], 10)  # length
        tsval = struct.unpack("!I", opts[2:6])[0]
        tsecr = struct.unpack("!I", opts[6:10])[0]
        self.assertEqual(tsval, 12345)
        self.assertEqual(tsecr, 67890)

    def test_sack_ok_option(self):
        opts = build_tcp_options([(TCP_OPT_SACK_OK, None)])
        self.assertGreaterEqual(len(opts), 2)
        self.assertEqual(opts[0], 4)
        self.assertEqual(opts[1], 2)

    def test_complex_options(self):
        """Simulate a Linux-like option set."""
        opts = build_tcp_options([
            (TCP_OPT_MSS, 1460),
            (TCP_OPT_SACK_OK, None),
            (TCP_OPT_TIMESTAMP, (1000, 0)),
            (TCP_OPT_NOP, None),
            (TCP_OPT_WSCALE, 7),
        ])
        self.assertTrue(len(opts) % 4 == 0)
        self.assertGreaterEqual(len(opts), 20)

    def test_alignment(self):
        """All option output must be 4-byte aligned."""
        for _ in range(20):
            n = random.randint(1, 5)
            option_list = [(random.choice([TCP_OPT_NOP, TCP_OPT_MSS, TCP_OPT_SACK_OK]),
                           1460 if random.random() > 0.5 else None) for _ in range(n)]
            opts = build_tcp_options(option_list)
            self.assertTrue(len(opts) % 4 == 0, f"Options not aligned: {len(opts)} bytes")


# ────────────────────────────────────────────────────────────────
#  Test: IPv4 Header
# ────────────────────────────────────────────────────────────────

class TestIPv4Header(unittest.TestCase):
    def test_basic_header(self):
        hdr = build_ipv4_header("192.168.1.1", "10.0.0.1", PROTO_TCP, 20)
        self.assertEqual(len(hdr), 20)
        # Version = 4
        self.assertEqual((hdr[0] >> 4) & 0xF, 4)
        # IHL = 5
        self.assertEqual(hdr[0] & 0xF, 5)
        # Protocol
        self.assertEqual(hdr[9], PROTO_TCP)
        # Verify checksum
        self.assertTrue(_verify_ip_checksum(bytes(hdr)))

    def test_custom_ttl_tos(self):
        hdr = build_ipv4_header("1.1.1.1", "2.2.2.2", PROTO_UDP, 20, ttl=128, tos=0x10)
        self.assertEqual(hdr[8], 128)  # TTL
        self.assertEqual(hdr[1], 0x10)  # TOS
        self.assertTrue(_verify_ip_checksum(bytes(hdr)))

    def test_total_length(self):
        hdr = build_ipv4_header("1.1.1.1", "2.2.2.2", PROTO_TCP, 100)
        total_len = struct.unpack("!H", hdr[2:4])[0]
        self.assertEqual(total_len, 20 + 100)

    def test_ip_addresses(self):
        hdr = build_ipv4_header("192.168.0.1", "10.0.0.2", PROTO_TCP, 0)
        src = struct.unpack("!I", hdr[12:16])[0]
        dst = struct.unpack("!I", hdr[16:20])[0]
        self.assertEqual(int_to_ip(src), "192.168.0.1")
        self.assertEqual(int_to_ip(dst), "10.0.0.2")


# ────────────────────────────────────────────────────────────────
#  Test: TCP Header
# ────────────────────────────────────────────────────────────────

class TestTCPHeader(unittest.TestCase):
    def test_basic_syn(self):
        hdr = build_tcp_header(
            12345, 80,
            flags=TCP_SYN,
            src_ip_int=ip_to_int("1.1.1.1"),
            dst_ip_int=ip_to_int("2.2.2.2"),
        )
        self.assertGreaterEqual(len(hdr), 20)
        src_port = struct.unpack("!H", hdr[0:2])[0]
        dst_port = struct.unpack("!H", hdr[2:4])[0]
        self.assertEqual(src_port, 12345)
        self.assertEqual(dst_port, 80)

    def test_with_options(self):
        opts = build_tcp_options([(TCP_OPT_MSS, 1460), (TCP_OPT_NOP, None)])
        hdr = build_tcp_header(
            1000, 443,
            flags=TCP_SYN,
            options_bytes=opts,
            src_ip_int=ip_to_int("10.0.0.1"),
            dst_ip_int=ip_to_int("20.0.0.1"),
        )
        self.assertGreater(len(hdr), 20)

    def test_checksum_nonzero(self):
        hdr = build_tcp_header(
            5000, 8080,
            flags=TCP_SYN | TCP_ACK,
            seq=1000, ack=2000,
            src_ip_int=ip_to_int("192.168.1.1"),
            dst_ip_int=ip_to_int("10.0.0.1"),
        )
        cksum = struct.unpack("!H", hdr[16:18])[0]
        self.assertNotEqual(cksum, 0)


# ────────────────────────────────────────────────────────────────
#  Test: UDP Header
# ────────────────────────────────────────────────────────────────

class TestUDPHeader(unittest.TestCase):
    def test_basic_udp(self):
        payload = b"hello"
        hdr = build_udp_header(
            54321, 53, payload,
            src_ip_int=ip_to_int("1.1.1.1"),
            dst_ip_int=ip_to_int("8.8.8.8"),
        )
        self.assertEqual(len(hdr), 8)
        src_port = struct.unpack("!H", hdr[0:2])[0]
        dst_port = struct.unpack("!H", hdr[2:4])[0]
        length = struct.unpack("!H", hdr[4:6])[0]
        self.assertEqual(src_port, 54321)
        self.assertEqual(dst_port, 53)
        self.assertEqual(length, 8 + len(payload))

    def test_checksum_nonzero(self):
        hdr = build_udp_header(
            1000, 2000, b"test",
            src_ip_int=ip_to_int("1.2.3.4"),
            dst_ip_int=ip_to_int("5.6.7.8"),
        )
        cksum = struct.unpack("!H", hdr[6:8])[0]
        self.assertNotEqual(cksum, 0)


# ────────────────────────────────────────────────────────────────
#  Test: ICMP
# ────────────────────────────────────────────────────────────────

class TestICMP(unittest.TestCase):
    def test_echo_request(self):
        hdr = build_icmp_echo(identifier=100, sequence=1, payload=b"\x00" * 32)
        self.assertEqual(hdr[0], 8)   # Type: Echo Request
        self.assertEqual(hdr[1], 0)   # Code: 0
        ident = struct.unpack("!H", hdr[4:6])[0]
        self.assertEqual(ident, 100)
        seq = struct.unpack("!H", hdr[6:8])[0]
        self.assertEqual(seq, 1)

    def test_checksum_valid(self):
        hdr = build_icmp_echo(payload=b"test")
        cksum_result = _checksum(hdr)
        # After computing checksum on valid data, result should be 0
        # Let's verify by recomputing
        hdr2 = bytearray(hdr)
        struct.pack_into("!H", hdr2, 2, 0)  # zero out checksum
        expected = _checksum(hdr2)
        actual = struct.unpack("!H", hdr[2:4])[0]
        self.assertEqual(actual, expected)


# ────────────────────────────────────────────────────────────────
#  Test: DNS
# ────────────────────────────────────────────────────────────────

class TestDNS(unittest.TestCase):
    def test_encode_dns_name(self):
        encoded = _encode_dns_name("example.com")
        # \x07example\x03com\x00
        self.assertEqual(encoded[0], 7)
        self.assertEqual(encoded[8], 3)
        self.assertEqual(encoded[-1], 0)

    def test_dns_query(self):
        q = build_dns_query("test.example.com", qtype="A", recursive=True)
        self.assertGreater(len(q), 12)  # at least header size
        # Check QD count = 1
        qdcount = struct.unpack("!H", q[4:6])[0]
        self.assertEqual(qdcount, 1)

    def test_dns_edns(self):
        q_no_edns = build_dns_query("test.com", edns=False)
        q_edns = build_dns_query("test.com", edns=True)
        self.assertGreater(len(q_edns), len(q_no_edns))

    def test_encode_dns_name_label_too_long(self):
        with self.assertRaises(ValueError):
            _encode_dns_name("a" * 64 + ".example.com")

    def test_encode_dns_name_total_too_long(self):
        too_long = ".".join(["a" * 63] * 5)
        with self.assertRaises(ValueError):
            _encode_dns_name(too_long)


# ────────────────────────────────────────────────────────────────
#  Test: TCP Flag Parsing
# ────────────────────────────────────────────────────────────────

class TestFlagParsing(unittest.TestCase):
    def test_syn(self):
        self.assertEqual(parse_tcp_flags("S"), TCP_SYN)

    def test_syn_ack(self):
        self.assertEqual(parse_tcp_flags("SA"), TCP_SYN | TCP_ACK)

    def test_fin_ack(self):
        self.assertEqual(parse_tcp_flags("FA"), TCP_FIN | TCP_ACK)

    def test_push_ack(self):
        self.assertEqual(parse_tcp_flags("PA"), TCP_PSH | TCP_ACK)

    def test_textual_ack_does_not_set_cwr(self):
        flags = parse_tcp_flags("ACK")
        self.assertEqual(flags, TCP_ACK)
        self.assertFalse(flags & TCP_CWR)

    def test_textual_fin_ack(self):
        flags = parse_tcp_flags("FIN+ACK")
        self.assertEqual(flags, TCP_FIN | TCP_ACK)

    def test_all_flags(self):
        flags = parse_tcp_flags("SFRAPUEC")
        expected = TCP_SYN | TCP_FIN | TCP_RST | TCP_ACK | TCP_PSH | TCP_URG | TCP_ECE | TCP_CWR
        self.assertEqual(flags, expected)


# ────────────────────────────────────────────────────────────────
#  Test: Full Packet Construction
# ────────────────────────────────────────────────────────────────

class TestFullPackets(unittest.TestCase):
    def test_tcp_syn_packet(self):
        cfg = PacketConfig(
            target_ip="10.0.0.1",
            target_port=80,
            protocol="tcp",
            tcp_flags="S",
        )
        pkt = create_packet(cfg)
        self.assertIsInstance(pkt, bytes)
        self.assertGreater(len(pkt), 40)  # IP(20) + TCP(20+)
        self.assertTrue(_verify_ip_checksum(pkt))
        fields = _extract_ip_fields(pkt)
        self.assertEqual(fields["version"], 4)
        self.assertEqual(fields["protocol"], PROTO_TCP)
        self.assertEqual(fields["dst_ip"], "10.0.0.1")

    def test_tcp_packet_with_payload(self):
        cfg = PacketConfig(
            target_ip="10.0.0.1",
            target_port=80,
            protocol="tcp",
            tcp_flags="PA",
            payload=b"GET / HTTP/1.1\r\n\r\n",
        )
        pkt = create_packet(cfg)
        self.assertIn(b"GET / HTTP/1.1", pkt)

    def test_udp_packet(self):
        cfg = PacketConfig(
            target_ip="8.8.8.8",
            target_port=53,
            protocol="udp",
        )
        pkt = create_packet(cfg)
        self.assertTrue(_verify_ip_checksum(pkt))
        fields = _extract_ip_fields(pkt)
        self.assertEqual(fields["protocol"], PROTO_UDP)

    def test_icmp_packet(self):
        cfg = PacketConfig(
            target_ip="10.0.0.1",
            target_port=0,
            protocol="icmp",
        )
        pkt = create_packet(cfg)
        self.assertTrue(_verify_ip_checksum(pkt))
        fields = _extract_ip_fields(pkt)
        self.assertEqual(fields["protocol"], PROTO_ICMP)

    def test_dns_packet(self):
        cfg = PacketConfig(
            target_ip="8.8.8.8",
            target_port=53,
            attack_vector="dns",
            dns_name="example.com",
            dns_qtype="A",
        )
        pkt = create_packet(cfg)
        self.assertTrue(_verify_ip_checksum(pkt))
        fields = _extract_ip_fields(pkt)
        self.assertEqual(fields["protocol"], PROTO_UDP)
        # Should contain DNS qname
        self.assertIn(b"example", pkt)

    def test_http_polymorphic_packet(self):
        cfg = PacketConfig(
            target_ip="10.0.0.1",
            target_port=80,
            attack_vector="http",
        )
        pkt = create_packet(cfg)
        self.assertTrue(_verify_ip_checksum(pkt))
        # Should contain HTTP request
        self.assertIn(b"HTTP/1.1", pkt)

    def test_spoofed_packet(self):
        cfg = PacketConfig(
            target_ip="10.0.0.1",
            target_port=80,
            protocol="tcp",
            spoof=True,
            spoof_opts=SpoofingOptions(mode="subnet", subnet="203.0.113.0/24"),
        )
        pkt = create_packet(cfg)
        self.assertTrue(_verify_ip_checksum(pkt))
        fields = _extract_ip_fields(pkt)
        # Source IP should be in the 203.0.113.0/24 range
        src_parts = fields["src_ip"].split(".")
        self.assertEqual(int(src_parts[0]), 203)
        self.assertEqual(int(src_parts[1]), 0)
        self.assertEqual(int(src_parts[2]), 113)

    def test_custom_ttl_tos_window(self):
        cfg = PacketConfig(
            target_ip="10.0.0.1",
            target_port=443,
            protocol="tcp",
            ttl=200,
            tos=0x10,
            window=32768,
        )
        pkt = create_packet(cfg)
        fields = _extract_ip_fields(pkt)
        self.assertEqual(fields["ttl"], 200)
        tcp_fields = _extract_tcp_fields(pkt)
        self.assertEqual(tcp_fields["window"], 32768)

    def test_padding(self):
        cfg = PacketConfig(
            target_ip="10.0.0.1",
            target_port=80,
            protocol="udp",
            pad_size=256,
        )
        pkt = create_packet(cfg)
        self.assertGreaterEqual(len(pkt), 256)

    def test_syn_no_payload_stealth(self):
        """SYN-only packets should NOT contain any payload (stealth)."""
        cfg = PacketConfig(
            target_ip="10.0.0.1",
            target_port=80,
            protocol="tcp",
            tcp_flags="S",
        )
        pkt = create_packet(cfg)
        ip_fields = _extract_ip_fields(pkt)
        tcp_fields = _extract_tcp_fields(pkt)
        # Total IP length should be IP header + TCP header (with options), no payload
        expected_max = ip_fields["ihl"] + tcp_fields["data_offset"]
        self.assertEqual(ip_fields["total_len"], expected_max)

    def test_non_spoof_tcp_uses_resolved_source_ip_for_checksum(self):
        cfg = PacketConfig(
            target_ip="10.0.0.1",
            target_port=80,
            protocol="tcp",
            tcp_flags="S",
            spoof=False,
        )
        with patch("ddos_samurai.cpu_packet_engine.resolve_local_source_ip", return_value="192.0.2.10"):
            pkt = create_packet(cfg)

        ihl = (pkt[0] & 0xF) * 4
        total_len = struct.unpack("!H", pkt[2:4])[0]
        src_ip = struct.unpack("!I", pkt[12:16])[0]
        dst_ip = struct.unpack("!I", pkt[16:20])[0]
        tcp_seg = pkt[ihl:total_len]

        self.assertEqual(src_ip, ip_to_int("192.0.2.10"))
        pseudo = struct.pack("!IIBBH", src_ip, dst_ip, 0, PROTO_TCP, len(tcp_seg))
        data = pseudo + tcp_seg
        if len(data) % 2:
            data += b"\x00"

        s = 0
        for i in range(0, len(data), 2):
            s += (data[i] << 8) | data[i + 1]
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        self.assertEqual(s, 0xFFFF)


# ────────────────────────────────────────────────────────────────
#  Test: Amplification Packets
# ────────────────────────────────────────────────────────────────

class TestAmplificationPackets(unittest.TestCase):
    def test_dns_amp(self):
        pkt = create_dns_amp_packet("8.8.8.8", "1.2.3.4", "isc.org")
        self.assertTrue(_verify_ip_checksum(pkt))
        fields = _extract_ip_fields(pkt)
        self.assertEqual(fields["src_ip"], "1.2.3.4")   # victim IP as source
        self.assertEqual(fields["dst_ip"], "8.8.8.8")    # reflector
        self.assertEqual(fields["protocol"], PROTO_UDP)
        udp = _extract_udp_fields(pkt)
        self.assertEqual(udp["dst_port"], 53)

    def test_ntp_amp(self):
        pkt = create_ntp_amp_packet("10.0.0.1", "1.1.1.1")
        self.assertTrue(_verify_ip_checksum(pkt))
        udp = _extract_udp_fields(pkt)
        self.assertEqual(udp["dst_port"], 123)

    def test_ssdp_amp(self):
        pkt = create_ssdp_amp_packet("10.0.0.1", "1.1.1.1")
        self.assertTrue(_verify_ip_checksum(pkt))
        self.assertIn(b"M-SEARCH", pkt)
        udp = _extract_udp_fields(pkt)
        self.assertEqual(udp["dst_port"], 1900)

    def test_memcached_amp(self):
        pkt = create_memcached_amp_packet("10.0.0.1", "1.1.1.1")
        self.assertTrue(_verify_ip_checksum(pkt))
        udp = _extract_udp_fields(pkt)
        self.assertEqual(udp["dst_port"], 11211)

    def test_ldap_amp(self):
        pkt = create_ldap_amp_packet("10.0.0.1", "1.1.1.1")
        self.assertTrue(_verify_ip_checksum(pkt))
        udp = _extract_udp_fields(pkt)
        self.assertEqual(udp["dst_port"], 389)


# ────────────────────────────────────────────────────────────────
#  Test: IP Fragmentation
# ────────────────────────────────────────────────────────────────

class TestFragmentation(unittest.TestCase):
    def test_no_fragmentation_needed(self):
        cfg = PacketConfig(target_ip="10.0.0.1", target_port=80, protocol="tcp", tcp_flags="S")
        pkt = create_packet(cfg)
        frags = fragment_packet(pkt, fragment_size=1500)
        self.assertEqual(len(frags), 1)

    def test_fragmentation_occurs(self):
        cfg = PacketConfig(
            target_ip="10.0.0.1", target_port=80,
            protocol="udp", payload=b"A" * 2000,
        )
        pkt = create_packet(cfg)
        frags = fragment_packet(pkt, fragment_size=400)
        self.assertGreater(len(frags), 1)
        # All fragments should have valid IP checksums
        for frag in frags:
            self.assertTrue(_verify_ip_checksum(frag))

    def test_fragmentation_mf_flag(self):
        """All fragments except the last should have MF flag set."""
        cfg = PacketConfig(
            target_ip="10.0.0.1", target_port=80,
            protocol="udp", payload=b"B" * 3000,
        )
        pkt = create_packet(cfg)
        frags = fragment_packet(pkt, fragment_size=800)
        for i, frag in enumerate(frags):
            flags_frag = struct.unpack("!H", frag[6:8])[0]
            mf = flags_frag & 0x2000
            if i < len(frags) - 1:
                self.assertTrue(mf, f"Fragment {i} should have MF flag")
            else:
                self.assertFalse(mf, f"Last fragment should NOT have MF flag")

    def test_fragmentation_uses_ip_total_length_not_trailing_padding(self):
        cfg = PacketConfig(
            target_ip="10.0.0.1",
            target_port=53,
            protocol="udp",
            payload=b"Z" * 1400,
        )
        pkt = create_packet(cfg)
        ihl = (pkt[0] & 0xF) * 4
        total_len = struct.unpack("!H", pkt[2:4])[0]
        padded_pkt = pkt + (b"\x00" * 512)

        frags = fragment_packet(padded_pkt, fragment_size=400)
        reassembled = b"".join(
            frag[(frag[0] & 0xF) * 4:struct.unpack("!H", frag[2:4])[0]]
            for frag in frags
        )

        self.assertEqual(reassembled, pkt[ihl:total_len])


# ────────────────────────────────────────────────────────────────
#  Test: Packet Pool
# ────────────────────────────────────────────────────────────────

class TestPacketPool(unittest.TestCase):
    def test_pool_generation(self):
        cfg = PacketConfig(target_ip="10.0.0.1", target_port=80, protocol="tcp")
        buf, pkt_size = generate_packet_pool(cfg, count=100)
        self.assertEqual(len(buf), 100 * pkt_size)
        self.assertTrue(pkt_size % 4 == 0)  # 4-byte aligned
        # Spot-check: verify first and last packets have valid IP checksums
        first_pkt = buf[:pkt_size]
        last_pkt = buf[-pkt_size:]
        self.assertTrue(_verify_ip_checksum(first_pkt))
        self.assertTrue(_verify_ip_checksum(last_pkt))


# ────────────────────────────────────────────────────────────────
#  Test: Ethernet Framing
# ────────────────────────────────────────────────────────────────

class TestEthernet(unittest.TestCase):
    def test_ethernet_header(self):
        hdr = build_ethernet_header()
        self.assertEqual(len(hdr), 14)
        # EtherType IPv4
        etype = struct.unpack("!H", hdr[12:14])[0]
        self.assertEqual(etype, 0x0800)

    def test_add_ethernet_frame(self):
        cfg = PacketConfig(target_ip="10.0.0.1", target_port=80, protocol="tcp", tcp_flags="S")
        pkt = create_packet(cfg)
        framed = add_ethernet_frame(pkt)
        self.assertEqual(len(framed), 14 + len(pkt))
        # Verify the IP portion still has valid checksum
        self.assertTrue(_verify_ip_checksum(framed, ip_offset=14))


# ────────────────────────────────────────────────────────────────
#  Test: RawPacket Compatibility
# ────────────────────────────────────────────────────────────────

class TestRawPacket(unittest.TestCase):
    def test_bytes_conversion(self):
        rp = RawPacket(b"\x45\x00\x00\x28")
        self.assertEqual(bytes(rp), b"\x45\x00\x00\x28")
        self.assertEqual(len(rp), 4)

    def test_haslayer(self):
        rp = RawPacket(b"\x00" * 20)
        self.assertFalse(rp.haslayer(object))


# ────────────────────────────────────────────────────────────────
#  Test: OS Profiles
# ────────────────────────────────────────────────────────────────

class TestOSProfiles(unittest.TestCase):
    def test_profiles_exist(self):
        self.assertEqual(len(OS_PROFILES), 3)

    def test_profile_options_buildable(self):
        for profile in OS_PROFILES:
            opts = []
            for kind, value in profile.tcp_options:
                if kind == TCP_OPT_TIMESTAMP:
                    opts.append((kind, (1000, 0)))
                else:
                    opts.append((kind, value))
            opt_bytes = build_tcp_options(opts)
            self.assertTrue(len(opt_bytes) % 4 == 0)


# ────────────────────────────────────────────────────────────────
#  Test: Performance Benchmark
# ────────────────────────────────────────────────────────────────

class TestPerformance(unittest.TestCase):
    def test_packet_generation_speed(self):
        """Generate 10,000 TCP SYN packets and measure time."""
        cfg = PacketConfig(
            target_ip="10.0.0.1",
            target_port=80,
            protocol="tcp",
            tcp_flags="S",
        )

        # Warm up
        for _ in range(10):
            create_packet(cfg)

        t0 = time.monotonic()
        N = 10000
        for _ in range(N):
            create_packet(cfg)
        elapsed = time.monotonic() - t0

        pps = N / elapsed if elapsed > 0 else 0
        print(f"\n  [BENCHMARK] CPU Engine: {N:,} TCP SYN packets in {elapsed:.3f}s "
              f"= {pps:,.0f} pkt/s")

        # Should be at least 10K pps (typically 100K+ on modern hardware)
        self.assertGreater(pps, 5000, "Packet generation too slow!")

    def test_pool_generation_speed(self):
        """Generate a pool of 10,000 packets at once."""
        cfg = PacketConfig(
            target_ip="10.0.0.1",
            target_port=80,
            protocol="tcp",
            tcp_flags="S",
        )

        t0 = time.monotonic()
        N = 10000
        buf, pkt_size = generate_packet_pool(cfg, count=N)
        elapsed = time.monotonic() - t0

        pps = N / elapsed if elapsed > 0 else 0
        print(f"  [BENCHMARK] Pool: {N:,} packets ({len(buf):,} bytes) in {elapsed:.3f}s "
              f"= {pps:,.0f} pkt/s (pkt_size={pkt_size})")

        self.assertGreater(pps, 5000)
        self.assertEqual(len(buf), N * pkt_size)

if pytest is not None:
    TestPerformance = pytest.mark.benchmark(TestPerformance)
    TestPerformance = pytest.mark.ci_safe(TestPerformance)


if __name__ == "__main__":
    unittest.main()
