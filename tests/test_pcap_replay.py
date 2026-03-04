"""
Tests for the PCAP Replay Engine (ddos_samurai.pcap_replay).

Covers:
    - Classic PCAP v2.4 parsing (LE/BE, µs/ns)
    - PCAP-NG (SHB + IDB + EPB) parsing
    - Packet filtering (protocol, IP, port, length)
    - IP/Port rewriting + checksum recalculation
    - Timing delay computation for all modes
    - Full replay preparation pipeline
    - Edge cases (empty files, truncated, malformed)
"""

import io
import os
import struct
import tempfile
import unittest
import asyncio
from unittest.mock import AsyncMock, patch

from ddos_samurai.pcap_replay import (
    PCAP_MAGIC_LE,
    PCAP_MAGIC_NS_LE,
    PCAPNG_SHB,
    PCAPNG_IDB,
    PCAPNG_EPB,
    DLT_EN10MB,
    DLT_RAW,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
    TimingMode,
    TIMING_MODE_MAP,
    PcapFilterConfig,
    PcapReplayConfig,
    PcapParseError,
    ParsedPacket,
    parse_pcap_file,
    replay_pcap,
    prepare_replay,
    pcap_summary,
    _ip_to_int,
    _int_to_ip,
    _ip_in_cidr,
    _get_ip_info,
    _apply_filter,
    _compute_delays,
    _ones_complement_sum,
    _rewrite_packet,
    _extract_ip_offset,
)


# ────────────────────────────────────────────────────────────────
#  Helpers: build synthetic PCAP / packets in memory
# ────────────────────────────────────────────────────────────────

def _build_pcap_global_header(
    magic=PCAP_MAGIC_LE,
    snaplen=65535,
    link_type=DLT_EN10MB,
):
    """Build a 24-byte PCAP global header."""
    return struct.pack(
        "<IHHIIII",
        magic,
        2, 4,           # version 2.4
        0,              # tz offset
        0,              # sigfigs
        snaplen,
        link_type,
    )


def _build_pcap_record(ts_sec, ts_usec, data: bytes):
    """Build a single PCAP record (header + data)."""
    return struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)) + data


def _build_ipv4_header(
    src_ip="192.168.1.1",
    dst_ip="10.0.0.1",
    protocol=PROTO_TCP,
    total_len=40,
    ttl=64,
    ihl=5,
):
    """Build a minimal 20-byte IPv4 header."""
    ver_ihl = (4 << 4) | ihl
    identification = 0x1234
    flags_frag = 0x4000  # DF
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl,        # ver + IHL
        0,              # TOS
        total_len,
        identification,
        flags_frag,
        ttl,
        protocol,
        0,              # checksum (will calculate)
        bytes(map(int, src_ip.split("."))),
        bytes(map(int, dst_ip.split("."))),
    )
    # Calculate IP checksum
    s = _ones_complement_sum(hdr, 0, len(hdr))
    cksum = (~s) & 0xFFFF
    hdr = hdr[:10] + struct.pack("!H", cksum) + hdr[12:]
    return hdr


def _build_tcp_header(src_port=12345, dst_port=80, seq=1000, ack=0, flags=0x02):
    """Build a minimal 20-byte TCP header (no options, no checksum)."""
    data_offset = 5 << 4  # data offset = 5 (20 bytes / 4)
    window = 65535
    return struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port,
        seq, ack,
        data_offset, flags,
        window,
        0,  # checksum
        0,  # urgent pointer
    )


def _build_udp_header(src_port=54321, dst_port=53, length=8):
    """Build an 8-byte UDP header."""
    return struct.pack("!HHHH", src_port, dst_port, length, 0)


def _build_ethernet_header(src_mac=b"\x00"*6, dst_mac=b"\xff"*6, ethertype=0x0800):
    """Build a 14-byte Ethernet header."""
    return dst_mac + src_mac + struct.pack("!H", ethertype)


def _build_eth_tcp_packet(
    src_ip="192.168.1.1",
    dst_ip="10.0.0.1",
    src_port=12345,
    dst_port=80,
):
    """Build a complete Ethernet + IPv4 + TCP(SYN) packet."""
    tcp = _build_tcp_header(src_port, dst_port)
    ip = _build_ipv4_header(src_ip, dst_ip, PROTO_TCP, 20 + len(tcp))
    eth = _build_ethernet_header()
    return eth + ip + tcp


def _build_eth_udp_packet(
    src_ip="192.168.1.1",
    dst_ip="10.0.0.1",
    src_port=54321,
    dst_port=53,
):
    """Build a complete Ethernet + IPv4 + UDP packet."""
    payload = b"\x00" * 8  # dummy payload
    udp = _build_udp_header(src_port, dst_port, 8 + len(payload))
    ip = _build_ipv4_header(src_ip, dst_ip, PROTO_UDP, 20 + len(udp) + len(payload))
    eth = _build_ethernet_header()
    return eth + ip + udp + payload


def _write_pcap_to_tempfile(packets_data, link_type=DLT_EN10MB, ns=False):
    """Write a list of (ts_sec, ts_frac, data) to a temp PCAP file. Return path."""
    magic = PCAP_MAGIC_NS_LE if ns else PCAP_MAGIC_LE
    buf = _build_pcap_global_header(magic=magic, link_type=link_type)
    for ts_sec, ts_frac, data in packets_data:
        buf += _build_pcap_record(ts_sec, ts_frac, data)
    fd, path = tempfile.mkstemp(suffix=".pcap")
    with os.fdopen(fd, "wb") as f:
        f.write(buf)
    return path


# ────────────────────────────────────────────────────────────────
#  Test: IP Utility Functions
# ────────────────────────────────────────────────────────────────

class TestIPUtilities(unittest.TestCase):
    def test_ip_to_int_and_back(self):
        self.assertEqual(_ip_to_int("192.168.1.1"), 0xC0A80101)
        self.assertEqual(_int_to_ip(0xC0A80101), "192.168.1.1")
        self.assertEqual(_int_to_ip(_ip_to_int("10.0.0.1")), "10.0.0.1")
        self.assertEqual(_int_to_ip(_ip_to_int("255.255.255.255")), "255.255.255.255")

    def test_ip_in_cidr(self):
        self.assertTrue(_ip_in_cidr("192.168.1.100", "192.168.1.0/24"))
        self.assertFalse(_ip_in_cidr("192.168.2.1", "192.168.1.0/24"))
        self.assertTrue(_ip_in_cidr("10.0.0.1", "10.0.0.0/8"))
        self.assertTrue(_ip_in_cidr("10.0.0.1", "10.0.0.1"))
        self.assertFalse(_ip_in_cidr("10.0.0.2", "10.0.0.1"))


# ────────────────────────────────────────────────────────────────
#  Test: Classic PCAP Parsing
# ────────────────────────────────────────────────────────────────

class TestPcapParsing(unittest.TestCase):
    def test_parse_simple_pcap(self):
        """Parse a PCAP with 3 Ethernet+TCP packets."""
        packets_data = [
            (1000, 0,      _build_eth_tcp_packet()),
            (1000, 500000, _build_eth_tcp_packet()),
            (1001, 0,      _build_eth_tcp_packet()),
        ]
        path = _write_pcap_to_tempfile(packets_data)
        try:
            packets, meta = parse_pcap_file(path)
            self.assertEqual(len(packets), 3)
            self.assertEqual(meta["format"], "pcap")
            self.assertEqual(meta["link_type"], DLT_EN10MB)
            self.assertAlmostEqual(packets[0].timestamp_s, 1000.0, places=3)
            self.assertAlmostEqual(packets[1].timestamp_s, 1000.5, places=3)
            self.assertAlmostEqual(packets[2].timestamp_s, 1001.0, places=3)
        finally:
            os.unlink(path)

    def test_parse_ns_resolution(self):
        """Parse a PCAP with nanosecond resolution."""
        packets_data = [
            (1000, 123456789, _build_eth_tcp_packet()),
        ]
        path = _write_pcap_to_tempfile(packets_data, ns=True)
        try:
            packets, meta = parse_pcap_file(path)
            self.assertEqual(len(packets), 1)
            self.assertTrue(meta["ns_resolution"])
            self.assertAlmostEqual(packets[0].timestamp_s, 1000.123456789, places=6)
        finally:
            os.unlink(path)

    def test_parse_raw_ip_link_type(self):
        """Parse a PCAP with DLT_RAW link type (no Ethernet header)."""
        tcp = _build_tcp_header()
        ip = _build_ipv4_header(total_len=20 + len(tcp))
        raw_pkt = ip + tcp

        packets_data = [(1000, 0, raw_pkt)]
        path = _write_pcap_to_tempfile(packets_data, link_type=DLT_RAW)
        try:
            packets, meta = parse_pcap_file(path)
            self.assertEqual(len(packets), 1)
            self.assertEqual(meta["link_type"], DLT_RAW)
            info = _get_ip_info(packets[0])
            self.assertIsNotNone(info)
            self.assertEqual(info["ip_offset"], 0)
        finally:
            os.unlink(path)

    def test_parse_empty_file_raises(self):
        """Ensure very small files raise PcapParseError."""
        fd, path = tempfile.mkstemp(suffix=".pcap")
        with os.fdopen(fd, "wb") as f:
            f.write(b"\x00" * 10)
        try:
            with self.assertRaises(PcapParseError):
                parse_pcap_file(path)
        finally:
            os.unlink(path)

    def test_parse_nonexistent_file(self):
        """Ensure missing files raise FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            parse_pcap_file("/nonexistent/path/file.pcap")


# ────────────────────────────────────────────────────────────────
#  Test: IP Info Extraction
# ────────────────────────────────────────────────────────────────

class TestIPInfoExtraction(unittest.TestCase):
    def test_extract_from_eth_tcp(self):
        data = _build_eth_tcp_packet("192.168.1.1", "10.0.0.1", 12345, 80)
        pkt = ParsedPacket(0, data, len(data), DLT_EN10MB)
        info = _get_ip_info(pkt)
        self.assertIsNotNone(info)
        self.assertEqual(info["src_ip"], "192.168.1.1")
        self.assertEqual(info["dst_ip"], "10.0.0.1")
        self.assertEqual(info["protocol"], PROTO_TCP)
        self.assertEqual(info["src_port"], 12345)
        self.assertEqual(info["dst_port"], 80)

    def test_extract_from_eth_udp(self):
        data = _build_eth_udp_packet("172.16.0.1", "8.8.8.8", 54321, 53)
        pkt = ParsedPacket(0, data, len(data), DLT_EN10MB)
        info = _get_ip_info(pkt)
        self.assertIsNotNone(info)
        self.assertEqual(info["src_ip"], "172.16.0.1")
        self.assertEqual(info["dst_ip"], "8.8.8.8")
        self.assertEqual(info["protocol"], PROTO_UDP)
        self.assertEqual(info["src_port"], 54321)
        self.assertEqual(info["dst_port"], 53)

    def test_extract_from_raw_ip(self):
        tcp = _build_tcp_header(80, 443)
        ip = _build_ipv4_header("1.2.3.4", "5.6.7.8", PROTO_TCP, 20 + len(tcp))
        pkt = ParsedPacket(0, ip + tcp, len(ip + tcp), DLT_RAW)
        info = _get_ip_info(pkt)
        self.assertIsNotNone(info)
        self.assertEqual(info["ip_offset"], 0)
        self.assertEqual(info["src_ip"], "1.2.3.4")
        self.assertEqual(info["dst_ip"], "5.6.7.8")

    def test_non_ipv4_returns_none(self):
        """Non-IPv4 (e.g. IPv6) should return None."""
        ipv6_stub = b"\x60" + b"\x00" * 39  # version 6
        eth = _build_ethernet_header(ethertype=0x86DD)
        pkt = ParsedPacket(0, eth + ipv6_stub, len(eth + ipv6_stub), DLT_EN10MB)
        info = _get_ip_info(pkt)
        self.assertIsNone(info)


# ────────────────────────────────────────────────────────────────
#  Test: Packet Filtering
# ────────────────────────────────────────────────────────────────

class TestFiltering(unittest.TestCase):
    def _make_pkt(self, protocol, src_ip, dst_ip, src_port=0, dst_port=0, pkt_len=54):
        data = bytearray(pkt_len)
        # fake enough for _get_ip_info
        info = {
            "ip_offset": 14,
            "ihl": 20,
            "total_len": pkt_len - 14,
            "protocol": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_ip_int": _ip_to_int(src_ip),
            "dst_ip_int": _ip_to_int(dst_ip),
            "src_port": src_port,
            "dst_port": dst_port,
        }
        pkt = ParsedPacket(0, bytes(data), pkt_len, DLT_EN10MB)
        return pkt, info

    def test_protocol_filter_tcp(self):
        pkt, info = self._make_pkt(PROTO_TCP, "10.0.0.1", "10.0.0.2")
        cfg = PcapFilterConfig(protocols=["tcp"])
        self.assertTrue(_apply_filter(pkt, info, cfg))

    def test_protocol_filter_reject_udp(self):
        pkt, info = self._make_pkt(PROTO_UDP, "10.0.0.1", "10.0.0.2")
        cfg = PcapFilterConfig(protocols=["tcp"])
        self.assertFalse(_apply_filter(pkt, info, cfg))

    def test_ip_filter_src(self):
        pkt, info = self._make_pkt(PROTO_TCP, "192.168.1.100", "10.0.0.1")
        cfg_match = PcapFilterConfig(src_ip="192.168.1.0/24")
        cfg_no = PcapFilterConfig(src_ip="10.0.0.0/8")
        self.assertTrue(_apply_filter(pkt, info, cfg_match))
        self.assertFalse(_apply_filter(pkt, info, cfg_no))

    def test_port_filter(self):
        pkt, info = self._make_pkt(PROTO_TCP, "10.0.0.1", "10.0.0.2", 12345, 80)
        cfg = PcapFilterConfig(dst_port=80)
        self.assertTrue(_apply_filter(pkt, info, cfg))
        cfg2 = PcapFilterConfig(dst_port=443)
        self.assertFalse(_apply_filter(pkt, info, cfg2))

    def test_length_filter(self):
        pkt, info = self._make_pkt(PROTO_TCP, "10.0.0.1", "10.0.0.2", pkt_len=100)
        cfg_min = PcapFilterConfig(min_len=50)
        cfg_max = PcapFilterConfig(max_len=80)
        self.assertTrue(_apply_filter(pkt, info, cfg_min))
        self.assertFalse(_apply_filter(pkt, info, cfg_max))

    def test_none_info_filtered_out(self):
        pkt = ParsedPacket(0, b"\x00" * 10, 10, DLT_EN10MB)
        cfg = PcapFilterConfig(protocols=["tcp"])
        self.assertFalse(_apply_filter(pkt, None, cfg))


# ────────────────────────────────────────────────────────────────
#  Test: IP/Port Rewriting
# ────────────────────────────────────────────────────────────────

class TestRewriting(unittest.TestCase):
    def test_rewrite_dst_ip(self):
        data = _build_eth_tcp_packet("1.1.1.1", "2.2.2.2", 1000, 80)
        pkt = ParsedPacket(0, data, len(data), DLT_EN10MB)
        info = _get_ip_info(pkt)
        self.assertEqual(info["dst_ip"], "2.2.2.2")

        raw = bytearray(data)
        raw = _rewrite_packet(raw, info["ip_offset"], info, "3.3.3.3", None, None, None)

        # Verify rewritten IP
        new_pkt = ParsedPacket(0, bytes(raw), len(raw), DLT_EN10MB)
        new_info = _get_ip_info(new_pkt)
        self.assertEqual(new_info["dst_ip"], "3.3.3.3")
        self.assertEqual(new_info["src_ip"], "1.1.1.1")  # unchanged

    def test_rewrite_dst_port(self):
        data = _build_eth_tcp_packet("1.1.1.1", "2.2.2.2", 1000, 80)
        pkt = ParsedPacket(0, data, len(data), DLT_EN10MB)
        info = _get_ip_info(pkt)

        raw = bytearray(data)
        raw = _rewrite_packet(raw, info["ip_offset"], info, None, 443, None, None)

        new_pkt = ParsedPacket(0, bytes(raw), len(raw), DLT_EN10MB)
        new_info = _get_ip_info(new_pkt)
        self.assertEqual(new_info["dst_port"], 443)
        self.assertEqual(new_info["src_port"], 1000)

    def test_rewrite_src_ip_and_port(self):
        data = _build_eth_tcp_packet("1.1.1.1", "2.2.2.2", 1000, 80)
        pkt = ParsedPacket(0, data, len(data), DLT_EN10MB)
        info = _get_ip_info(pkt)

        raw = bytearray(data)
        raw = _rewrite_packet(raw, info["ip_offset"], info, None, None, "5.5.5.5", 9999)

        new_pkt = ParsedPacket(0, bytes(raw), len(raw), DLT_EN10MB)
        new_info = _get_ip_info(new_pkt)
        self.assertEqual(new_info["src_ip"], "5.5.5.5")
        self.assertEqual(new_info["src_port"], 9999)

    def test_ip_checksum_valid_after_rewrite(self):
        """After rewriting, IP header checksum should validate (sum → 0)."""
        data = _build_eth_tcp_packet("10.0.0.1", "20.0.0.1", 5000, 443)
        pkt = ParsedPacket(0, data, len(data), DLT_EN10MB)
        info = _get_ip_info(pkt)

        raw = bytearray(data)
        raw = _rewrite_packet(raw, info["ip_offset"], info, "99.99.99.99", 8080, "11.11.11.11", 7777)

        # Verify IP checksum: sum of entire header should be 0xFFFF
        ip_off = info["ip_offset"]
        ihl = info["ihl"]
        s = _ones_complement_sum(bytes(raw), ip_off, ihl)
        self.assertEqual(s, 0xFFFF)


# ────────────────────────────────────────────────────────────────
#  Test: Timing Delay Computation
# ────────────────────────────────────────────────────────────────

class TestTimingDelays(unittest.TestCase):
    def test_topspeed_all_zero(self):
        ts = [0.0, 0.1, 0.3, 0.6]
        delays = _compute_delays(ts, TimingMode.TOPSPEED)
        self.assertEqual(len(delays), 4)
        self.assertTrue(all(d == 0.0 for d in delays))

    def test_original_preserves_gaps(self):
        ts = [10.0, 10.5, 11.0, 12.0]
        delays = _compute_delays(ts, TimingMode.ORIGINAL)
        self.assertAlmostEqual(delays[0], 0.0)
        self.assertAlmostEqual(delays[1], 0.5)
        self.assertAlmostEqual(delays[2], 0.5)
        self.assertAlmostEqual(delays[3], 1.0)

    def test_multiplier_halves_gaps(self):
        ts = [10.0, 11.0, 13.0]
        delays = _compute_delays(ts, TimingMode.MULTIPLIER, multiplier=2.0)
        self.assertAlmostEqual(delays[0], 0.0)
        self.assertAlmostEqual(delays[1], 0.5)
        self.assertAlmostEqual(delays[2], 1.0)

    def test_rps_constant_gap(self):
        ts = [0.0, 0.1, 0.2]  # original timing doesn't matter for RPS
        delays = _compute_delays(ts, TimingMode.RPS, target_rps=100)
        self.assertAlmostEqual(delays[0], 0.0)
        self.assertAlmostEqual(delays[1], 0.01)
        self.assertAlmostEqual(delays[2], 0.01)

    def test_empty_timestamps(self):
        delays = _compute_delays([], TimingMode.ORIGINAL)
        self.assertEqual(delays, [])


class TestTimingDeterministic(unittest.TestCase):
    """Deterministic timing tests for TRex-style benchmark reproducibility."""

    def test_schedule_offsets_cumulative(self):
        """_compute_schedule_offsets should produce cumulative absolute offsets."""
        from ddos_samurai.pcap_replay import _compute_schedule_offsets
        delays = [0.0, 0.1, 0.2, 0.5]
        offsets = _compute_schedule_offsets(delays)
        self.assertEqual(len(offsets), 4)
        self.assertAlmostEqual(offsets[0], 0.0)
        self.assertAlmostEqual(offsets[1], 0.1)
        self.assertAlmostEqual(offsets[2], 0.3)
        self.assertAlmostEqual(offsets[3], 0.8)

    def test_schedule_offsets_topspeed_all_zero(self):
        """Topspeed offsets should all be zero."""
        from ddos_samurai.pcap_replay import _compute_schedule_offsets
        delays = _compute_delays([0.0, 1.0, 2.0], TimingMode.TOPSPEED)
        offsets = _compute_schedule_offsets(delays)
        self.assertTrue(all(o == 0.0 for o in offsets))

    def test_single_packet_all_modes(self):
        """Single packet should always return delay[0]=0.0 regardless of mode."""
        for mode in TimingMode:
            delays = _compute_delays([42.0], mode, multiplier=10.0, target_rps=1000)
            self.assertEqual(len(delays), 1)
            self.assertAlmostEqual(delays[0], 0.0, msg=f"Failed for mode {mode}")

    def test_multiplier_extreme_slowdown(self):
        """Very small multiplier should produce very large delays."""
        ts = [0.0, 1.0, 2.0]
        delays = _compute_delays(ts, TimingMode.MULTIPLIER, multiplier=0.001)
        # 1s gap / 0.001 speed = 1000s delay
        self.assertAlmostEqual(delays[1], 1000.0, places=1)
        self.assertAlmostEqual(delays[2], 1000.0, places=1)

    def test_rps_high_rate(self):
        """High RPS should produce very small inter-packet gaps."""
        ts = [0.0, 1.0, 2.0, 3.0, 4.0]
        delays = _compute_delays(ts, TimingMode.RPS, target_rps=1_000_000)
        expected_gap = 1.0 / 1_000_000
        for i in range(1, len(delays)):
            self.assertAlmostEqual(delays[i], expected_gap, places=9)

    def test_original_negative_timestamp_gap_clamped(self):
        """If timestamps go backwards, delay should be clamped to 0."""
        ts = [10.0, 9.0, 11.0]  # second is earlier than first
        delays = _compute_delays(ts, TimingMode.ORIGINAL)
        self.assertAlmostEqual(delays[1], 0.0)  # clamped
        self.assertAlmostEqual(delays[2], 2.0)   # 11 - 9 = 2


# ────────────────────────────────────────────────────────────────
#  Test: Replay Preparation
# ────────────────────────────────────────────────────────────────

class TestPrepareReplay(unittest.TestCase):
    def test_basic_preparation(self):
        """Prepare a PCAP with 3 TCP packets."""
        packets_data = [
            (1000, 0,      _build_eth_tcp_packet()),
            (1000, 500000, _build_eth_tcp_packet()),
            (1001, 0,      _build_eth_tcp_packet()),
        ]
        path = _write_pcap_to_tempfile(packets_data)
        try:
            cfg = PcapReplayConfig(pcap_file=path)
            prep = prepare_replay(cfg)
            self.assertEqual(prep.count, 3)
            self.assertGreater(prep.packet_size, 0)
            self.assertEqual(len(prep.packets_buffer), prep.count * prep.packet_size)
            self.assertEqual(len(prep.timestamps), 3)
        finally:
            os.unlink(path)

    def test_preparation_with_filter(self):
        """Only TCP packets should pass the filter."""
        tcp_pkt = _build_eth_tcp_packet()
        udp_pkt = _build_eth_udp_packet()
        packets_data = [
            (1000, 0, tcp_pkt),
            (1001, 0, udp_pkt),
            (1002, 0, tcp_pkt),
        ]
        path = _write_pcap_to_tempfile(packets_data)
        try:
            cfg = PcapReplayConfig(
                pcap_file=path,
                filter_cfg=PcapFilterConfig(protocols=["tcp"]),
            )
            prep = prepare_replay(cfg)
            self.assertEqual(prep.count, 2)  # only TCP packets
        finally:
            os.unlink(path)

    def test_preparation_with_ip_rewrite(self):
        """Destination IP should be rewritten in prepared packets."""
        packets_data = [
            (1000, 0, _build_eth_tcp_packet("10.0.0.1", "20.0.0.1", 1111, 80)),
        ]
        path = _write_pcap_to_tempfile(packets_data)
        try:
            cfg = PcapReplayConfig(
                pcap_file=path,
                target_ip_override="99.99.99.99",
                target_port_override=443,
            )
            prep = prepare_replay(cfg)
            self.assertEqual(prep.count, 1)
            # Verify the buffer has the rewritten IP
            pkt = ParsedPacket(0, prep.packets_buffer[:prep.packet_size], prep.packet_size, DLT_EN10MB)
            info = _get_ip_info(pkt)
            self.assertIsNotNone(info)
            self.assertEqual(info["dst_ip"], "99.99.99.99")
            self.assertEqual(info["dst_port"], 443)
        finally:
            os.unlink(path)

    def test_preparation_with_max_packets(self):
        """max_packets should limit the number of prepared packets."""
        packets_data = [(1000 + i, 0, _build_eth_tcp_packet()) for i in range(10)]
        path = _write_pcap_to_tempfile(packets_data)
        try:
            cfg = PcapReplayConfig(pcap_file=path, max_packets=5)
            prep = prepare_replay(cfg)
            self.assertEqual(prep.count, 5)
        finally:
            os.unlink(path)

    def test_preparation_strip_ethernet(self):
        """strip_ethernet should remove Ethernet header."""
        packets_data = [(1000, 0, _build_eth_tcp_packet())]
        path = _write_pcap_to_tempfile(packets_data)
        try:
            cfg = PcapReplayConfig(pcap_file=path, strip_ethernet=True)
            prep = prepare_replay(cfg)
            self.assertEqual(prep.count, 1)
            # Check that first byte looks like IPv4 (0x45)
            first_byte = prep.packets_buffer[0]
            self.assertEqual((first_byte >> 4) & 0xF, 4, "Should be IPv4 after stripping Ethernet")
        finally:
            os.unlink(path)

    def test_use_l2_and_strip_eth_conflict(self):
        packets_data = [(1000, 0, _build_eth_tcp_packet())]
        path = _write_pcap_to_tempfile(packets_data)
        try:
            cfg = PcapReplayConfig(
                pcap_file=path,
                use_l2=True,
                strip_ethernet=True,
            )
            with self.assertRaises(PcapParseError):
                prepare_replay(cfg)
        finally:
            os.unlink(path)

    def test_flow_aware_rewrite_adjusts_seq_on_colliding_flows(self):
        tcp_a = _build_tcp_header(src_port=1111, dst_port=80, seq=1000, ack=0, flags=0x02)
        ip_a = _build_ipv4_header(src_ip="10.0.0.1", dst_ip="20.0.0.1", protocol=PROTO_TCP, total_len=20 + len(tcp_a))
        pkt_a = _build_ethernet_header() + ip_a + tcp_a

        tcp_b = _build_tcp_header(src_port=2222, dst_port=80, seq=2000, ack=0, flags=0x02)
        ip_b = _build_ipv4_header(src_ip="10.0.0.2", dst_ip="20.0.0.1", protocol=PROTO_TCP, total_len=20 + len(tcp_b))
        pkt_b = _build_ethernet_header() + ip_b + tcp_b

        packets_data = [(1000, 0, pkt_a), (1000, 1000, pkt_b)]
        path = _write_pcap_to_tempfile(packets_data)
        try:
            cfg = PcapReplayConfig(
                pcap_file=path,
                src_ip_override="30.30.30.30",
                src_port_override=5555,
                flow_aware_rewrite=True,
            )
            prep = prepare_replay(cfg)
            self.assertEqual(prep.count, 2)
            self.assertGreaterEqual(int(prep.stats.get("flow_collision_count", 0) or 0), 1)
            self.assertGreaterEqual(int(prep.stats.get("tcp_seq_adjusted", 0) or 0), 1)

            pkt0 = prep.packets_buffer[:prep.packet_size]
            pkt1 = prep.packets_buffer[prep.packet_size:2 * prep.packet_size]
            info0 = _get_ip_info(ParsedPacket(0, pkt0, len(pkt0), DLT_EN10MB))
            info1 = _get_ip_info(ParsedPacket(0, pkt1, len(pkt1), DLT_EN10MB))
            self.assertIsNotNone(info0)
            self.assertIsNotNone(info1)
            off0 = int(info0["ip_offset"]) + int(info0["ihl"]) + 4
            off1 = int(info1["ip_offset"]) + int(info1["ihl"]) + 4
            seq0 = struct.unpack("!I", pkt0[off0:off0 + 4])[0]
            seq1 = struct.unpack("!I", pkt1[off1:off1 + 4])[0]

            self.assertEqual(seq0, 1000)
            self.assertNotEqual(seq1, 2000)
        finally:
            os.unlink(path)


class TestReplayExecution(unittest.IsolatedAsyncioTestCase):
    async def test_replay_use_l2_passes_force_l2_to_sender(self):
        packets_data = [(1000, 0, _build_eth_tcp_packet())]
        path = _write_pcap_to_tempfile(packets_data)
        try:
            cfg = PcapReplayConfig(
                pcap_file=path,
                timing_mode="topspeed",
                use_l2=True,
                target_ip_override="127.0.0.1",
                target_port_override=80,
            )
            mock_sender = AsyncMock(return_value={"attempted": 1, "sent": 1, "errors": 0, "bytes_sent_est": 64})
            with patch("ddos_samurai.senders.paced_raw_socket_sender", mock_sender):
                out = await replay_pcap(cfg)
            self.assertEqual(out["attempted"], 1)
            self.assertEqual(out["sent"], 1)
            _args, kwargs = mock_sender.call_args
            self.assertTrue(bool(kwargs.get("force_l2", False)))
        finally:
            os.unlink(path)


# ────────────────────────────────────────────────────────────────
#  Test: PCAP Summary
# ────────────────────────────────────────────────────────────────

class TestPcapSummary(unittest.TestCase):
    def test_summary_basic(self):
        tcp_pkt = _build_eth_tcp_packet("10.0.0.1", "20.0.0.1")
        udp_pkt = _build_eth_udp_packet("10.0.0.2", "20.0.0.2")
        packets_data = [
            (1000, 0, tcp_pkt),
            (1000, 500000, udp_pkt),
            (1001, 0, tcp_pkt),
        ]
        path = _write_pcap_to_tempfile(packets_data)
        try:
            summary = pcap_summary(path)
            self.assertEqual(summary["packets"], 3)
            self.assertEqual(summary["protocols"]["tcp"], 2)
            self.assertEqual(summary["protocols"]["udp"], 1)
            self.assertGreater(summary["duration_s"], 0)
            self.assertGreaterEqual(summary["unique_src_ips"], 2)
        finally:
            os.unlink(path)


# ────────────────────────────────────────────────────────────────
#  Test: Timing Mode Map
# ────────────────────────────────────────────────────────────────

class TestTimingModeMap(unittest.TestCase):
    def test_all_modes_mapped(self):
        self.assertEqual(TIMING_MODE_MAP["original"], TimingMode.ORIGINAL)
        self.assertEqual(TIMING_MODE_MAP["topspeed"], TimingMode.TOPSPEED)
        self.assertEqual(TIMING_MODE_MAP["multiplier"], TimingMode.MULTIPLIER)
        self.assertEqual(TIMING_MODE_MAP["rps"], TimingMode.RPS)


# ────────────────────────────────────────────────────────────────
#  Test: Extract IP Offset
# ────────────────────────────────────────────────────────────────

class TestExtractIPOffset(unittest.TestCase):
    def test_ethernet(self):
        pkt = ParsedPacket(0, b"\x00"*60, 60, DLT_EN10MB)
        self.assertEqual(_extract_ip_offset(pkt), 14)

    def test_raw(self):
        pkt = ParsedPacket(0, b"\x00"*40, 40, DLT_RAW)
        self.assertEqual(_extract_ip_offset(pkt), 0)

    def test_linux_sll(self):
        pkt = ParsedPacket(0, b"\x00"*60, 60, 113)  # DLT_LINUX_SLL
        self.assertEqual(_extract_ip_offset(pkt), 16)


# ────────────────────────────────────────────────────────────────
#  Test: Checksum Utility
# ────────────────────────────────────────────────────────────────

class TestChecksum(unittest.TestCase):
    def test_ones_complement_simple(self):
        # Two bytes: 0x00 0x00 → sum should be 0
        data = b"\x00\x00"
        self.assertEqual(_ones_complement_sum(data, 0, 2), 0)

    def test_ones_complement_nonzero(self):
        data = b"\xFF\xFF"
        self.assertEqual(_ones_complement_sum(data, 0, 2), 0xFFFF)


if __name__ == "__main__":
    unittest.main()
