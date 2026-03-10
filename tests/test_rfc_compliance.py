"""
Samurai — RFC Compliance Scoring Suite
=========================================

Validates packet correctness against:
    RFC 791  — Internet Protocol (IPv4)
    RFC 793  — Transmission Control Protocol (TCP)
    RFC 768  — User Datagram Protocol (UDP)
    RFC 792  — Internet Control Message Protocol (ICMP)
    RFC 1071 — Computing the Internet Checksum
    RFC 1035 — Domain Name System (DNS)
    RFC 894  — Ethernet II Framing
    RFC 7414 — TCP Options (MSS, SACK, Timestamp, WScale)

Engines tested:
    1. CPU Packet Engine  (cpu_packet_engine.py)
    2. GPU Packet Engine  (gpu_packet.py)  — skipped if no CUDA

Each check is scored. A final report is printed with a letter grade.
"""

import json
import os
import struct
import sys
import tempfile
import unittest

# ── CPU Engine Imports ──────────────────────────────────────────────────────
from ddos_samurai.cpu_packet_engine import (
    PacketConfig, SpoofingOptions,
    create_packet, build_transport_packet, build_dns_packet,
    build_polymorphic_http_packet, generate_packet_pool,
    create_dns_amp_packet, create_ntp_amp_packet,
    create_ssdp_amp_packet, create_memcached_amp_packet,
    create_ldap_amp_packet, fragment_packet, add_ethernet_frame,
    build_ipv4_header, build_tcp_header, build_udp_header,
    build_icmp_echo, build_tcp_options, build_dns_query,
    _checksum, ip_to_int, int_to_ip,
    PROTO_TCP, PROTO_UDP, PROTO_ICMP,
    TCP_SYN, TCP_ACK, TCP_PSH, TCP_FIN,
    TCP_OPT_MSS, TCP_OPT_NOP, TCP_OPT_WSCALE,
    TCP_OPT_SACK_OK, TCP_OPT_TIMESTAMP,
    OS_PROFILES,
)

# ── GPU availability ────────────────────────────────────────────────────────
GPU_AVAILABLE = False
try:
    import numpy as np
    import cupy as cp
    from numba import cuda
    if cuda.is_available():
        from ddos_samurai import gpu_packet
        GPU_AVAILABLE = True
except Exception:
    pass

try:
    import pytest
    pytestmark = [pytest.mark.rfc_positive, pytest.mark.ci_safe]
except Exception:  # pragma: no cover - unittest-only environments
    pytestmark = []

# ════════════════════════════════════════════════════════════════════════════
#  Scoring Infrastructure
# ════════════════════════════════════════════════════════════════════════════

class _ScoreBoard:
    """Collects per-check results for the final report."""
    _checks: list = []

    @classmethod
    def reset(cls):
        cls._checks = []

    @classmethod
    def record(cls, rfc: str, name: str, passed: bool, weight: float = 1.0):
        cls._checks.append({"rfc": rfc, "name": name, "passed": passed, "weight": weight})

    @classmethod
    def report(cls):
        total_w = sum(c["weight"] for c in cls._checks)
        scored  = sum(c["weight"] for c in cls._checks if c["passed"])
        pct = (scored / total_w * 100) if total_w else 0
        if pct >= 95: grade = "A+"
        elif pct >= 90: grade = "A"
        elif pct >= 80: grade = "B"
        elif pct >= 70: grade = "C"
        elif pct >= 60: grade = "D"
        else: grade = "F"
        return {"score": round(pct, 2), "grade": grade, "passed": int(scored),
                "total": int(total_w), "checks": cls._checks}


def _score(rfc, name, weight=1.0):
    """Decorator that records pass/fail into the scoreboard."""
    def decorator(fn):
        orig = fn
        def wrapper(self, *a, **kw):
            try:
                orig(self, *a, **kw)
                _ScoreBoard.record(rfc, name, True, weight)
            except Exception:
                _ScoreBoard.record(rfc, name, False, weight)
                raise
        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        return wrapper
    return decorator


def _write_json_with_fallback(path: str, payload: dict, fallback_name: str) -> str:
    content = json.dumps(payload, indent=2)
    candidates = [
        os.path.abspath(path),
        os.path.abspath(os.path.join(os.getcwd(), ".pytest_artifacts", fallback_name)),
        os.path.abspath(os.path.join(tempfile.gettempdir(), ".pytest_artifacts", fallback_name)),
    ]
    seen = set()
    for cand in candidates:
        if cand in seen:
            continue
        seen.add(cand)
        try:
            os.makedirs(os.path.dirname(cand), exist_ok=True)
            with open(cand, "w", encoding="utf-8") as f:
                f.write(content)
            return cand
        except PermissionError:
            continue
    raise PermissionError(f"Unable to write RFC report to any candidate path: {candidates}")

_ScoreBoard.reset()


# ════════════════════════════════════════════════════════════════════════════
#  Shared helpers
# ════════════════════════════════════════════════════════════════════════════

def _ip_cksum_valid(pkt: bytes, off: int = 0) -> bool:
    ihl = (pkt[off] & 0xF) * 4
    s = 0
    for i in range(0, ihl, 2):
        s += (pkt[off+i] << 8) | pkt[off+i+1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s == 0xFFFF


def _tcp_cksum_valid(pkt: bytes, ip_off: int = 0) -> bool:
    ihl = (pkt[ip_off] & 0xF) * 4
    total = struct.unpack("!H", pkt[ip_off+2:ip_off+4])[0]
    tcp_off = ip_off + ihl
    tcp_len = total - ihl
    src = struct.unpack("!I", pkt[ip_off+12:ip_off+16])[0]
    dst = struct.unpack("!I", pkt[ip_off+16:ip_off+20])[0]
    pseudo = struct.pack("!IIBBH", src, dst, 0, 6, tcp_len)
    data = pseudo + pkt[tcp_off:tcp_off+tcp_len]
    if len(data) % 2: data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i+1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s == 0xFFFF


def _udp_cksum_valid(pkt: bytes, ip_off: int = 0) -> bool:
    ihl = (pkt[ip_off] & 0xF) * 4
    total = struct.unpack("!H", pkt[ip_off+2:ip_off+4])[0]
    udp_off = ip_off + ihl
    udp_len = total - ihl
    src = struct.unpack("!I", pkt[ip_off+12:ip_off+16])[0]
    dst = struct.unpack("!I", pkt[ip_off+16:ip_off+20])[0]
    cksum_field = struct.unpack("!H", pkt[udp_off+6:udp_off+8])[0]
    if cksum_field == 0:
        return True  # RFC 768: 0 means "not computed"
    pseudo = struct.pack("!IIBBH", src, dst, 0, 17, udp_len)
    data = pseudo + pkt[udp_off:udp_off+udp_len]
    if len(data) % 2: data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i+1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s == 0xFFFF


def _ipf(pkt, off=0):
    """Extract IP fields dict."""
    ihl = (pkt[off] & 0xF) * 4
    return {
        "ver": (pkt[off] >> 4) & 0xF,
        "ihl": ihl,
        "total": struct.unpack("!H", pkt[off+2:off+4])[0],
        "ttl": pkt[off+8],
        "proto": pkt[off+9],
        "src": int_to_ip(struct.unpack("!I", pkt[off+12:off+16])[0]),
        "dst": int_to_ip(struct.unpack("!I", pkt[off+16:off+20])[0]),
    }


# ════════════════════════════════════════════════════════════════════════════
#  CPU ENGINE RFC COMPLIANCE
# ════════════════════════════════════════════════════════════════════════════

class TestCPU_RFC791_IPv4(unittest.TestCase):
    """RFC 791 — Internet Protocol v4 header compliance."""

    @_score("RFC 791", "Version field == 4")
    def test_version(self):
        p = create_packet(PacketConfig("10.0.0.1", 80))
        self.assertEqual((p[0] >> 4) & 0xF, 4)

    @_score("RFC 791", "IHL >= 5 (20 bytes minimum)")
    def test_ihl_minimum(self):
        p = create_packet(PacketConfig("10.0.0.1", 80))
        self.assertGreaterEqual(p[0] & 0xF, 5)

    @_score("RFC 791", "Total Length matches actual packet")
    def test_total_length(self):
        p = create_packet(PacketConfig("10.0.0.1", 80, tcp_flags="S"))
        total = struct.unpack("!H", p[2:4])[0]
        self.assertEqual(total, len(p))

    @_score("RFC 791", "TTL > 0 (non-zero)")
    def test_ttl_nonzero(self):
        p = create_packet(PacketConfig("10.0.0.1", 80))
        self.assertGreater(p[8], 0)

    @_score("RFC 791", "Protocol field correct (TCP=6)")
    def test_protocol_tcp(self):
        p = create_packet(PacketConfig("10.0.0.1", 80, protocol="tcp"))
        self.assertEqual(p[9], 6)

    @_score("RFC 791", "Protocol field correct (UDP=17)")
    def test_protocol_udp(self):
        p = create_packet(PacketConfig("10.0.0.1", 53, protocol="udp"))
        self.assertEqual(p[9], 17)

    @_score("RFC 791", "Protocol field correct (ICMP=1)")
    def test_protocol_icmp(self):
        p = create_packet(PacketConfig("10.0.0.1", 0, protocol="icmp"))
        self.assertEqual(p[9], 1)

    @_score("RFC 791", "Header checksum validates (sum → 0xFFFF)", 2)
    def test_checksum(self):
        for proto in ("tcp", "udp", "icmp"):
            p = create_packet(PacketConfig("10.0.0.1", 80, protocol=proto))
            self.assertTrue(_ip_cksum_valid(p), f"IP cksum invalid for {proto}")

    @_score("RFC 791", "Destination IP matches config")
    def test_dst_ip(self):
        p = create_packet(PacketConfig("99.88.77.66", 80))
        self.assertEqual(_ipf(p)["dst"], "99.88.77.66")

    @_score("RFC 791", "Spoofed source IP applied correctly")
    def test_spoofed_src(self):
        cfg = PacketConfig("10.0.0.1", 80, spoof=True,
                           spoof_opts=SpoofingOptions("subnet", "203.0.113.0/24"))
        p = create_packet(cfg)
        self.assertTrue(_ipf(p)["src"].startswith("203.0.113."))

    @_score("RFC 791", "Fragmentation MF/offset correct", 2)
    def test_fragmentation(self):
        cfg = PacketConfig("10.0.0.1", 80, protocol="udp", payload=b"X"*3000)
        p = create_packet(cfg)
        frags = fragment_packet(p, 400)
        self.assertGreater(len(frags), 1)
        for i, f in enumerate(frags):
            self.assertTrue(_ip_cksum_valid(f))
            flags = struct.unpack("!H", f[6:8])[0]
            if i < len(frags)-1:
                self.assertTrue(flags & 0x2000, "MF should be set")
            else:
                self.assertFalse(flags & 0x2000, "MF must be clear on last fragment")


class TestCPU_RFC793_TCP(unittest.TestCase):
    """RFC 793 — TCP header compliance."""

    def _tcp(self, **kw):
        cfg = PacketConfig("10.0.0.1", 80, protocol="tcp", **kw)
        return create_packet(cfg)

    @_score("RFC 793", "Destination port matches config")
    def test_dst_port(self):
        p = self._tcp()
        ihl = (p[0] & 0xF) * 4
        self.assertEqual(struct.unpack("!H", p[ihl+2:ihl+4])[0], 80)

    @_score("RFC 793", "Source port in ephemeral range (1024-65535)")
    def test_src_port_range(self):
        for _ in range(50):
            p = self._tcp()
            ihl = (p[0] & 0xF) * 4
            sp = struct.unpack("!H", p[ihl:ihl+2])[0]
            self.assertGreaterEqual(sp, 1024)

    @_score("RFC 793", "Data offset >= 5 (20 bytes)")
    def test_data_offset(self):
        p = self._tcp()
        ihl = (p[0] & 0xF) * 4
        doff = (struct.unpack("!H", p[ihl+12:ihl+14])[0] >> 12) * 4
        self.assertGreaterEqual(doff, 20)

    @_score("RFC 793", "SYN flag set correctly")
    def test_syn_flag(self):
        p = self._tcp(tcp_flags="S")
        ihl = (p[0] & 0xF) * 4
        flags = struct.unpack("!H", p[ihl+12:ihl+14])[0] & 0x1FF
        self.assertTrue(flags & TCP_SYN)

    @_score("RFC 793", "SYN-only has no payload (stealth)")
    def test_syn_no_payload(self):
        p = self._tcp(tcp_flags="S")
        f = _ipf(p)
        ihl = f["ihl"]
        tcp_off = ihl
        doff = (struct.unpack("!H", p[tcp_off+12:tcp_off+14])[0] >> 12) * 4
        self.assertEqual(f["total"], ihl + doff)

    @_score("RFC 793", "TCP checksum validates (pseudo-header)", 2)
    def test_tcp_checksum(self):
        for flags in ("S", "SA", "PA", "FA"):
            p = self._tcp(tcp_flags=flags, payload=b"test" if "P" in flags else None)
            self.assertTrue(_tcp_cksum_valid(p), f"TCP cksum invalid for flags={flags}")

    @_score("RFC 793", "Window size > 0")
    def test_window(self):
        p = self._tcp()
        ihl = (p[0] & 0xF) * 4
        win = struct.unpack("!H", p[ihl+14:ihl+16])[0]
        self.assertGreater(win, 0)


class TestCPU_RFC7414_TCPOptions(unittest.TestCase):
    """RFC 7414 — TCP option encoding."""

    @_score("RFC 7414", "MSS option (Kind=2, Len=4)")
    def test_mss(self):
        opts = build_tcp_options([(TCP_OPT_MSS, 1460)])
        self.assertEqual(opts[0], 2)
        self.assertEqual(opts[1], 4)
        self.assertEqual(struct.unpack("!H", opts[2:4])[0], 1460)

    @_score("RFC 7414", "SACK Permitted (Kind=4, Len=2)")
    def test_sack_ok(self):
        opts = build_tcp_options([(TCP_OPT_SACK_OK, None)])
        self.assertEqual(opts[0], 4)
        self.assertEqual(opts[1], 2)

    @_score("RFC 7414", "Timestamp (Kind=8, Len=10)")
    def test_timestamp(self):
        opts = build_tcp_options([(TCP_OPT_TIMESTAMP, (12345, 0))])
        self.assertEqual(opts[0], 8)
        self.assertEqual(opts[1], 10)

    @_score("RFC 7414", "Window Scale (Kind=3, Len=3)")
    def test_wscale(self):
        opts = build_tcp_options([(TCP_OPT_WSCALE, 7)])
        self.assertEqual(opts[0], 3)
        self.assertEqual(opts[1], 3)

    @_score("RFC 7414", "Options 32-bit aligned")
    def test_alignment(self):
        for profile in OS_PROFILES:
            opts_list = [(k, (1,0) if k == TCP_OPT_TIMESTAMP else v) for k,v in profile.tcp_options]
            raw = build_tcp_options(opts_list)
            self.assertTrue(len(raw) % 4 == 0, f"{profile.name} options not aligned")


class TestCPU_RFC768_UDP(unittest.TestCase):
    """RFC 768 — UDP compliance."""

    @_score("RFC 768", "UDP length = header(8) + payload")
    def test_length(self):
        p = create_packet(PacketConfig("8.8.8.8", 53, protocol="udp", payload=b"test"))
        ihl = (p[0] & 0xF) * 4
        udp_len = struct.unpack("!H", p[ihl+4:ihl+6])[0]
        self.assertEqual(udp_len, 8 + 4)

    @_score("RFC 768", "UDP checksum validates", 2)
    def test_udp_checksum(self):
        p = create_packet(PacketConfig("8.8.8.8", 53, protocol="udp", payload=b"hello"))
        self.assertTrue(_udp_cksum_valid(p))


class TestCPU_RFC792_ICMP(unittest.TestCase):
    """RFC 792 — ICMP Echo Request."""

    @_score("RFC 792", "Type=8 (Echo Request), Code=0")
    def test_echo_type(self):
        p = create_packet(PacketConfig("10.0.0.1", 0, protocol="icmp"))
        ihl = (p[0] & 0xF) * 4
        self.assertEqual(p[ihl], 8)
        self.assertEqual(p[ihl+1], 0)

    @_score("RFC 792", "ICMP checksum validates")
    def test_icmp_checksum(self):
        p = create_packet(PacketConfig("10.0.0.1", 0, protocol="icmp"))
        ihl = (p[0] & 0xF) * 4
        icmp_data = p[ihl:]
        self.assertEqual(_checksum(icmp_data), 0)


class TestCPU_RFC1035_DNS(unittest.TestCase):
    """RFC 1035 — DNS wire format."""

    @_score("RFC 1035", "QDCount == 1")
    def test_qdcount(self):
        q = build_dns_query("example.com")
        self.assertEqual(struct.unpack("!H", q[4:6])[0], 1)

    @_score("RFC 1035", "Label encoding (length-prefixed)")
    def test_label(self):
        q = build_dns_query("test.example.com")
        # Header=12 bytes, then labels
        self.assertEqual(q[12], 4)  # "test" length
        self.assertEqual(q[13:17], b"test")

    @_score("RFC 1035", "Root label terminator (0x00)")
    def test_root_label(self):
        q = build_dns_query("a.b")
        # find 0x00 after labels
        found = False
        for i in range(12, len(q)):
            if q[i] == 0 and i > 12:
                found = True; break
        self.assertTrue(found)


class TestCPU_RFC894_Ethernet(unittest.TestCase):
    """RFC 894 — Ethernet II framing."""

    @_score("RFC 894", "EtherType 0x0800 (IPv4)")
    def test_ethertype(self):
        p = create_packet(PacketConfig("10.0.0.1", 80))
        framed = add_ethernet_frame(p)
        self.assertEqual(struct.unpack("!H", framed[12:14])[0], 0x0800)

    @_score("RFC 894", "Frame length >= 14 + IP packet")
    def test_frame_length(self):
        p = create_packet(PacketConfig("10.0.0.1", 80))
        framed = add_ethernet_frame(p)
        self.assertEqual(len(framed), 14 + len(p))


class TestCPU_RFC1071_Checksum(unittest.TestCase):
    """RFC 1071 — Internet Checksum algorithm."""

    @_score("RFC 1071", "Checksum of all-zeros = 0xFFFF")
    def test_zeros(self):
        self.assertEqual(_checksum(b"\x00\x00\x00\x00"), 0xFFFF)

    @_score("RFC 1071", "Checksum of all-ones = 0x0000")
    def test_ones(self):
        self.assertEqual(_checksum(b"\xFF\xFF\xFF\xFF"), 0x0000)

    @_score("RFC 1071", "Odd-length data handled")
    def test_odd(self):
        r = _checksum(b"\x01\x02\x03")
        self.assertIsInstance(r, int)
        self.assertTrue(0 <= r <= 0xFFFF)

    @_score("RFC 1071", "Checksum of valid header == 0 (verify)")
    def test_verify(self):
        hdr = build_ipv4_header("1.2.3.4", "5.6.7.8", PROTO_TCP, 20)
        self.assertEqual(_checksum(hdr), 0)


# ════════════════════════════════════════════════════════════════════════════
#  GPU ENGINE RFC COMPLIANCE  (skipped if CUDA unavailable)
# ════════════════════════════════════════════════════════════════════════════

@unittest.skipUnless(GPU_AVAILABLE, "CUDA/GPU not available")
class TestGPU_RFC791(unittest.TestCase):
    """RFC 791 compliance for GPU-generated packets."""

    def _gen(self, proto="tcp", count=64, eth=False):
        pmap = {"tcp": 6, "udp": 17, "icmp": 1}
        buf_gpu, pkt_size = gpu_packet.generate_packets(
            count, "10.0.0.1", 80, protocol=proto,
            spoof_ip=False, real_src_ip="192.168.1.100",
            has_ethernet=eth, tcp_flags=0x02)
        buf = cp.asnumpy(buf_gpu)
        return buf, pkt_size

    @_score("RFC 791", "[GPU] Version == 4", 2)
    def test_version(self):
        buf, ps = self._gen()
        for i in range(min(64, len(buf)//ps)):
            self.assertEqual((buf[i*ps] >> 4) & 0xF, 4)

    @_score("RFC 791", "[GPU] IHL == 5")
    def test_ihl(self):
        buf, ps = self._gen()
        self.assertEqual(buf[0] & 0xF, 5)

    @_score("RFC 791", "[GPU] IP checksum valid (sample)", 2)
    def test_ip_checksum(self):
        buf, ps = self._gen(count=100)
        for i in range(min(50, len(buf)//ps)):
            pkt = bytes(buf[i*ps:(i+1)*ps])
            self.assertTrue(_ip_cksum_valid(pkt), f"GPU pkt {i} IP cksum invalid")

    @_score("RFC 791", "[GPU] Total length matches pkt size")
    def test_total_len(self):
        buf, ps = self._gen()
        total = struct.unpack("!H", buf[2:4])[0]
        self.assertEqual(total, ps)

    @_score("RFC 791", "[GPU] TTL > 0")
    def test_ttl(self):
        buf, ps = self._gen()
        self.assertGreater(buf[8], 0)

    @_score("RFC 791", "[GPU] Protocol fields correct")
    def test_proto(self):
        for proto, num in [("tcp", 6), ("udp", 17)]:
            buf, ps = self._gen(proto=proto)
            self.assertEqual(buf[9], num)


@unittest.skipUnless(GPU_AVAILABLE, "CUDA/GPU not available")
class TestGPU_RFC793(unittest.TestCase):
    """RFC 793 TCP compliance for GPU packets."""

    def _gen_tcp(self, count=64):
        buf_gpu, ps = gpu_packet.generate_packets(
            count, "10.0.0.1", 80, protocol="tcp",
            spoof_ip=False, real_src_ip="192.168.1.100",
            has_ethernet=False, tcp_flags=0x02)
        return cp.asnumpy(buf_gpu), ps

    @_score("RFC 793", "[GPU] Dst port == 80")
    def test_dst_port(self):
        buf, ps = self._gen_tcp()
        ihl = (buf[0] & 0xF) * 4
        dp = struct.unpack("!H", buf[ihl+2:ihl+4])[0]
        self.assertEqual(dp, 80)

    @_score("RFC 793", "[GPU] Data offset == 10 (40-byte header)")
    def test_data_offset(self):
        buf, ps = self._gen_tcp()
        ihl = (buf[0] & 0xF) * 4
        doff = (buf[ihl+12] >> 4)
        self.assertEqual(doff, 10)

    @_score("RFC 793", "[GPU] TCP checksum valid (sample)", 2)
    def test_tcp_checksum(self):
        buf, ps = self._gen_tcp(count=100)
        for i in range(min(50, len(buf)//ps)):
            pkt = bytes(buf[i*ps:(i+1)*ps])
            self.assertTrue(_tcp_cksum_valid(pkt), f"GPU TCP cksum invalid pkt {i}")

    @_score("RFC 793", "[GPU] SYN flag set")
    def test_syn_flag(self):
        buf, ps = self._gen_tcp()
        ihl = (buf[0] & 0xF) * 4
        self.assertTrue(buf[ihl+13] & 0x02)

    @_score("RFC 7414", "[GPU] MSS option present (Kind=2)")
    def test_mss_option(self):
        buf, ps = self._gen_tcp()
        ihl = (buf[0] & 0xF) * 4
        opt_off = ihl + 20
        self.assertEqual(buf[opt_off], 2)  # MSS kind
        self.assertEqual(buf[opt_off+1], 4)  # MSS len

    @_score("RFC 7414", "[GPU] Timestamp option present (Kind=8)")
    def test_ts_option(self):
        buf, ps = self._gen_tcp()
        ihl = (buf[0] & 0xF) * 4
        opt_off = ihl + 20
        # MSS(4) + SACK_PERM(2) = 6 bytes, then TS at offset 6
        self.assertEqual(buf[opt_off+6], 8)
        self.assertEqual(buf[opt_off+7], 10)


@unittest.skipUnless(GPU_AVAILABLE, "CUDA/GPU not available")
class TestGPU_RFC768(unittest.TestCase):
    """RFC 768 UDP compliance for GPU packets."""

    @_score("RFC 768", "[GPU] UDP checksum valid (sample)", 2)
    def test_udp_checksum(self):
        buf_gpu, ps = gpu_packet.generate_packets(
            100, "10.0.0.1", 53, protocol="udp",
            spoof_ip=False, real_src_ip="192.168.1.100",
            has_ethernet=False, tcp_flags=0)
        buf = cp.asnumpy(buf_gpu)
        for i in range(min(50, len(buf)//ps)):
            pkt = bytes(buf[i*ps:(i+1)*ps])
            self.assertTrue(_udp_cksum_valid(pkt), f"GPU UDP cksum invalid pkt {i}")

if "pytest" in globals():
    TestGPU_RFC791 = pytest.mark.gpu(TestGPU_RFC791)
    TestGPU_RFC793 = pytest.mark.gpu(TestGPU_RFC793)
    TestGPU_RFC768 = pytest.mark.gpu(TestGPU_RFC768)


class TestAmplificationRFC(unittest.TestCase):
    """Amplification packets RFC checks."""

    @_score("RFC 791", "DNS-AMP: victim IP as source")
    def test_dns_amp_src(self):
        p = create_dns_amp_packet("8.8.8.8", "1.2.3.4")
        self.assertEqual(_ipf(p)["src"], "1.2.3.4")
        self.assertTrue(_ip_cksum_valid(p))

    @_score("RFC 768", "NTP-AMP: dst port 123")
    def test_ntp_port(self):
        p = create_ntp_amp_packet("10.0.0.1", "1.1.1.1")
        ihl = (p[0] & 0xF) * 4
        dp = struct.unpack("!H", p[ihl+2:ihl+4])[0]
        self.assertEqual(dp, 123)
        self.assertTrue(_ip_cksum_valid(p))

    @_score("RFC 768", "SSDP-AMP: dst port 1900 + valid")
    def test_ssdp(self):
        p = create_ssdp_amp_packet("10.0.0.1", "1.1.1.1")
        ihl = (p[0] & 0xF) * 4
        self.assertEqual(struct.unpack("!H", p[ihl+2:ihl+4])[0], 1900)
        self.assertIn(b"M-SEARCH", p)
        self.assertTrue(_ip_cksum_valid(p))

    @_score("RFC 768", "Memcached-AMP: dst port 11211")
    def test_memcached(self):
        p = create_memcached_amp_packet("10.0.0.1", "1.1.1.1")
        ihl = (p[0] & 0xF) * 4
        self.assertEqual(struct.unpack("!H", p[ihl+2:ihl+4])[0], 11211)

    @_score("RFC 768", "LDAP-AMP: dst port 389")
    def test_ldap(self):
        p = create_ldap_amp_packet("10.0.0.1", "1.1.1.1")
        ihl = (p[0] & 0xF) * 4
        self.assertEqual(struct.unpack("!H", p[ihl+2:ihl+4])[0], 389)


# ════════════════════════════════════════════════════════════════════════════
#  FINAL REPORT
# ════════════════════════════════════════════════════════════════════════════

class TestZZ_FinalReport(unittest.TestCase):
    """Must run last (ZZ prefix) — prints the scored report."""

    def test_zzz_print_report(self):
        r = _ScoreBoard.report()
        print("\n")
        print("╔════════════════════════════════════════════════════════════╗")
        print("║        Samurai — RFC Compliance Score Report           ║")
        print("╠════════════════════════════════════════════════════════════╣")
        print(f"║  Score:  {r['score']:6.2f} / 100         Grade: {r['grade']:<4s}              ║")
        print(f"║  Passed: {r['passed']:3d} / {r['total']:3d} weighted checks                    ║")
        print("╠════════════════════════════════════════════════════════════╣")

        by_rfc = {}
        for c in r["checks"]:
            by_rfc.setdefault(c["rfc"], []).append(c)
        for rfc, checks in sorted(by_rfc.items()):
            passed = sum(1 for c in checks if c["passed"])
            total = len(checks)
            icon = "✅" if passed == total else "⚠️ "
            print(f"║  {icon} {rfc:<12s}  {passed}/{total} checks passed"
                  + " " * max(0, 29 - len(rfc)) + "║")
        print("╚════════════════════════════════════════════════════════════╝")

        # Write JSON report without polluting repo state by default.
        # - SAMURAI_RFC_REPORT_OUT may point to a file path.
        # - Default: system temp dir.
        base = str(os.environ.get("SAMURAI_RFC_REPORT_OUT", "") or "").strip()
        if not base:
            path = os.path.join(tempfile.gettempdir(), "rfc_positive_report.json")
        else:
            base_path = os.path.abspath(os.path.expanduser(base))
            if os.path.splitext(base_path)[1]:
                path = base_path
            else:
                path = os.path.join(base_path, "rfc_positive_report.json")
        path = _write_json_with_fallback(path, r, "rfc_positive_report.json")
        print(f"\n  Report saved → {path}")

        self.assertGreaterEqual(r["score"], 95, "RFC compliance score below 95%!")


if __name__ == "__main__":
    _ScoreBoard.reset()
    unittest.main(verbosity=2)
