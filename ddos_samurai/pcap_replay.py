"""
Samurai — PCAP Replay Engine
================================

Reads a PCAP (or PCAP-NG) capture file and replays its packets on the network.

Features
--------
- PCAP v2.4 and basic PCAP-NG (SHB + IDB + EPB/SPB) parsing
- Multiple timing modes:
    * ``original``  — preserve inter-packet gaps from the capture
    * ``topspeed``  — blast as fast as possible (no timing)
    * ``multiplier``— replay at N× original speed  (e.g. 2.0 = 2× faster)
    * ``rps``       — constant packets-per-second rate
- Loop / repeat: replay the file *N* times (0 = infinite until Ctrl-C)
- Per-packet IP rewriting  (destination IP + port override)
- Lightweight BPF-like filter (protocol / src-ip / dst-ip / port)
- L2 (Ethernet) and L3 (raw IP) output depending on sender backend
- Full integration with Samurai pacing engine & live metrics

Usage (programmatic)::

    from ddos_samurai.pcap_replay import PcapReplayConfig, replay_pcap

    cfg = PcapReplayConfig(
        pcap_file="capture.pcap",
        timing_mode="original",
        target_ip_override="10.0.0.1",
        target_port_override=80,
    )
    stats = await replay_pcap(cfg)

CLI::

    python -m ddos_samurai.cli --attack-vector pcap-replay \\
        --pcap-file capture.pcap --pcap-timing original \\
        -t 10.0.0.1 -p 80

Author: Samurai Team
"""

from __future__ import annotations

import asyncio
import ipaddress
import io
import logging
import os
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════
#  Constants
# ════════════════════════════════════════════════════════════════════════════

# PCAP magic numbers
PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D  # nanosecond resolution
PCAP_MAGIC_NS_BE = 0x4DC3B2A1

# PCAP-NG block types
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_IDB = 0x00000001
PCAPNG_EPB = 0x00000006
PCAPNG_SPB = 0x00000003

# Link-layer header types
DLT_NULL = 0
DLT_EN10MB = 1       # Ethernet
DLT_RAW = 101        # Raw IP
DLT_LINUX_SLL = 113  # Linux "cooked" capture

# Protocol numbers
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1

# Ethernet header + EtherType
ETH_HEADER_LEN = 14
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD

# Replay timing controls (hybrid scheduler: sleep then short spin)
TIMING_SPIN_THRESHOLD_S = 0.0002
TIMING_COARSE_SLEEP_MIN_S = 0.0005


# ════════════════════════════════════════════════════════════════════════════
#  Enums / Config
# ════════════════════════════════════════════════════════════════════════════

class TimingMode(IntEnum):
    ORIGINAL   = 0   # preserve inter-packet timing from capture
    TOPSPEED   = 1   # blast as fast as possible
    MULTIPLIER = 2   # replay at N× original speed
    RPS        = 3   # constant rate (packets/second)


TIMING_MODE_MAP = {
    "original":   TimingMode.ORIGINAL,
    "topspeed":   TimingMode.TOPSPEED,
    "multiplier": TimingMode.MULTIPLIER,
    "rps":        TimingMode.RPS,
}


@dataclass
class PcapFilterConfig:
    """Lightweight BPF-like filter for selecting packets from the PCAP."""
    protocols: Optional[List[str]] = None   # ["tcp", "udp", "icmp"]
    src_ip:    Optional[str]       = None   # e.g. "192.168.1.0/24" or "10.0.0.1"
    dst_ip:    Optional[str]       = None
    src_port:  Optional[int]       = None
    dst_port:  Optional[int]       = None
    min_len:   int                 = 0
    max_len:   int                 = 0      # 0 = unlimited


@dataclass
class PcapReplayConfig:
    """All parameters for a single PCAP replay operation."""
    pcap_file:            str
    timing_mode:          str  = "original"   # key into TIMING_MODE_MAP
    speed_multiplier:     float = 1.0         # used with TimingMode.MULTIPLIER
    target_rps:           float = 0.0         # used with TimingMode.RPS
    loops:                int   = 1           # 0 = infinite
    # IP / port rewriting
    target_ip_override:   Optional[str] = None
    target_port_override: Optional[int] = None
    src_ip_override:      Optional[str] = None
    src_port_override:    Optional[int] = None
    # Filtering
    filter_cfg:           PcapFilterConfig = field(default_factory=PcapFilterConfig)
    # Sender integration
    use_l2:               bool = False   # True → prepend Ethernet (for TX_RING / AF_XDP)
    verbose:              bool = False
    # Advanced
    skip_malformed:       bool = True
    strip_ethernet:       bool = False   # strip Ethernet + rewrite to raw IP
    batch_size:           int  = 512
    # Statistics
    max_packets:          int  = 0       # 0 = all
    # Advanced rewrite
    flow_aware_rewrite:   bool = True    # TCP flow-aware seq/ack delta remap


# ════════════════════════════════════════════════════════════════════════════
#  PCAP / PCAP-NG Parser
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class ParsedPacket:
    """A single parsed packet from a capture file."""
    timestamp_s:  float      # seconds (float, µs or ns precision)
    raw_data:     bytes      # captured bytes (up to caplen)
    orig_len:     int        # original on-wire length
    link_type:    int        # DLT_ value


class PcapParseError(Exception):
    """Raised when the PCAP file cannot be parsed."""


def _validate_port(value: Optional[int], field_name: str) -> None:
    if value is None:
        return
    if not (0 <= int(value) <= 65535):
        raise PcapParseError(f"Invalid {field_name}: {value} (expected 0..65535)")


def _validate_ip_or_cidr(value: Optional[str], field_name: str, *, allow_cidr: bool) -> None:
    if value is None:
        return
    text = str(value).strip()
    if not text:
        return
    try:
        if allow_cidr and "/" in text:
            ipaddress.ip_network(text, strict=False)
        else:
            ipaddress.ip_address(text)
    except ValueError as exc:
        raise PcapParseError(f"Invalid {field_name}: {value!r}") from exc


def _validate_replay_config(cfg: PcapReplayConfig) -> None:
    if cfg.timing_mode not in TIMING_MODE_MAP:
        raise PcapParseError(f"Invalid timing_mode: {cfg.timing_mode!r}")
    if int(cfg.batch_size) <= 0:
        raise PcapParseError(f"Invalid batch_size: {cfg.batch_size} (expected > 0)")
    if int(cfg.loops) < 0:
        raise PcapParseError(f"Invalid loops: {cfg.loops} (expected >= 0)")
    if float(cfg.speed_multiplier) <= 0:
        raise PcapParseError(
            f"Invalid speed_multiplier: {cfg.speed_multiplier} (expected > 0)"
        )
    if float(cfg.target_rps) < 0:
        raise PcapParseError(f"Invalid target_rps: {cfg.target_rps} (expected >= 0)")
    if int(cfg.max_packets) < 0:
        raise PcapParseError(f"Invalid max_packets: {cfg.max_packets} (expected >= 0)")
    if bool(cfg.use_l2) and bool(cfg.strip_ethernet):
        raise PcapParseError("Invalid config: use_l2=True cannot be combined with strip_ethernet=True")

    _validate_port(cfg.target_port_override, "target_port_override")
    _validate_port(cfg.src_port_override, "src_port_override")
    _validate_port(cfg.filter_cfg.src_port, "filter_cfg.src_port")
    _validate_port(cfg.filter_cfg.dst_port, "filter_cfg.dst_port")

    _validate_ip_or_cidr(cfg.target_ip_override, "target_ip_override", allow_cidr=False)
    _validate_ip_or_cidr(cfg.src_ip_override, "src_ip_override", allow_cidr=False)
    _validate_ip_or_cidr(cfg.filter_cfg.src_ip, "filter_cfg.src_ip", allow_cidr=True)
    _validate_ip_or_cidr(cfg.filter_cfg.dst_ip, "filter_cfg.dst_ip", allow_cidr=True)

    if cfg.filter_cfg.protocols:
        for proto in cfg.filter_cfg.protocols:
            if str(proto).lower() not in _PROTO_NAME_MAP:
                raise PcapParseError(
                    f"Invalid protocol in filter_cfg.protocols: {proto!r} "
                    f"(expected one of: {', '.join(sorted(_PROTO_NAME_MAP))})"
                )

    if int(cfg.filter_cfg.min_len) < 0:
        raise PcapParseError(
            f"Invalid filter_cfg.min_len: {cfg.filter_cfg.min_len} (expected >= 0)"
        )
    if int(cfg.filter_cfg.max_len) < 0:
        raise PcapParseError(
            f"Invalid filter_cfg.max_len: {cfg.filter_cfg.max_len} (expected >= 0)"
        )
    if int(cfg.filter_cfg.max_len) > 0 and int(cfg.filter_cfg.min_len) > int(cfg.filter_cfg.max_len):
        raise PcapParseError(
            "Invalid length filter: filter_cfg.min_len cannot be greater than filter_cfg.max_len"
        )


def _stream_pcap_classic(
    fp: io.BufferedIOBase,
    on_packet: Callable[[ParsedPacket], Any],
) -> dict:
    """Stream a classic PCAP file and invoke `on_packet` per decoded packet."""
    header = fp.read(24)
    if len(header) < 24:
        raise PcapParseError("PCAP file too short for global header")

    magic = struct.unpack("<I", header[:4])[0]
    if magic == PCAP_MAGIC_LE:
        endian = "<"
        ns_resolution = False
    elif magic == PCAP_MAGIC_BE:
        endian = ">"
        ns_resolution = False
    elif magic == PCAP_MAGIC_NS_LE:
        endian = "<"
        ns_resolution = True
    elif magic == PCAP_MAGIC_NS_BE:
        endian = ">"
        ns_resolution = True
    else:
        raise PcapParseError(f"Unknown PCAP magic: 0x{magic:08X}")

    (ver_major, ver_minor, tz_off, sig_figs,
     snap_len, link_type) = struct.unpack(f"{endian}HHiIII", header[4:24])

    meta = {
        "format": "pcap",
        "version": f"{ver_major}.{ver_minor}",
        "snap_len": snap_len,
        "link_type": link_type,
        "ns_resolution": ns_resolution,
        "endian": endian,
    }

    rec_hdr_fmt = f"{endian}IIII"
    rec_hdr_size = 16
    total_packets = 0

    while True:
        hdr_bytes = fp.read(rec_hdr_size)
        if len(hdr_bytes) == 0:
            break
        if len(hdr_bytes) < rec_hdr_size:
            break  # truncated record at EOF

        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(rec_hdr_fmt, hdr_bytes)

        # Sanity check against crazy lengths
        if incl_len > 262144:  # 256 KB per packet max
            break

        pkt_data = fp.read(incl_len)
        if len(pkt_data) < incl_len:
            break  # truncated

        if ns_resolution:
            ts = float(ts_sec) + float(ts_frac) / 1e9
        else:
            ts = float(ts_sec) + float(ts_frac) / 1e6

        pkt = ParsedPacket(
            timestamp_s=ts,
            raw_data=pkt_data,
            orig_len=orig_len,
            link_type=link_type,
        )
        total_packets += 1
        if on_packet(pkt) is False:
            break

    meta["total_packets"] = int(total_packets)
    return meta


def _read_pcapng_block(fp: io.BufferedIOBase, endian: str) -> Optional[Tuple[int, bytes]]:
    """Read a single PCAP-NG block. Returns (block_type, block_body) or None."""
    hdr = fp.read(8)
    if len(hdr) < 8:
        return None
    btype, blen = struct.unpack(f"{endian}II", hdr)
    if blen < 12:
        raise PcapParseError(f"Invalid PCAP-NG block length: {blen} (< 12)")
    if (blen % 4) != 0:
        raise PcapParseError(f"Invalid PCAP-NG block length alignment: {blen} (must be multiple of 4)")

    body_len = blen - 12  # btype(4) + blen(4) + trailing_blen(4)
    body = fp.read(body_len)
    if len(body) < body_len:
        raise PcapParseError("Truncated PCAP-NG block body")

    trail = fp.read(4)  # trailing block length
    if len(trail) < 4:
        raise PcapParseError("Truncated PCAP-NG trailing block length")
    trailing_blen = struct.unpack(f"{endian}I", trail)[0]
    if trailing_blen != blen:
        raise PcapParseError(
            f"PCAP-NG trailing block length mismatch: header={blen}, trailing={trailing_blen}"
        )
    return (btype, body)


def _stream_pcapng(
    fp: io.BufferedIOBase,
    on_packet: Callable[[ParsedPacket], Any],
) -> dict:
    """Stream a PCAP-NG file and invoke `on_packet` per decoded packet."""
    # Read SHB to determine endianness
    shb_header = fp.read(12)
    if len(shb_header) < 12:
        raise PcapParseError("PCAP-NG file too short for SHB")

    btype = struct.unpack("<I", shb_header[:4])[0]
    if btype != PCAPNG_SHB:
        raise PcapParseError(f"Expected SHB block, got 0x{btype:08X}")

    blen = struct.unpack("<I", shb_header[4:8])[0]
    if blen < 28:
        raise PcapParseError(f"Invalid SHB length: {blen} (< 28)")
    if (blen % 4) != 0:
        raise PcapParseError(f"Invalid SHB length alignment: {blen} (must be multiple of 4)")
    byte_order_magic = struct.unpack("<I", shb_header[8:12])[0]

    if byte_order_magic == 0x1A2B3C4D:
        endian = "<"
    elif byte_order_magic == 0x4D3C2B1A:
        endian = ">"
    else:
        raise PcapParseError(f"Unknown PCAP-NG byte order magic: 0x{byte_order_magic:08X}")

    # Read rest of SHB. We already consumed 12 bytes:
    # block type(4) + block len(4) + byte-order-magic(4).
    remaining_body_len = blen - 16
    remaining_body = fp.read(remaining_body_len)
    if len(remaining_body) < remaining_body_len:
        raise PcapParseError("Truncated SHB body")
    trailing = fp.read(4)
    if len(trailing) < 4:
        raise PcapParseError("Truncated SHB trailing block length")
    trailing_len = struct.unpack(f"{endian}I", trailing)[0]
    if trailing_len != blen:
        raise PcapParseError(
            f"SHB trailing block length mismatch: header={blen}, trailing={trailing_len}"
        )

    meta = {
        "format": "pcapng",
        "endian": endian,
        "link_types": {},
    }
    iface_link_types: Dict[int, int] = {}
    # interface → (base, exponent), e.g. (10, 6) == microseconds
    iface_ts_resol: Dict[int, Tuple[int, int]] = {}
    iface_idx = 0

    total_packets = 0

    while True:
        result = _read_pcapng_block(fp, endian)
        if result is None:
            break
        btype, body = result

        if btype == PCAPNG_IDB:
            # Interface Description Block
            if len(body) < 8:
                continue
            lt, snap = struct.unpack(f"{endian}HxxI", body[:8])
            iface_link_types[iface_idx] = lt
            iface_ts_resol[iface_idx] = (10, 6)  # default: microseconds
            # Parse options for ts_resol
            opts = body[8:]
            pos = 0
            while pos + 4 <= len(opts):
                opt_code, opt_len = struct.unpack(f"{endian}HH", opts[pos:pos+4])
                pos += 4
                if opt_code == 0:
                    break
                if pos + opt_len > len(opts):
                    break
                opt_data = opts[pos:pos+opt_len]
                padded = (opt_len + 3) & ~3
                pos += padded
                if opt_code == 9 and opt_len == 1:  # if_tsresol
                    resol_byte = opt_data[0]
                    if resol_byte & 0x80:
                        iface_ts_resol[iface_idx] = (2, resol_byte & 0x7F)
                    else:
                        iface_ts_resol[iface_idx] = (10, resol_byte)
            iface_idx += 1

        elif btype == PCAPNG_EPB:
            # Enhanced Packet Block
            if len(body) < 20:
                continue
            iface_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(
                f"{endian}IIIII", body[:20]
            )
            pkt_data = body[20:20+cap_len]
            if len(pkt_data) < cap_len:
                continue

            # Calculate timestamp
            ts_raw = (ts_hi << 32) | ts_lo
            base, exponent = iface_ts_resol.get(iface_id, (10, 6))
            ts = ts_raw / float(base ** exponent)

            lt = iface_link_types.get(iface_id, DLT_EN10MB)
            pkt = ParsedPacket(
                timestamp_s=ts,
                raw_data=pkt_data,
                orig_len=orig_len,
                link_type=lt,
            )
            total_packets += 1
            if on_packet(pkt) is False:
                break

        elif btype == PCAPNG_SPB:
            # Simple Packet Block
            if len(body) < 4:
                continue
            orig_len = struct.unpack(f"{endian}I", body[:4])[0]
            pkt_data = body[4:]
            lt = iface_link_types.get(0, DLT_EN10MB)
            pkt = ParsedPacket(
                timestamp_s=0.0,
                raw_data=pkt_data,
                orig_len=orig_len,
                link_type=lt,
            )
            total_packets += 1
            if on_packet(pkt) is False:
                break

    meta["link_types"] = iface_link_types
    meta["total_packets"] = int(total_packets)
    return meta


def _stream_parse_pcap_file(
    file_path: str,
    on_packet: Callable[[ParsedPacket], Any],
) -> dict:
    """
    Stream parse a PCAP/PCAP-NG file.

    `on_packet` is called for each decoded packet; if it returns False, parsing stops.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    file_size = os.path.getsize(file_path)
    if file_size < 24:
        raise PcapParseError(f"File too small to be a valid PCAP: {file_size} bytes")

    with open(file_path, "rb") as fp:
        magic_bytes = fp.read(4)
        fp.seek(0)
        magic = struct.unpack("<I", magic_bytes)[0]

        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE):
            meta = _stream_pcap_classic(fp, on_packet)
        elif magic == PCAPNG_SHB:
            meta = _stream_pcapng(fp, on_packet)
        else:
            magic_be = struct.unpack(">I", magic_bytes)[0]
            if magic_be == PCAPNG_SHB:
                meta = _stream_pcapng(fp, on_packet)
            else:
                raise PcapParseError(
                    f"Unrecognized file format (magic: 0x{magic:08X})"
                )

    meta["file_path"] = file_path
    meta["file_size"] = file_size
    return meta


def _parse_pcap_classic(fp: io.BufferedIOBase) -> Tuple[List[ParsedPacket], dict]:
    """Parse a classic PCAP file (libpcap v2.4 format)."""
    packets: List[ParsedPacket] = []
    meta = _stream_pcap_classic(fp, packets.append)
    return packets, meta


def _parse_pcapng(fp: io.BufferedIOBase) -> Tuple[List[ParsedPacket], dict]:
    """Parse a PCAP-NG file (basic SHB + IDB + EPB/SPB support)."""
    packets: List[ParsedPacket] = []
    meta = _stream_pcapng(fp, packets.append)
    return packets, meta


def parse_pcap_file(file_path: str) -> Tuple[List[ParsedPacket], dict]:
    """
    Parse a PCAP or PCAP-NG file.

    Returns:
        (packets, metadata) — list of ParsedPacket and format metadata dict
    """
    packets: List[ParsedPacket] = []
    meta = _stream_parse_pcap_file(file_path, packets.append)
    meta["total_packets"] = len(packets)
    return packets, meta


# ════════════════════════════════════════════════════════════════════════════
#  Packet Processing  (filtering, IP extraction, rewriting)
# ════════════════════════════════════════════════════════════════════════════

def _ip_to_int(ip_str: str) -> int:
    """Convert dotted-quad IPv4 to 32-bit integer."""
    parts = ip_str.split(".")
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])


def _int_to_ip(val: int) -> str:
    """Convert 32-bit integer to dotted-quad IPv4."""
    return f"{(val >> 24) & 0xFF}.{(val >> 16) & 0xFF}.{(val >> 8) & 0xFF}.{val & 0xFF}"


def _ip_in_cidr(ip_str: str, cidr: str) -> bool:
    """Check if an IP is within a CIDR range."""
    ip_obj = ipaddress.ip_address(ip_str)
    if "/" not in cidr:
        return ip_obj == ipaddress.ip_address(cidr)
    return ip_obj in ipaddress.ip_network(cidr, strict=False)


def _extract_ip_offset(pkt: ParsedPacket) -> int:
    """Return the byte offset of the IPv4 header within pkt.raw_data."""
    lt = pkt.link_type
    if lt == DLT_EN10MB:
        # Check for 802.1Q VLAN tag
        if len(pkt.raw_data) >= 16:
            ethertype = struct.unpack("!H", pkt.raw_data[12:14])[0]
            if ethertype == 0x8100:  # VLAN tagged
                return 18
        return 14
    elif lt == DLT_RAW:
        return 0
    elif lt == DLT_NULL:
        return 4
    elif lt == DLT_LINUX_SLL:
        return 16
    return 14  # default: treat as Ethernet


def _get_ip_info(pkt: ParsedPacket) -> Optional[Dict[str, Any]]:
    """Extract basic IP header fields from a parsed packet."""
    ip_off = _extract_ip_offset(pkt)
    data = pkt.raw_data

    if len(data) < ip_off + 20:
        return None

    version_ihl = data[ip_off]
    version = (version_ihl >> 4) & 0xF
    if version != 4:
        return None  # We only handle IPv4 for now

    ihl = (version_ihl & 0xF) * 4
    total_len = struct.unpack("!H", data[ip_off+2:ip_off+4])[0]
    protocol = data[ip_off + 9]
    src_ip_int = struct.unpack("!I", data[ip_off+12:ip_off+16])[0]
    dst_ip_int = struct.unpack("!I", data[ip_off+16:ip_off+20])[0]

    info: Dict[str, Any] = {
        "ip_offset": ip_off,
        "ihl": ihl,
        "total_len": total_len,
        "protocol": protocol,
        "src_ip": _int_to_ip(src_ip_int),
        "dst_ip": _int_to_ip(dst_ip_int),
        "src_ip_int": src_ip_int,
        "dst_ip_int": dst_ip_int,
    }

    # Extract ports for TCP/UDP
    l4_off = ip_off + ihl
    if protocol in (PROTO_TCP, PROTO_UDP) and len(data) >= l4_off + 4:
        src_port, dst_port = struct.unpack("!HH", data[l4_off:l4_off+4])
        info["src_port"] = src_port
        info["dst_port"] = dst_port
    else:
        info["src_port"] = 0
        info["dst_port"] = 0

    return info


_PROTO_NAME_MAP = {"tcp": PROTO_TCP, "udp": PROTO_UDP, "icmp": PROTO_ICMP}


def _apply_filter(pkt: ParsedPacket, info: Optional[Dict], cfg: PcapFilterConfig) -> bool:
    """Return True if the packet passes the filter."""
    if info is None:
        return False  # non-IPv4 packets are dropped when filter is active

    # Protocol filter
    if cfg.protocols:
        allowed = set()
        for p in cfg.protocols:
            pnum = _PROTO_NAME_MAP.get(p.lower())
            if pnum is not None:
                allowed.add(pnum)
        if info["protocol"] not in allowed:
            return False

    # IP filters
    if cfg.src_ip and not _ip_in_cidr(info["src_ip"], cfg.src_ip):
        return False
    if cfg.dst_ip and not _ip_in_cidr(info["dst_ip"], cfg.dst_ip):
        return False

    # Port filters
    if cfg.src_port and info.get("src_port", 0) != cfg.src_port:
        return False
    if cfg.dst_port and info.get("dst_port", 0) != cfg.dst_port:
        return False

    # Length filters
    pkt_len = len(pkt.raw_data)
    if cfg.min_len > 0 and pkt_len < cfg.min_len:
        return False
    if cfg.max_len > 0 and pkt_len > cfg.max_len:
        return False

    return True


def _ones_complement_sum(data: bytes, start: int, length: int) -> int:
    """Calculate one's complement sum for checksum recalculation."""
    s = 0
    end = start + length
    i = start
    while i < end - 1:
        s += (data[i] << 8) | data[i + 1]
        i += 2
    if i < end:
        s += data[i] << 8
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def _stable_tcp_seq_delta(flow_key: Tuple[str, int, str, int]) -> int:
    """
    Deterministic non-zero 32-bit delta from a 4-tuple direction key.
    """
    src_ip, src_port, dst_ip, dst_port = flow_key
    a = _ip_to_int(src_ip)
    b = _ip_to_int(dst_ip)
    mixed = (
        ((a * 2654435761) ^ (b * 2246822519) ^ (int(src_port) << 16) ^ int(dst_port))
        & 0xFFFFFFFF
    )
    if mixed == 0:
        mixed = 0x10001
    return mixed


def _apply_flow_aware_tcp_rewrite(
    raw: bytearray,
    ip_off: int,
    info: Dict[str, Any],
    dst_ip_override: Optional[str],
    dst_port_override: Optional[int],
    src_ip_override: Optional[str],
    src_port_override: Optional[int],
    flow_state: Dict[str, Any],
) -> None:
    if info.get("protocol") != PROTO_TCP:
        return

    ihl = int(info.get("ihl", 0) or 0)
    l4_off = ip_off + ihl
    if ihl < 20 or len(raw) < l4_off + 20:
        return

    orig_key = (
        str(info.get("src_ip", "")),
        int(info.get("src_port", 0) or 0),
        str(info.get("dst_ip", "")),
        int(info.get("dst_port", 0) or 0),
    )
    new_key = (
        str(src_ip_override or info.get("src_ip", "")),
        int(src_port_override if src_port_override is not None else int(info.get("src_port", 0) or 0)),
        str(dst_ip_override or info.get("dst_ip", "")),
        int(dst_port_override if dst_port_override is not None else int(info.get("dst_port", 0) or 0)),
    )

    owner_map = flow_state.setdefault("new_key_owner", {})
    seq_delta_map = flow_state.setdefault("seq_delta_by_orig", {})
    collision_keys = flow_state.setdefault("collision_keys", set())
    owner = owner_map.get(new_key)
    if owner is None:
        owner_map[new_key] = orig_key
    elif owner != orig_key:
        collision_sig = (owner, orig_key, new_key)
        if collision_sig not in collision_keys:
            collision_keys.add(collision_sig)
            flow_state["flow_collision_count"] = int(flow_state.get("flow_collision_count", 0) or 0) + 1

    if orig_key not in seq_delta_map:
        seq_delta_map[orig_key] = 0 if owner_map.get(new_key) == orig_key and owner is None else _stable_tcp_seq_delta(orig_key)

    seq_delta = int(seq_delta_map.get(orig_key, 0) or 0)
    if seq_delta:
        seq = struct.unpack("!I", raw[l4_off + 4:l4_off + 8])[0]
        struct.pack_into("!I", raw, l4_off + 4, (seq + seq_delta) & 0xFFFFFFFF)
        flow_state["tcp_seq_adjusted"] = int(flow_state.get("tcp_seq_adjusted", 0) or 0) + 1

    flags = int(raw[l4_off + 13])
    ack_is_set = bool(flags & 0x10)
    if ack_is_set:
        ack = struct.unpack("!I", raw[l4_off + 8:l4_off + 12])[0]
        reverse_orig = (orig_key[2], orig_key[3], orig_key[0], orig_key[1])
        reverse_delta = int(seq_delta_map.get(reverse_orig, 0) or 0)
        if ack and reverse_delta:
            struct.pack_into("!I", raw, l4_off + 8, (ack + reverse_delta) & 0xFFFFFFFF)
            flow_state["tcp_ack_adjusted"] = int(flow_state.get("tcp_ack_adjusted", 0) or 0) + 1


def _rewrite_packet(
    raw: bytearray,
    ip_off: int,
    info: Dict[str, Any],
    dst_ip_override: Optional[str],
    dst_port_override: Optional[int],
    src_ip_override: Optional[str],
    src_port_override: Optional[int],
    flow_state: Optional[Dict[str, Any]] = None,
) -> bytearray:
    """Rewrite IP addresses and/or ports in a packet, then fix checksums."""
    ihl = int(info["ihl"])
    protocol = info["protocol"]
    if ihl < 20:
        raise ValueError(f"Malformed IPv4 IHL: {ihl}")
    if ip_off < 0 or ip_off + ihl > len(raw):
        raise ValueError(
            f"Malformed IPv4 offset/length: ip_off={ip_off}, ihl={ihl}, raw_len={len(raw)}"
        )

    # Rewrite destination IP
    if dst_ip_override:
        new_dst = _ip_to_int(dst_ip_override)
        struct.pack_into("!I", raw, ip_off + 16, new_dst)

    # Rewrite source IP
    if src_ip_override:
        new_src = _ip_to_int(src_ip_override)
        struct.pack_into("!I", raw, ip_off + 12, new_src)

    # Rewrite ports
    l4_off = ip_off + ihl
    if protocol in (PROTO_TCP, PROTO_UDP) and len(raw) >= l4_off + 4:
        if src_port_override is not None:
            struct.pack_into("!H", raw, l4_off, src_port_override)
        if dst_port_override is not None:
            struct.pack_into("!H", raw, l4_off + 2, dst_port_override)

    if flow_state is not None and protocol == PROTO_TCP:
        _apply_flow_aware_tcp_rewrite(
            raw=raw,
            ip_off=ip_off,
            info=info,
            dst_ip_override=dst_ip_override,
            dst_port_override=dst_port_override,
            src_ip_override=src_ip_override,
            src_port_override=src_port_override,
            flow_state=flow_state,
        )

    # Recalculate IP header checksum
    struct.pack_into("!H", raw, ip_off + 10, 0)  # zero out checksum field
    ip_hdr_sum = _ones_complement_sum(bytes(raw), ip_off, ihl)
    struct.pack_into("!H", raw, ip_off + 10, (~ip_hdr_sum) & 0xFFFF)

    # Recalculate L4 checksum
    total_len = struct.unpack("!H", raw[ip_off+2:ip_off+4])[0]
    if total_len < ihl:
        raise ValueError(f"Malformed IPv4 total_len={total_len} < ihl={ihl}")
    if ip_off + total_len > len(raw):
        raise ValueError(
            f"Malformed IPv4 total_len exceeds packet bytes: total_len={total_len}, raw_len={len(raw)-ip_off}"
        )
    l4_len = total_len - ihl

    if protocol == PROTO_TCP and len(raw) >= l4_off + 20 and l4_len > 0:
        # Zero TCP checksum
        struct.pack_into("!H", raw, l4_off + 16, 0)
        # Pseudo-header
        pseudo = struct.pack(
            "!4s4sBBH",
            raw[ip_off+12:ip_off+16],  # src IP
            raw[ip_off+16:ip_off+20],  # dst IP
            0, protocol, l4_len
        )
        pseudo_sum = _ones_complement_sum(pseudo, 0, len(pseudo))
        tcp_sum = _ones_complement_sum(bytes(raw), l4_off, l4_len)
        total = pseudo_sum + tcp_sum
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        struct.pack_into("!H", raw, l4_off + 16, (~total) & 0xFFFF)

    elif protocol == PROTO_UDP and len(raw) >= l4_off + 8 and l4_len > 0:
        # Zero UDP checksum
        struct.pack_into("!H", raw, l4_off + 6, 0)
        pseudo = struct.pack(
            "!4s4sBBH",
            raw[ip_off+12:ip_off+16],
            raw[ip_off+16:ip_off+20],
            0, protocol, l4_len
        )
        pseudo_sum = _ones_complement_sum(pseudo, 0, len(pseudo))
        udp_sum = _ones_complement_sum(bytes(raw), l4_off, l4_len)
        total = pseudo_sum + udp_sum
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        cksum = (~total) & 0xFFFF
        if cksum == 0:
            cksum = 0xFFFF  # UDP zero checksum → 0xFFFF
        struct.pack_into("!H", raw, l4_off + 6, cksum)

    return raw


# ════════════════════════════════════════════════════════════════════════════
#  Replay Preparation (build flat buffer for sender)
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class PreparedReplay:
    """Result of preparing packets for replay."""
    packets_buffer: bytes         # flat contiguous buffer (uniform packet size)
    packet_size:    int           # uniform size (each packet is padded/truncated)
    count:          int           # number of packets
    timestamps:     List[float]   # per-packet timestamp (for timing)
    meta:           dict          # parsed file metadata
    stats:          dict          # prep-phase statistics


def prepare_replay(
    cfg: PcapReplayConfig,
) -> PreparedReplay:
    """
    Parse and prepare packets for replay.

    1. Parse PCAP file
    2. Filter packets
    3. Rewrite IPs / ports
    4. Normalize to uniform packet size → flat buffer
    5. Return timing info for replay scheduling
    """
    _validate_replay_config(cfg)

    # ── Filtering ───────────────────────────────────────────────
    has_filter = (
        cfg.filter_cfg.protocols or cfg.filter_cfg.src_ip or
        cfg.filter_cfg.dst_ip or cfg.filter_cfg.src_port or
        cfg.filter_cfg.dst_port or cfg.filter_cfg.min_len > 0 or
        cfg.filter_cfg.max_len > 0
    )

    # ── IP Rewriting & Strip Ethernet ───────────────────────────
    needs_rewrite = (
        cfg.target_ip_override or cfg.target_port_override or
        cfg.src_ip_override or cfg.src_port_override
    )
    flow_state: Optional[Dict[str, Any]] = None
    if bool(needs_rewrite) and bool(getattr(cfg, "flow_aware_rewrite", True)):
        flow_state = {
            "new_key_owner": {},
            "seq_delta_by_orig": {},
            "collision_keys": set(),
            "flow_collision_count": 0,
            "tcp_seq_adjusted": 0,
            "tcp_ack_adjusted": 0,
        }

    skipped = 0
    malformed_errors = 0
    malformed_skipped = 0
    selected_count = 0
    total_in_file = 0
    max_size = 0
    uniform_size = 0
    prepared_count = 0
    timestamps: List[float] = []

    base_capacity = max(1, int(cfg.batch_size))
    if int(cfg.max_packets) > 0:
        capacity_packets = min(int(cfg.max_packets), max(1024, base_capacity))
    else:
        capacity_packets = max(1024, base_capacity)
    buf = bytearray()

    def _grow_capacity(min_packets: int) -> None:
        nonlocal buf, capacity_packets
        if uniform_size <= 0:
            return
        target = max(int(min_packets), int(capacity_packets) * 2, 1)
        if int(cfg.max_packets) > 0:
            target = min(target, int(cfg.max_packets))
        if target <= capacity_packets:
            return
        new_buf = bytearray(target * uniform_size)
        if prepared_count > 0:
            used = prepared_count * uniform_size
            new_buf[:used] = buf[:used]
        buf = new_buf
        capacity_packets = target

    def _on_packet(pkt: ParsedPacket) -> bool:
        nonlocal total_in_file, skipped, malformed_errors, malformed_skipped
        nonlocal selected_count, uniform_size, prepared_count, max_size, buf, capacity_packets
        total_in_file += 1

        # Preserve old max_packets semantics: selection stops after N filter-passing packets.
        if int(cfg.max_packets) > 0 and selected_count >= int(cfg.max_packets):
            return True

        try:
            ip_info = _get_ip_info(pkt)
        except (IndexError, struct.error, ValueError) as exc:
            malformed_errors += 1
            if cfg.skip_malformed:
                malformed_skipped += 1
                return True
            raise PcapParseError(f"Malformed packet while extracting IP info: {exc}") from exc

        if has_filter:
            try:
                keep = _apply_filter(pkt, ip_info, cfg.filter_cfg)
            except ValueError as exc:
                raise PcapParseError(f"Invalid filter configuration: {exc}") from exc
            if not keep:
                skipped += 1
                return True

        selected_count += 1

        try:
            raw = bytearray(pkt.raw_data)

            if cfg.strip_ethernet and pkt.link_type == DLT_EN10MB and len(raw) > ETH_HEADER_LEN:
                ethertype = struct.unpack("!H", raw[12:14])[0]
                if ethertype == 0x8100 and len(raw) > 18:
                    raw = raw[18:]
                else:
                    raw = raw[ETH_HEADER_LEN:]
                if ip_info:
                    ip_info = dict(ip_info)
                    ip_info["ip_offset"] = 0

            if needs_rewrite and ip_info:
                ip_off = ip_info.get("ip_offset", 0)
                if cfg.strip_ethernet:
                    ip_off = 0
                raw = _rewrite_packet(
                    raw,
                    ip_off,
                    ip_info,
                    cfg.target_ip_override,
                    cfg.target_port_override,
                    cfg.src_ip_override,
                    cfg.src_port_override,
                    flow_state=flow_state,
                )
        except (IndexError, struct.error, ValueError) as exc:
            malformed_errors += 1
            if cfg.skip_malformed:
                malformed_skipped += 1
                return True
            raise PcapParseError(f"Malformed packet during rewrite/strip: {exc}") from exc

        data_len = len(raw)
        if data_len > max_size:
            max_size = data_len

        needed_size = (data_len + 3) & ~3
        if uniform_size == 0:
            uniform_size = needed_size
            cap = max(1, capacity_packets)
            buf = bytearray(uniform_size * cap)
            capacity_packets = cap
        elif needed_size > uniform_size:
            old_uniform = uniform_size
            new_uniform = max(needed_size, (uniform_size * 3) // 2)
            new_uniform = (new_uniform + 3) & ~3
            new_buf = bytearray(new_uniform * max(1, capacity_packets))
            for i in range(prepared_count):
                old_off = i * old_uniform
                new_off = i * new_uniform
                new_buf[new_off:new_off + old_uniform] = buf[old_off:old_off + old_uniform]
            buf = new_buf
            uniform_size = new_uniform

        if prepared_count >= capacity_packets:
            _grow_capacity(prepared_count + 1)

        write_off = prepared_count * uniform_size
        buf[write_off:write_off + data_len] = raw
        prepared_count += 1
        timestamps.append(pkt.timestamp_s)
        return True

    meta = _stream_parse_pcap_file(cfg.pcap_file, _on_packet)
    if total_in_file <= 0:
        raise PcapParseError(f"No packets found in {cfg.pcap_file}")

    if prepared_count <= 0:
        if selected_count <= 0:
            raise PcapParseError(
                f"No packets remaining after filtering (total={total_in_file}, skipped={skipped})"
            )
        raise PcapParseError(
            "No packets remained after malformed-packet handling "
            f"(malformed_errors={malformed_errors}, malformed_skipped={malformed_skipped})"
        )

    if len(buf) != (uniform_size * prepared_count):
        buf = buf[: uniform_size * prepared_count]

    prep_stats = {
        "total_in_file": int(meta.get("total_packets", total_in_file)),
        "filtered_out": skipped,
        "prepared_count": prepared_count,
        "uniform_packet_size": uniform_size,
        "max_raw_size": max_size,
        "buffer_size_bytes": len(buf),
        "has_rewrite": bool(needs_rewrite),
        "duration_capture_s": (timestamps[-1] - timestamps[0]) if len(timestamps) > 1 else 0.0,
        "malformed_errors": malformed_errors,
        "malformed_skipped": malformed_skipped,
        "flow_aware_rewrite": int(bool(flow_state is not None)),
        "flow_rewrite_direction_count": int(len((flow_state or {}).get("seq_delta_by_orig", {}))),
        "flow_collision_count": int((flow_state or {}).get("flow_collision_count", 0) or 0),
        "tcp_seq_adjusted": int((flow_state or {}).get("tcp_seq_adjusted", 0) or 0),
        "tcp_ack_adjusted": int((flow_state or {}).get("tcp_ack_adjusted", 0) or 0),
    }

    return PreparedReplay(
        packets_buffer=bytes(buf),
        packet_size=uniform_size,
        count=prepared_count,
        timestamps=timestamps,
        meta=meta,
        stats=prep_stats,
    )


# ════════════════════════════════════════════════════════════════════════════
#  Replay Execution
# ════════════════════════════════════════════════════════════════════════════

def _compute_delays(
    timestamps: List[float],
    mode: TimingMode,
    multiplier: float = 1.0,
    target_rps: float = 0.0,
) -> List[float]:
    """
    Compute per-packet delay (in seconds) from timestamps and timing mode.

    Returns a list of delays (delay[0] is always 0 for the first packet).
    """
    n = len(timestamps)
    if n == 0:
        return []

    delays = [0.0] * n

    if mode == TimingMode.TOPSPEED:
        return delays  # all zeros

    if mode == TimingMode.RPS and target_rps > 0:
        gap = 1.0 / target_rps
        for i in range(1, n):
            delays[i] = gap
        return delays

    if mode in (TimingMode.ORIGINAL, TimingMode.MULTIPLIER):
        speed = max(multiplier, 0.001) if mode == TimingMode.MULTIPLIER else 1.0
        for i in range(1, n):
            original_gap = max(0.0, timestamps[i] - timestamps[i - 1])
            delays[i] = original_gap / speed
        return delays

    return delays  # fallback: no delay


def _compute_schedule_offsets(delays: List[float]) -> List[float]:
    """Convert per-packet inter-arrival delays into absolute offsets."""
    offsets = [0.0] * len(delays)
    running = 0.0
    for i, d in enumerate(delays):
        running += max(0.0, float(d))
        offsets[i] = running
    return offsets


def _open_raw_socket():
    """Open a raw socket configured for user-supplied IPv4 headers."""
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return s


async def _wait_until(target_time: float) -> float:
    """
    Wait until target monotonic time using a hybrid sleep/spin strategy.
    Returns positive lateness in milliseconds.

    Strategy:
    - Large gaps (>0.5ms): asyncio.sleep
    - Medium gaps (>0.2ms): yield to event loop, then short sleep
    - Tiny gaps (<0.2ms): spin but yield every 64 iterations to avoid starving
    """
    _SPIN_YIELD_INTERVAL = 64  # yield back every N spins

    while True:
        now = time.monotonic()
        remaining = target_time - now
        if remaining <= 0.0:
            return max(0.0, (now - target_time) * 1000.0)

        if remaining > TIMING_SPIN_THRESHOLD_S:
            sleep_for = max(0.0, remaining - TIMING_SPIN_THRESHOLD_S)
            if sleep_for >= TIMING_COARSE_SLEEP_MIN_S:
                await asyncio.sleep(sleep_for)
                continue
            # Small remaining but above spin threshold: yield once
            await asyncio.sleep(0)
            continue

        # Below spin threshold: tight loop with periodic yields
        spin_count = 0
        while True:
            now = time.monotonic()
            if now >= target_time:
                return max(0.0, (now - target_time) * 1000.0)
            spin_count += 1
            if spin_count % _SPIN_YIELD_INTERVAL == 0:
                await asyncio.sleep(0)


async def replay_pcap(
    cfg: PcapReplayConfig,
    *,
    live_sent=None,
    live_errors=None,
    live_progress=None,
    pacing_config=None,
) -> Dict[str, Any]:
    """
    Main PCAP replay entry point.

    Parses the PCAP file, prepares packets, and sends them using the
    Samurai sender infrastructure.

    Returns:
        Statistics dictionary with attempted, sent, errors, etc.
    """
    raise RuntimeError(
        "pcap replay legacy sender path kaldırıldı (M6). "
        "ZMQ worker execution backend kullanın."
    )
    from .utils import log_info, log_error, log_warning

    _validate_replay_config(cfg)
    timing_mode = TIMING_MODE_MAP.get(cfg.timing_mode, TimingMode.ORIGINAL)
    if cfg.use_l2:
        log_info("[PCAP Replay] use_l2=True: replay will use L2 sender path (TX_RING).")

    log_info(f"[PCAP Replay] Parsing: {cfg.pcap_file}")
    prep = prepare_replay(cfg)
    log_info(
        f"[PCAP Replay] Loaded {prep.count} packets "
        f"(file total: {prep.stats['total_in_file']}, "
        f"filtered: {prep.stats['filtered_out']}, "
        f"size: {prep.packet_size} B/pkt, "
        f"capture duration: {prep.stats['duration_capture_s']:.3f}s)"
    )

    # Compute delays
    delays = _compute_delays(
        prep.timestamps,
        timing_mode,
        multiplier=cfg.speed_multiplier,
        target_rps=cfg.target_rps,
    )

    stats: Dict[str, Any] = {
        "attempted": 0,
        "sent": 0,
        "errors": 0,
        "bytes_sent_est": 0,
        "loops_completed": 0,
        "timing_mode": cfg.timing_mode,
        "pcap_file": cfg.pcap_file,
        "packets_in_file": prep.stats["total_in_file"],
        "packets_prepared": prep.count,
        "malformed_skipped": int(prep.stats.get("malformed_skipped", 0) or 0),
        "malformed_errors": int(prep.stats.get("malformed_errors", 0) or 0),
        "timing_drift_ms_avg": 0.0,
        "timing_drift_ms_max": 0.0,
        "socket_open_count": 0,
        "use_l2": int(bool(cfg.use_l2)),
        "prep_stats": prep.stats,
    }

    loop_count = cfg.loops if cfg.loops > 0 else 999_999_999  # quasi-infinite
    schedule_offsets = _compute_schedule_offsets(delays)
    drift_total_ms = 0.0
    drift_samples = 0
    drift_max_ms = 0.0
    t0 = time.monotonic()
    stop_replay = False

    try:
        for loop_idx in range(loop_count):
            if stop_replay:
                break
            log_info(f"[PCAP Replay] Loop {loop_idx + 1}/{cfg.loops if cfg.loops > 0 else '∞'}")

            if timing_mode == TimingMode.TOPSPEED:
                # ── BLAST MODE: send entire buffer at once via raw socket ──
                result = await senders.paced_raw_socket_sender(
                    packets_buffer=prep.packets_buffer,
                    target_ip=cfg.target_ip_override or "0.0.0.0",
                    target_port=cfg.target_port_override or 0,
                    count=prep.count,
                    verbose=cfg.verbose,
                    pacing_config=pacing_config,
                    force_l2=bool(cfg.use_l2),
                    live_sent=live_sent,
                    live_errors=live_errors,
                    live_progress=live_progress,
                )
                stats["attempted"] += int(result.get("attempted", 0) or 0)
                stats["sent"] += int(result.get("sent", 0) or 0)
                stats["errors"] += int(result.get("errors", 0) or 0)
                stats["bytes_sent_est"] += int(result.get("bytes_sent_est", 0) or 0)

            elif timing_mode == TimingMode.RPS and pacing_config is not None:
                # ── RPS via pacing engine: send in batches ──
                result = await senders.paced_raw_socket_sender(
                    packets_buffer=prep.packets_buffer,
                    target_ip=cfg.target_ip_override or "0.0.0.0",
                    target_port=cfg.target_port_override or 0,
                    count=prep.count,
                    verbose=cfg.verbose,
                    pacing_config=pacing_config,
                    force_l2=bool(cfg.use_l2),
                    live_sent=live_sent,
                    live_errors=live_errors,
                    live_progress=live_progress,
                )
                stats["attempted"] += int(result.get("attempted", 0) or 0)
                stats["sent"] += int(result.get("sent", 0) or 0)
                stats["errors"] += int(result.get("errors", 0) or 0)
                stats["bytes_sent_est"] += int(result.get("bytes_sent_est", 0) or 0)

            else:
                # ── TIMING-AWARE REPLAY (original / multiplier / rps-without-pacing) ──
                # Single socket per loop + absolute schedule to reduce drift.
                if cfg.use_l2:
                    mv = memoryview(prep.packets_buffer)
                    loop_start_t = time.monotonic()
                    pkt_idx = 0
                    max_window = max(1, int(cfg.batch_size))
                    while pkt_idx < prep.count:
                        if pkt_idx > 0:
                            target_t = loop_start_t + schedule_offsets[pkt_idx]
                            drift_ms = await _wait_until(target_t)
                            drift_total_ms += drift_ms
                            drift_samples += 1
                            if drift_ms > drift_max_ms:
                                drift_max_ms = drift_ms

                        now_off = max(0.0, time.monotonic() - loop_start_t)
                        send_end = min(prep.count, pkt_idx + 1)
                        hard_limit = min(prep.count, pkt_idx + max_window)
                        while send_end < hard_limit:
                            if schedule_offsets[send_end] > now_off:
                                break
                            send_end += 1

                        batch_count = max(1, int(send_end - pkt_idx))
                        pkt_start = int(pkt_idx * prep.packet_size)
                        pkt_end = int(pkt_start + (batch_count * prep.packet_size))
                        batch_buffer = bytes(mv[pkt_start:pkt_end])

                        result = await senders.paced_raw_socket_sender(
                            packets_buffer=batch_buffer,
                            target_ip=cfg.target_ip_override or "0.0.0.0",
                            target_port=cfg.target_port_override or 0,
                            count=batch_count,
                            verbose=cfg.verbose,
                            pacing_config=None,
                            force_l2=True,
                            live_sent=live_sent,
                            live_errors=live_errors,
                            live_progress=live_progress,
                        )
                        stats["attempted"] += int(result.get("attempted", 0) or 0)
                        stats["sent"] += int(result.get("sent", 0) or 0)
                        stats["errors"] += int(result.get("errors", 0) or 0)
                        stats["bytes_sent_est"] += int(result.get("bytes_sent_est", 0) or 0)

                        pkt_idx += batch_count
                        if pkt_idx % max_window == 0:
                            await asyncio.sleep(0)

                    stats["loops_completed"] += 1
                    continue

                mv = memoryview(prep.packets_buffer)
                try:
                    s = _open_raw_socket()
                    stats["socket_open_count"] += 1
                except PermissionError:
                    log_error("[PCAP Replay] Raw socket requires root privileges.")
                    stats["errors"] += prep.count
                    stop_replay = True
                    break
                except OSError as e:
                    log_error(f"[PCAP Replay] Socket error: {e}")
                    stats["errors"] += prep.count
                    stop_replay = True
                    break

                loop_sent = 0
                loop_errors = 0
                loop_start_t = time.monotonic()
                dst_ip = cfg.target_ip_override or "0.0.0.0"
                dst_port = cfg.target_port_override or 0
                address = (dst_ip, dst_port)
                has_sendmmsg = hasattr(s, "sendmmsg")

                try:
                    pkt_idx = 0
                    while pkt_idx < prep.count:
                        if pkt_idx > 0:
                            target_t = loop_start_t + schedule_offsets[pkt_idx]
                            drift_ms = await _wait_until(target_t)
                            drift_total_ms += drift_ms
                            drift_samples += 1
                            if drift_ms > drift_max_ms:
                                drift_max_ms = drift_ms

                        if has_sendmmsg:
                            now_off = max(0.0, time.monotonic() - loop_start_t)
                            max_window = max(1, int(cfg.batch_size))
                            send_end = min(prep.count, pkt_idx + 1)
                            hard_limit = min(prep.count, pkt_idx + max_window)
                            while send_end < hard_limit:
                                if schedule_offsets[send_end] > now_off:
                                    break
                                send_end += 1

                            datagrams = []
                            for send_i in range(pkt_idx, send_end):
                                pkt_start = send_i * prep.packet_size
                                pkt_end = pkt_start + prep.packet_size
                                datagrams.append((mv[pkt_start:pkt_end], []))

                            batch_count = len(datagrams)
                            batch_sent = 0
                            try:
                                while batch_sent < batch_count:
                                    sent_now = int(s.sendmmsg(datagrams[batch_sent:], 0, address) or 0)
                                    if sent_now <= 0:
                                        break
                                    batch_sent += sent_now
                            except OSError:
                                batch_sent = 0

                            loop_sent += int(batch_sent)
                            batch_errors = max(0, batch_count - int(batch_sent))
                            loop_errors += batch_errors

                            if live_progress:
                                try:
                                    live_progress.value += int(batch_count)
                                except (AttributeError, TypeError, ValueError):
                                    pass
                            if live_sent and batch_sent > 0:
                                try:
                                    live_sent.value += int(batch_sent)
                                except (AttributeError, TypeError, ValueError):
                                    pass
                            if live_errors and batch_errors > 0:
                                try:
                                    live_errors.value += int(batch_errors)
                                except (AttributeError, TypeError, ValueError):
                                    pass

                            pkt_idx += batch_count
                        else:
                            pkt_start = pkt_idx * prep.packet_size
                            pkt_end = pkt_start + prep.packet_size
                            pkt_view = mv[pkt_start:pkt_end]

                            try:
                                s.sendto(pkt_view, address)
                                loop_sent += 1
                                if live_sent:
                                    try:
                                        live_sent.value += 1
                                    except (AttributeError, TypeError, ValueError):
                                        pass
                            except OSError:
                                loop_errors += 1
                                if live_errors:
                                    try:
                                        live_errors.value += 1
                                    except (AttributeError, TypeError, ValueError):
                                        pass

                            if live_progress:
                                try:
                                    live_progress.value += 1
                                except (AttributeError, TypeError, ValueError):
                                    pass
                            pkt_idx += 1

                        # Cooperative yield at configured chunk boundaries.
                        if pkt_idx % max(1, int(cfg.batch_size)) == 0:
                            await asyncio.sleep(0)
                finally:
                    s.close()

                stats["attempted"] += prep.count
                stats["sent"] += loop_sent
                stats["errors"] += loop_errors
                stats["bytes_sent_est"] += loop_sent * prep.packet_size

            stats["loops_completed"] += 1

    except KeyboardInterrupt:
        log_warning("[PCAP Replay] Interrupted by user (Ctrl-C)")
    except (RuntimeError, OSError, ValueError, TypeError) as e:
        log_error(f"[PCAP Replay] Error: {e}")
        if cfg.verbose:
            import traceback
            traceback.print_exc()

    wall_s = max(0.001, time.monotonic() - t0)
    stats["timing_drift_ms_avg"] = (drift_total_ms / drift_samples) if drift_samples > 0 else 0.0
    stats["timing_drift_ms_max"] = drift_max_ms
    stats["wall_time_s"] = wall_s
    stats["effective_pps"] = stats["sent"] / wall_s if wall_s > 0 else 0.0
    stats["effective_mbps"] = (stats["bytes_sent_est"] * 8) / (wall_s * 1e6) if wall_s > 0 else 0.0

    log_info(
        f"[PCAP Replay] Done: {stats['sent']:,} pkts sent, "
        f"{stats['errors']:,} errors, "
        f"{stats['loops_completed']} loops, "
        f"{stats['effective_pps']:,.0f} pps, "
        f"{stats['effective_mbps']:.2f} Mbps, "
        f"wall={wall_s:.2f}s"
    )

    return stats


# ════════════════════════════════════════════════════════════════════════════
#  PCAP Summary / Inspection  (CLI --pcap-info mode)
# ════════════════════════════════════════════════════════════════════════════

def pcap_summary(file_path: str) -> Dict[str, Any]:
    """
    Quick summary of a PCAP file without full replay preparation.

    Returns a dict with packet count, duration, protocol breakdown, etc.
    """
    packets, meta = parse_pcap_file(file_path)

    if not packets:
        return {"file": file_path, "packets": 0, **meta}

    ts_first = packets[0].timestamp_s
    ts_last = packets[-1].timestamp_s
    duration = ts_last - ts_first

    sizes = [len(p.raw_data) for p in packets]
    protocols: Dict[str, int] = {"tcp": 0, "udp": 0, "icmp": 0, "other": 0}
    src_ips: set = set()
    dst_ips: set = set()

    for pkt in packets:
        info = _get_ip_info(pkt)
        if info:
            proto = info["protocol"]
            if proto == PROTO_TCP:
                protocols["tcp"] += 1
            elif proto == PROTO_UDP:
                protocols["udp"] += 1
            elif proto == PROTO_ICMP:
                protocols["icmp"] += 1
            else:
                protocols["other"] += 1
            src_ips.add(info["src_ip"])
            dst_ips.add(info["dst_ip"])
        else:
            protocols["other"] += 1

    return {
        "file": file_path,
        "format": meta.get("format", "unknown"),
        "packets": len(packets),
        "duration_s": round(duration, 6),
        "avg_pps": round(len(packets) / duration, 1) if duration > 0 else 0,
        "size_min": min(sizes),
        "size_max": max(sizes),
        "size_avg": round(sum(sizes) / len(sizes), 1),
        "total_bytes": sum(sizes),
        "protocols": protocols,
        "unique_src_ips": len(src_ips),
        "unique_dst_ips": len(dst_ips),
        "link_type": meta.get("link_type", -1),
        **meta,
    }
