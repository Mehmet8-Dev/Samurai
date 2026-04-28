"""
GPU PCAP Generator (Test Utility)

This module generates a synthetic PCAP file on the GPU for testing pipelines
(parsers, ingestion, analytics). It does NOT transmit any traffic.

PCAP layout (V2):
  - Global header is written on host (24 bytes).
  - Per-packet record header (16 bytes) is followed by variable packet bytes.
  - incl_len/orig_len are set to the generated packet length.
"""

from __future__ import annotations

import json
import os
import struct
import time
from dataclasses import dataclass
from typing import Dict, Literal, Optional, Tuple


_RECOVERABLE_ERRORS = (
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
    AttributeError,
    ImportError,
    KeyError,
    IndexError,
)

PCAP_GLOBAL_HEADER = bytes(
    [
        0xD4,
        0xC3,
        0xB2,
        0xA1,  # magic (little-endian)
        0x02,
        0x00,  # version major
        0x04,
        0x00,  # version minor
        0x00,
        0x00,
        0x00,
        0x00,  # thiszone
        0x00,
        0x00,
        0x00,
        0x00,  # sigfigs
        0xFF,
        0xFF,
        0x00,
        0x00,  # snaplen (65535)
        0x01,
        0x00,
        0x00,
        0x00,  # linktype (DLT_EN10MB / Ethernet)
    ]
)

PCAP_RECORD_HEADER_LEN = 16
ETH_HEADER_LEN = 14
IP_HEADER_LEN = 20
TCP_HEADER_BASE_LEN = 20
UDP_HEADER_LEN = 8
TCP_OPT_MSS_LEN = 4
DEFAULT_MTU = 1500


def _ip_to_int(ip: str) -> int:
    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError(f"Invalid IPv4 address: {ip!r}")
    out = 0
    for p in parts:
        n = int(p)
        if n < 0 or n > 255:
            raise ValueError(f"Invalid IPv4 address: {ip!r}")
        out = (out << 8) | n
    return out


def _sanitize_output_path(filename: str, project_dir: str) -> str:
    # Requirement: save into project folder. Force basename and join.
    base = os.path.basename(filename) if filename else filename
    if not base:
        raise ValueError("Output filename is empty")
    return os.path.join(project_dir, base)


def check_gpu_available() -> Tuple[bool, str]:
    try:
        from numba import cuda
    except _RECOVERABLE_ERRORS as e:
        return False, f"Numba CUDA import failed: {e}"

    if not cuda.is_available():
        return False, "CUDA not available (numba.cuda.is_available() is False)"

    try:
        import cupy as cp

        # CuPy can import even if the driver/runtime isn't available.
        _ = cp.cuda.runtime.getDeviceCount()
    except _RECOVERABLE_ERRORS as e:
        return False, f"CuPy CUDA runtime not available: {e}"

    try:
        # Confirm the active Numba context is healthy, not just present.
        cuda.current_context().synchronize()
    except _RECOVERABLE_ERRORS as e:
        return False, f"Numba CUDA context is not healthy: {e}"

    return True, "GPU ready"


def _is_context_destroyed_error(exc: BaseException) -> bool:
    code = getattr(exc, "code", None)
    if code == 709:
        return True
    return "CUDA_ERROR_CONTEXT_IS_DESTROYED" in str(exc)


def _reset_cuda_context_best_effort() -> None:
    # Best effort cleanup for a broken CUDA context between test runs.
    try:
        import cupy as cp

        try:
            cp.get_default_memory_pool().free_all_blocks()
        except _RECOVERABLE_ERRORS:
            pass
        try:
            cp.get_default_pinned_memory_pool().free_all_blocks()
        except _RECOVERABLE_ERRORS:
            pass
    except _RECOVERABLE_ERRORS:
        pass

    try:
        from numba import cuda

        cuda.close()
    except _RECOVERABLE_ERRORS:
        pass


# CUDA pieces are defined lazily (import-time safe). They will compile on first use.
def _get_cuda_kernels():
    import cupy as cp
    from numba import cuda, int32, int64, uint8, uint16, uint32, uint64

    @cuda.jit(device=True)
    def _write_u16_be(buf, off, v):
        buf[off] = (v >> 8) & 0xFF
        buf[off + 1] = v & 0xFF

    @cuda.jit(device=True)
    def _write_u32_be(buf, off, v):
        buf[off] = (v >> 24) & 0xFF
        buf[off + 1] = (v >> 16) & 0xFF
        buf[off + 2] = (v >> 8) & 0xFF
        buf[off + 3] = v & 0xFF

    @cuda.jit(device=True)
    def _write_u32_le(buf, off, v):
        buf[off] = v & 0xFF
        buf[off + 1] = (v >> 8) & 0xFF
        buf[off + 2] = (v >> 16) & 0xFF
        buf[off + 3] = (v >> 24) & 0xFF

    @cuda.jit(device=True)
    def _splitmix64(seed, idx, salt):
        x = uint64(seed) ^ uint64(idx) ^ uint64(salt)
        x ^= x >> uint64(30)
        x *= uint64(0xBF58476D1CE4E5B9)
        x ^= x >> uint64(27)
        x *= uint64(0x94D049BB133111EB)
        x ^= x >> uint64(31)
        return x

    @cuda.jit(device=True)
    def _fold_checksum(s):
        s = (s & uint32(0xFFFF)) + (s >> uint32(16))
        s = (s & uint32(0xFFFF)) + (s >> uint32(16))
        return uint16((~s) & uint32(0xFFFF))

    @cuda.jit(device=True)
    def _pick_ttl(r):
        m = uint32(r % 100)
        if m < 55:
            return uint8(64)
        if m < 82:
            return uint8(128)
        if m < 95:
            return uint8(255)
        return uint8(32)

    @cuda.jit(device=True)
    def _pick_tos(r):
        m = uint32(r % 100)
        if m < 80:
            return uint8(0)
        if m < 90:
            return uint8(16)
        if m < 95:
            return uint8(40)
        return uint8(184)

    @cuda.jit(device=True)
    def _ipv4_checksum(buf, ip_off):
        s = uint32(0)
        for i in range(0, IP_HEADER_LEN, 2):
            if i == 10:
                continue
            w = (uint32(buf[ip_off + i]) << 8) | uint32(buf[ip_off + i + 1])
            s += w
        return _fold_checksum(s)

    @cuda.jit(device=True)
    def _tcp_checksum(buf, tcp_off, tcp_len, src_ip_int, dst_ip_int):
        s = uint32(0)
        s += uint32((src_ip_int >> 16) & 0xFFFF)
        s += uint32(src_ip_int & 0xFFFF)
        s += uint32((dst_ip_int >> 16) & 0xFFFF)
        s += uint32(dst_ip_int & 0xFFFF)
        s += uint32(6)
        s += uint32(tcp_len)

        for i in range(0, tcp_len, 2):
            if i == 16:
                continue
            if (i + 1) < tcp_len:
                w = (uint32(buf[tcp_off + i]) << 8) | uint32(buf[tcp_off + i + 1])
            else:
                w = uint32(buf[tcp_off + i]) << uint32(8)
            s += w
        return _fold_checksum(s)

    @cuda.jit(device=True)
    def _udp_checksum(buf, udp_off, udp_len, src_ip_int, dst_ip_int):
        s = uint32(0)
        s += uint32((src_ip_int >> 16) & 0xFFFF)
        s += uint32(src_ip_int & 0xFFFF)
        s += uint32((dst_ip_int >> 16) & 0xFFFF)
        s += uint32(dst_ip_int & 0xFFFF)
        s += uint32(17)
        s += uint32(udp_len)

        for i in range(0, udp_len, 2):
            if i == 6:
                continue
            if (i + 1) < udp_len:
                w = (uint32(buf[udp_off + i]) << 8) | uint32(buf[udp_off + i + 1])
            else:
                w = uint32(buf[udp_off + i]) << uint32(8)
            s += w

        csum = _fold_checksum(s)
        if csum == 0:
            return uint16(0xFFFF)
        return csum

    @cuda.jit
    def pcap_records_kernel(
        out_data,
        num_packets,
        record_slot_len,
        base_ts_us,
        pps,
        base_index,
        src_ip_int,
        dst_ip_int,
        tcp_dport,
        udp_dport,
        mode,
        seed,
        realistic,
        flow_count,
        udp_checksum_enabled,
        variable_size,
        mtu,
        size_profile,
    ):
        idx = cuda.grid(1)
        if idx >= num_packets:
            return

        gidx = int64(base_index) + int64(idx)
        delta_us = (gidx * int64(1000000)) // int64(pps)
        ts_us = int64(base_ts_us) + delta_us
        ts_sec = uint32(ts_us // int64(1000000))
        ts_usec = uint32(ts_us % int64(1000000))

        rec_off = int64(idx) * int64(record_slot_len)
        pkt_off = rec_off + int64(PCAP_RECORD_HEADER_LEN)

        r1 = _splitmix64(seed, gidx, uint64(0x9E3779B97F4A7C15))
        r2 = _splitmix64(seed, gidx, uint64(0xD1B54A32D192ED03))
        r3 = _splitmix64(seed, gidx, uint64(0x94D049BB133111EB))

        if mode == 1:
            is_tcp = int32(1)
        elif mode == 2:
            is_tcp = int32(0)
        else:
            is_tcp = int32(1 if (r1 % uint64(100)) < uint64(60) else 0)

        if flow_count <= 0:
            flow_count = 1
        flow_id = gidx % int64(flow_count)

        flow_r1 = _splitmix64(seed, flow_id, uint64(0xA0761D6478BD642F))
        flow_r2 = _splitmix64(seed, flow_id, uint64(0xE7037ED1A0B428DB))

        src_base = uint32(src_ip_int)
        dst_base = uint32(dst_ip_int)
        client_ip = src_base
        server_ip = dst_base

        if realistic != 0:
            client_ip = (src_base & uint32(0xFFFFFF00)) | uint32((flow_id % 253) + 1)

        phase = int32(0)
        c2s = int32(1)
        if realistic != 0 and is_tcp == 1:
            phase = int32((gidx // int64(flow_count)) & int64(0x7))
            if phase == 1 or phase == 4 or phase == 7:
                c2s = int32(0)

        if c2s == 1:
            src_ip_pkt = client_ip
            dst_ip_pkt = server_ip
            mac_src_seed = flow_r1
            mac_dst_seed = flow_r2
        else:
            src_ip_pkt = server_ip
            dst_ip_pkt = client_ip
            mac_src_seed = flow_r2
            mac_dst_seed = flow_r1

        # Packet sizing model.
        tcp_opt_len = int32(0)
        tcp_hdr_len = int32(TCP_HEADER_BASE_LEN)
        payload_len = int32(0)

        if is_tcp == 1:
            if realistic != 0 and (phase == 0 or phase == 1 or phase == 2 or phase == 5 or phase == 6 or phase == 7):
                tcp_opt_len = int32(TCP_OPT_MSS_LEN)
            tcp_hdr_len = int32(TCP_HEADER_BASE_LEN) + tcp_opt_len

            max_payload = int32(mtu - (IP_HEADER_LEN + tcp_hdr_len))
            if max_payload < 0:
                max_payload = 0

            if realistic != 0 and phase != 3 and phase != 4:
                payload_len = int32(0)
            elif variable_size != 0:
                m = int32(r3 % uint64(100))
                if size_profile == 1:  # web
                    if m < 65:
                        payload_len = int32((r1 >> uint64(8)) % uint64(96))
                    elif m < 95:
                        payload_len = int32(96 + ((r2 >> uint64(16)) % uint64(804)))
                    else:
                        payload_len = int32(900 + ((r3 >> uint64(24)) % uint64(500)))
                elif size_profile == 2:  # dns/amplification-ish
                    if m < 85:
                        payload_len = int32(12 + ((r1 >> uint64(8)) % uint64(69)))
                    elif m < 98:
                        payload_len = int32(81 + ((r2 >> uint64(16)) % uint64(220)))
                    else:
                        payload_len = int32(301 + ((r3 >> uint64(24)) % uint64(900)))
                else:  # mixed
                    if m < 50:
                        payload_len = int32((r1 >> uint64(8)) % uint64(80))
                    elif m < 85:
                        payload_len = int32(80 + ((r2 >> uint64(16)) % uint64(600)))
                    else:
                        payload_len = int32(680 + ((r3 >> uint64(24)) % uint64(720)))
            else:
                payload_len = int32(4)

            if payload_len > max_payload:
                payload_len = max_payload

            ip_total_len = int32(IP_HEADER_LEN) + tcp_hdr_len + payload_len
            transport_len = tcp_hdr_len + payload_len
        else:
            max_payload = int32(mtu - (IP_HEADER_LEN + UDP_HEADER_LEN))
            if max_payload < 0:
                max_payload = 0

            if variable_size != 0:
                m = int32(r3 % uint64(100))
                if size_profile == 1:  # web-like
                    if m < 70:
                        payload_len = int32((r1 >> uint64(8)) % uint64(120))
                    elif m < 95:
                        payload_len = int32(120 + ((r2 >> uint64(16)) % uint64(620)))
                    else:
                        payload_len = int32(740 + ((r3 >> uint64(24)) % uint64(620)))
                elif size_profile == 2:  # dns/amplification-ish
                    if m < 85:
                        payload_len = int32(12 + ((r1 >> uint64(8)) % uint64(69)))
                    elif m < 98:
                        payload_len = int32(81 + ((r2 >> uint64(16)) % uint64(220)))
                    else:
                        payload_len = int32(301 + ((r3 >> uint64(24)) % uint64(900)))
                else:  # mixed
                    if m < 60:
                        payload_len = int32((r1 >> uint64(8)) % uint64(96))
                    elif m < 90:
                        payload_len = int32(96 + ((r2 >> uint64(16)) % uint64(512)))
                    else:
                        payload_len = int32(608 + ((r3 >> uint64(24)) % uint64(760)))
            else:
                payload_len = int32(16)

            if payload_len > max_payload:
                payload_len = max_payload

            ip_total_len = int32(IP_HEADER_LEN + UDP_HEADER_LEN) + payload_len
            transport_len = int32(UDP_HEADER_LEN) + payload_len

        pkt_len = int32(ETH_HEADER_LEN) + ip_total_len

        # PCAP record header (little-endian)
        _write_u32_le(out_data, rec_off + 0, ts_sec)
        _write_u32_le(out_data, rec_off + 4, ts_usec)
        _write_u32_le(out_data, rec_off + 8, uint32(pkt_len))
        _write_u32_le(out_data, rec_off + 12, uint32(pkt_len))

        # Ethernet header (14)
        for i in range(6):
            out_data[pkt_off + i] = uint8((mac_dst_seed >> uint64(i * 8)) & uint64(0xFF))
            out_data[pkt_off + 6 + i] = uint8((mac_src_seed >> uint64(i * 8)) & uint64(0xFF))
        out_data[pkt_off + 12] = 0x08
        out_data[pkt_off + 13] = 0x00

        ip_off = pkt_off + ETH_HEADER_LEN

        out_data[ip_off + 0] = 0x45
        if realistic != 0:
            out_data[ip_off + 1] = _pick_tos(uint32(r3 & uint64(0xFFFFFFFF)))
        else:
            out_data[ip_off + 1] = 0x00

        _write_u16_be(out_data, ip_off + 2, uint16(ip_total_len))
        _write_u16_be(out_data, ip_off + 4, uint16(gidx & int64(0xFFFF)))
        _write_u16_be(out_data, ip_off + 6, uint16(0x4000))

        if realistic != 0:
            out_data[ip_off + 8] = _pick_ttl(uint32((r2 >> uint64(8)) & uint64(0xFFFFFFFF)))
        else:
            out_data[ip_off + 8] = 64

        out_data[ip_off + 9] = 6 if is_tcp == 1 else 17
        _write_u16_be(out_data, ip_off + 10, uint16(0))

        out_data[ip_off + 12] = uint8((src_ip_pkt >> 24) & 0xFF)
        out_data[ip_off + 13] = uint8((src_ip_pkt >> 16) & 0xFF)
        out_data[ip_off + 14] = uint8((src_ip_pkt >> 8) & 0xFF)
        out_data[ip_off + 15] = uint8(src_ip_pkt & 0xFF)
        out_data[ip_off + 16] = uint8((dst_ip_pkt >> 24) & 0xFF)
        out_data[ip_off + 17] = uint8((dst_ip_pkt >> 16) & 0xFF)
        out_data[ip_off + 18] = uint8((dst_ip_pkt >> 8) & 0xFF)
        out_data[ip_off + 19] = uint8(dst_ip_pkt & 0xFF)

        ip_csum = _ipv4_checksum(out_data, ip_off)
        _write_u16_be(out_data, ip_off + 10, ip_csum)

        tr_off = ip_off + IP_HEADER_LEN

        if is_tcp == 1:
            if realistic != 0:
                cli_port = uint16(1024 + (flow_id % 50000))
                srv_port = uint16(tcp_dport)
                if c2s == 1:
                    sport = cli_port
                    dport = srv_port
                else:
                    sport = srv_port
                    dport = cli_port
            else:
                sport = uint16((r1 % uint64(64512)) + uint64(1024))
                dport = uint16(tcp_dport)

            _write_u16_be(out_data, tr_off + 0, sport)
            _write_u16_be(out_data, tr_off + 2, dport)

            if realistic != 0:
                cli_seq = uint32(_splitmix64(seed, flow_id, uint64(0x8CB92BA72F3D8DD7)) & uint64(0xFFFFFFFF))
                srv_seq = uint32(_splitmix64(seed, flow_id, uint64(0xDB4F0B9175AE2165)) & uint64(0xFFFFFFFF))

                if phase == 0:
                    seq = cli_seq
                    ack = uint32(0)
                    flags = uint8(0x02)
                elif phase == 1:
                    seq = srv_seq
                    ack = cli_seq + uint32(1)
                    flags = uint8(0x12)
                elif phase == 2:
                    seq = cli_seq + uint32(1)
                    ack = srv_seq + uint32(1)
                    flags = uint8(0x10)
                elif phase == 3:
                    seq = cli_seq + uint32(1)
                    ack = srv_seq + uint32(1)
                    flags = uint8(0x18)
                elif phase == 4:
                    seq = srv_seq + uint32(1)
                    ack = cli_seq + uint32(5)
                    flags = uint8(0x18)
                elif phase == 5:
                    seq = cli_seq + uint32(5)
                    ack = srv_seq + uint32(5)
                    flags = uint8(0x10)
                elif phase == 6:
                    seq = cli_seq + uint32(5)
                    ack = srv_seq + uint32(5)
                    flags = uint8(0x11)
                else:
                    seq = srv_seq + uint32(5)
                    ack = cli_seq + uint32(6)
                    flags = uint8(0x11)
            else:
                seq = uint32(r2 & uint64(0xFFFFFFFF))
                ack = uint32(0)
                flags = uint8(0x02)

            _write_u32_be(out_data, tr_off + 4, seq)
            _write_u32_be(out_data, tr_off + 8, ack)

            out_data[tr_off + 12] = uint8((tcp_hdr_len // 4) << 4)
            out_data[tr_off + 13] = flags

            if realistic != 0:
                wsel = uint32(flow_id & 0x3)
                if wsel == 0:
                    wnd = uint16(29200)
                elif wsel == 1:
                    wnd = uint16(64240)
                elif wsel == 2:
                    wnd = uint16(65535)
                else:
                    wnd = uint16(32768)
            else:
                wnd = uint16(64240)

            _write_u16_be(out_data, tr_off + 14, wnd)
            _write_u16_be(out_data, tr_off + 16, uint16(0))
            _write_u16_be(out_data, tr_off + 18, uint16(0))

            if tcp_opt_len == TCP_OPT_MSS_LEN:
                out_data[tr_off + 20] = 0x02
                out_data[tr_off + 21] = 0x04
                out_data[tr_off + 22] = 0x05
                out_data[tr_off + 23] = 0xB4

            payload_off = tr_off + tcp_hdr_len
            for i in range(payload_len):
                shift_a = uint64((i & 7) * 8)
                shift_b = uint64(((i + 3) & 7) * 8)
                mix = (r1 >> shift_a) ^ (r2 >> shift_b) ^ r3 ^ uint64(i * 17)
                out_data[payload_off + i] = uint8(mix & uint64(0xFF))

            tcp_csum = _tcp_checksum(out_data, tr_off, transport_len, src_ip_pkt, dst_ip_pkt)
            _write_u16_be(out_data, tr_off + 16, tcp_csum)
        else:
            if realistic != 0:
                cli_port = uint16(1024 + (flow_id % 50000))
                srv_port = uint16(udp_dport)
                if (r3 % uint64(100)) < uint64(12):
                    sport = srv_port
                    dport = cli_port
                    src_ip_pkt = server_ip
                    dst_ip_pkt = client_ip

                    out_data[ip_off + 12] = uint8((src_ip_pkt >> 24) & 0xFF)
                    out_data[ip_off + 13] = uint8((src_ip_pkt >> 16) & 0xFF)
                    out_data[ip_off + 14] = uint8((src_ip_pkt >> 8) & 0xFF)
                    out_data[ip_off + 15] = uint8(src_ip_pkt & 0xFF)
                    out_data[ip_off + 16] = uint8((dst_ip_pkt >> 24) & 0xFF)
                    out_data[ip_off + 17] = uint8((dst_ip_pkt >> 16) & 0xFF)
                    out_data[ip_off + 18] = uint8((dst_ip_pkt >> 8) & 0xFF)
                    out_data[ip_off + 19] = uint8(dst_ip_pkt & 0xFF)

                    ip_csum = _ipv4_checksum(out_data, ip_off)
                    _write_u16_be(out_data, ip_off + 10, ip_csum)
                else:
                    sport = cli_port
                    dport = srv_port
            else:
                sport = uint16((r1 % uint64(64512)) + uint64(1024))
                dport = uint16(udp_dport)

            _write_u16_be(out_data, tr_off + 0, sport)
            _write_u16_be(out_data, tr_off + 2, dport)
            _write_u16_be(out_data, tr_off + 4, uint16(transport_len))
            _write_u16_be(out_data, tr_off + 6, uint16(0))

            payload_off = tr_off + UDP_HEADER_LEN
            for i in range(payload_len):
                shift_a = uint64((i & 7) * 8)
                shift_b = uint64(((i + 5) & 7) * 8)
                mix = (r1 >> shift_a) ^ (r2 >> shift_b) ^ r3 ^ uint64(i * 29)
                out_data[payload_off + i] = uint8(mix & uint64(0xFF))

            if udp_checksum_enabled != 0:
                udp_csum = _udp_checksum(out_data, tr_off, transport_len, src_ip_pkt, dst_ip_pkt)
                _write_u16_be(out_data, tr_off + 6, udp_csum)

    @cuda.jit
    def extract_incl_lens_kernel(out_data, incl_lens, num_packets, record_slot_len):
        """Extract per-packet incl_len from fixed-slot PCAP records."""
        idx = cuda.grid(1)
        if idx >= num_packets:
            return

        rec_off = int64(idx) * int64(record_slot_len)
        # incl_len is little-endian at record header offset 8.
        b0 = uint32(out_data[rec_off + 8])
        b1 = uint32(out_data[rec_off + 9])
        b2 = uint32(out_data[rec_off + 10])
        b3 = uint32(out_data[rec_off + 11])
        incl_lens[idx] = b0 | (b1 << uint32(8)) | (b2 << uint32(16)) | (b3 << uint32(24))

    @cuda.jit
    def pack_records_kernel(out_data, packed_out, offsets, rec_lens, num_packets, record_slot_len):
        """
        Pack variable-length PCAP records into a contiguous output buffer.

        Source layout: fixed-size slots (record_slot_len) per packet.
        Dest layout: concatenated records of length rec_lens[idx], starting at offsets[idx].
        """
        idx = cuda.grid(1)
        if idx >= num_packets:
            return

        src_off = int64(idx) * int64(record_slot_len)
        dst_off = int64(offsets[idx])
        nbytes = int32(rec_lens[idx])

        for j in range(nbytes):
            packed_out[dst_off + int64(j)] = out_data[src_off + int64(j)]

    return {
        "cp": cp,
        "cuda": cuda,
        "kernel": pcap_records_kernel,
        "extract_incl_lens": extract_incl_lens_kernel,
        "pack_records": pack_records_kernel,
    }


TrafficMode = Literal["mix", "tcp", "udp"]
SizeProfile = Literal["mixed", "web", "dns"]


@dataclass(frozen=True)
class PcapGenConfig:
    duration_s: int
    pps: int
    mode: TrafficMode = "mix"
    src_ip: str = "192.168.1.100"
    dst_ip: str = "127.0.0.1"
    tcp_dport: int = 80
    udp_dport: int = 53
    chunk_size: int = 200_000
    seed: int = 0
    flow_count: int = 4096
    realistic: bool = False
    udp_checksum: bool = False
    variable_size: bool = False
    mtu: int = DEFAULT_MTU
    size_profile: SizeProfile = "mixed"
    output_filename: str = "gpu_generated.pcap"


def generate_pcap(config: PcapGenConfig, project_dir: Optional[str] = None) -> str:
    """
    Generate a PCAP file into project_dir (defaults to current working directory).

    Returns the absolute output path.
    """
    if config.duration_s <= 0:
        raise ValueError("duration_s must be > 0")
    if config.pps <= 0:
        raise ValueError("pps must be > 0")
    if config.chunk_size <= 0:
        raise ValueError("chunk_size must be > 0")
    if config.flow_count <= 0:
        raise ValueError("flow_count must be > 0")
    if config.tcp_dport <= 0 or config.tcp_dport > 65535:
        raise ValueError("tcp_dport must be in 1..65535")
    if config.udp_dport <= 0 or config.udp_dport > 65535:
        raise ValueError("udp_dport must be in 1..65535")
    if config.mtu < 128 or config.mtu > 1500:
        raise ValueError("mtu must be in 128..1500")

    size_profile_map = {"mixed": 0, "web": 1, "dns": 2}
    if config.size_profile not in size_profile_map:
        raise ValueError("size_profile must be one of: mixed, web, dns")

    ok, msg = check_gpu_available()
    if not ok:
        raise RuntimeError(msg)

    project_dir = project_dir or os.getcwd()
    out_path = _sanitize_output_path(config.output_filename, project_dir)

    src_ip_int = _ip_to_int(config.src_ip)
    dst_ip_int = _ip_to_int(config.dst_ip)

    mode_val = {"mix": 0, "tcp": 1, "udp": 2}[config.mode]

    total_packets = config.duration_s * config.pps
    base_ts_us = int(time.time() * 1_000_000)

    record_slot_len = PCAP_RECORD_HEADER_LEN + ETH_HEADER_LEN + int(config.mtu)
    max_attempts = 2
    for attempt in range(max_attempts):
        try:
            cuda_bits = _get_cuda_kernels()
            cp = cuda_bits["cp"]
            cuda = cuda_bits["cuda"]
            kernel = cuda_bits["kernel"]
            extract_incl_lens = cuda_bits["extract_incl_lens"]
            pack_records = cuda_bits["pack_records"]

            # Write global header once; then append chunk records.
            with open(out_path, "wb") as f:
                f.write(PCAP_GLOBAL_HEADER)

                remaining = total_packets
                base_index = 0

                threads_per_block = 256

                seed = config.seed if config.seed else int(time.time()) & 0xFFFFFFFF
                realistic = 1 if config.realistic else 0
                udp_checksum_enabled = 1 if (config.udp_checksum or config.realistic) else 0
                variable_size = 1 if (config.variable_size or config.realistic) else 0
                size_profile = size_profile_map[config.size_profile]

                while remaining > 0:
                    n = min(config.chunk_size, remaining)
                    out_gpu = cp.empty((n * record_slot_len,), dtype=cp.uint8)

                    blocks = (n + (threads_per_block - 1)) // threads_per_block
                    kernel[blocks, threads_per_block](
                        out_gpu,
                        n,
                        record_slot_len,
                        base_ts_us,
                        config.pps,
                        base_index,
                        src_ip_int,
                        dst_ip_int,
                        config.tcp_dport,
                        config.udp_dport,
                        mode_val,
                        seed,
                        realistic,
                        config.flow_count,
                        udp_checksum_enabled,
                        variable_size,
                        config.mtu,
                        size_profile,
                    )
                    cuda.synchronize()

                    # ---- New fast path: pack variable-length records on GPU, then single host copy + write ----
                    max_packet_len = ETH_HEADER_LEN + int(config.mtu)

                    incl_lens_gpu = cp.empty((n,), dtype=cp.uint32)
                    extract_incl_lens[blocks, threads_per_block](out_gpu, incl_lens_gpu, n, record_slot_len)
                    cuda.synchronize()

                    # Validate incl_len range without pulling the full out_gpu buffer to host.
                    incl_min = int(cp.min(incl_lens_gpu).item())
                    incl_max = int(cp.max(incl_lens_gpu).item())
                    if incl_min <= 0 or incl_max > max_packet_len:
                        raise RuntimeError(f"Generated invalid incl_len range: min={incl_min}, max={incl_max}")

                    rec_lens_gpu = incl_lens_gpu.astype(cp.uint64) + int(PCAP_RECORD_HEADER_LEN)
                    prefix = cp.cumsum(rec_lens_gpu, dtype=cp.uint64)
                    total_len = int(prefix[-1].item()) if n > 0 else 0

                    offsets = cp.empty_like(prefix)
                    offsets[0] = 0
                    if n > 1:
                        offsets[1:] = prefix[:-1]

                    packed_gpu = cp.empty((total_len,), dtype=cp.uint8)
                    pack_records[blocks, threads_per_block](out_gpu, packed_gpu, offsets, rec_lens_gpu, n, record_slot_len)
                    cuda.synchronize()

                    f.write(packed_gpu.get().tobytes())

                    remaining -= n
                    base_index += n

            return os.path.abspath(out_path)
        except _RECOVERABLE_ERRORS as e:
            if os.path.exists(out_path):
                try:
                    os.remove(out_path)
                except _RECOVERABLE_ERRORS:
                    pass
            if attempt + 1 < max_attempts and _is_context_destroyed_error(e):
                _reset_cuda_context_best_effort()
                continue
            raise

    raise RuntimeError("GPU PCAP generation failed after retries")


def _normalize_counter(counter: Dict[str, int]) -> Dict[str, float]:
    total = float(sum(counter.values()))
    if total <= 0.0:
        return {k: 0.0 for k in counter}
    return {k: float(v) / total for k, v in counter.items()}


def _distribution_score(observed: Dict[str, float], target: Dict[str, float]) -> float:
    keys = set(observed.keys()) | set(target.keys())
    if not keys:
        return 100.0
    l1 = 0.0
    for k in keys:
        l1 += abs(float(observed.get(k, 0.0)) - float(target.get(k, 0.0)))
    return max(0.0, 100.0 * (1.0 - 0.5 * l1))


def _scalar_score(value: float, target: float, tolerance: float) -> float:
    if tolerance <= 0:
        return 100.0 if value == target else 0.0
    return max(0.0, 100.0 * (1.0 - abs(value - target) / tolerance))


def _at_least_score(value: float, minimum: float, tolerance: float) -> float:
    if value >= minimum:
        return 100.0
    if tolerance <= 0:
        return 0.0
    floor = minimum - tolerance
    if value <= floor:
        return 0.0
    return max(0.0, min(100.0, 100.0 * (value - floor) / tolerance))


def _at_most_score(value: float, maximum: float, tolerance: float) -> float:
    if value <= maximum:
        return 100.0
    if tolerance <= 0:
        return 0.0
    ceil = maximum + tolerance
    if value >= ceil:
        return 0.0
    return max(0.0, min(100.0, 100.0 * (ceil - value) / tolerance))


def _bucket_packet_len(length: int) -> str:
    if length < 80:
        return "lt80"
    if length < 200:
        return "80_199"
    if length < 600:
        return "200_599"
    if length < 1000:
        return "600_999"
    return "ge1000"


def _extract_pcap_metrics(pcap_path: str, sample_packets: int) -> Dict[str, object]:
    if sample_packets <= 0:
        raise ValueError("sample_packets must be > 0")

    total_packets = 0
    invalid_records = 0
    with open(pcap_path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            raise ValueError(f"Invalid PCAP: too small ({pcap_path})")
        while True:
            hdr = f.read(PCAP_RECORD_HEADER_LEN)
            if not hdr:
                break
            if len(hdr) < PCAP_RECORD_HEADER_LEN:
                invalid_records += 1
                break
            _, _, incl_len, _ = struct.unpack("<IIII", hdr)
            if incl_len <= 0 or incl_len > 65535:
                invalid_records += 1
                break
            f.seek(incl_len, os.SEEK_CUR)
            total_packets += 1

    sampled_target = min(sample_packets, total_packets)
    if sampled_target <= 0:
        return {
            "packets_total": total_packets,
            "packets_sampled": 0,
            "invalid_records": invalid_records,
            "flows_unique": 0,
            "src_ip_unique": 0,
            "src_ip_ratio": 0.0,
            "reverse_flow_ratio": 0.0,
            "udp_zero_checksum_ratio": 0.0,
            "proto_dist": {"tcp": 0.0, "udp": 0.0, "other": 0.0},
            "size_dist": {"lt80": 0.0, "80_199": 0.0, "200_599": 0.0, "600_999": 0.0, "ge1000": 0.0},
            "ttl_dist": {"32": 0.0, "64": 0.0, "128": 0.0, "255": 0.0, "other": 0.0},
            "tos_dist": {"0": 0.0, "16": 0.0, "40": 0.0, "184": 0.0, "other": 0.0},
            "tcp_flag_dist": {"syn": 0.0, "synack": 0.0, "ack": 0.0, "pshack": 0.0, "finack": 0.0, "other": 0.0},
            "tcp_doff_dist": {"5": 0.0, "6": 0.0, "other": 0.0},
        }

    stride = max(1, total_packets // sampled_target)

    packets = 0
    packet_index = 0
    next_pick = 0

    proto_counts = {"tcp": 0, "udp": 0, "other": 0}
    size_counts = {"lt80": 0, "80_199": 0, "200_599": 0, "600_999": 0, "ge1000": 0}
    ttl_counts = {"32": 0, "64": 0, "128": 0, "255": 0, "other": 0}
    tos_counts = {"0": 0, "16": 0, "40": 0, "184": 0, "other": 0}
    tcp_flag_counts = {"syn": 0, "synack": 0, "ack": 0, "pshack": 0, "finack": 0, "other": 0}
    tcp_doff_counts = {"5": 0, "6": 0, "other": 0}

    src_ips = set()
    flows = set()
    reverse_hits = 0
    udp_total = 0
    udp_zero_checksum = 0

    with open(pcap_path, "rb") as f:
        f.seek(24, os.SEEK_SET)
        while packets < sampled_target:
            hdr = f.read(PCAP_RECORD_HEADER_LEN)
            if not hdr:
                break
            if len(hdr) < PCAP_RECORD_HEADER_LEN:
                invalid_records += 1
                break
            _, _, incl_len, _ = struct.unpack("<IIII", hdr)
            if incl_len <= 0 or incl_len > 65535:
                invalid_records += 1
                break

            if packet_index < next_pick:
                f.seek(incl_len, os.SEEK_CUR)
                packet_index += 1
                continue

            pkt = f.read(incl_len)
            if len(pkt) < incl_len:
                invalid_records += 1
                break

            packets += 1
            packet_index += 1
            next_pick += stride

            size_counts[_bucket_packet_len(incl_len)] += 1

            if len(pkt) < ETH_HEADER_LEN + IP_HEADER_LEN:
                continue
            if pkt[12] != 0x08 or pkt[13] != 0x00:
                continue

            ip_off = ETH_HEADER_LEN
            ihl = (pkt[ip_off] & 0x0F) * 4
            if ihl < IP_HEADER_LEN or len(pkt) < ip_off + ihl:
                continue

            proto = pkt[ip_off + 9]
            ttl = pkt[ip_off + 8]
            tos = pkt[ip_off + 1]
            src_ip = bytes(pkt[ip_off + 12:ip_off + 16])
            dst_ip = bytes(pkt[ip_off + 16:ip_off + 20])
            src_ips.add(src_ip)

            if ttl == 32:
                ttl_counts["32"] += 1
            elif ttl == 64:
                ttl_counts["64"] += 1
            elif ttl == 128:
                ttl_counts["128"] += 1
            elif ttl == 255:
                ttl_counts["255"] += 1
            else:
                ttl_counts["other"] += 1

            if tos == 0:
                tos_counts["0"] += 1
            elif tos == 16:
                tos_counts["16"] += 1
            elif tos == 40:
                tos_counts["40"] += 1
            elif tos == 184:
                tos_counts["184"] += 1
            else:
                tos_counts["other"] += 1

            tr_off = ip_off + ihl
            if proto == 6 and len(pkt) >= tr_off + TCP_HEADER_BASE_LEN:
                proto_counts["tcp"] += 1
                sport = (pkt[tr_off] << 8) | pkt[tr_off + 1]
                dport = (pkt[tr_off + 2] << 8) | pkt[tr_off + 3]
                flags = pkt[tr_off + 13]
                doff = (pkt[tr_off + 12] >> 4) & 0x0F

                if flags == 0x02:
                    tcp_flag_counts["syn"] += 1
                elif flags == 0x12:
                    tcp_flag_counts["synack"] += 1
                elif flags == 0x10:
                    tcp_flag_counts["ack"] += 1
                elif flags == 0x18:
                    tcp_flag_counts["pshack"] += 1
                elif flags == 0x11:
                    tcp_flag_counts["finack"] += 1
                else:
                    tcp_flag_counts["other"] += 1

                if doff == 5:
                    tcp_doff_counts["5"] += 1
                elif doff == 6:
                    tcp_doff_counts["6"] += 1
                else:
                    tcp_doff_counts["other"] += 1

                flow = (src_ip, dst_ip, sport, dport, 6)
                rev = (dst_ip, src_ip, dport, sport, 6)
                if rev in flows:
                    reverse_hits += 1
                flows.add(flow)
            elif proto == 17 and len(pkt) >= tr_off + UDP_HEADER_LEN:
                proto_counts["udp"] += 1
                udp_total += 1
                csum = (pkt[tr_off + 6] << 8) | pkt[tr_off + 7]
                if csum == 0:
                    udp_zero_checksum += 1

                sport = (pkt[tr_off] << 8) | pkt[tr_off + 1]
                dport = (pkt[tr_off + 2] << 8) | pkt[tr_off + 3]
                flow = (src_ip, dst_ip, sport, dport, 17)
                rev = (dst_ip, src_ip, dport, sport, 17)
                if rev in flows:
                    reverse_hits += 1
                flows.add(flow)
            else:
                proto_counts["other"] += 1

    proto_dist = _normalize_counter(proto_counts)
    size_dist = _normalize_counter(size_counts)
    ttl_dist = _normalize_counter(ttl_counts)
    tos_dist = _normalize_counter(tos_counts)
    tcp_flag_dist = _normalize_counter(tcp_flag_counts)
    tcp_doff_dist = _normalize_counter(tcp_doff_counts)

    src_ip_ratio = (len(src_ips) / packets) if packets > 0 else 0.0
    reverse_flow_ratio = (reverse_hits / max(1, len(flows))) if flows else 0.0
    udp_zero_checksum_ratio = (udp_zero_checksum / udp_total) if udp_total > 0 else 0.0

    return {
        "packets_total": total_packets,
        "packets_sampled": packets,
        "invalid_records": invalid_records,
        "flows_unique": len(flows),
        "src_ip_unique": len(src_ips),
        "src_ip_ratio": src_ip_ratio,
        "reverse_flow_ratio": reverse_flow_ratio,
        "udp_zero_checksum_ratio": udp_zero_checksum_ratio,
        "proto_dist": proto_dist,
        "size_dist": size_dist,
        "ttl_dist": ttl_dist,
        "tos_dist": tos_dist,
        "tcp_flag_dist": tcp_flag_dist,
        "tcp_doff_dist": tcp_doff_dist,
    }


def _profile_targets(
    *,
    mode: TrafficMode,
    size_profile: SizeProfile,
    realistic: bool,
) -> Dict[str, object]:
    if mode == "tcp":
        proto_dist = {"tcp": 1.0, "udp": 0.0, "other": 0.0}
    elif mode == "udp":
        proto_dist = {"tcp": 0.0, "udp": 1.0, "other": 0.0}
    else:
        if size_profile == "dns":
            proto_dist = {"tcp": 0.35, "udp": 0.65, "other": 0.0}
        else:
            proto_dist = {"tcp": 0.60, "udp": 0.40, "other": 0.0}

    if size_profile == "web":
        size_dist = {"lt80": 0.35, "80_199": 0.30, "200_599": 0.20, "600_999": 0.10, "ge1000": 0.05}
    elif size_profile == "dns":
        size_dist = {"lt80": 0.55, "80_199": 0.25, "200_599": 0.12, "600_999": 0.06, "ge1000": 0.02}
    else:
        size_dist = {"lt80": 0.45, "80_199": 0.25, "200_599": 0.15, "600_999": 0.10, "ge1000": 0.05}

    if realistic:
        ttl_dist = {"32": 0.05, "64": 0.55, "128": 0.27, "255": 0.13, "other": 0.0}
        tos_dist = {"0": 0.80, "16": 0.10, "40": 0.05, "184": 0.05, "other": 0.0}
        # Fin-ACK share is intentionally low because short captures may not include full closes.
        tcp_flag_dist = {"syn": 0.18, "synack": 0.18, "ack": 0.30, "pshack": 0.30, "finack": 0.04, "other": 0.0}
        tcp_doff_dist = {"5": 0.20, "6": 0.80, "other": 0.0}
        src_ip_unique_target = 128.0
        reverse_flow_ratio_target = 0.30
        udp_zero_checksum_ratio_target = 0.0
        src_ip_unique_tolerance = 64.0
        reverse_flow_ratio_tolerance = 0.25
        udp_zero_checksum_tolerance = 0.20
        src_ip_metric = "at_least"
        reverse_flow_metric = "at_least"
        udp_checksum_metric = "at_most"
    else:
        ttl_dist = {"32": 0.0, "64": 1.0, "128": 0.0, "255": 0.0, "other": 0.0}
        tos_dist = {"0": 1.0, "16": 0.0, "40": 0.0, "184": 0.0, "other": 0.0}
        tcp_flag_dist = {"syn": 1.0, "synack": 0.0, "ack": 0.0, "pshack": 0.0, "finack": 0.0, "other": 0.0}
        tcp_doff_dist = {"5": 1.0, "6": 0.0, "other": 0.0}
        src_ip_unique_target = 1.0
        reverse_flow_ratio_target = 0.0
        udp_zero_checksum_ratio_target = 1.0
        src_ip_unique_tolerance = 1.0
        reverse_flow_ratio_tolerance = 0.10
        udp_zero_checksum_tolerance = 0.20
        src_ip_metric = "target"
        reverse_flow_metric = "target"
        udp_checksum_metric = "target"

    return {
        "name": f"profile:{size_profile}:{'realistic' if realistic else 'legacy'}:{mode}",
        "proto_dist": proto_dist,
        "size_dist": size_dist,
        "ttl_dist": ttl_dist,
        "tos_dist": tos_dist,
        "tcp_flag_dist": tcp_flag_dist,
        "tcp_doff_dist": tcp_doff_dist,
        "src_ip_unique_target": src_ip_unique_target,
        "reverse_flow_ratio_target": reverse_flow_ratio_target,
        "udp_zero_checksum_ratio_target": udp_zero_checksum_ratio_target,
        "src_ip_unique_tolerance": src_ip_unique_tolerance,
        "reverse_flow_ratio_tolerance": reverse_flow_ratio_tolerance,
        "udp_zero_checksum_tolerance": udp_zero_checksum_tolerance,
        "src_ip_metric": src_ip_metric,
        "reverse_flow_metric": reverse_flow_metric,
        "udp_checksum_metric": udp_checksum_metric,
    }


def generate_realism_report(
    pcap_path: str,
    *,
    mode: TrafficMode = "mix",
    size_profile: SizeProfile = "mixed",
    realistic: bool = False,
    baseline_pcap: Optional[str] = None,
    sample_packets: int = 100_000,
    output_filename: Optional[str] = None,
    project_dir: Optional[str] = None,
) -> Tuple[Dict[str, object], Optional[str]]:
    if sample_packets <= 0:
        raise ValueError("sample_packets must be > 0")

    observed = _extract_pcap_metrics(pcap_path, sample_packets)

    if baseline_pcap:
        baseline = _extract_pcap_metrics(baseline_pcap, sample_packets)
        target = {
            "name": f"baseline:{os.path.abspath(baseline_pcap)}",
            "proto_dist": baseline["proto_dist"],
            "size_dist": baseline["size_dist"],
            "ttl_dist": baseline["ttl_dist"],
            "tos_dist": baseline["tos_dist"],
            "tcp_flag_dist": baseline["tcp_flag_dist"],
            "tcp_doff_dist": baseline["tcp_doff_dist"],
            "src_ip_unique_target": float(baseline["src_ip_unique"]),
            "reverse_flow_ratio_target": baseline["reverse_flow_ratio"],
            "udp_zero_checksum_ratio_target": baseline["udp_zero_checksum_ratio"],
            "src_ip_unique_tolerance": max(8.0, float(baseline["src_ip_unique"]) * 0.25),
            "reverse_flow_ratio_tolerance": 0.25,
            "udp_zero_checksum_tolerance": 0.20,
            "src_ip_metric": "target",
            "reverse_flow_metric": "target",
            "udp_checksum_metric": "target",
        }
    else:
        target = _profile_targets(mode=mode, size_profile=size_profile, realistic=realistic)

    if target["src_ip_metric"] == "at_least":
        src_ip_score = _at_least_score(
            float(observed["src_ip_unique"]),
            float(target["src_ip_unique_target"]),
            float(target["src_ip_unique_tolerance"]),
        )
    else:
        src_ip_score = _scalar_score(
            float(observed["src_ip_unique"]),
            float(target["src_ip_unique_target"]),
            float(target["src_ip_unique_tolerance"]),
        )

    if target["reverse_flow_metric"] == "at_least":
        reverse_flow_score = _at_least_score(
            float(observed["reverse_flow_ratio"]),
            float(target["reverse_flow_ratio_target"]),
            float(target["reverse_flow_ratio_tolerance"]),
        )
    else:
        reverse_flow_score = _scalar_score(
            float(observed["reverse_flow_ratio"]),
            float(target["reverse_flow_ratio_target"]),
            float(target["reverse_flow_ratio_tolerance"]),
        )

    if target["udp_checksum_metric"] == "at_most":
        udp_checksum_score = _at_most_score(
            float(observed["udp_zero_checksum_ratio"]),
            float(target["udp_zero_checksum_ratio_target"]),
            float(target["udp_zero_checksum_tolerance"]),
        )
    else:
        udp_checksum_score = _scalar_score(
            float(observed["udp_zero_checksum_ratio"]),
            float(target["udp_zero_checksum_ratio_target"]),
            float(target["udp_zero_checksum_tolerance"]),
        )

    component_scores = {
        "proto": _distribution_score(observed["proto_dist"], target["proto_dist"]),
        "size": _distribution_score(observed["size_dist"], target["size_dist"]),
        "ttl": _distribution_score(observed["ttl_dist"], target["ttl_dist"]),
        "tos": _distribution_score(observed["tos_dist"], target["tos_dist"]),
        "tcp_flags": _distribution_score(observed["tcp_flag_dist"], target["tcp_flag_dist"]),
        "tcp_doff": _distribution_score(observed["tcp_doff_dist"], target["tcp_doff_dist"]),
        "src_ip_diversity": src_ip_score,
        "bidirectional_flows": reverse_flow_score,
        "udp_checksum": udp_checksum_score,
    }

    weights = {
        "proto": 15.0,
        "size": 25.0,
        "ttl": 10.0,
        "tos": 10.0,
        "tcp_flags": 15.0,
        "tcp_doff": 5.0,
        "src_ip_diversity": 10.0,
        "bidirectional_flows": 8.0,
        "udp_checksum": 5.0,
    }
    total_weight = sum(weights.values())
    weighted_sum = 0.0
    for k, w in weights.items():
        weighted_sum += component_scores[k] * w
    overall_score = weighted_sum / total_weight if total_weight > 0 else 0.0

    report = {
        "version": "v3",
        "generated_at_unix": int(time.time()),
        "pcap_path": os.path.abspath(pcap_path),
        "target": target["name"],
        "overall_score": round(overall_score, 3),
        "component_scores": {k: round(v, 3) for k, v in component_scores.items()},
        "observed": observed,
    }

    report_path = None
    if output_filename:
        project_dir = project_dir or os.getcwd()
        report_path = _sanitize_output_path(output_filename, project_dir)
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

    return report, (os.path.abspath(report_path) if report_path else None)
