#!/usr/bin/env python3
"""
GPU dataplane validation and research benchmark helper.

This script benchmarks the in-memory parts of a TRex-like hybrid pipeline:
flow generation (GPU), packet building (GPU), GPU->host copy, and packet
timing schedulers (CPU).

It does not transmit traffic to the network.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    s = sorted(values)
    idx = int(round((pct / 100.0) * (len(s) - 1)))
    idx = max(0, min(len(s) - 1, idx))
    return float(s[idx])


def _safe_mean(values: list[float]) -> float:
    return float(statistics.mean(values)) if values else 0.0


def _safe_stdev(values: list[float]) -> float:
    if len(values) <= 1:
        return 0.0
    return float(statistics.pstdev(values))


def _parse_batches_mb(raw: str) -> list[int]:
    out: list[int] = []
    for part in str(raw or "").split(","):
        token = part.strip()
        if not token:
            continue
        mb = float(token)
        if mb <= 0:
            continue
        out.append(int(mb * 1024 * 1024))
    if not out:
        out = [1 * 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024, 64 * 1024 * 1024]
    return sorted(set(out))


def architecture_map() -> dict[str, Any]:
    return {
        "pipeline": [
            "AI Traffic Model",
            "GPU Flow Generator",
            "GPU Packet Builder",
            "GPU->CPU copy (pinned host memory)",
            "CPU TX Engine (AF_XDP/DPDK/netmap/PF_RING adapter)",
            "NIC",
        ],
        "stage_ownership": {
            "gpu_stage": [
                "flow field generation (ip/port/state)",
                "packet header/payload assembly",
                "checksum preparation",
            ],
            "cpu_stage": [
                "rate scheduling and backpressure",
                "queueing to dataplane backend",
                "control-plane orchestration",
            ],
            "nic_stage": [
                "DMA from host memory",
                "wire transmission",
                "driver/NIC counters",
            ],
        },
        "memory_transfer_points": [
            "template/metadata H2D (CPU->GPU)",
            "packet buffers D2H (GPU->host pinned)",
            "host buffer->dataplane descriptors (mbuf/umem/netmap slot)",
            "NIC DMA read from host memory",
        ],
        "control_questions": {
            "gpu_which_stage": "Flow generation + packet build + checksum",
            "cpu_which_stage": "Scheduling + TX queueing + dataplane control",
            "nic_which_stage": "Final DMA/TX on wire",
        },
    }


def probe_dataplane_backends() -> dict[str, Any]:
    dpdk_bin = shutil.which("dpdk-testpmd") or shutil.which("testpmd")
    netmap_dev = Path("/dev/netmap").exists()
    netmap_tools = [x for x in ("pkt-gen", "bridge", "vale-ctl") if shutil.which(x)]
    pfring_hint_paths = [
        Path("/proc/net/pf_ring"),
        Path("/proc/net/pf_ring/info"),
        Path("/usr/local/lib/libpfring.so"),
        Path("/usr/lib/libpfring.so"),
    ]
    pfring_installed = any(p.exists() for p in pfring_hint_paths) or bool(shutil.which("pfcount"))

    af_xdp_status = {"available": False, "message": "xdp sender probe not executed"}
    try:
        from ddos_samurai import af_xdp_sender

        available, message = af_xdp_sender.check_xdp_available(quiet=True)
        af_xdp_status = {"available": bool(available), "message": str(message)}
    except Exception as exc:
        af_xdp_status = {"available": False, "message": f"probe failed: {type(exc).__name__}: {exc}"}

    return {
        "dpdk": {
            "ready": bool(dpdk_bin),
            "probe": {"binary": dpdk_bin or ""},
            "benchmark_hint": "Use testpmd txonly + NIC counters for PPS/latency/CPU.",
        },
        "af_xdp": {
            "ready": bool(af_xdp_status.get("available")),
            "probe": af_xdp_status,
            "benchmark_hint": "Use AF_XDP native/copy mode and compare queue counters.",
        },
        "netmap": {
            "ready": bool(netmap_dev or netmap_tools),
            "probe": {"dev_netmap": int(netmap_dev), "tools": netmap_tools},
            "benchmark_hint": "Use netmap pkt-gen and collect pps + host CPU.",
        },
        "pf_ring": {
            "ready": bool(pfring_installed),
            "probe": {
                "installed": int(bool(pfring_installed)),
                "pfcount_bin": shutil.which("pfcount") or "",
            },
            "benchmark_hint": "Use PF_RING zc path when supported by NIC/driver.",
        },
    }


def gpu_runtime_status() -> dict[str, Any]:
    info: dict[str, Any] = {
        "cupy_import": False,
        "numba_cuda_import": False,
        "cuda_available": False,
        "device_count": 0,
        "driver_version": "",
        "runtime_version": "",
        "error": "",
    }
    try:
        import cupy as cp

        info["cupy_import"] = True
        try:
            info["device_count"] = int(cp.cuda.runtime.getDeviceCount())
            drv = cp.cuda.runtime.driverGetVersion()
            rt = cp.cuda.runtime.runtimeGetVersion()
            info["driver_version"] = str(drv)
            info["runtime_version"] = str(rt)
        except Exception as exc:
            info["error"] = f"cupy runtime probe failed: {exc}"
    except Exception as exc:
        info["error"] = f"cupy import failed: {exc}"
        return info

    try:
        from numba import cuda

        info["numba_cuda_import"] = True
        info["cuda_available"] = bool(cuda.is_available())
    except Exception as exc:
        info["error"] = f"numba.cuda import failed: {exc}"

    return info


def _skip(reason: str) -> dict[str, Any]:
    return {"status": "skipped", "reason": reason}


def _error(exc: BaseException) -> dict[str, Any]:
    return {"status": "error", "error": f"{type(exc).__name__}: {exc}"}


def benchmark_flow_rng(count: int, iterations: int, seed: int) -> dict[str, Any]:
    try:
        import numpy as np
        import cupy as cp
        from numba import cuda, uint16, uint32, uint8
        from numba.cuda.random import create_xoroshiro128p_states, xoroshiro128p_uniform_float32
    except Exception as exc:
        return _skip(f"GPU dependencies missing: {exc}")

    if not cuda.is_available():
        return _skip("numba.cuda.is_available() is False")

    try:
        @cuda.jit
        def _flow_rng_kernel(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            tcp_state,
            seq,
            ack,
            rng_states,
            src_base,
            src_span,
            dst_base,
            dst_span,
            n,
        ):
            idx = cuda.grid(1)
            if idx >= n:
                return
            r0 = xoroshiro128p_uniform_float32(rng_states, idx)
            r1 = xoroshiro128p_uniform_float32(rng_states, idx)
            r2 = xoroshiro128p_uniform_float32(rng_states, idx)
            r3 = xoroshiro128p_uniform_float32(rng_states, idx)
            r4 = xoroshiro128p_uniform_float32(rng_states, idx)
            r5 = xoroshiro128p_uniform_float32(rng_states, idx)

            src_ip[idx] = uint32(src_base + uint32(r0 * src_span))
            dst_ip[idx] = uint32(dst_base + uint32(r1 * dst_span))
            src_port[idx] = uint16(1024 + uint16(r2 * 64511.0))
            dst_port[idx] = uint16(1 + uint16(r3 * 65534.0))

            # 1=SYN_SENT, 2=ESTABLISHED, 3=FIN_WAIT
            if r4 < 0.2:
                tcp_state[idx] = uint8(1)
            elif r4 < 0.9:
                tcp_state[idx] = uint8(2)
            else:
                tcp_state[idx] = uint8(3)

            seq[idx] = uint32(r5 * 4294967295.0)
            ack[idx] = uint32((r0 + r1) * 2147483647.0)

        count = max(1, int(count))
        iterations = max(1, int(iterations))
        tpb = 256
        blocks = (count + tpb - 1) // tpb

        src_ip = cp.empty(count, dtype=cp.uint32)
        dst_ip = cp.empty(count, dtype=cp.uint32)
        src_port = cp.empty(count, dtype=cp.uint16)
        dst_port = cp.empty(count, dtype=cp.uint16)
        tcp_state = cp.empty(count, dtype=cp.uint8)
        seq = cp.empty(count, dtype=cp.uint32)
        ack = cp.empty(count, dtype=cp.uint32)
        rng_states = create_xoroshiro128p_states(count, seed=int(seed))

        src_base = np.uint32(0x0A000000)  # 10.0.0.0
        src_span = np.uint32(0x00FFFFFF)  # /8 span
        dst_base = np.uint32(0xC0A80000)  # 192.168.0.0
        dst_span = np.uint32(0x0000FFFF)  # /16 span

        _flow_rng_kernel[blocks, tpb](
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            tcp_state,
            seq,
            ack,
            rng_states,
            src_base,
            src_span,
            dst_base,
            dst_span,
            count,
        )
        cuda.synchronize()

        samples_ms: list[float] = []
        for _ in range(iterations):
            ev_start = cp.cuda.Event()
            ev_stop = cp.cuda.Event()
            ev_start.record()
            _flow_rng_kernel[blocks, tpb](
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                tcp_state,
                seq,
                ack,
                rng_states,
                src_base,
                src_span,
                dst_base,
                dst_span,
                count,
            )
            ev_stop.record()
            ev_stop.synchronize()
            samples_ms.append(float(cp.cuda.get_elapsed_time(ev_start, ev_stop)))

        sample_n = min(count, 100000)
        state_sample = cp.asnumpy(tcp_state[:sample_n])
        bins = np.bincount(state_sample, minlength=4).tolist()
        flow_state_dist = {
            "syn_sent": int(bins[1]) if len(bins) > 1 else 0,
            "established": int(bins[2]) if len(bins) > 2 else 0,
            "fin_wait": int(bins[3]) if len(bins) > 3 else 0,
        }

        mean_ms = _safe_mean(samples_ms)
        pps = float(count / max(1e-9, mean_ms / 1000.0))
        return {
            "status": "ok",
            "count": int(count),
            "iterations": int(iterations),
            "threads_per_block": int(tpb),
            "blocks_per_grid": int(blocks),
            "latency_ms": {
                "mean": mean_ms,
                "p95": _percentile(samples_ms, 95.0),
                "stdev": _safe_stdev(samples_ms),
            },
            "throughput_flows_per_s": pps,
            "flow_state_distribution_sample": flow_state_dist,
            "notes": [
                "Thread-per-flow mapping validated.",
                "Divergence risk increases when protocol/state branches grow.",
                "SoA arrays used for coalesced memory access.",
            ],
        }
    except Exception as exc:
        return _error(exc)


def _checksum16(data: bytes) -> int:
    if len(data) % 2 == 1:
        data = data + b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _validate_ipv4_tcp_packet(pkt: bytes, expected_src_ip: int, expected_dst_ip: int, expected_src_port: int, expected_dst_port: int) -> dict[str, Any]:
    if len(pkt) < 54:
        return {"ok": False, "reason": "packet too short"}
    eth_type = int.from_bytes(pkt[12:14], "big")
    if eth_type != 0x0800:
        return {"ok": False, "reason": "ether type is not IPv4"}

    ip_off = 14
    ihl = pkt[ip_off] & 0x0F
    ip_hlen = ihl * 4
    if ip_hlen < 20:
        return {"ok": False, "reason": "invalid IP header length"}

    src_ip = int.from_bytes(pkt[ip_off + 12 : ip_off + 16], "big")
    dst_ip = int.from_bytes(pkt[ip_off + 16 : ip_off + 20], "big")
    if src_ip != expected_src_ip or dst_ip != expected_dst_ip:
        return {"ok": False, "reason": "ip address mismatch"}

    ip_header = bytearray(pkt[ip_off : ip_off + ip_hlen])
    ip_given = int.from_bytes(ip_header[10:12], "big")
    ip_header[10] = 0
    ip_header[11] = 0
    ip_calc = _checksum16(bytes(ip_header))
    if ip_calc != ip_given:
        return {"ok": False, "reason": "ip checksum mismatch"}

    tcp_off = ip_off + ip_hlen
    src_port = int.from_bytes(pkt[tcp_off : tcp_off + 2], "big")
    dst_port = int.from_bytes(pkt[tcp_off + 2 : tcp_off + 4], "big")
    if src_port != expected_src_port or dst_port != expected_dst_port:
        return {"ok": False, "reason": "tcp port mismatch"}

    total_len = int.from_bytes(pkt[ip_off + 2 : ip_off + 4], "big")
    tcp_len = max(0, total_len - ip_hlen)
    tcp_seg = bytearray(pkt[tcp_off : tcp_off + tcp_len])
    if len(tcp_seg) < 20:
        return {"ok": False, "reason": "tcp segment too short"}
    tcp_given = int.from_bytes(tcp_seg[16:18], "big")
    tcp_seg[16] = 0
    tcp_seg[17] = 0
    pseudo = (
        pkt[ip_off + 12 : ip_off + 16]
        + pkt[ip_off + 16 : ip_off + 20]
        + bytes([0, 6])
        + tcp_len.to_bytes(2, "big")
    )
    tcp_calc = _checksum16(pseudo + bytes(tcp_seg))
    if tcp_calc != tcp_given:
        return {"ok": False, "reason": "tcp checksum mismatch"}

    return {"ok": True}


def benchmark_packet_builder(count: int, iterations: int, payload_bytes: int) -> dict[str, Any]:
    try:
        import cupy as cp
        from numba import cuda
    except Exception as exc:
        return _skip(f"GPU dependencies missing: {exc}")

    if not cuda.is_available():
        return _skip("numba.cuda.is_available() is False")

    try:
        payload_bytes = max(0, int(payload_bytes))
        packet_size = 14 + 20 + 20 + payload_bytes
        count = max(1, int(count))
        iterations = max(1, int(iterations))

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
        def _fold_checksum(s):
            s = (s & 0xFFFF) + (s >> 16)
            s = (s & 0xFFFF) + (s >> 16)
            return (~s) & 0xFFFF

        @cuda.jit(device=True)
        def _ip_checksum(buf, ip_off):
            s = 0
            for i in range(0, 20, 2):
                if i == 10:
                    continue
                s += (buf[ip_off + i] << 8) | buf[ip_off + i + 1]
            return _fold_checksum(s)

        @cuda.jit(device=True)
        def _tcp_checksum(buf, tcp_off, tcp_len, src_ip, dst_ip):
            s = 0
            s += (src_ip >> 16) & 0xFFFF
            s += src_ip & 0xFFFF
            s += (dst_ip >> 16) & 0xFFFF
            s += dst_ip & 0xFFFF
            s += 6
            s += tcp_len
            for i in range(0, tcp_len, 2):
                if i == 16:
                    continue
                if i + 1 < tcp_len:
                    w = (buf[tcp_off + i] << 8) | buf[tcp_off + i + 1]
                else:
                    w = buf[tcp_off + i] << 8
                s += w
            return _fold_checksum(s)

        @cuda.jit
        def _packet_builder_kernel(
            out_buf,
            packet_size_local,
            payload_size_local,
            src_ips,
            dst_ips,
            src_ports,
            dst_ports,
            seqs,
            acks,
            n,
        ):
            idx = cuda.grid(1)
            if idx >= n:
                return
            off = idx * packet_size_local
            ip_off = off + 14
            tcp_off = ip_off + 20
            tcp_len = 20 + payload_size_local
            total_ip_len = 20 + tcp_len

            src_ip = src_ips[idx]
            dst_ip = dst_ips[idx]

            # Ethernet
            out_buf[off + 0] = 0x02
            out_buf[off + 1] = 0x00
            out_buf[off + 2] = 0x00
            out_buf[off + 3] = 0x00
            out_buf[off + 4] = 0x00
            out_buf[off + 5] = 0x01
            out_buf[off + 6] = 0x02
            out_buf[off + 7] = 0x00
            out_buf[off + 8] = 0x00
            out_buf[off + 9] = 0x00
            out_buf[off + 10] = 0x00
            out_buf[off + 11] = 0x02
            _write_u16_be(out_buf, off + 12, 0x0800)

            # IPv4 header
            out_buf[ip_off + 0] = 0x45
            out_buf[ip_off + 1] = 0
            _write_u16_be(out_buf, ip_off + 2, total_ip_len)
            _write_u16_be(out_buf, ip_off + 4, idx & 0xFFFF)
            _write_u16_be(out_buf, ip_off + 6, 0x4000)
            out_buf[ip_off + 8] = 64
            out_buf[ip_off + 9] = 6
            _write_u16_be(out_buf, ip_off + 10, 0)
            _write_u32_be(out_buf, ip_off + 12, src_ip)
            _write_u32_be(out_buf, ip_off + 16, dst_ip)
            _write_u16_be(out_buf, ip_off + 10, _ip_checksum(out_buf, ip_off))

            # TCP header
            _write_u16_be(out_buf, tcp_off + 0, src_ports[idx])
            _write_u16_be(out_buf, tcp_off + 2, dst_ports[idx])
            _write_u32_be(out_buf, tcp_off + 4, seqs[idx])
            _write_u32_be(out_buf, tcp_off + 8, acks[idx])
            out_buf[tcp_off + 12] = 0x50
            out_buf[tcp_off + 13] = 0x18
            _write_u16_be(out_buf, tcp_off + 14, 64240)
            _write_u16_be(out_buf, tcp_off + 16, 0)
            _write_u16_be(out_buf, tcp_off + 18, 0)

            # Payload
            for j in range(payload_size_local):
                out_buf[tcp_off + 20 + j] = 0x58  # 'X'

            _write_u16_be(out_buf, tcp_off + 16, _tcp_checksum(out_buf, tcp_off, tcp_len, src_ip, dst_ip))

        idx32 = cp.arange(count, dtype=cp.uint32)
        src_ips = cp.uint32(0x0A000000) + (idx32 & cp.uint32(0x0000FFFF))
        dst_ips = cp.uint32(0xC0A80000) + (idx32 & cp.uint32(0x0000FFFF))
        src_ports = (idx32 % cp.uint32(64511)).astype(cp.uint16) + cp.uint16(1024)
        dst_ports = cp.full(count, 443, dtype=cp.uint16)
        seqs = idx32 * cp.uint32(17) + cp.uint32(1)
        acks = idx32 * cp.uint32(29)
        out_buf = cp.empty(count * packet_size, dtype=cp.uint8)

        tpb = 256
        blocks = (count + tpb - 1) // tpb

        _packet_builder_kernel[blocks, tpb](
            out_buf,
            packet_size,
            payload_bytes,
            src_ips,
            dst_ips,
            src_ports,
            dst_ports,
            seqs,
            acks,
            count,
        )
        cuda.synchronize()

        samples_ms: list[float] = []
        for _ in range(iterations):
            ev_start = cp.cuda.Event()
            ev_stop = cp.cuda.Event()
            ev_start.record()
            _packet_builder_kernel[blocks, tpb](
                out_buf,
                packet_size,
                payload_bytes,
                src_ips,
                dst_ips,
                src_ports,
                dst_ports,
                seqs,
                acks,
                count,
            )
            ev_stop.record()
            ev_stop.synchronize()
            samples_ms.append(float(cp.cuda.get_elapsed_time(ev_start, ev_stop)))

        verify_n = min(8, count)
        host = cp.asnumpy(out_buf[: verify_n * packet_size]).tobytes()
        src_ip_h = cp.asnumpy(src_ips[:verify_n]).tolist()
        dst_ip_h = cp.asnumpy(dst_ips[:verify_n]).tolist()
        src_port_h = cp.asnumpy(src_ports[:verify_n]).tolist()
        dst_port_h = cp.asnumpy(dst_ports[:verify_n]).tolist()

        failures: list[str] = []
        for i in range(verify_n):
            pkt = host[i * packet_size : (i + 1) * packet_size]
            verdict = _validate_ipv4_tcp_packet(
                pkt,
                int(src_ip_h[i]),
                int(dst_ip_h[i]),
                int(src_port_h[i]),
                int(dst_port_h[i]),
            )
            if not verdict.get("ok"):
                failures.append(str(verdict.get("reason", "unknown")))

        mean_ms = _safe_mean(samples_ms)
        pps = float(count / max(1e-9, mean_ms / 1000.0))
        return {
            "status": "ok",
            "count": int(count),
            "iterations": int(iterations),
            "packet_size": int(packet_size),
            "payload_bytes": int(payload_bytes),
            "latency_ms": {
                "mean": mean_ms,
                "p95": _percentile(samples_ms, 95.0),
                "stdev": _safe_stdev(samples_ms),
            },
            "throughput_packets_per_s": pps,
            "validation": {
                "checked_packets": int(verify_n),
                "valid_packets": int(verify_n - len(failures)),
                "failures": failures,
            },
        }
    except Exception as exc:
        return _error(exc)


def _copy_metrics(batch_bytes: int, samples_ms: list[float]) -> dict[str, float]:
    mean_ms = _safe_mean(samples_ms)
    throughput_gbs = (float(batch_bytes) / max(1e-9, mean_ms / 1000.0)) / 1e9
    return {
        "mean_ms": mean_ms,
        "p95_ms": _percentile(samples_ms, 95.0),
        "stdev_ms": _safe_stdev(samples_ms),
        "throughput_gbs": float(throughput_gbs),
    }


def benchmark_gpu_to_host_copy(batch_sizes_bytes: list[int], iterations: int) -> dict[str, Any]:
    try:
        import cupy as cp
        from numba import cuda
        from ddos_samurai import gpu_packet
    except Exception as exc:
        return _skip(f"GPU copy stack unavailable: {exc}")

    if not cuda.is_available():
        return _skip("numba.cuda.is_available() is False")

    try:
        iterations = max(1, int(iterations))
        rows: list[dict[str, Any]] = []
        for batch_bytes in batch_sizes_bytes:
            arr = cp.arange(batch_bytes, dtype=cp.uint8)
            key = f"d2h_{batch_bytes}"

            gpu_packet.copy_gpu_to_host_pinned(arr, key=key, blocking=True)
            _ = arr.get()
            cp.cuda.runtime.deviceSynchronize()

            pinned_ms: list[float] = []
            plain_ms: list[float] = []

            for _ in range(iterations):
                t0 = time.perf_counter_ns()
                _ = gpu_packet.copy_gpu_to_host_pinned(arr, key=key, blocking=True)
                cp.cuda.runtime.deviceSynchronize()
                t1 = time.perf_counter_ns()
                pinned_ms.append((t1 - t0) / 1e6)

                t0 = time.perf_counter_ns()
                _ = arr.get()
                cp.cuda.runtime.deviceSynchronize()
                t1 = time.perf_counter_ns()
                plain_ms.append((t1 - t0) / 1e6)

            rows.append(
                {
                    "batch_bytes": int(batch_bytes),
                    "batch_mb": round(batch_bytes / (1024 * 1024), 3),
                    "pinned": _copy_metrics(batch_bytes, pinned_ms),
                    "plain_get": _copy_metrics(batch_bytes, plain_ms),
                }
            )

        pool_telemetry = {}
        try:
            pool_telemetry = gpu_packet.get_pool_telemetry()
        except Exception:
            pool_telemetry = {}

        return {
            "status": "ok",
            "iterations": int(iterations),
            "results": rows,
            "pool_telemetry": pool_telemetry,
            "notes": [
                "GB/s is end-to-end D2H copy throughput including synchronization.",
                "Pinned path should dominate at medium-large batch sizes.",
            ],
        }
    except Exception as exc:
        return _error(exc)


def _run_token_bucket(n: int, target_rps: float, burst: int = 128) -> tuple[list[int], float, float]:
    rate = max(1.0, float(target_rps))
    tokens = float(max(1, burst))
    cap = float(max(1, burst))
    last_ns = time.perf_counter_ns()
    ts: list[int] = []
    cpu0 = time.process_time()
    wall0 = time.perf_counter()
    for _ in range(n):
        while True:
            now = time.perf_counter_ns()
            elapsed_s = max(0.0, (now - last_ns) / 1e9)
            if elapsed_s > 0.0:
                tokens = min(cap, tokens + elapsed_s * rate)
                last_ns = now
            if tokens >= 1.0:
                tokens -= 1.0
                ts.append(now)
                break
    return ts, time.perf_counter() - wall0, time.process_time() - cpu0


def _run_leaky_bucket(n: int, target_rps: float) -> tuple[list[int], float, float]:
    interval_ns = max(1, int(1e9 / max(1.0, target_rps)))
    next_ns = time.perf_counter_ns()
    ts: list[int] = []
    cpu0 = time.process_time()
    wall0 = time.perf_counter()
    for _ in range(n):
        next_ns += interval_ns
        while True:
            now = time.perf_counter_ns()
            remain = next_ns - now
            if remain <= 0:
                ts.append(now)
                break
            if remain > 300_000:
                time.sleep((remain - 150_000) / 1e9)
    return ts, time.perf_counter() - wall0, time.process_time() - cpu0


def _run_precise_timer(n: int, target_rps: float, spin_ns: int = 150_000) -> tuple[list[int], float, float]:
    interval_ns = max(1, int(1e9 / max(1.0, target_rps)))
    start_ns = time.perf_counter_ns()
    ts: list[int] = []
    cpu0 = time.process_time()
    wall0 = time.perf_counter()
    for i in range(n):
        target_ns = start_ns + ((i + 1) * interval_ns)
        while True:
            now = time.perf_counter_ns()
            remain = target_ns - now
            if remain <= 0:
                ts.append(now)
                break
            if remain > spin_ns:
                time.sleep((remain - spin_ns) / 1e9)
    return ts, time.perf_counter() - wall0, time.process_time() - cpu0


def _summarize_scheduler(name: str, ts: list[int], target_rps: float, wall_s: float, cpu_s: float) -> dict[str, Any]:
    if len(ts) < 2:
        return {"name": name, "status": "error", "reason": "insufficient timestamps"}
    interval_target_ns = float(1e9 / max(1.0, target_rps))
    iats = [float(ts[i] - ts[i - 1]) for i in range(1, len(ts))]
    jitter_abs = [abs(x - interval_target_ns) for x in iats]
    actual_rps = float(len(ts) / max(1e-9, wall_s))
    cpu_usage_pct = float((cpu_s / max(1e-9, wall_s)) * 100.0)
    return {
        "name": name,
        "status": "ok",
        "packets": int(len(ts)),
        "wall_s": float(wall_s),
        "cpu_s": float(cpu_s),
        "cpu_usage_pct": cpu_usage_pct,
        "actual_rps": actual_rps,
        "rate_accuracy_pct": float((actual_rps / max(1e-9, target_rps)) * 100.0),
        "iat_ns": {
            "mean": _safe_mean(iats),
            "p95": _percentile(iats, 95.0),
            "p99": _percentile(iats, 99.0),
            "stdev": _safe_stdev(iats),
        },
        "jitter_abs_ns": {
            "mean": _safe_mean(jitter_abs),
            "p95": _percentile(jitter_abs, 95.0),
            "p99": _percentile(jitter_abs, 99.0),
        },
    }


def benchmark_schedulers(packets: int, target_rps: float) -> dict[str, Any]:
    packets = max(10, int(packets))
    target_rps = max(10.0, float(target_rps))

    token_ts, token_wall, token_cpu = _run_token_bucket(packets, target_rps, burst=128)
    leaky_ts, leaky_wall, leaky_cpu = _run_leaky_bucket(packets, target_rps)
    precise_ts, precise_wall, precise_cpu = _run_precise_timer(packets, target_rps, spin_ns=150_000)

    calib = {}
    caps = {}
    try:
        from ddos_samurai import pacing

        try:
            calib = pacing.calibrate()
        except Exception:
            calib = {}
        try:
            caps = pacing.check_capabilities()
        except Exception:
            caps = {}
    except Exception:
        pass

    return {
        "status": "ok",
        "target_rps": target_rps,
        "packets": packets,
        "modes": [
            _summarize_scheduler("token_bucket", token_ts, target_rps, token_wall, token_cpu),
            _summarize_scheduler("leaky_bucket", leaky_ts, target_rps, leaky_wall, leaky_cpu),
            _summarize_scheduler("precise_timer", precise_ts, target_rps, precise_wall, precise_cpu),
        ],
        "pacing_engine_probe": {
            "calibrate": calib,
            "capabilities": caps,
        },
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    copy_batches = _parse_batches_mb(args.copy_batches_mb)

    return {
        "schema": "samurai.gpu.dataplane.validation.v1",
        "generated_utc": _utc_now_iso(),
        "host": {
            "hostname": platform.node(),
            "os": platform.platform(),
            "python": platform.python_version(),
            "cwd": os.getcwd(),
        },
        "architecture_map": architecture_map(),
        "runtime_probe": {
            "gpu": gpu_runtime_status(),
            "dataplane_backends": probe_dataplane_backends(),
        },
        "benchmarks": {
            "gpu_flow_rng": benchmark_flow_rng(args.count, args.iterations, args.seed),
            "gpu_packet_builder": benchmark_packet_builder(args.count, args.iterations, args.payload_bytes),
            "gpu_to_host_copy": benchmark_gpu_to_host_copy(copy_batches, args.iterations),
            "flow_scheduling": benchmark_schedulers(args.scheduler_packets, args.target_rps),
        },
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="GPU dataplane validation benchmark (flow/build/copy/scheduler)."
    )
    p.add_argument("--count", type=int, default=200000, help="Packet/flow count per GPU benchmark iteration.")
    p.add_argument("--iterations", type=int, default=3, help="Timed iterations per benchmark.")
    p.add_argument("--seed", type=int, default=1337, help="RNG seed for GPU flow benchmark.")
    p.add_argument("--payload-bytes", type=int, default=0, help="TCP payload size used by packet builder benchmark.")
    p.add_argument(
        "--copy-batches-mb",
        default="1,4,16,64",
        help="Comma-separated batch sizes in MB for GPU->host copy benchmark.",
    )
    p.add_argument(
        "--scheduler-packets",
        type=int,
        default=5000,
        help="Number of synthetic packets for scheduler micro-benchmarks.",
    )
    p.add_argument(
        "--target-rps",
        type=float,
        default=100000.0,
        help="Target packet rate for scheduler benchmarks.",
    )
    p.add_argument("--out", default="", help="Optional JSON output path.")
    p.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON to stdout (always prints compact summary otherwise).",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(args)

    out_path = str(args.out or "").strip()
    if out_path:
        out = Path(out_path).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    if args.pretty:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        summary = {
            "schema": report.get("schema"),
            "generated_utc": report.get("generated_utc"),
            "gpu_status": ((report.get("runtime_probe") or {}).get("gpu") or {}).get("cuda_available"),
            "benchmark_statuses": {
                k: (v or {}).get("status")
                for k, v in ((report.get("benchmarks") or {}).items())
            },
            "out": out_path,
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

