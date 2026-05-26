"""ZMQ-only GPU control facade.

The old Python CUDA bridge was intentionally removed.  This module keeps the
public import path ``ddos_samurai.gpu_packet`` for control-plane callers, but it
never loads ``libgpu_packet_cuda.so`` directly.  GPU work is submitted to the
native ZMQ GPU worker.
"""

from __future__ import annotations

import ipaddress
import itertools
import os
import time
from typing import Any, Mapping

try:  # Optional: callers may still use the symbol for CPU-side arrays.
    import numpy as np
except Exception:  # pragma: no cover - import-environment dependent
    np = None  # type: ignore

from .zmq.dispatcher import DispatchResult, ZmqDispatcher
from .zmq.wire import FlowUpdateEventV1, WorkerKind

ACTIVE_GPU_PACKET_BACKEND = "zmq"

ETHERNET_HEADER_LEN = 14
IP_HEADER_LEN = 20
TCP_HEADER_LEN_NO_OPT = 20
TCP_HEADER_LEN_WITH_OPT = 40
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8
TCP_PROTOCOL = 6
UDP_PROTOCOL = 17
ICMP_PROTOCOL = 1
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80

DESCRIPTOR_STATE_FREE = 0
DESCRIPTOR_STATE_GPU_WRITING = 1
DESCRIPTOR_STATE_READY_FOR_NIC = 2
DESCRIPTOR_STATE_NIC_OWNED = 3
DESCRIPTOR_STATE_COMPLETE = 4

TEMPLATE_CONST_MAX = 4096
POOL_CONST_MAX = 32768
if np is not None:
    TEMPLATE_CONST_HOST = np.zeros(TEMPLATE_CONST_MAX, dtype=np.uint8)
    POOL_CONST_HOST = np.zeros(POOL_CONST_MAX, dtype=np.uint8)
else:  # pragma: no cover
    TEMPLATE_CONST_HOST = bytearray(TEMPLATE_CONST_MAX)
    POOL_CONST_HOST = bytearray(POOL_CONST_MAX)

# Legacy kernel symbols are gone with the Python bridge.
template_kernel = None
pool_kernel = None
stateful_pool_kernel = None
create_tcp_packets_kernel_spoof = None
create_tcp_packets_kernel_nospoof = None
create_udp_packets_kernel_spoof = None
create_udp_packets_kernel_nospoof = None
create_icmp_packets_kernel = None
create_fragmented_packets_kernel = None
amplification_kernel_v2 = None

_CORRELATION_IDS = itertools.count(int(time.time() * 1000) & 0x7FFFFFFF)
_DEFAULT_DISPATCHER: ZmqDispatcher | None = None


class GPUPacketError(RuntimeError):
    pass


class GPUMemoryError(GPUPacketError):
    pass


def _next_correlation_id() -> int:
    return int(next(_CORRELATION_IDS))


def _dispatcher(dispatcher: ZmqDispatcher | None = None) -> ZmqDispatcher:
    global _DEFAULT_DISPATCHER
    if dispatcher is not None:
        return dispatcher
    if _DEFAULT_DISPATCHER is None:
        _DEFAULT_DISPATCHER = ZmqDispatcher()
    return _DEFAULT_DISPATCHER


def _bridge_removed(name: str):
    raise GPUPacketError(
        f"{name} removed: Python CUDA bridge is disabled; submit GPU work through the ZMQ GPU worker"
    )


def ip_to_int(ip: str) -> int:
    return int(ipaddress.IPv4Address(str(ip)))


def int_to_ip(value: int) -> str:
    return str(ipaddress.IPv4Address(int(value) & 0xFFFFFFFF))


def parse_subnet(subnet: str) -> tuple[int, int]:
    net = ipaddress.ip_network(str(subnet), strict=False)
    if net.version != 4:
        raise ValueError("Only IPv4 subnet is supported")
    return int(net.network_address), int(net.prefixlen)


def _buf_get(buffer: Any, offset: int) -> int:
    return int(buffer[int(offset)]) & 0xFF


def read_uint16_be(buffer: Any, offset: int) -> int:
    return (_buf_get(buffer, offset) << 8) | _buf_get(buffer, int(offset) + 1)


def read_uint32_be(buffer: Any, offset: int) -> int:
    return (
        (_buf_get(buffer, offset) << 24)
        | (_buf_get(buffer, int(offset) + 1) << 16)
        | (_buf_get(buffer, int(offset) + 2) << 8)
        | _buf_get(buffer, int(offset) + 3)
    )


def write_uint16_be(buffer: Any, offset: int, value: int) -> None:
    buffer[int(offset)] = (int(value) >> 8) & 0xFF
    buffer[int(offset) + 1] = int(value) & 0xFF


def write_uint32_be(buffer: Any, offset: int, value: int) -> None:
    buffer[int(offset)] = (int(value) >> 24) & 0xFF
    buffer[int(offset) + 1] = (int(value) >> 16) & 0xFF
    buffer[int(offset) + 2] = (int(value) >> 8) & 0xFF
    buffer[int(offset) + 3] = int(value) & 0xFF


def calculate_checksum(buffer: Any, offset: int, length: int) -> int:
    end = int(offset) + int(length)
    s = 0
    i = int(offset)
    while i + 1 < end:
        s += read_uint16_be(buffer, i)
        s = (s & 0xFFFF) + (s >> 16)
        i += 2
    if i < end:
        s += _buf_get(buffer, i) << 8
        s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _pseudo_header_sum(src_ip: int, dst_ip: int, protocol: int, length: int) -> int:
    src = int(src_ip) & 0xFFFFFFFF
    dst = int(dst_ip) & 0xFFFFFFFF
    s = ((src >> 16) & 0xFFFF) + (src & 0xFFFF)
    s += ((dst >> 16) & 0xFFFF) + (dst & 0xFFFF)
    s += int(protocol) & 0xFF
    s += int(length) & 0xFFFF
    return s


def _checksum_from_words(words_sum: int) -> int:
    s = int(words_sum)
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def calculate_tcp_checksum_optimized(buffer: Any, offset: int, length: int, src_ip: int, dst_ip: int) -> int:
    s = _pseudo_header_sum(src_ip, dst_ip, TCP_PROTOCOL, length)
    end = int(offset) + int(length)
    i = int(offset)
    while i + 1 < end:
        s += read_uint16_be(buffer, i)
        i += 2
    if i < end:
        s += _buf_get(buffer, i) << 8
    return _checksum_from_words(s)


def calculate_udp_checksum_optimized(buffer: Any, offset: int, length: int, src_ip: int, dst_ip: int) -> int:
    out = calculate_tcp_checksum_optimized(buffer, offset, length, src_ip, dst_ip)
    return out if out != 0 else 0xFFFF


def calculate_icmp_checksum(buffer: Any, offset: int, length: int) -> int:
    return calculate_checksum(buffer, offset, length)


def get_active_backend_name() -> str:
    return ACTIVE_GPU_PACKET_BACKEND


def is_native_path_enabled() -> bool:
    return False


def is_native_library_available() -> bool:
    return False


def is_native_path_active() -> bool:
    return False


def get_native_policy() -> str:
    return "removed"


def is_native_policy_require() -> bool:
    return False


def init_gpu() -> bool:
    _dispatcher()
    return True


def set_kernel_mode(mode: str):
    if str(mode or "").strip().lower() != "persistent":
        raise GPUPacketError("ZMQ GPU runtime supports persistent worker mode only")
    return "persistent"


def get_kernel_mode() -> str:
    return "persistent"


def start_stream(profile: Mapping[str, Any] | None = None, *, dispatcher: ZmqDispatcher | None = None, endpoint: str | None = None) -> DispatchResult:
    args = dict(profile or {})
    return _dispatcher(dispatcher).dispatch_start_job(
        worker_kind=WorkerKind.GPU,
        correlation_id=_next_correlation_id(),
        job_id=str(args.get("job_id") or args.get("stream_id") or "gpu-zmq-stream"),
        args=args,
        endpoint=endpoint,
    )


def update_stream(stream_id: Any, update: Mapping[str, Any] | None = None, *, dispatcher: ZmqDispatcher | None = None, endpoint: str | None = None) -> DispatchResult:
    args = dict(update or {})
    args.setdefault("stream_id", stream_id)
    args.setdefault("op", "update_stream")
    return _dispatcher(dispatcher).dispatch_start_job(
        worker_kind=WorkerKind.GPU,
        correlation_id=_next_correlation_id(),
        job_id=str(args.get("job_id") or f"gpu-zmq-update-{stream_id}"),
        args=args,
        endpoint=endpoint,
    )


def stop_stream(stream_id: Any, *, dispatcher: ZmqDispatcher | None = None, endpoint: str | None = None) -> DispatchResult:
    return _dispatcher(dispatcher).dispatch_stop_job(
        worker_kind=WorkerKind.GPU,
        correlation_id=_next_correlation_id(),
        job_id=str(stream_id or "gpu-zmq-stream"),
        endpoint=endpoint,
    )


def shutdown_persistent_runtime(*, dispatcher: ZmqDispatcher | None = None, endpoint: str | None = None) -> DispatchResult:
    return _dispatcher(dispatcher).dispatch_shutdown_worker(
        worker_kind=WorkerKind.GPU,
        correlation_id=_next_correlation_id(),
        endpoint=endpoint,
    )


def read_stream_stats(stream_id: Any = None) -> dict[str, Any]:
    _ = stream_id
    return {
        "backend": ACTIVE_GPU_PACKET_BACKEND,
        "transport": "zmq",
        "python_cuda_bridge_active": 0,
        "runtime_active": 0,
    }


def read_stream_stats_snapshot(stream_id: Any = None) -> dict[str, Any]:
    return read_stream_stats(stream_id)


def publication_budget_us(rtt_us: int) -> int:
    return max(50, min(1000, int(rtt_us) // 10))


def seqlock_next_versions(current_version: int) -> tuple[int, int]:
    base = int(current_version)
    if base & 1:
        base += 1
    return base + 1, base + 2


def descriptor_transition_valid(from_state: int, to_state: int) -> bool:
    return (int(from_state), int(to_state)) in {
        (DESCRIPTOR_STATE_FREE, DESCRIPTOR_STATE_GPU_WRITING),
        (DESCRIPTOR_STATE_GPU_WRITING, DESCRIPTOR_STATE_READY_FOR_NIC),
        (DESCRIPTOR_STATE_READY_FOR_NIC, DESCRIPTOR_STATE_NIC_OWNED),
        (DESCRIPTOR_STATE_NIC_OWNED, DESCRIPTOR_STATE_COMPLETE),
        (DESCRIPTOR_STATE_COMPLETE, DESCRIPTOR_STATE_FREE),
    }


def compute_flow_affinity(block_idx: int, block_dim: int, thread_idx: int, flows_per_warp: int, warp_size: int = 32) -> dict[str, int]:
    bd = max(1, int(block_dim))
    ws = max(1, int(warp_size))
    fpw = max(1, int(flows_per_warp))
    tid = int(block_idx) * bd + int(thread_idx)
    global_warp_id = tid // ws
    lane = int(thread_idx) % ws
    flow_start = global_warp_id * fpw
    return {
        "global_tid": tid,
        "global_warp_id": global_warp_id,
        "lane": lane,
        "flow_start": flow_start,
        "flow_id": flow_start + lane,
    }


def _coerce_flow_update(event: Any) -> FlowUpdateEventV1:
    if isinstance(event, FlowUpdateEventV1):
        return event
    if not isinstance(event, Mapping):
        raise TypeError("flow update event must be FlowUpdateEventV1 or mapping")
    return FlowUpdateEventV1(
        version=int(event.get("version", 0) or 0),
        epoch=int(event.get("epoch", 0) or 0),
        flow_id=int(event.get("flow_id", 0) or 0),
        tcp_seq=int(event.get("tcp_seq", 0) or 0),
        tcp_ack=int(event.get("tcp_ack", 0) or 0),
        src_port=int(event.get("src_port", 0) or 0),
        dst_port=int(event.get("dst_port", 0) or 0),
        tcp_state=int(event.get("tcp_state", 0) or 0),
        proto=int(event.get("proto", 0) or 0),
        flags=int(event.get("flags", 0) or 0),
        rtt_us=int(event.get("rtt_us", 0) or 0),
        dpu_ts_ns=int(event.get("dpu_ts_ns", 0) or 0),
    )


def contract_publish_flow_update_v1(
    event: Any,
    *,
    dispatcher: ZmqDispatcher | None = None,
    endpoint: str | None = None,
    correlation_id: int | None = None,
    job_id: str = "flow-update",
    allow_version_gap: bool = False,
) -> DispatchResult:
    ev = _coerce_flow_update(event)
    return _dispatcher(dispatcher).dispatch_flow_update(
        correlation_id=int(correlation_id if correlation_id is not None else _next_correlation_id()),
        job_id=str(job_id or f"flow-{ev.flow_id}"),
        event=ev,
        allow_version_gap=bool(allow_version_gap),
        endpoint=endpoint,
    )


def contract_read_hot_flow_v1(flow_id: int) -> dict[str, int]:
    raise GPUPacketError(
        f"hot-flow read for flow_id={int(flow_id)} is not available through Python; consume worker metrics/events over ZMQ"
    )


def generate_packets(*args, **kwargs):
    _ = args, kwargs
    return _bridge_removed("generate_packets")


def generate_packets_from_template(*args, **kwargs):
    _ = args, kwargs
    return _bridge_removed("generate_packets_from_template")


def generate_packets_from_template_pool(*args, **kwargs):
    _ = args, kwargs
    return _bridge_removed("generate_packets_from_template_pool")


def generate_fragmented_packets(*args, **kwargs):
    _ = args, kwargs
    return _bridge_removed("generate_fragmented_packets")


def generate_amplification_packets(*args, **kwargs):
    _ = args, kwargs
    return _bridge_removed("generate_amplification_packets")


def generate_stateful_packets(*args, **kwargs):
    _ = args, kwargs
    return _bridge_removed("generate_stateful_packets")


def benchmark_template_generation_paths(*args, **kwargs):
    _ = args, kwargs
    return _bridge_removed("benchmark_template_generation_paths")


def generate_icmp_packets(*args, **kwargs):
    _ = args, kwargs
    return _bridge_removed("generate_icmp_packets")


def get_generation_telemetry() -> dict[str, Any]:
    return {"backend": ACTIVE_GPU_PACKET_BACKEND, "python_cuda_bridge_active": 0}


def reset_generation_telemetry() -> None:
    return None


def clear_generation_caches() -> None:
    return None


def get_memory_pool():
    return None


def get_pinned_host_pool():
    return None


def configure_pinned_host_pool(*args, **kwargs) -> None:
    _ = args, kwargs
    return None


def copy_gpu_to_host_pinned(*args, **kwargs):
    _ = args, kwargs
    return _bridge_removed("copy_gpu_to_host_pinned")


def get_pool_telemetry() -> dict[str, int]:
    return {}


def safe_kernel_launch(*args, **kwargs):
    _ = args, kwargs
    return _bridge_removed("safe_kernel_launch")


def check_gpu_available() -> bool:
    return True


def get_gpu_info() -> dict[str, Any]:
    return {"backend": ACTIVE_GPU_PACKET_BACKEND, "transport": "zmq"}


def is_gpu_available() -> bool:
    try:
        _dispatcher()
        return True
    except Exception:
        return False


class GPUPacketGenerator:
    """Compatibility wrapper that rejects synchronous packet generation."""

    def __init__(self, max_batch_size: int = 100000, **kwargs: Any):
        self.max_batch_size = int(max(1, max_batch_size))
        self.options = dict(kwargs)

    def generate_batch(self, template_bytes: bytes, batch_size: int):
        _ = template_bytes, batch_size
        return _bridge_removed("GPUPacketGenerator.generate_batch")
