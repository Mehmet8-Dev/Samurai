"""Native CUDA packet facade.

Public import path remains ``ddos_samurai.gpu_packet``.
This module exposes the native C++/CUDA backend only.
"""

from __future__ import annotations

import ipaddress
import os
import random
import threading
import numpy as np

try:
    from numba import cuda as _numba_cuda
    from numba.cuda.random import create_xoroshiro128p_states
except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):  # pragma: no cover - depends on runtime
    _numba_cuda = None

    def create_xoroshiro128p_states(*_args, **_kwargs):
        return None

try:
    from . import _gpu_packet_cuda_backend as _backend
except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError) as _cuda_import_exc:  # pragma: no cover - depends on runtime
    _backend = None
    _CUDA_IMPORT_ERROR = _cuda_import_exc
else:
    _CUDA_IMPORT_ERROR = None


ACTIVE_GPU_PACKET_BACKEND = "cuda_cpp"

# Native-only public errors/types
GPUPacketError = getattr(_backend, "GPUPacketError", RuntimeError) if _backend is not None else RuntimeError
GPUMemoryError = getattr(_backend, "GPUMemoryError", RuntimeError) if _backend is not None else RuntimeError
cp = getattr(_backend, "cp", None)

# Shared packet constants used by anomaly helpers/tests.
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

# Legacy constants retained as inert placeholders for callers that still import them.
TEMPLATE_CONST_MAX = 4096
POOL_CONST_MAX = 32768
TEMPLATE_CONST_HOST = np.zeros(TEMPLATE_CONST_MAX, dtype=np.uint8)
POOL_CONST_HOST = np.zeros(POOL_CONST_MAX, dtype=np.uint8)
_CONST_FINGERPRINTS = {
    "TEMPLATE_CONST_HOST": None,
    "POOL_CONST_HOST": None,
}

# Legacy kernel symbols are intentionally unavailable on native-only path.
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

_PY_GPU_CACHE_LOCK = threading.Lock()
_PY_TEMPLATE_CACHE: dict[tuple[int, bool], bool] = {}
_PY_RNG_STATE_POOL: dict[int, object] = {}
_PY_GPU_TELEMETRY = {
    "gpu_template_h2d_copy_count": 0,
    "gpu_template_cache_hit_count": 0,
    "gpu_rng_state_alloc_count": 0,
    "gpu_rng_state_reuse_count": 0,
}


def ip_to_int(ip: str) -> int:
    return int(ipaddress.IPv4Address(str(ip)))


def int_to_ip(value: int) -> str:
    return str(ipaddress.IPv4Address(int(value) & 0xFFFFFFFF))


def parse_subnet(subnet: str) -> tuple[int, int]:
    net = ipaddress.ip_network(str(subnet), strict=False)
    if net.version != 4:
        raise ValueError("Only IPv4 subnet is supported")
    return int(net.network_address), int(net.prefixlen)


def _device_jit(py_func):
    if _numba_cuda is None:
        return py_func
    return _numba_cuda.jit(device=True)(py_func)


@_device_jit
def read_uint16_be(buffer, offset):
    return ((int(buffer[offset]) & 0xFF) << 8) | (int(buffer[offset + 1]) & 0xFF)


@_device_jit
def read_uint32_be(buffer, offset):
    return (
        ((int(buffer[offset]) & 0xFF) << 24)
        | ((int(buffer[offset + 1]) & 0xFF) << 16)
        | ((int(buffer[offset + 2]) & 0xFF) << 8)
        | (int(buffer[offset + 3]) & 0xFF)
    )


@_device_jit
def write_uint16_be(buffer, offset, value):
    buffer[offset] = (int(value) >> 8) & 0xFF
    buffer[offset + 1] = int(value) & 0xFF


@_device_jit
def write_uint32_be(buffer, offset, value):
    buffer[offset] = (int(value) >> 24) & 0xFF
    buffer[offset + 1] = (int(value) >> 16) & 0xFF
    buffer[offset + 2] = (int(value) >> 8) & 0xFF
    buffer[offset + 3] = int(value) & 0xFF


@_device_jit
def calculate_checksum(buffer, offset, length):
    end = int(offset) + int(length)
    s = 0
    i = int(offset)
    while i + 1 < end:
        s += ((int(buffer[i]) & 0xFF) << 8) | (int(buffer[i + 1]) & 0xFF)
        s = (s & 0xFFFF) + (s >> 16)
        i += 2
    if i < end:
        s += (int(buffer[i]) & 0xFF) << 8
        s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


@_device_jit
def _pseudo_header_sum(src_ip, dst_ip, protocol, length):
    src = int(src_ip) & 0xFFFFFFFF
    dst = int(dst_ip) & 0xFFFFFFFF
    s = ((src >> 16) & 0xFFFF) + (src & 0xFFFF)
    s += ((dst >> 16) & 0xFFFF) + (dst & 0xFFFF)
    s += int(protocol) & 0xFF
    s += int(length) & 0xFFFF
    return s


@_device_jit
def _checksum_from_words(words_sum):
    s = int(words_sum)
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


@_device_jit
def calculate_tcp_checksum_optimized(buffer, offset, length, src_ip, dst_ip):
    s = _pseudo_header_sum(src_ip, dst_ip, TCP_PROTOCOL, length)
    end = int(offset) + int(length)
    i = int(offset)
    while i + 1 < end:
        s += ((int(buffer[i]) & 0xFF) << 8) | (int(buffer[i + 1]) & 0xFF)
        i += 2
    if i < end:
        s += (int(buffer[i]) & 0xFF) << 8
    return _checksum_from_words(s)


@_device_jit
def calculate_udp_checksum_optimized(buffer, offset, length, src_ip, dst_ip):
    s = _pseudo_header_sum(src_ip, dst_ip, UDP_PROTOCOL, length)
    end = int(offset) + int(length)
    i = int(offset)
    while i + 1 < end:
        s += ((int(buffer[i]) & 0xFF) << 8) | (int(buffer[i + 1]) & 0xFF)
        i += 2
    if i < end:
        s += (int(buffer[i]) & 0xFF) << 8
    out = _checksum_from_words(s)
    return out if out != 0 else 0xFFFF


@_device_jit
def calculate_icmp_checksum(buffer, offset, length):
    return calculate_checksum(buffer, offset, length)


def _require_native_backend():
    if _backend is None:
        raise GPUPacketError(f"cuda_cpp backend import failed: {_CUDA_IMPORT_ERROR}")
    return _backend


def _backend_call(name: str, *args, **kwargs):
    backend = _require_native_backend()
    fn = getattr(backend, name, None)
    if not callable(fn):
        raise AttributeError(f"cuda_cpp backend does not expose {name}")
    return fn(*args, **kwargs)


def _telemetry_inc(key: str, delta: int = 1) -> None:
    with _PY_GPU_CACHE_LOCK:
        _PY_GPU_TELEMETRY[key] = int(_PY_GPU_TELEMETRY.get(key, 0) or 0) + int(delta)


def _telemetry_snapshot() -> dict:
    with _PY_GPU_CACHE_LOCK:
        return {str(k): int(v) for k, v in _PY_GPU_TELEMETRY.items()}


def _telemetry_reset() -> None:
    with _PY_GPU_CACHE_LOCK:
        for key in list(_PY_GPU_TELEMETRY.keys()):
            _PY_GPU_TELEMETRY[key] = 0


def _template_cache_key(template_bytes, has_ethernet) -> tuple[int, bool]:
    payload = bytes(template_bytes or b"")
    return (hash(payload), bool(has_ethernet))


def _cache_max_entries() -> int:
    raw = str(os.environ.get("SAMURAI_GPU_CACHE_MAX_ENTRIES", "128") or "128").strip()
    try:
        return max(1, int(raw))
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        return 128


def _rng_pool_max_entries() -> int:
    raw = str(os.environ.get("SAMURAI_GPU_RNG_POOL_MAX_ENTRIES", "16") or "16").strip()
    try:
        return max(1, int(raw))
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        return 16


def _touch_template_cache(template_bytes, has_ethernet) -> None:
    key = _template_cache_key(template_bytes, has_ethernet)
    with _PY_GPU_CACHE_LOCK:
        if key in _PY_TEMPLATE_CACHE:
            _PY_GPU_TELEMETRY["gpu_template_cache_hit_count"] = int(
                _PY_GPU_TELEMETRY.get("gpu_template_cache_hit_count", 0)
            ) + 1
            return
        if len(_PY_TEMPLATE_CACHE) >= _cache_max_entries():
            _PY_TEMPLATE_CACHE.pop(next(iter(_PY_TEMPLATE_CACHE)))
        _PY_TEMPLATE_CACHE[key] = True
        _PY_GPU_TELEMETRY["gpu_template_h2d_copy_count"] = int(
            _PY_GPU_TELEMETRY.get("gpu_template_h2d_copy_count", 0)
        ) + 1


def _touch_rng_pool(count: int) -> None:
    c = max(0, int(count))
    with _PY_GPU_CACHE_LOCK:
        if c in _PY_RNG_STATE_POOL:
            _PY_GPU_TELEMETRY["gpu_rng_state_reuse_count"] = int(
                _PY_GPU_TELEMETRY.get("gpu_rng_state_reuse_count", 0)
            ) + 1
            return
    state = create_xoroshiro128p_states(c, seed=random.randint(0, 0xFFFFFFFF))
    with _PY_GPU_CACHE_LOCK:
        if len(_PY_RNG_STATE_POOL) >= _rng_pool_max_entries() and c not in _PY_RNG_STATE_POOL:
            _PY_RNG_STATE_POOL.pop(next(iter(_PY_RNG_STATE_POOL)))
        if c not in _PY_RNG_STATE_POOL:
            _PY_RNG_STATE_POOL[c] = state
            _PY_GPU_TELEMETRY["gpu_rng_state_alloc_count"] = int(
                _PY_GPU_TELEMETRY.get("gpu_rng_state_alloc_count", 0)
            ) + 1


def _const_payload_fingerprint(src: np.ndarray):
    src_bytes = src.tobytes(order="C")
    return (int(src.size), hash(src_bytes))


def _update_gpu_constant(symbol_name, host_data):
    if symbol_name == "TEMPLATE_CONST_HOST":
        backing = TEMPLATE_CONST_HOST
        dispatcher = template_kernel
    elif symbol_name == "POOL_CONST_HOST":
        backing = POOL_CONST_HOST
        dispatcher = pool_kernel
    else:
        raise ValueError(f"Unknown constant symbol: {symbol_name}")

    src = np.asarray(host_data, dtype=np.uint8).ravel(order="A")
    if src.nbytes > backing.nbytes:
        return False

    new_fingerprint = _const_payload_fingerprint(src)
    old_fingerprint = _CONST_FINGERPRINTS.get(symbol_name)
    dispatchers_compiled = bool(getattr(dispatcher, "overloads", None))
    if dispatchers_compiled and old_fingerprint != new_fingerprint:
        return False

    if old_fingerprint == new_fingerprint:
        return True

    backing[:src.size] = src
    if src.size < backing.size:
        backing[src.size:] = 0
    _CONST_FINGERPRINTS[symbol_name] = new_fingerprint
    return True


def get_active_backend_name() -> str:
    return str(ACTIVE_GPU_PACKET_BACKEND)


def is_native_path_enabled() -> bool:
    return True


def is_native_library_available() -> bool:
    return bool(_backend_call("is_native_library_available"))


def is_native_path_active() -> bool:
    return bool(_backend_call("is_native_path_active"))


def get_native_policy() -> str:
    return "require"


def is_native_policy_require() -> bool:
    return True


def init_gpu():
    return _backend_call("init_gpu")


def set_kernel_mode(mode: str):
    return _backend_call("set_kernel_mode", mode)


def get_kernel_mode() -> str:
    return _backend_call("get_kernel_mode")


def start_stream(profile):
    return _backend_call("start_stream", profile)


def update_stream(stream_id, update):
    return _backend_call("update_stream", stream_id, update)


def stop_stream(stream_id):
    return _backend_call("stop_stream", stream_id)


def read_stream_stats(stream_id=None):
    return _backend_call("read_stream_stats", stream_id)


def read_stream_stats_snapshot(stream_id=None):
    return _backend_call("read_stream_stats_snapshot", stream_id)


def shutdown_persistent_runtime():
    return _backend_call("shutdown_persistent_runtime")


def generate_packets(*args, **kwargs):
    return _backend_call("generate_packets", *args, **kwargs)


def generate_packets_from_template(*args, **kwargs):
    template_bytes = kwargs.get("template_bytes")
    if template_bytes is None and args:
        template_bytes = args[0]
    has_ethernet = kwargs.get("has_ethernet", False)
    count = kwargs.get("count")
    if count is None and len(args) > 1:
        count = args[1]
    _touch_template_cache(template_bytes, has_ethernet)
    _touch_rng_pool(int(count or 0))
    return _backend_call("generate_packets_from_template", *args, **kwargs)


def generate_packets_from_template_pool(*args, **kwargs):
    return _backend_call("generate_packets_from_template_pool", *args, **kwargs)


def generate_fragmented_packets(*args, **kwargs):
    return _backend_call("generate_fragmented_packets", *args, **kwargs)


def generate_amplification_packets(*args, **kwargs):
    return _backend_call("generate_amplification_packets", *args, **kwargs)


def generate_stateful_packets(*args, **kwargs):
    return _backend_call("generate_stateful_packets", *args, **kwargs)


def benchmark_template_generation_paths(*args, **kwargs):
    return _backend_call("benchmark_template_generation_paths", *args, **kwargs)


def generate_icmp_packets(*args, **kwargs):
    return _backend_call("generate_icmp_packets", *args, **kwargs)


def get_generation_telemetry() -> dict:
    out = dict(_backend_call("get_generation_telemetry") or {})
    py_tel = _telemetry_snapshot()
    for key, value in py_tel.items():
        out[key] = int(value)
    return out


def reset_generation_telemetry() -> None:
    _telemetry_reset()
    _backend_call("reset_generation_telemetry")


def clear_generation_caches() -> None:
    with _PY_GPU_CACHE_LOCK:
        _PY_TEMPLATE_CACHE.clear()
        _PY_RNG_STATE_POOL.clear()
    _backend_call("clear_generation_caches")


def get_memory_pool():
    return _backend_call("get_memory_pool")


def get_pinned_host_pool():
    return _backend_call("get_pinned_host_pool")


def configure_pinned_host_pool(*args, **kwargs) -> None:
    _backend_call("configure_pinned_host_pool", *args, **kwargs)


def copy_gpu_to_host_pinned(*args, **kwargs):
    return _backend_call("copy_gpu_to_host_pinned", *args, **kwargs)


def get_pool_telemetry() -> dict:
    return _backend_call("get_pool_telemetry")


def safe_kernel_launch(*args, **kwargs):
    return _backend_call("safe_kernel_launch", *args, **kwargs)


def check_gpu_available():
    return _backend_call("check_gpu_available")


def get_gpu_info() -> dict:
    return _backend_call("get_gpu_info")


def is_gpu_available() -> bool:
    return bool(_backend_call("is_gpu_available"))


class GPUPacketGenerator:
    """Native-only wrapper preserving the public constructor contract."""

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
            return_host_ready=True,
        )
        if isinstance(packets_gpu, memoryview):
            packets_host = np.frombuffer(packets_gpu, dtype=np.uint8)
        else:
            packets_host = np.asarray(packets_gpu, dtype=np.uint8)
        return [
            bytes(packets_host[i * packet_size : (i + 1) * packet_size])
            for i in range(count)
        ]
