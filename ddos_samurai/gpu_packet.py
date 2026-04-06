"""Native CUDA packet facade.

Public import path remains ``ddos_samurai.gpu_packet``.

Packet generation is native-only and routed through the CUDA C++ bridge.
Shared constants, validation helpers, and diagnostics are re-exported from
``gpu_packet_py_backend`` to preserve the public module surface.
"""

from __future__ import annotations

from . import gpu_packet_py_backend as _support
from .gpu_packet_py_backend import *  # noqa: F401,F403 - public compatibility surface

try:
    from . import _gpu_packet_cuda_backend as _cuda_cpp_backend
except Exception as _cuda_import_exc:  # pragma: no cover - depends on runtime
    _cuda_cpp_backend = None
    _CUDA_IMPORT_ERROR = _cuda_import_exc
else:
    _CUDA_IMPORT_ERROR = None


ACTIVE_GPU_PACKET_BACKEND = "cuda_cpp"
_ACTIVE_BACKEND = _cuda_cpp_backend

# Backward-compatible aliases used by tests and by anomaly_packet imports.
GPUPacketError = _support.GPUPacketError
GPUMemoryError = _support.GPUMemoryError
cp = _support.cp
_CONST_FINGERPRINTS = _support._CONST_FINGERPRINTS
TEMPLATE_CONST_HOST = _support.TEMPLATE_CONST_HOST
POOL_CONST_HOST = _support.POOL_CONST_HOST
create_xoroshiro128p_states = _support.create_xoroshiro128p_states
template_kernel = _support.template_kernel
pool_kernel = _support.pool_kernel
stateful_pool_kernel = _support.stateful_pool_kernel
create_tcp_packets_kernel_spoof = _support.create_tcp_packets_kernel_spoof
create_tcp_packets_kernel_nospoof = _support.create_tcp_packets_kernel_nospoof
create_udp_packets_kernel_spoof = _support.create_udp_packets_kernel_spoof
create_udp_packets_kernel_nospoof = _support.create_udp_packets_kernel_nospoof
create_icmp_packets_kernel = _support.create_icmp_packets_kernel
create_fragmented_packets_kernel = _support.create_fragmented_packets_kernel
amplification_kernel_v2 = _support.amplification_kernel_v2


def _require_native_backend():
    if _ACTIVE_BACKEND is None:
        raise GPUPacketError(f"cuda_cpp backend import failed: {_CUDA_IMPORT_ERROR}")
    return _ACTIVE_BACKEND


def _backend_call(name: str, *args, **kwargs):
    backend = _require_native_backend()
    fn = getattr(backend, name, None)
    if not callable(fn):
        raise AttributeError(f"cuda_cpp backend does not expose {name}")
    return fn(*args, **kwargs)


def get_active_backend_name() -> str:
    return str(ACTIVE_GPU_PACKET_BACKEND)


def is_native_path_enabled() -> bool:
    return True


def is_native_library_available() -> bool:
    backend = _require_native_backend()
    fn = getattr(backend, "is_native_library_available", None)
    return bool(fn()) if callable(fn) else False


def is_native_path_active() -> bool:
    backend = _require_native_backend()
    fn = getattr(backend, "is_native_path_active", None)
    return bool(fn()) if callable(fn) else False


def get_native_policy() -> str:
    return "require"


def is_native_policy_require() -> bool:
    return True


def init_gpu():
    return _backend_call("init_gpu")


def generate_packets(*args, **kwargs):
    return _backend_call("generate_packets", *args, **kwargs)


def generate_packets_from_template(*args, **kwargs):
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
    return _backend_call("get_generation_telemetry")


def reset_generation_telemetry() -> None:
    _backend_call("reset_generation_telemetry")


def clear_generation_caches() -> None:
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


def _update_gpu_constant(*args, **kwargs):
    return _support._update_gpu_constant(*args, **kwargs)


def is_gpu_available() -> bool:
    return bool(_backend_call("is_gpu_available"))


class GPUPacketGenerator(_support.GPUPacketGenerator):
    """Native-only wrapper preserving the public constructor contract."""

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
