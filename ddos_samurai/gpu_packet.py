"""GPU packet facade with selectable backend.

Public import path remains ``ddos_samurai.gpu_packet``.
Backend selection is controlled by ``SAMURAI_GPU_PACKET_BACKEND``:
  - ``cuda_cpp`` (default)
  - ``legacy``

When ``cuda_cpp`` is active, native C ABI packet generation is controlled by
``SAMURAI_GPU_PACKET_CUDA_CPP_NATIVE`` (default: enabled).

If ``cuda_cpp`` is requested but unavailable, the module falls back to legacy.
"""

from __future__ import annotations

import logging
import os
import contextlib
from typing import Any

from . import gpu_packet_legacy as _legacy
from .gpu_packet_legacy import *  # noqa: F401,F403 - compatibility re-export

try:
    from . import _gpu_packet_cuda_backend as _cuda_cpp_backend
except Exception as _cuda_import_exc:  # pragma: no cover - depends on runtime
    _cuda_cpp_backend = None
    _CUDA_IMPORT_ERROR = _cuda_import_exc
else:
    _CUDA_IMPORT_ERROR = None

_BACKEND_ENV = "SAMURAI_GPU_PACKET_BACKEND"


def _normalize_backend(raw: str | None) -> str:
    val = str(raw or "cuda_cpp").strip().lower()
    if val in {"legacy", "cuda_cpp"}:
        return val
    return "cuda_cpp"


def _resolve_backend() -> tuple[str, Any]:
    requested = _normalize_backend(os.environ.get(_BACKEND_ENV, "cuda_cpp"))
    if requested == "legacy":
        return "legacy", _legacy

    if _cuda_cpp_backend is not None:
        try:
            if bool(getattr(_cuda_cpp_backend, "is_available", lambda: True)()):
                return "cuda_cpp", _cuda_cpp_backend
        except Exception:
            pass

    if _CUDA_IMPORT_ERROR is not None:
        logging.warning("gpu_packet: cuda_cpp backend import failed, using legacy: %s", _CUDA_IMPORT_ERROR)
    else:
        logging.warning("gpu_packet: cuda_cpp backend unavailable, using legacy")
    return "legacy", _legacy


ACTIVE_GPU_PACKET_BACKEND, _ACTIVE_BACKEND = _resolve_backend()

# Backward-compatibility for tests and callers that introspect legacy internals.
_CONST_FINGERPRINTS = getattr(_legacy, "_CONST_FINGERPRINTS", {})


# Keep monkeypatch-based legacy tests compatible after facade split.
# These symbols are patched on ddos_samurai.gpu_packet in existing tests.
_SYNC_SYMBOLS = [
    "cp",
    "create_xoroshiro128p_states",
    "template_kernel",
    "pool_kernel",
    "stateful_pool_kernel",
    "create_tcp_packets_kernel_spoof",
    "create_tcp_packets_kernel_nospoof",
    "create_udp_packets_kernel_spoof",
    "create_udp_packets_kernel_nospoof",
    "create_icmp_packets_kernel",
    "create_fragmented_packets_kernel",
    "amplification_kernel_v2",
]


@contextlib.contextmanager
def _temporary_synced_legacy_symbols():
    if _legacy is None:
        yield
        return
    g = globals()
    previous = {}
    for name in _SYNC_SYMBOLS:
        if name not in g:
            continue
        previous[name] = getattr(_legacy, name, None)
        try:
            setattr(_legacy, name, g[name])
        except Exception:
            pass
    try:
        yield
    finally:
        for name, value in previous.items():
            try:
                setattr(_legacy, name, value)
            except Exception:
                pass


def _backend_call(name: str, *args, **kwargs):
    if ACTIVE_GPU_PACKET_BACKEND == "legacy":
        with _temporary_synced_legacy_symbols():
            return getattr(_legacy, name)(*args, **kwargs)

    fn = getattr(_ACTIVE_BACKEND, name, None)
    if callable(fn):
        return fn(*args, **kwargs)

    with _temporary_synced_legacy_symbols():
        return getattr(_legacy, name)(*args, **kwargs)


def get_active_backend_name() -> str:
    return str(ACTIVE_GPU_PACKET_BACKEND)


def is_native_path_enabled() -> bool:
    fn = getattr(_ACTIVE_BACKEND, "is_native_path_enabled", None)
    return bool(fn()) if callable(fn) else False


def is_native_library_available() -> bool:
    fn = getattr(_ACTIVE_BACKEND, "is_native_library_available", None)
    return bool(fn()) if callable(fn) else False


def is_native_path_active() -> bool:
    fn = getattr(_ACTIVE_BACKEND, "is_native_path_active", None)
    return bool(fn()) if callable(fn) else False


def get_native_policy() -> str:
    fn = getattr(_ACTIVE_BACKEND, "get_native_policy", None)
    if callable(fn):
        try:
            return str(fn() or "allow")
        except Exception:
            return "allow"
    return "allow"


def is_native_policy_require() -> bool:
    fn = getattr(_ACTIVE_BACKEND, "is_native_policy_require", None)
    if callable(fn):
        try:
            return bool(fn())
        except Exception:
            return False
    return False


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
    # Compatibility: tests patch template_kernel on this facade.
    with _temporary_synced_legacy_symbols():
        return _legacy._update_gpu_constant(*args, **kwargs)


def is_gpu_available() -> bool:
    return bool(_backend_call("is_gpu_available"))


class GPUPacketGenerator(_legacy.GPUPacketGenerator):
    """Facade-aware wrapper preserving legacy constructor contract."""

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
