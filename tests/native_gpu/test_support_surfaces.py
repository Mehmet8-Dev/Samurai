import importlib.util

import numpy as np
import pytest

_NUMBA_AVAILABLE = importlib.util.find_spec("numba") is not None
if not _NUMBA_AVAILABLE:
    pytest.skip(
        "numba not installed in CI-safe environment; skipping native GPU support tests",
        allow_module_level=True,
    )

import ddos_samurai._gpu_packet_cuda_backend as backend


def test_copy_gpu_to_host_pinned_passthroughs_contiguous_host_array():
    arr = np.arange(8, dtype=np.uint8)
    out = backend.copy_gpu_to_host_pinned(arr, key="unused")
    assert out is arr


def test_check_gpu_available_reports_native_library_state(monkeypatch):
    monkeypatch.setattr(backend, "_LIB", None, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)
    available, message = backend.check_gpu_available()
    assert available is False
    assert "libgpu_packet_cuda.so" in message


def test_get_gpu_info_exposes_native_metadata(monkeypatch):
    marker = object()
    monkeypatch.setattr(backend, "_LIB", marker, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)

    info = backend.get_gpu_info()

    assert info["available"] is True
    assert info["native_enabled"] is True
    assert info["library_loaded"] is True
    assert info["policy"] == "require"
