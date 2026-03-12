import importlib
import importlib.util
import os

import numpy as np
import pytest


_NUMBA_AVAILABLE = importlib.util.find_spec("numba") is not None
pytestmark = [
    pytest.mark.skipif(
        not _NUMBA_AVAILABLE,
        reason="numba not installed in CI-safe environment; skipping GPU backend facade tests",
    )
]


class _FakeKernel:
    def __getitem__(self, _cfg):
        def _launch(*_args, **_kwargs):
            return None

        return _launch


def _load_gpu_packet(backend: str):
    os.environ["SAMURAI_GPU_PACKET_BACKEND"] = backend
    import ddos_samurai.gpu_packet as gp

    return importlib.reload(gp)


def _patch_numpy_runtime(monkeypatch, gp):
    monkeypatch.setattr(
        gp,
        "create_xoroshiro128p_states",
        lambda _c, seed=None: None,
        raising=True,
    )
    monkeypatch.setattr(gp, "create_udp_packets_kernel_nospoof", _FakeKernel(), raising=True)
    monkeypatch.setattr(gp, "template_kernel", _FakeKernel(), raising=True)

    monkeypatch.setattr(
        gp.cp,
        "zeros",
        lambda shape, dtype=None: np.zeros(shape, dtype=np.uint8),
        raising=True,
    )
    monkeypatch.setattr(
        gp.cp,
        "array",
        lambda arr, dtype=None: np.array(arr, dtype=np.uint8),
        raising=True,
    )
    monkeypatch.setattr(
        gp.cp,
        "asarray",
        lambda arr, dtype=None: np.asarray(arr, dtype=np.uint8),
        raising=True,
    )


def test_backend_selection_legacy():
    gp = _load_gpu_packet("legacy")
    assert gp.get_active_backend_name() == "legacy"


def test_backend_selection_cuda_cpp():
    gp = _load_gpu_packet("cuda_cpp")
    assert gp.get_active_backend_name() == "cuda_cpp"


def test_generate_packets_parity_legacy_vs_cuda_cpp(monkeypatch):
    gp_legacy = _load_gpu_packet("legacy")
    _patch_numpy_runtime(monkeypatch, gp_legacy)
    packets_legacy, size_legacy = gp_legacy.generate_packets(
        count=2,
        target_ip="203.0.113.1",
        target_port=53,
        protocol="udp",
        spoof_ip=False,
        has_ethernet=True,
    )

    gp_cpp = _load_gpu_packet("cuda_cpp")
    _patch_numpy_runtime(monkeypatch, gp_cpp)
    packets_cpp, size_cpp = gp_cpp.generate_packets(
        count=2,
        target_ip="203.0.113.1",
        target_port=53,
        protocol="udp",
        spoof_ip=False,
        has_ethernet=True,
    )

    assert size_legacy == size_cpp
    assert np.asarray(packets_legacy, dtype=np.uint8).tobytes() == np.asarray(
        packets_cpp, dtype=np.uint8
    ).tobytes()


def test_generate_template_parity_legacy_vs_cuda_cpp(monkeypatch):
    template = bytes([0x45]) + bytes([0x00] * 63)

    gp_legacy = _load_gpu_packet("legacy")
    _patch_numpy_runtime(monkeypatch, gp_legacy)
    packets_legacy, size_legacy = gp_legacy.generate_packets_from_template(
        template_bytes=template,
        count=8,
        real_src_ip="192.168.1.10",
        spoof_ip=False,
        has_ethernet=False,
    )

    gp_cpp = _load_gpu_packet("cuda_cpp")
    _patch_numpy_runtime(monkeypatch, gp_cpp)
    packets_cpp, size_cpp = gp_cpp.generate_packets_from_template(
        template_bytes=template,
        count=8,
        real_src_ip="192.168.1.10",
        spoof_ip=False,
        has_ethernet=False,
    )

    assert size_legacy == size_cpp
    assert np.asarray(packets_legacy, dtype=np.uint8).tobytes() == np.asarray(
        packets_cpp, dtype=np.uint8
    ).tobytes()


def test_anomaly_import_compatibility():
    gp = _load_gpu_packet("cuda_cpp")
    import ddos_samurai.anomaly_packet as ap

    assert ap.ETHERNET_HEADER_LEN == gp.ETHERNET_HEADER_LEN
    assert callable(ap.calculate_checksum)
