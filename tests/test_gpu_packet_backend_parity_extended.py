import importlib
import importlib.util
import os

import numpy as np
import pytest


_NUMBA_AVAILABLE = importlib.util.find_spec("numba") is not None
pytestmark = [
    pytest.mark.skipif(
        not _NUMBA_AVAILABLE,
        reason="numba not installed in CI-safe environment; skipping GPU backend parity tests",
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
    monkeypatch.setattr(gp, "template_kernel", _FakeKernel(), raising=True)
    monkeypatch.setattr(gp, "pool_kernel", _FakeKernel(), raising=True)
    monkeypatch.setattr(gp, "stateful_pool_kernel", _FakeKernel(), raising=True)
    monkeypatch.setattr(gp, "create_fragmented_packets_kernel", _FakeKernel(), raising=True)
    monkeypatch.setattr(gp, "amplification_kernel_v2", _FakeKernel(), raising=True)
    monkeypatch.setattr(gp, "create_icmp_packets_kernel", _FakeKernel(), raising=True)

    monkeypatch.setattr(
        gp.cp,
        "zeros",
        lambda shape, dtype=None: np.zeros(shape, dtype=(dtype if dtype is not None else np.uint8)),
        raising=True,
    )
    monkeypatch.setattr(
        gp.cp,
        "array",
        lambda arr, dtype=None: np.array(arr, dtype=(dtype if dtype is not None else np.uint8)),
        raising=True,
    )
    monkeypatch.setattr(
        gp.cp,
        "asarray",
        lambda arr, dtype=None: np.asarray(arr, dtype=(dtype if dtype is not None else np.uint8)),
        raising=True,
    )


def _bytes(v) -> bytes:
    return np.asarray(v, dtype=np.uint8).tobytes()


def test_pool_template_parity(monkeypatch):
    templates = [bytes([0x45]) + bytes([0x00] * 63), bytes([0x45]) + bytes([0x11] * 63)]

    gp_legacy = _load_gpu_packet("legacy")
    _patch_numpy_runtime(monkeypatch, gp_legacy)
    packets_legacy, size_legacy = gp_legacy.generate_packets_from_template_pool(
        templates_bytes_list=templates,
        count=8,
        target_ip="203.0.113.10",
        spoof_ip=False,
        has_ethernet=False,
    )

    gp_cpp = _load_gpu_packet("cuda_cpp")
    _patch_numpy_runtime(monkeypatch, gp_cpp)
    packets_cpp, size_cpp = gp_cpp.generate_packets_from_template_pool(
        templates_bytes_list=templates,
        count=8,
        target_ip="203.0.113.10",
        spoof_ip=False,
        has_ethernet=False,
    )

    assert size_legacy == size_cpp
    assert _bytes(packets_legacy) == _bytes(packets_cpp)


def test_stateful_pool_parity(monkeypatch):
    templates = [bytes([0x45]) + bytes([0xAA] * 63), bytes([0x45]) + bytes([0xBB] * 63)]

    gp_legacy = _load_gpu_packet("legacy")
    _patch_numpy_runtime(monkeypatch, gp_legacy)
    packets_legacy, size_legacy = gp_legacy.generate_stateful_packets(
        templates_bytes_list=templates,
        count=4,
        target_ip="203.0.113.11",
        spoof_ip=False,
        has_ethernet=True,
        seq_list=[1, 2, 3, 4],
        ack_list=[10, 20, 30, 40],
        state_list=[0, 1, 2, 3],
        actual_lengths=[64, 64],
        window_sizes=[1024, 1024, 1024, 1024],
        mss_values=[1460, 1460, 1460, 1460],
        ttls=[64, 64, 64, 64],
    )

    gp_cpp = _load_gpu_packet("cuda_cpp")
    _patch_numpy_runtime(monkeypatch, gp_cpp)
    packets_cpp, size_cpp = gp_cpp.generate_stateful_packets(
        templates_bytes_list=templates,
        count=4,
        target_ip="203.0.113.11",
        spoof_ip=False,
        has_ethernet=True,
        seq_list=[1, 2, 3, 4],
        ack_list=[10, 20, 30, 40],
        state_list=[0, 1, 2, 3],
        actual_lengths=[64, 64],
        window_sizes=[1024, 1024, 1024, 1024],
        mss_values=[1460, 1460, 1460, 1460],
        ttls=[64, 64, 64, 64],
    )

    assert size_legacy == size_cpp
    assert _bytes(packets_legacy) == _bytes(packets_cpp)


def test_fragmented_parity(monkeypatch):
    payload = b"A" * 128

    gp_legacy = _load_gpu_packet("legacy")
    _patch_numpy_runtime(monkeypatch, gp_legacy)
    packets_legacy, size_legacy = gp_legacy.generate_fragmented_packets(
        payload_bytes=payload,
        count=2,
        target_ip="203.0.113.12",
        target_port=53,
        protocol="udp",
        spoof_ip=False,
        has_ethernet=True,
        frag1_size=1514,
        frag2_size=1500,
    )

    gp_cpp = _load_gpu_packet("cuda_cpp")
    _patch_numpy_runtime(monkeypatch, gp_cpp)
    packets_cpp, size_cpp = gp_cpp.generate_fragmented_packets(
        payload_bytes=payload,
        count=2,
        target_ip="203.0.113.12",
        target_port=53,
        protocol="udp",
        spoof_ip=False,
        has_ethernet=True,
        frag1_size=1514,
        frag2_size=1500,
    )

    assert size_legacy == size_cpp
    assert _bytes(packets_legacy) == _bytes(packets_cpp)


def test_amplification_parity(monkeypatch):
    template = bytes([0x45]) + bytes([0x00] * 63)
    reflectors = ["198.51.100.1", "198.51.100.2"]

    gp_legacy = _load_gpu_packet("legacy")
    _patch_numpy_runtime(monkeypatch, gp_legacy)
    packets_legacy, size_legacy = gp_legacy.generate_amplification_packets(
        template_bytes=template,
        reflectors_ips=reflectors,
        victim_ip="203.0.113.100",
        count=4,
        has_ethernet=True,
    )

    gp_cpp = _load_gpu_packet("cuda_cpp")
    _patch_numpy_runtime(monkeypatch, gp_cpp)
    packets_cpp, size_cpp = gp_cpp.generate_amplification_packets(
        template_bytes=template,
        reflectors_ips=reflectors,
        victim_ip="203.0.113.100",
        count=4,
        has_ethernet=True,
    )

    assert size_legacy == size_cpp
    assert _bytes(packets_legacy) == _bytes(packets_cpp)


def test_icmp_parity(monkeypatch):
    gp_legacy = _load_gpu_packet("legacy")
    _patch_numpy_runtime(monkeypatch, gp_legacy)
    packets_legacy, size_legacy = gp_legacy.generate_icmp_packets(
        count=4,
        target_ip="203.0.113.15",
        real_src_ip="192.168.1.10",
        spoof_ip=False,
        has_ethernet=True,
        payload_size=32,
    )

    gp_cpp = _load_gpu_packet("cuda_cpp")
    _patch_numpy_runtime(monkeypatch, gp_cpp)
    packets_cpp, size_cpp = gp_cpp.generate_icmp_packets(
        count=4,
        target_ip="203.0.113.15",
        real_src_ip="192.168.1.10",
        spoof_ip=False,
        has_ethernet=True,
        payload_size=32,
    )

    assert size_legacy == size_cpp
    assert _bytes(packets_legacy) == _bytes(packets_cpp)
