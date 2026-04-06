import importlib
import importlib.util

import numpy as np
import pytest


_NUMBA_AVAILABLE = importlib.util.find_spec("numba") is not None
pytestmark = [
    pytest.mark.skipif(
        not _NUMBA_AVAILABLE,
        reason="numba not installed in CI-safe environment; skipping native GPU facade tests",
    )
]


def _reload_gpu_packet():
    import ddos_samurai.gpu_packet as gp

    return importlib.reload(gp)


def test_backend_selection_is_native_only():
    gp = _reload_gpu_packet()
    assert gp.get_active_backend_name() == "cuda_cpp"
    assert gp.get_native_policy() == "require"
    assert gp.is_native_policy_require() is True
    assert gp.is_native_path_enabled() is True


def test_anomaly_import_compatibility():
    gp = _reload_gpu_packet()
    import ddos_samurai.anomaly_packet as ap

    assert ap.ETHERNET_HEADER_LEN == gp.ETHERNET_HEADER_LEN
    assert callable(ap.calculate_checksum)


def test_generator_uses_native_template_path(monkeypatch):
    gp = _reload_gpu_packet()
    seen = {}

    def _fake_generate_packets_from_template(**kwargs):
        seen.update(kwargs)
        return np.arange(12, dtype=np.uint8), 4

    monkeypatch.setattr(gp, "generate_packets_from_template", _fake_generate_packets_from_template, raising=True)
    monkeypatch.setattr(gp.cp, "asnumpy", lambda arr: np.asarray(arr, dtype=np.uint8), raising=True)

    generator = gp.GPUPacketGenerator(
        max_batch_size=8,
        real_src_ip="192.168.1.9",
        spoof_ip=False,
        has_ethernet=True,
    )
    packets = generator.generate_batch(bytes([0x45]) + bytes([0x00] * 7), 3)

    assert seen["count"] == 3
    assert seen["real_src_ip"] == "192.168.1.9"
    assert seen["spoof_ip"] is False
    assert seen["has_ethernet"] is True
    assert len(packets) == 3
    assert packets[0] == bytes([0, 1, 2, 3])
