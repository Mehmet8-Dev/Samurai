import types
import sys

import numpy as np
import ddos_samurai

from ddos_samurai._senders import gpu_defense
from ddos_samurai._senders.context import close_sender_context


class _FakeDefenseBackend:
    def __init__(self):
        self.inited = False
        self.shutdown_called = False

    def init(self, **_kwargs):
        self.inited = True

    def classify_batch(self, packets):
        labels = np.asarray([1 if (len(p) > 0 and p[0] == ord("b")) else 0 for p in packets], dtype=np.int32)
        confs = np.asarray([0.9 if int(x) == 1 else 0.6 for x in labels], dtype=np.float32)
        return labels, confs, "none"

    def read_classifier_stats(self):
        return {
            "gpu_cls_infer_qps": 321,
            "gpu_rdma_direct_active": 1,
        }

    def shutdown(self):
        self.shutdown_called = True


def test_gpu_defense_disabled_returns_bypass(monkeypatch):
    monkeypatch.setenv("SAMURAI_GPU_DEFENSE_MODE", "off")
    out = gpu_defense.classify_packets_if_enabled(
        b"\x00" * 128,
        count=2,
        packet_size=64,
        packet_stride=0,
        sender_context={},
    )
    assert out["gpu_defense_mode"] == "off"
    assert int(out["gpu_classifier_invoked"]) == 0


def test_gpu_defense_enabled_classifies_and_emits_telemetry(monkeypatch):
    monkeypatch.setenv("SAMURAI_GPU_DEFENSE_MODE", "on")
    monkeypatch.setenv("SAMURAI_GPU_RDMA_STRICT", "0")
    monkeypatch.setenv("SAMURAI_GPU_BATCH_MAX", "1")
    fake_backend_mod = types.SimpleNamespace(DefenseCUDABackend=_FakeDefenseBackend)
    monkeypatch.setitem(sys.modules, "ddos_samurai._gpu_packet_cuda_backend", fake_backend_mod)
    monkeypatch.setattr(ddos_samurai, "_gpu_packet_cuda_backend", fake_backend_mod, raising=False)

    ctx = {}
    # 2 packets: first benign, second suspicious
    buf = (b"a" * 32) + (b"b" * 32)
    out = gpu_defense.classify_packets_if_enabled(
        buf,
        count=2,
        packet_size=32,
        packet_stride=32,
        sender_context=ctx,
    )

    assert out["gpu_defense_mode"] == "on"
    assert int(out["gpu_classifier_invoked"]) == 1
    assert out["gpu_classifier_status"] == "ok"
    assert int(out["gpu_classifier_total"]) == 2
    assert int(out["gpu_classifier_suspicious"]) == 1
    assert int(out["gpu_classifier_benign"]) == 1
    assert int(out["gpu_classifier_gpu_cls_infer_qps"]) == 321
    assert int(out["gpu_classifier_gpu_rdma_direct_active"]) == 1
    assert "gpu_defense_backend" in ctx


def test_gpu_defense_strict_hard_fail_on_import_error(monkeypatch):
    monkeypatch.setenv("SAMURAI_GPU_DEFENSE_MODE", "on")
    monkeypatch.setenv("SAMURAI_GPU_RDMA_STRICT", "1")

    monkeypatch.delitem(sys.modules, "ddos_samurai._gpu_packet_cuda_backend", raising=False)
    import builtins
    orig_import = builtins.__import__

    def _fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 2 and fromlist and "_gpu_packet_cuda_backend" in fromlist:
            raise ImportError("forced")
        return orig_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _fake_import)

    out = gpu_defense.classify_packets_if_enabled(
        b"\x00" * 64,
        count=1,
        packet_size=64,
        sender_context={},
    )
    assert out["gpu_classifier_status"] == "unavailable"
    assert int(out["gpu_classifier_hard_fail"]) == 1


def test_close_sender_context_shutdowns_gpu_defense_backend():
    backend = _FakeDefenseBackend()
    ctx = {"gpu_defense_backend": backend}
    close_sender_context(ctx)
    assert backend.shutdown_called is True
    assert "gpu_defense_backend" not in ctx
