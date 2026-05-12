import ctypes
import importlib.util

import numpy as np
import pytest

_NUMBA_AVAILABLE = importlib.util.find_spec("numba") is not None
if not _NUMBA_AVAILABLE:
    pytest.skip(
        "numba not installed in CI-safe environment; skipping defense CUDA bridge tests",
        allow_module_level=True,
    )

import ddos_samurai._gpu_packet_cuda_backend as backend


def _scalar(v):
    return int(getattr(v, "value", v))


class _FakeDefenseLib:
    def __init__(self):
        self.rc_init = 0
        self.rc_classify = 0
        self.rc_classify_ingress = 0
        self.rc_shutdown = 0
        self.last_error = b""
        self.last_reason = b"none"
        self.calls = []

    def samurai_gpu_packet_defense_init(self, runtime, engine_path, rdma_mode, rdma_strict, max_batch_size, flush_timeout_ms):
        self.calls.append(
            {
                "name": "init",
                "runtime": (ctypes.cast(runtime, ctypes.c_char_p).value or b"").decode("utf-8", errors="ignore"),
                "engine_path": (ctypes.cast(engine_path, ctypes.c_char_p).value or b"").decode("utf-8", errors="ignore"),
                "rdma_mode": (ctypes.cast(rdma_mode, ctypes.c_char_p).value or b"").decode("utf-8", errors="ignore"),
                "rdma_strict": _scalar(rdma_strict),
                "max_batch_size": _scalar(max_batch_size),
                "flush_timeout_ms": _scalar(flush_timeout_ms),
            }
        )
        return int(self.rc_init)

    def samurai_gpu_packet_classify_batch(self, packets_flat, packet_lengths, packet_count, out_labels, out_confidences, out_reason):
        n = _scalar(packet_count)
        lens = np.ctypeslib.as_array(ctypes.cast(packet_lengths, ctypes.POINTER(ctypes.c_int32)), shape=(n,))
        labels = np.ctypeslib.as_array(ctypes.cast(out_labels, ctypes.POINTER(ctypes.c_int32)), shape=(n,))
        confidences = np.ctypeslib.as_array(ctypes.cast(out_confidences, ctypes.POINTER(ctypes.c_float)), shape=(n,))
        for i in range(n):
            labels[i] = 1 if int(lens[i]) > 32 else 0
            confidences[i] = np.float32(0.9 if labels[i] == 1 else 0.6)
        ctypes.cast(out_reason, ctypes.POINTER(ctypes.c_char_p)).contents.value = self.last_reason
        self.calls.append({"name": "classify", "count": n})
        return int(self.rc_classify)

    def samurai_gpu_packet_read_classifier_stats(self):
        return (
            '{"gpu_cls_infer_qps":123,"gpu_cls_latency_p50_ms":0.12,'
            '"gpu_cls_latency_p95_ms":0.31,"gpu_cls_latency_p99_ms":0.55,'
            '"gpu_cls_queue_backpressure":2,"gpu_stream_overlap_ratio":0.9,'
            '"gpu_rdma_direct_active":1,"gpu_rdma_fallback_reason":"none",'
            '"gpu_cls_confidence_mean":0.75}'
        ).encode("utf-8")

    def samurai_gpu_packet_classify_from_ingress(
        self,
        max_packets,
        max_packet_size,
        out_packet_count,
        out_labels,
        out_confidences,
        out_reason,
    ):
        max_n = max(0, _scalar(max_packets))
        n = min(max_n, 3)
        labels = np.ctypeslib.as_array(ctypes.cast(out_labels, ctypes.POINTER(ctypes.c_int32)), shape=(max_n,))
        confidences = np.ctypeslib.as_array(ctypes.cast(out_confidences, ctypes.POINTER(ctypes.c_float)), shape=(max_n,))
        for i in range(n):
            labels[i] = 1 if i % 2 else 0
            confidences[i] = np.float32(0.8 if labels[i] == 1 else 0.55)
        ctypes.cast(out_packet_count, ctypes.POINTER(ctypes.c_int32)).contents.value = int(n)
        ctypes.cast(out_reason, ctypes.POINTER(ctypes.c_char_p)).contents.value = self.last_reason
        self.calls.append(
            {
                "name": "classify_from_ingress",
                "max_packets": _scalar(max_packets),
                "max_packet_size": _scalar(max_packet_size),
            }
        )
        return int(self.rc_classify_ingress)

    def samurai_gpu_packet_defense_shutdown(self):
        self.calls.append({"name": "shutdown"})
        return int(self.rc_shutdown)

    def samurai_gpu_packet_defense_last_error(self):
        return self.last_error


def test_defense_backend_init_and_classify(monkeypatch):
    fake = _FakeDefenseLib()
    monkeypatch.setattr(backend, "_DEFENSE_LIB", fake, raising=True)

    b = backend.DefenseCUDABackend()
    b.init(
        runtime="tensorrt",
        engine_path="/tmp/model.engine",
        rdma_mode="auto",
        rdma_strict=False,
        max_batch_size=256,
        flush_timeout_ms=3,
    )

    labels, confidences, reason = b.classify_batch([b"a" * 8, b"b" * 64])
    assert reason == "none"
    assert labels.tolist() == [0, 1]
    assert np.allclose(confidences, np.array([0.6, 0.9], dtype=np.float32), atol=1e-6)

    stats = b.read_classifier_stats()
    assert int(stats["gpu_cls_infer_qps"]) == 123
    assert int(stats["gpu_rdma_direct_active"]) == 1
    assert float(stats["gpu_cls_latency_p95_ms"]) >= float(stats["gpu_cls_latency_p50_ms"])
    assert float(stats["gpu_cls_latency_p99_ms"]) >= float(stats["gpu_cls_latency_p95_ms"])
    assert int(stats["gpu_cls_queue_backpressure"]) == 2

    b.shutdown()
    assert [c["name"] for c in fake.calls] == ["init", "classify", "shutdown"]


def test_defense_backend_reason_code_on_failure(monkeypatch):
    fake = _FakeDefenseLib()
    fake.rc_classify = -1
    fake.last_reason = b"rdma_strict_fail"
    fake.last_error = b"rdma_strict_fail"
    monkeypatch.setattr(backend, "_DEFENSE_LIB", fake, raising=True)

    b = backend.DefenseCUDABackend()
    with pytest.raises(backend.GPUPacketError, match="rdma_strict_fail"):
        b.classify_batch([b"x" * 60])


def test_defense_backend_classify_from_ingress(monkeypatch):
    fake = _FakeDefenseLib()
    monkeypatch.setattr(backend, "_DEFENSE_LIB", fake, raising=True)

    b = backend.DefenseCUDABackend()
    labels, confidences, reason = b.classify_from_ingress(max_packets=8, max_packet_size=2048)
    assert reason == "none"
    assert labels.tolist() == [0, 1, 0]
    assert np.allclose(confidences, np.array([0.55, 0.8, 0.55], dtype=np.float32), atol=1e-6)


def test_defense_backend_requires_library(monkeypatch):
    monkeypatch.setattr(backend, "_DEFENSE_LIB", None, raising=True)
    with pytest.raises(backend.GPUPacketError, match="libgpu_packet_cuda_defense.so not found"):
        backend.DefenseCUDABackend()
