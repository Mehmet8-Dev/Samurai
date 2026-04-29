from __future__ import annotations

import types
import sys

from ddos_samurai import af_xdp_sender
from ddos_samurai.cli.args import build_parser


class _FakeXDP:
    def __init__(self, frames: list[bytes]):
        self._frames = list(frames)

    def xdp_create(self, *_args):
        return 7

    def xdp_destroy(self, *_args):
        return True

    def xdp_recv_ctx(self, _h, max_packets, _snaplen):
        out = []
        n = max(0, int(max_packets))
        while self._frames and len(out) < n:
            out.append(self._frames.pop(0))
        return out


class _FakeBackend:
    def __init__(self):
        self.shutdown_called = False

    def init(self, **_kwargs):
        return None

    def classify_batch(self, packets):
        labels = [1 if (len(p) > 0 and p[0] == ord("x")) else 0 for p in packets]
        confs = [0.9 if x == 1 else 0.6 for x in labels]
        import numpy as np

        return np.asarray(labels, dtype=np.int32), np.asarray(confs, dtype=np.float32), "none"

    def read_classifier_stats(self):
        return {"gpu_cls_infer_qps": 1000}

    def shutdown(self):
        self.shutdown_called = True


def test_gpu_rx_pipeline_basic(monkeypatch):
    fake_backend_mod = types.SimpleNamespace(DefenseCUDABackend=_FakeBackend)
    monkeypatch.setattr(af_xdp_sender, "_resolve_gpu_rx_iface", lambda _x: "lo")
    monkeypatch.setitem(__import__("sys").modules, "ddos_samurai._gpu_packet_cuda_backend", fake_backend_mod)
    import ddos_samurai

    monkeypatch.setattr(ddos_samurai, "_gpu_packet_cuda_backend", fake_backend_mod, raising=False)
    import ddos_samurai.xdp_sender as real_xdp
    fake_xdp = _FakeXDP([b"a1", b"x2", b"a3"])
    monkeypatch.setattr(real_xdp, "xdp_create", fake_xdp.xdp_create, raising=True)
    monkeypatch.setattr(real_xdp, "xdp_destroy", fake_xdp.xdp_destroy, raising=True)
    monkeypatch.setattr(real_xdp, "xdp_recv_ctx", fake_xdp.xdp_recv_ctx, raising=True)
    out = af_xdp_sender.run_gpu_rx_pipeline(
        interface="lo",
        duration_s=1,
        batch_size=2,
        max_packets=3,
        snaplen=512,
    )
    assert int(out["gpu_rx_pipeline_active"]) == 1
    assert int(out["gpu_rx_packets_total"]) == 3
    assert int(out["gpu_rx_classified_total"]) == 3
    assert int(out["gpu_rx_suspicious_total"]) == 1
    assert int(out["gpu_classifier_gpu_cls_infer_qps"]) == 1000


def test_gpu_rx_cli_args_present():
    parser = build_parser()
    args = parser.parse_args(
        [
            "--gpu-rx-pipeline",
            "on",
            "--gpu-rx-iface",
            "eth0",
            "--gpu-rx-duration-s",
            "5",
            "--gpu-rx-batch-size",
            "128",
            "--gpu-rx-max-packets",
            "1234",
            "--gpu-rx-snaplen",
            "1024",
        ]
    )
    assert args.gpu_rx_pipeline == "on"
    assert args.gpu_rx_iface == "eth0"
    assert int(args.gpu_rx_duration_s) == 5
    assert int(args.gpu_rx_batch_size) == 128
    assert int(args.gpu_rx_max_packets) == 1234
    assert int(args.gpu_rx_snaplen) == 1024
