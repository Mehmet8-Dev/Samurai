from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

torch = pytest.importorskip("torch")

from samurai.models.vae.config import VAEConfig
from samurai.models.vae.model import DenseVAE
from samurai.models.vae.service import VAEDefenseService


def _write_artifacts(tmp_path: Path, *, threshold: float) -> tuple[Path, Path, Path]:
    feature_names = (
        "rps",
        "p95_latency",
        "p99_latency",
        "error_rate",
        "cpu_usage",
        "memory_usage",
        "active_connections",
        "timeout_count",
    )
    in_dim = 60 * len(feature_names)
    hidden_dim = 32
    latent_dim = 16

    model = DenseVAE(in_dim=in_dim, hidden_dim=hidden_dim, latent_dim=latent_dim)
    model_path = tmp_path / "l4_vae.pt"
    torch.save(model.state_dict(), model_path)

    scaler_path = tmp_path / "l4_scaler.npz"
    np.savez(
        scaler_path,
        mean_=np.zeros((len(feature_names),), dtype=np.float64),
        scale_=np.ones((len(feature_names),), dtype=np.float64),
        var_=np.ones((len(feature_names),), dtype=np.float64),
    )

    meta_path = tmp_path / "l4_vae_meta.json"
    meta_path.write_text(
        json.dumps(
            {
                "feature_names": list(feature_names),
                "input_dim": in_dim,
                "hidden_dim": hidden_dim,
                "latent_dim": latent_dim,
                "beta_kl": 0.1,
                "threshold": float(threshold),
            }
        ),
        encoding="utf-8",
    )

    return model_path, scaler_path, meta_path


def test_vae_service_emits_result_after_window_ready(tmp_path: Path):
    model_path, scaler_path, meta_path = _write_artifacts(tmp_path, threshold=1e-12)
    cfg = VAEConfig(model_path=model_path, scaler_path=scaler_path, meta_path=meta_path)
    svc = VAEDefenseService(cfg, device="cpu")

    point = {
        "rps": 300.0,
        "p95_latency": 120.0,
        "p99_latency": 220.0,
        "error_rate": 0.02,
        "cpu_usage": 70.0,
        "memory_usage": 68.0,
        "active_connections": 1100.0,
        "timeout_count": 2.0,
    }

    out = None
    for _ in range(60):
        out = svc.push_metric_point(point, test_id="t-1")
    assert out is None

    for _ in range(4):
        out = svc.push_metric_point(point, test_id="t-1")
        assert out is None

    out = svc.push_metric_point(point, test_id="t-1")
    assert out is not None
    assert out.test_id == "t-1"
    assert out.model_version == "vae-loadtest-v1"
    assert isinstance(out.top_contributors, list)
    assert len(out.top_contributors) == 3
    assert out.is_anomaly is True
    assert out.severity in {"low", "medium", "high"}


def test_vae_service_supports_non_anomaly_path(tmp_path: Path):
    model_path, scaler_path, meta_path = _write_artifacts(tmp_path, threshold=999999.0)
    cfg = VAEConfig(model_path=model_path, scaler_path=scaler_path, meta_path=meta_path)
    svc = VAEDefenseService(cfg, device="cpu")

    window = np.zeros((cfg.window_size, cfg.feature_count), dtype=np.float32)
    out = svc.analyze_window(window, test_id="t-2")

    assert out.is_anomaly is False
    assert out.severity == "normal"
    assert "within learned normal profile" in out.message
