from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
try:
    import torch
except ImportError:  # pragma: no cover - optional runtime dependency
    torch = None

from .config import VAEConfig
from .model import DenseVAE


@dataclass(frozen=True)
class ScalerStats:
    mean_: np.ndarray
    scale_: np.ndarray


@dataclass(frozen=True)
class VAEArtifacts:
    model: DenseVAE
    scaler: ScalerStats
    threshold: float
    beta_kl: float
    hidden_dim: int


def _load_meta(meta_path: Path) -> dict:
    data = json.loads(meta_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("VAE meta must be a JSON object")
    return data


def _load_scaler(scaler_path: Path) -> ScalerStats:
    npz = np.load(scaler_path)
    mean = np.asarray(npz["mean_"], dtype=np.float32)
    scale = np.asarray(npz["scale_"], dtype=np.float32)
    scale = np.where(scale == 0.0, 1.0, scale)
    return ScalerStats(mean_=mean, scale_=scale)


def load_artifacts(config: VAEConfig, device: str = "cpu") -> VAEArtifacts:
    if torch is None:
        raise RuntimeError("PyTorch is required for VAE runtime. Install with: pip install -r requirements-ml.txt")
    for p in (config.model_path, config.scaler_path, config.meta_path):
        if not Path(p).exists():
            raise FileNotFoundError(f"VAE artifact not found: {p}")

    meta = _load_meta(config.meta_path)
    feature_names = tuple(meta.get("feature_names") or ())
    if feature_names and feature_names != config.feature_names:
        raise ValueError("Feature name order mismatch between config and meta")

    input_dim = int(meta.get("input_dim", config.input_dim))
    hidden_dim = int(meta.get("hidden_dim", 128))
    latent_dim = int(meta.get("latent_dim", config.latent_dim))
    threshold = float(meta.get("threshold", 0.0))
    beta_kl = float(meta.get("beta_kl", 0.1))

    model = DenseVAE(in_dim=input_dim, hidden_dim=hidden_dim, latent_dim=latent_dim)
    state = torch.load(config.model_path, map_location=device)
    model.load_state_dict(state)
    model.to(device)
    model.eval()

    scaler = _load_scaler(config.scaler_path)
    if scaler.mean_.shape[0] != config.feature_count:
        raise ValueError("Scaler feature_count does not match VAE config")

    if threshold <= 0.0:
        threshold = 1.0

    return VAEArtifacts(model=model, scaler=scaler, threshold=threshold, beta_kl=beta_kl, hidden_dim=hidden_dim)
