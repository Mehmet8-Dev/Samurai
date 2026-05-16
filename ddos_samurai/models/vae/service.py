from __future__ import annotations

from datetime import datetime, timezone

import numpy as np
try:
    import torch
except ImportError:  # pragma: no cover - optional runtime dependency
    torch = None

from .artifacts import VAEArtifacts, load_artifacts
from .config import VAEConfig
from .rules import reason_tag_from_contributors
from .schemas import VAEInferenceResult
from .windowing import SlidingWindowBuffer


class VAEDefenseService:
    """Defensive VAE service: window -> score -> severity -> reason tag."""

    def __init__(self, config: VAEConfig, *, device: str = "cpu"):
        self._cfg = config
        self._device = device
        self._artifacts: VAEArtifacts = load_artifacts(config, device=device)
        self._window = SlidingWindowBuffer(config)

    @property
    def threshold(self) -> float:
        return float(self._artifacts.threshold)

    def push_metric_point(self, point: dict[str, float], *, test_id: str) -> VAEInferenceResult | None:
        window = self._window.push(point)
        if window is None:
            return None
        return self.analyze_window(window, test_id=test_id)

    def analyze_window(self, window: np.ndarray, *, test_id: str) -> VAEInferenceResult:
        if window.shape != (self._cfg.window_size, self._cfg.feature_count):
            raise ValueError(
                f"Window shape mismatch: expected {(self._cfg.window_size, self._cfg.feature_count)}, got {window.shape}"
            )

        z = self._normalize(window)
        x = z.reshape(1, -1)
        xr, mu, logvar = self._forward(x)

        score = self._compute_score(x, xr, mu, logvar)
        threshold = float(self._artifacts.threshold)
        severity = self._severity(score, threshold)
        is_anomaly = bool(score > threshold)

        contributors = self._top_contributors(x, xr)
        window_mean = {
            name: float(window[:, i].mean())
            for i, name in enumerate(self._cfg.feature_names)
        }
        reason_tag = reason_tag_from_contributors(window_mean, contributors)
        msg = self._build_message(is_anomaly, severity, contributors, reason_tag)

        return VAEInferenceResult(
            test_id=str(test_id),
            timestamp=datetime.now(timezone.utc).isoformat(),
            is_anomaly=is_anomaly,
            anomaly_score=float(score),
            threshold=threshold,
            severity=severity,
            top_contributors=contributors,
            reason_tag=reason_tag,
            message=msg,
            model_version=self._cfg.model_version,
        )

    def _normalize(self, window: np.ndarray) -> np.ndarray:
        mean = self._artifacts.scaler.mean_[None, :]
        scale = self._artifacts.scaler.scale_[None, :]
        return (window - mean) / scale

    def _forward(self, flat: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        if torch is None:
            raise RuntimeError("PyTorch is required for VAE runtime. Install with: pip install -r requirements-ml.txt")
        tx = torch.from_numpy(flat.astype(np.float32)).to(self._device)
        with torch.no_grad():
            xr, mu, logvar = self._artifacts.model(tx)
        return xr.detach().cpu().numpy(), mu.detach().cpu().numpy(), logvar.detach().cpu().numpy()

    def _compute_score(self, x: np.ndarray, xr: np.ndarray, mu: np.ndarray, logvar: np.ndarray) -> float:
        rec_err = float(np.mean((xr - x) ** 2))
        kl = float(-0.5 * np.mean(1.0 + logvar - np.square(mu) - np.exp(logvar)))
        return rec_err + (self._artifacts.beta_kl * kl)

    def _top_contributors(self, x: np.ndarray, xr: np.ndarray) -> list[str]:
        err = np.square((xr - x).reshape(self._cfg.window_size, self._cfg.feature_count))
        per_feature = err.mean(axis=0)
        order = np.argsort(per_feature)[::-1]
        return [self._cfg.feature_names[int(i)] for i in order[:3]]

    def _severity(self, score: float, threshold: float) -> str:
        if score < threshold:
            return "normal"
        if score < threshold * self._cfg.threshold_multiplier_low:
            return "low"
        if score < threshold * self._cfg.threshold_multiplier_medium:
            return "medium"
        return "high"

    @staticmethod
    def _build_message(is_anomaly: bool, severity: str, contributors: list[str], reason_tag: str) -> str:
        if not is_anomaly:
            return "Behavior window is within learned normal profile."
        c = ", ".join(contributors)
        return f"{severity.upper()} anomaly detected. Main contributors: {c}. Pattern: {reason_tag}."
