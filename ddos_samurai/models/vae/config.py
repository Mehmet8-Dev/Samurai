from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class VAEConfig:
    model_path: Path
    scaler_path: Path
    meta_path: Path
    model_version: str = "vae-loadtest-v1"
    window_size: int = 60
    step_size: int = 5
    sampling_rate_s: int = 1
    latent_dim: int = 16
    threshold_multiplier_low: float = 1.5
    threshold_multiplier_medium: float = 2.5
    threshold_quantile_fallback: float = 0.95
    feature_names: tuple[str, ...] = field(
        default=(
            "rps",
            "p95_latency",
            "p99_latency",
            "error_rate",
            "cpu_usage",
            "memory_usage",
            "active_connections",
            "timeout_count",
        )
    )

    @property
    def feature_count(self) -> int:
        return len(self.feature_names)

    @property
    def input_dim(self) -> int:
        return int(self.window_size) * int(self.feature_count)
