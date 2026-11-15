from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class VAEInferenceResult:
    test_id: str
    timestamp: str
    is_anomaly: bool
    anomaly_score: float
    threshold: float
    severity: str
    top_contributors: list[str]
    reason_tag: str
    message: str
    model_version: str

    def to_dict(self) -> dict:
        return asdict(self)
