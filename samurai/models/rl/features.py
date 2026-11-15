"""State feature extraction — swappable via the ``FeatureExtractor`` protocol.

A feature extractor maps a raw measured window (``RawState``) plus its run context
into the fixed-width float vector the policy consumes. It is deliberately separate
from reward and dataset assembly so an alternate state representation (e.g. a
sequence/­history encoder for the Phase-3 mamba policy) is a drop-in replacement:
pass a different extractor to ``build_dataset``.
"""

from __future__ import annotations

from typing import Protocol

import numpy as np

from .config import RLConfig
from .schemas import RawState, Transition


class FeatureExtractor(Protocol):
    """Maps (state, transition-context) -> 1-D float32 feature vector."""

    @property
    def dim(self) -> int: ...

    def state_vector(self, s: RawState, t: Transition) -> np.ndarray: ...


class DefaultFeatureExtractor:
    """Flat, single-window feature vector with explicit unknown-masking.

    Unknown (<0) raw fields are imputed to ``cfg.impute_value`` and, when
    ``cfg.mask_unknown`` is set, accompanied by a companion "known" bit so the
    policy can distinguish a genuine 0 from a missing signal. rps is normalized by
    the run's ``max_rps``; the window index by ``cfg.step_horizon``.
    """

    def __init__(self, cfg: RLConfig):
        self._cfg = cfg

    @property
    def dim(self) -> int:
        return self._cfg.feature_count

    def state_vector(self, s: RawState, t: Transition) -> np.ndarray:
        cfg = self._cfg
        max_rps = t.max_rps if t.max_rps > 0 else 1.0

        rps_norm = s.rps / max_rps
        # error_pct: use the effective (derived-if-unknown) value; the others are
        # unknown exactly when the master left them < 0. The defense-reaction
        # ratios are UNKNOWN (< 0) whenever their source counters were absent.
        d = s.defense
        raw = {
            "error_pct": s.effective_error_pct,
            "loss_pct": s.loss_pct,
            "rate_accuracy_pct": s.rate_accuracy_pct,
            "p99_ms": s.p99_ms,
            "rate_limited_ratio": d.rate_limited_ratio,
            "overload_ratio": d.overload_ratio,
            "conn_drop_ratio": d.conn_drop_ratio,
            "reset_pressure": d.reset_pressure,
            "challenge_rate": d.challenge_rate,
        }

        vec: list[float] = []
        for name in cfg.feature_names:
            if name == "rps_norm":
                vec.append(rps_norm)
            elif name == "step_norm":
                vec.append(t.win / cfg.step_horizon)
            elif name in raw:
                val = raw[name]
                vec.append(cfg.impute_value if val < 0.0 else val)
            else:  # pragma: no cover - guards against a stale feature_names entry
                raise KeyError(f"unknown feature name: {name}")

        if cfg.mask_unknown:
            for name in cfg.maskable_features:
                vec.append(0.0 if raw[name] < 0.0 else 1.0)

        return np.asarray(vec, dtype=np.float32)
