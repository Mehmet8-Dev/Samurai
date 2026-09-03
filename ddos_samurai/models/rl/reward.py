"""Reward shaping — swappable via the ``RewardFn`` protocol.

Reward is computed offline (never in the C++ capture path) so it can be retuned
without recapturing the corpus. Keeping it behind a protocol means an alternate
objective — pure capacity-finding, latency-weighted, cost-aware — is a drop-in
replacement passed to ``build_dataset``.
"""

from __future__ import annotations

from typing import Protocol

from .config import RLConfig
from .schemas import SloThresholds, Transition


def slo_overshoot(s2, slo: SloThresholds) -> float:
    """Worst normalized SLO breach across the active rules for a window.

    Each rule contributes only when its knob is enabled (> 0) and its input is
    known (>= 0). The breach is normalized by the threshold so heterogeneous rules
    (percent vs milliseconds) compose on one scale; the window's overshoot is the
    worst (max) breach, so being deep in the red on any single SLO dominates.
    """
    breaches: list[float] = []

    err = s2.effective_error_pct
    if slo.max_error_pct > 0.0 and err >= 0.0:
        breaches.append(max(0.0, err - slo.max_error_pct) / slo.max_error_pct)

    if slo.max_loss_pct > 0.0 and s2.loss_pct >= 0.0:
        breaches.append(max(0.0, s2.loss_pct - slo.max_loss_pct) / slo.max_loss_pct)

    if slo.min_rate_accuracy_pct > 0.0 and s2.rate_accuracy_pct >= 0.0:
        breaches.append(
            max(0.0, slo.min_rate_accuracy_pct - s2.rate_accuracy_pct)
            / slo.min_rate_accuracy_pct
        )

    if slo.max_latency_ms > 0.0 and s2.p99_ms >= 0.0:
        breaches.append(max(0.0, s2.p99_ms - slo.max_latency_ms) / slo.max_latency_ms)

    return max(breaches) if breaches else 0.0


class RewardFn(Protocol):
    def __call__(self, t: Transition) -> float: ...


class SloProgressReward:
    """r = progress - lambda_slo * slo_overshoot - step_cost.

    ``progress`` credits advancing the *sustainable* load: the rps gain from s to
    s2, normalized, and only when the window stayed SLO-green. Overshoot penalizes
    breaching the ceiling; the flat step cost rewards converging in fewer windows.
    """

    def __init__(self, cfg: RLConfig):
        self._cfg = cfg

    def __call__(self, t: Transition) -> float:
        cfg = self._cfg
        scale = cfg.rps_scale if cfg.rps_scale > 0.0 else (t.max_rps if t.max_rps > 0 else 1.0)

        progress = 0.0
        if t.healthy:
            progress = max(0.0, t.s2.rps - t.s.rps) / scale

        overshoot = slo_overshoot(t.s2, t.slo)
        return progress - cfg.lambda_slo * overshoot - cfg.step_cost
