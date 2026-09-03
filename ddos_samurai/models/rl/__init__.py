"""Offline-RL layer for the closed-loop (autopilot) load controller.

The native ``ClosedLoopController`` (see ``ddos_samurai/control/closed_loop.hpp``)
exposes a pure ``Step(LoadSample) -> Decision{setpoint_rps}`` seam that is already
an RL interface: state = measured window, action = next setpoint, reward = SLO-safe
throughput progress. This package owns the *training* half of the RL layer:

  * ``schemas``  — the raw corpus transition record emitted by ``samurai_master
                   --rl-corpus`` (one NDJSON line per closed-loop window).
  * ``config``   — feature layout, reward shaping (lambda / step-cost), imputation.
  * ``dataset``  — NDJSON corpus -> (s, a, r, s') arrays + normalization stats,
                   grouped into episodes for off-policy evaluation.

Serving is deliberately elsewhere and in C++: the trained policy is exported to a
flat weight file and evaluated in the master's hot loop with no torch dependency.
"""

from __future__ import annotations

from .config import RLConfig
from .corpus import group_episodes, iter_transitions, load_transitions
from .dataset import Dataset, Normalizer, build_dataset
from .features import DefaultFeatureExtractor, FeatureExtractor
from .reward import RewardFn, SloProgressReward, slo_overshoot
from .schemas import Action, DefenseSignals, RawState, SloThresholds, Transition

__all__ = [
    "RLConfig",
    "Transition",
    "RawState",
    "SloThresholds",
    "DefenseSignals",
    "Action",
    "iter_transitions",
    "load_transitions",
    "group_episodes",
    "FeatureExtractor",
    "DefaultFeatureExtractor",
    "RewardFn",
    "SloProgressReward",
    "slo_overshoot",
    "build_dataset",
    "Dataset",
    "Normalizer",
]
