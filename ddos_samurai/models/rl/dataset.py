"""Dataset assembly — the orchestrator that ties the modular parts together.

``build_dataset`` is pure composition: it reads a corpus (``corpus``), extracts
state vectors (a ``FeatureExtractor``), scores reward (a ``RewardFn``), and stacks
the result into the (S, A, R, S2, done) arrays an offline-RL trainer consumes. The
extractor and reward are injected, so swapping either is a one-line change and no
other module needs to know.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from . import corpus as corpus_io
from .config import RLConfig
from .features import DefaultFeatureExtractor, FeatureExtractor
from .reward import RewardFn, SloProgressReward
from .schemas import Transition


@dataclass(frozen=True)
class Normalizer:
    """Per-feature mean/std for state standardization.

    Exported alongside the policy weights so the C++ serving path standardizes the
    live state identically. std is floored to avoid divide-by-zero on constant
    features (e.g. an SLO signal that was inert for the whole corpus).
    """

    mean: np.ndarray
    std: np.ndarray

    @classmethod
    def fit(cls, states: np.ndarray, *, eps: float = 1e-6) -> "Normalizer":
        mean = states.mean(axis=0)
        std = states.std(axis=0)
        std = np.where(std < eps, 1.0, std)
        return cls(mean=mean.astype(np.float32), std=std.astype(np.float32))

    def transform(self, states: np.ndarray) -> np.ndarray:
        return ((states - self.mean) / self.std).astype(np.float32)


@dataclass(frozen=True)
class Dataset:
    """A stacked offline-RL dataset. Actions are raw setpoints; normalize per use."""

    states: np.ndarray       # (N, F) raw (un-normalized) state features
    actions: np.ndarray      # (N,)   setpoint_rps taken
    rewards: np.ndarray      # (N,)
    next_states: np.ndarray  # (N, F)
    dones: np.ndarray        # (N,)   episode-terminal flag
    episode_ids: np.ndarray  # (N,)   run_id index, for per-trajectory OPE
    feature_names: tuple[str, ...]
    normalizer: Normalizer

    def __len__(self) -> int:
        return int(self.states.shape[0])

    @property
    def action_bounds(self) -> tuple[float, float]:
        if len(self) == 0:
            return (0.0, 0.0)
        return (float(self.actions.min()), float(self.actions.max()))


def _keep(t: Transition, cfg: RLConfig) -> bool:
    if cfg.drop_leading and not t.s_valid:
        return False
    if cfg.drop_no_traffic and t.s2.attempted <= 0.0:
        return False
    return True


def build_dataset(
    paths: str | Path | Iterable[str | Path],
    cfg: RLConfig | None = None,
    *,
    extractor: FeatureExtractor | None = None,
    reward_fn: RewardFn | None = None,
) -> Dataset:
    """Compose corpus -> (extractor, reward) -> stacked arrays.

    ``extractor`` / ``reward_fn`` default to the built-in flat-window /
    SLO-progress implementations but can be overridden to change the state
    representation or objective without touching this function.
    """
    cfg = cfg or RLConfig()
    extractor = extractor or DefaultFeatureExtractor(cfg)
    reward_fn = reward_fn or SloProgressReward(cfg)

    transitions = corpus_io.load_transitions(paths)
    episodes = corpus_io.group_episodes(transitions)

    s_list: list[np.ndarray] = []
    a_list: list[float] = []
    r_list: list[float] = []
    s2_list: list[np.ndarray] = []
    done_list: list[float] = []
    eid_list: list[int] = []

    for eid, (run_id, eps) in enumerate(sorted(episodes.items())):
        kept = [t for t in eps if _keep(t, cfg)]
        for i, t in enumerate(kept):
            s_list.append(extractor.state_vector(t.s, t))
            s2_list.append(extractor.state_vector(t.s2, t))
            a_list.append(t.action_rps)
            r_list.append(reward_fn(t))
            # Terminal if the controller converged, or it's the last kept window of
            # the trajectory (the corpus was cut here) — bootstrapping past it is wrong.
            done_list.append(1.0 if (t.done or i == len(kept) - 1) else 0.0)
            eid_list.append(eid)

    dim = extractor.dim
    if s_list:
        states = np.stack(s_list).astype(np.float32)
        next_states = np.stack(s2_list).astype(np.float32)
    else:
        states = np.zeros((0, dim), dtype=np.float32)
        next_states = np.zeros((0, dim), dtype=np.float32)

    return Dataset(
        states=states,
        actions=np.asarray(a_list, dtype=np.float32),
        rewards=np.asarray(r_list, dtype=np.float32),
        next_states=next_states,
        dones=np.asarray(done_list, dtype=np.float32),
        episode_ids=np.asarray(eid_list, dtype=np.int64),
        feature_names=tuple(cfg.feature_names)
        + (tuple(f"{n}_known" for n in cfg.maskable_features) if cfg.mask_unknown else ()),
        normalizer=Normalizer.fit(states) if len(states) else Normalizer(
            mean=np.zeros(dim, dtype=np.float32), std=np.ones(dim, dtype=np.float32)
        ),
    )
