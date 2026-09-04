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
from .action_spec import RPS_ONLY, ActionSpec
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
    """A stacked offline-RL dataset. Actions are raw (per-dim) values; the trainer
    normalizes each dimension by [action_lo, action_hi] (which travel to serving)."""

    states: np.ndarray       # (N, F) raw (un-normalized) state features
    actions: np.ndarray      # (N, A) raw action per controlled dim; col 0 == rps
    rewards: np.ndarray      # (N,)
    next_states: np.ndarray  # (N, F)
    dones: np.ndarray        # (N,)   episode-terminal flag
    episode_ids: np.ndarray  # (N,)   run_id index, for per-trajectory OPE
    feature_names: tuple[str, ...]
    normalizer: Normalizer
    action_spec: ActionSpec = RPS_ONLY
    action_lo: np.ndarray = None  # (A,) per-dim lower bound (data-derived)
    action_hi: np.ndarray = None  # (A,) per-dim upper bound
    # Per-dim head kind ("continuous"/"categorical") and, for categorical dims, the
    # sorted unique category values observed in the corpus (None for continuous).
    # These travel with the exported policy so serving maps a softmax argmax back to
    # the raw lever value identically.
    action_kinds: tuple[str, ...] = ()
    action_categories: tuple = ()

    def __len__(self) -> int:
        return int(self.states.shape[0])

    @property
    def action_dim(self) -> int:
        return int(self.actions.shape[1]) if self.actions.ndim == 2 else 1

    @property
    def action_bounds(self) -> tuple[float, float]:
        """Bounds of the primary (rps) dimension — back-compat scalar accessor."""
        if len(self) == 0:
            return (0.0, 0.0)
        return (float(self.action_lo[0]), float(self.action_hi[0]))


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
    action_spec: ActionSpec | None = None,
) -> Dataset:
    """Compose corpus -> (extractor, reward) -> stacked arrays.

    ``extractor`` / ``reward_fn`` default to the built-in flat-window /
    SLO-progress implementations but can be overridden. ``action_spec`` selects the
    controlled action dimensions (default: rps only); pass action_spec.MAHORAGA for
    the full vector.
    """
    cfg = cfg or RLConfig()
    extractor = extractor or DefaultFeatureExtractor(cfg)
    reward_fn = reward_fn or SloProgressReward(cfg)
    action_spec = action_spec or RPS_ONLY

    transitions = corpus_io.load_transitions(paths)
    episodes = corpus_io.group_episodes(transitions)

    s_list: list[np.ndarray] = []
    a_list: list[list[float]] = []
    r_list: list[float] = []
    s2_list: list[np.ndarray] = []
    done_list: list[float] = []
    eid_list: list[int] = []

    for eid, (run_id, eps) in enumerate(sorted(episodes.items())):
        kept = [t for t in eps if _keep(t, cfg)]
        for i, t in enumerate(kept):
            s_list.append(extractor.state_vector(t.s, t))
            s2_list.append(extractor.state_vector(t.s2, t))
            a_list.append([t.action.value(action_spec.field_of(n)) for n in action_spec.names])
            r_list.append(reward_fn(t))
            # Terminal if the controller converged, or it's the last kept window of
            # the trajectory (the corpus was cut here) — bootstrapping past it is wrong.
            done_list.append(1.0 if (t.done or i == len(kept) - 1) else 0.0)
            eid_list.append(eid)

    dim = extractor.dim
    a_dim = action_spec.dim
    if s_list:
        states = np.stack(s_list).astype(np.float32)
        next_states = np.stack(s2_list).astype(np.float32)
        actions = np.asarray(a_list, dtype=np.float32).reshape(-1, a_dim)
    else:
        states = np.zeros((0, dim), dtype=np.float32)
        next_states = np.zeros((0, dim), dtype=np.float32)
        actions = np.zeros((0, a_dim), dtype=np.float32)

    # Per-dim bounds from the data; collapse a degenerate (constant/undriven) dim
    # to [lo, lo+1] so normalization never divides by zero.
    if len(actions):
        action_lo = actions.min(axis=0)
        action_hi = actions.max(axis=0)
    else:
        action_lo = np.zeros(a_dim, dtype=np.float32)
        action_hi = np.ones(a_dim, dtype=np.float32)
    action_hi = np.where(action_hi <= action_lo, action_lo + 1.0, action_hi).astype(np.float32)
    action_lo = action_lo.astype(np.float32)

    # Per-dim head kind + data-derived categories. For a categorical dim we take the
    # sorted unique (integer-rounded) values it took across the corpus as its class
    # set, and pin its [lo, hi] to the category range so the critic's scalar action
    # embedding (used by IQL's Q and FQE) stays consistent with serving.
    kinds = tuple(
        "categorical" if action_spec.is_categorical(n) else "continuous"
        for n in action_spec.names
    )
    categories: list = []
    for k in range(a_dim):
        if kinds[k] == "categorical" and len(actions):
            uniq = np.unique(np.rint(actions[:, k]).astype(np.int64)).astype(np.float32)
            if uniq.size == 0:
                uniq = np.array([0.0], dtype=np.float32)
            categories.append(uniq)
            action_lo[k] = float(uniq.min())
            action_hi[k] = float(uniq.max() if uniq.max() > uniq.min() else uniq.min() + 1.0)
        else:
            categories.append(None)

    return Dataset(
        states=states,
        actions=actions,
        rewards=np.asarray(r_list, dtype=np.float32),
        next_states=next_states,
        dones=np.asarray(done_list, dtype=np.float32),
        episode_ids=np.asarray(eid_list, dtype=np.int64),
        feature_names=tuple(cfg.feature_names)
        + (tuple(f"{n}_known" for n in cfg.maskable_features) if cfg.mask_unknown else ()),
        normalizer=Normalizer.fit(states) if len(states) else Normalizer(
            mean=np.zeros(dim, dtype=np.float32), std=np.ones(dim, dtype=np.float32)
        ),
        action_spec=action_spec,
        action_lo=action_lo,
        action_hi=action_hi,
        action_kinds=kinds,
        action_categories=tuple(categories),
    )
