"""Off-policy evaluation (FQE) — the pre-production gate.

Before a learned policy is ever allowed to drive a live target, we score it on the
corpus alone. Fitted Q Evaluation trains Q^pi for the (deterministic) learned
policy off the logged transitions, then estimates its value at the corpus's
initial states. We compare that to the behavior policy's realized return (the
discounted Monte-Carlo return of the logged AIMD/binsearch trajectories). If the
learned policy doesn't beat the behavior offline, it does not ship — no live SUT
is risked to find that out.

The gate is uncertainty-aware. On the small corpora this trains on, a bare
"fqe >= behavior" point comparison ships on noise, so by default we bootstrap the
per-episode improvement (fqe(s0) - behavior return, paired by episode) and require
its LOWER confidence bound to clear zero (``pessimistic_gate``). The result also
carries the effective planning horizon 1/(1-gamma) against the mean episode length:
a large gap (``horizon_mismatch``) means gamma discounts over far more windows than
an episode contains, and gamma should be tuned toward 1 - 1/mean_episode_len.

torch is optional and only needed for the FQE fit; the behavior baseline is pure
numpy.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .dataset import Dataset
from .policy_artifact import PolicyArtifact

try:
    import torch
    import torch.nn as nn
except ImportError:  # pragma: no cover - optional dependency
    torch = None
    nn = None


@dataclass(frozen=True)
class FQEConfig:
    hidden_dims: tuple[int, ...] = (64, 64)
    lr: float = 3e-4
    gamma: float = 0.99
    polyak: float = 0.005
    batch_size: int = 256
    steps: int = 2000
    seed: int = 0
    # Uncertainty-aware gate. On the small corpora this pipeline trains on, a point
    # FQE estimate is high-variance and a bare "fqe >= behavior" gate ships on noise.
    # We bootstrap the per-episode improvement (fqe(s0) - behavior return, paired by
    # episode) and, when `pessimistic_gate` is set, require its LOWER confidence bound
    # to clear zero — the policy must beat behavior with margin, not by luck.
    n_bootstrap: int = 2000
    ci_alpha: float = 0.10       # 90% CI (two-sided) => 5th-percentile lower bound
    pessimistic_gate: bool = True


@dataclass(frozen=True)
class OPEResult:
    fqe_value: float        # estimated discounted return of the learned policy
    behavior_return: float  # realized discounted return in the logged data
    gate_pass: bool         # pessimistic: improvement_ci_low >= 0 (else fqe >= behavior)
    n_episodes: int
    n_initial_states: int
    # Uncertainty on the improvement (fqe - behavior), bootstrapped over episodes.
    improvement_ci_low: float = 0.0
    improvement_ci_high: float = 0.0
    fqe_ci_low: float = 0.0
    fqe_ci_high: float = 0.0
    # Effective vs actual planning horizon — a large gap means gamma is discounting
    # over far more windows than an episode contains, so tune gamma ~ 1 - 1/mean_len.
    effective_horizon: float = 0.0   # 1 / (1 - gamma)
    mean_episode_len: float = 0.0

    @property
    def improvement(self) -> float:
        return self.fqe_value - self.behavior_return

    @property
    def horizon_mismatch(self) -> bool:
        """True when the discount horizon overshoots the episode length ~2x+."""
        return self.mean_episode_len > 0.0 and self.effective_horizon > 2.0 * self.mean_episode_len


def behavior_returns_per_episode(dataset: Dataset, gamma: float) -> np.ndarray:
    """Per-episode discounted Monte-Carlo returns, ordered by np.unique(episode_ids)."""
    eids = dataset.episode_ids
    rewards = dataset.rewards
    returns: list[float] = []
    for eid in np.unique(eids):
        rs = rewards[eids == eid]
        g = 0.0
        for rr in reversed(rs):
            g = rr + gamma * g
        returns.append(g)
    return np.asarray(returns, dtype=np.float64)


def behavior_return(dataset: Dataset, gamma: float) -> float:
    """Mean discounted Monte-Carlo return of the logged trajectories (the baseline)."""
    per_ep = behavior_returns_per_episode(dataset, gamma)
    return float(per_ep.mean()) if per_ep.size else 0.0


def _paired_bootstrap_ci(a: np.ndarray, b: np.ndarray, n_boot: int, alpha: float,
                         seed: int) -> tuple[float, float]:
    """CI on mean(a) - mean(b), resampling episodes together (paired) with replacement."""
    n = a.shape[0]
    if n == 0 or n_boot <= 0:
        return 0.0, 0.0
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, n, size=(n_boot, n))
    diff = a[idx].mean(axis=1) - b[idx].mean(axis=1)
    lo = float(np.percentile(diff, 100.0 * alpha / 2.0))
    hi = float(np.percentile(diff, 100.0 * (1.0 - alpha / 2.0)))
    return lo, hi


def _mlp(sizes: list[int]):
    layers = []
    for i in range(len(sizes) - 1):
        layers.append(nn.Linear(sizes[i], sizes[i + 1]))
        if i < len(sizes) - 2:
            layers.append(nn.ReLU())
    return nn.Sequential(*layers)


def _policy_action_norm(artifact: PolicyArtifact, states_raw: np.ndarray,
                        lo: np.ndarray, hi: np.ndarray) -> np.ndarray:
    """The learned policy's (N, A) action on raw states, in the [0,1] space Q was fit on."""
    act = artifact.act_batch(states_raw)  # (N, A) de-normalized
    span = np.where(hi <= lo, 1.0, hi - lo)
    return ((act - lo) / span).clip(0.0, 1.0)


def evaluate_policy(dataset: Dataset, artifact: PolicyArtifact,
                    cfg: FQEConfig | None = None) -> OPEResult:
    """FQE value of ``artifact`` vs the behavior return. Gate = learned >= behavior."""
    if torch is None:  # pragma: no cover
        raise ImportError("FQE requires torch (pip install -r requirements-ml.txt)")
    cfg = cfg or FQEConfig()
    beh_per_ep = behavior_returns_per_episode(dataset, cfg.gamma)
    base = float(beh_per_ep.mean()) if beh_per_ep.size else 0.0
    n_eps = int(np.unique(dataset.episode_ids).size)
    eff_h = 1.0 / max(1e-9, 1.0 - cfg.gamma)
    mean_len = float(len(dataset) / n_eps) if n_eps else 0.0

    if len(dataset) == 0:
        return OPEResult(0.0, base, True, n_eps, 0,
                         effective_horizon=eff_h, mean_episode_len=mean_len)

    torch.manual_seed(cfg.seed)
    np.random.seed(cfg.seed)

    norm = dataset.normalizer
    feat_dim = dataset.states.shape[1]
    a_dim = dataset.action_dim
    lo = np.asarray(dataset.action_lo, dtype=np.float32)
    hi = np.asarray(dataset.action_hi, dtype=np.float32)
    span = np.where(hi <= lo, 1.0, hi - lo)

    S = norm.transform(dataset.states)
    S2 = norm.transform(dataset.next_states)
    A = ((dataset.actions - lo) / span).clip(0.0, 1.0).reshape(-1, a_dim)
    # Learned policy's action at s' (for the FQE bootstrap) and at initial states.
    A2_pi = _policy_action_norm(artifact, dataset.next_states, lo, hi)

    dev = torch.device("cpu")
    s = torch.tensor(S, dtype=torch.float32, device=dev)
    s2 = torch.tensor(S2, dtype=torch.float32, device=dev)
    a = torch.tensor(A, dtype=torch.float32, device=dev)
    a2 = torch.tensor(A2_pi, dtype=torch.float32, device=dev)
    r = torch.tensor(dataset.rewards.reshape(-1, 1), dtype=torch.float32, device=dev)
    done = torch.tensor(dataset.dones.reshape(-1, 1), dtype=torch.float32, device=dev)

    q = _mlp([feat_dim + a_dim, *cfg.hidden_dims, 1]).to(dev)
    q_t = _mlp([feat_dim + a_dim, *cfg.hidden_dims, 1]).to(dev)
    q_t.load_state_dict(q.state_dict())
    opt = torch.optim.Adam(q.parameters(), lr=cfg.lr)

    n = s.shape[0]
    bs = min(cfg.batch_size, n)
    for _ in range(cfg.steps):
        idx = torch.randint(0, n, (bs,), device=dev)
        sab = torch.cat([s[idx], a[idx]], dim=1)
        with torch.no_grad():
            s2a2 = torch.cat([s2[idx], a2[idx]], dim=1)
            td = r[idx] + cfg.gamma * (1.0 - done[idx]) * q_t(s2a2)
        loss = (q(sab) - td).pow(2).mean()
        opt.zero_grad(); loss.backward(); opt.step()
        with torch.no_grad():
            for tp, sp in zip(q_t.parameters(), q.parameters()):
                tp.mul_(1 - cfg.polyak).add_(cfg.polyak * sp)

    # Value estimate: Q(s0, pi(s0)) at each episode's initial state (per-episode, so
    # it pairs 1:1 with beh_per_ep for the bootstrap; np.unique gives the same order).
    eids = dataset.episode_ids
    first_idx = [int(np.where(eids == e)[0][0]) for e in np.unique(eids)]
    s0_raw = dataset.states[first_idx]
    a0 = _policy_action_norm(artifact, s0_raw, lo, hi)
    with torch.no_grad():
        s0 = torch.tensor(norm.transform(s0_raw), dtype=torch.float32, device=dev)
        s0a0 = torch.cat([s0, torch.tensor(a0, dtype=torch.float32, device=dev)], dim=1)
        fqe_per_ep = q(s0a0).squeeze(-1).cpu().numpy().astype(np.float64)
    fqe = float(fqe_per_ep.mean())

    imp_lo, imp_hi = _paired_bootstrap_ci(
        fqe_per_ep, beh_per_ep, cfg.n_bootstrap, cfg.ci_alpha, cfg.seed)
    fqe_lo, fqe_hi = _paired_bootstrap_ci(
        fqe_per_ep, np.zeros_like(fqe_per_ep), cfg.n_bootstrap, cfg.ci_alpha, cfg.seed)

    # Pessimistic gate: the policy must beat behavior with margin (lower CI bound of
    # the paired improvement clears zero), not on a lucky point estimate. Falls back
    # to the bare point comparison when pessimism is disabled or there is no spread.
    if cfg.pessimistic_gate and cfg.n_bootstrap > 0 and n_eps > 1:
        gate = imp_lo >= 0.0
    else:
        gate = fqe >= base

    return OPEResult(
        fqe_value=fqe,
        behavior_return=base,
        gate_pass=gate,
        n_episodes=n_eps,
        n_initial_states=len(first_idx),
        improvement_ci_low=imp_lo,
        improvement_ci_high=imp_hi,
        fqe_ci_low=fqe_lo,
        fqe_ci_high=fqe_hi,
        effective_horizon=eff_h,
        mean_episode_len=mean_len,
    )
