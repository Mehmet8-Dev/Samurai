"""Off-policy evaluation (FQE) — the pre-production gate.

Before a learned policy is ever allowed to drive a live target, we score it on the
corpus alone. Fitted Q Evaluation trains Q^pi for the (deterministic) learned
policy off the logged transitions, then estimates its value at the corpus's
initial states. We compare that to the behavior policy's realized return (the
discounted Monte-Carlo return of the logged AIMD/binsearch trajectories). If the
learned policy doesn't beat the behavior offline, it does not ship — no live SUT
is risked to find that out.

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


@dataclass(frozen=True)
class OPEResult:
    fqe_value: float        # estimated discounted return of the learned policy
    behavior_return: float  # realized discounted return in the logged data
    gate_pass: bool         # fqe_value >= behavior_return
    n_episodes: int
    n_initial_states: int

    @property
    def improvement(self) -> float:
        return self.fqe_value - self.behavior_return


def behavior_return(dataset: Dataset, gamma: float) -> float:
    """Mean discounted Monte-Carlo return of the logged trajectories (the baseline)."""
    eids = dataset.episode_ids
    rewards = dataset.rewards
    returns: list[float] = []
    for eid in np.unique(eids):
        rs = rewards[eids == eid]
        g = 0.0
        for rr in reversed(rs):
            g = rr + gamma * g
        returns.append(g)
    return float(np.mean(returns)) if returns else 0.0


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
    base = behavior_return(dataset, cfg.gamma)
    n_eps = int(np.unique(dataset.episode_ids).size)

    if len(dataset) == 0:
        return OPEResult(0.0, base, True, n_eps, 0)

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

    # Value estimate: Q(s0, pi(s0)) averaged over each episode's initial state.
    eids = dataset.episode_ids
    first_idx = [int(np.where(eids == e)[0][0]) for e in np.unique(eids)]
    s0_raw = dataset.states[first_idx]
    a0 = _policy_action_norm(artifact, s0_raw, lo, hi)
    with torch.no_grad():
        s0 = torch.tensor(norm.transform(s0_raw), dtype=torch.float32, device=dev)
        s0a0 = torch.cat([s0, torch.tensor(a0, dtype=torch.float32, device=dev)], dim=1)
        fqe = float(q(s0a0).mean().item())

    return OPEResult(
        fqe_value=fqe,
        behavior_return=base,
        gate_pass=fqe >= base,
        n_episodes=n_eps,
        n_initial_states=len(first_idx),
    )
