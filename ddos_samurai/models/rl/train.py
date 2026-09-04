"""Offline-RL trainer (IQL) — learns a setpoint policy from a fixed corpus.

Implicit Q-Learning fits a value function with expectile regression and extracts
a policy by advantage-weighted regression, *never querying actions outside the
data* — the right fit for our small, noisy, off-policy corpus where online methods
(PPO/SAC) would be unstable and, worse, would need to probe a live target.

The action is the setpoint rps, trained in a normalized [0,1] space and extracted
as a deterministic MLP so it exports directly to the torch-free ``PolicyArtifact``
that C++ serves. torch is an optional dependency (see requirements-ml.txt); import
fails loudly only when you actually train.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .dataset import Dataset
from .policy_artifact import PolicyArtifact

try:
    import torch
    import torch.nn as nn
except ImportError:  # pragma: no cover - optional training dependency
    torch = None
    nn = None


@dataclass(frozen=True)
class IQLConfig:
    hidden_dims: tuple[int, ...] = (64, 64)
    lr: float = 3e-4
    gamma: float = 0.99
    tau: float = 0.7          # expectile (>0.5 => optimistic value, IQL default 0.7)
    beta: float = 3.0         # AWR temperature
    adv_clip: float = 100.0   # cap on exp(beta*adv) so a few transitions can't dominate
    polyak: float = 0.005
    batch_size: int = 256
    steps: int = 2000
    seed: int = 0


def _mlp(sizes: list[int]):
    layers = []
    for i in range(len(sizes) - 1):
        layers.append(nn.Linear(sizes[i], sizes[i + 1]))
        if i < len(sizes) - 2:
            layers.append(nn.ReLU())
    return nn.Sequential(*layers)


def _expectile_loss(diff, tau: float):
    # L2 expectile: asymmetric squared error. tau>0.5 penalizes under-estimates more.
    weight = torch.where(diff > 0, tau, 1.0 - tau)
    return (weight * diff.pow(2)).mean()


def _require_torch() -> None:
    if torch is None:  # pragma: no cover - exercised only without torch installed
        raise ImportError(
            "training requires torch (pip install -r requirements-ml.txt); "
            "serving/export/OPE-of-a-loaded-policy do not."
        )


def train_iql(dataset: Dataset, cfg: IQLConfig | None = None) -> PolicyArtifact:
    """Train an IQL policy on the corpus and return the torch-free artifact."""
    _require_torch()
    cfg = cfg or IQLConfig()
    if len(dataset) == 0:
        raise ValueError("empty dataset — capture a corpus first")

    torch.manual_seed(cfg.seed)
    np.random.seed(cfg.seed)

    feat_dim = dataset.states.shape[1]
    norm = dataset.normalizer
    S = norm.transform(dataset.states)
    S2 = norm.transform(dataset.next_states)

    lo, hi = dataset.action_bounds
    if hi <= lo:
        hi = lo + 1.0
    A = ((dataset.actions - lo) / (hi - lo)).clip(0.0, 1.0).reshape(-1, 1)

    dev = torch.device("cpu")
    s = torch.tensor(S, dtype=torch.float32, device=dev)
    s2 = torch.tensor(S2, dtype=torch.float32, device=dev)
    a = torch.tensor(A, dtype=torch.float32, device=dev)
    r = torch.tensor(dataset.rewards.reshape(-1, 1), dtype=torch.float32, device=dev)
    done = torch.tensor(dataset.dones.reshape(-1, 1), dtype=torch.float32, device=dev)

    qnet = lambda: _mlp([feat_dim + 1, *cfg.hidden_dims, 1]).to(dev)
    q1, q2 = qnet(), qnet()
    q1_t, q2_t = qnet(), qnet()
    q1_t.load_state_dict(q1.state_dict())
    q2_t.load_state_dict(q2.state_dict())
    vnet = _mlp([feat_dim, *cfg.hidden_dims, 1]).to(dev)
    policy = _mlp([feat_dim, *cfg.hidden_dims, 1]).to(dev)

    opt_q = torch.optim.Adam([*q1.parameters(), *q2.parameters()], lr=cfg.lr)
    opt_v = torch.optim.Adam(vnet.parameters(), lr=cfg.lr)
    opt_p = torch.optim.Adam(policy.parameters(), lr=cfg.lr)

    n = s.shape[0]
    bs = min(cfg.batch_size, n)

    for _ in range(cfg.steps):
        idx = torch.randint(0, n, (bs,), device=dev)
        sb, s2b, ab, rb, db = s[idx], s2[idx], a[idx], r[idx], done[idx]
        sab = torch.cat([sb, ab], dim=1)

        # Value: expectile regression toward min of target Q.
        with torch.no_grad():
            q_target = torch.min(q1_t(sab), q2_t(sab))
        v = vnet(sb)
        loss_v = _expectile_loss(q_target - v, cfg.tau)
        opt_v.zero_grad(); loss_v.backward(); opt_v.step()

        # Q: TD toward r + gamma * V(s').
        with torch.no_grad():
            td = rb + cfg.gamma * (1.0 - db) * vnet(s2b)
        loss_q = ((q1(sab) - td).pow(2) + (q2(sab) - td).pow(2)).mean()
        opt_q.zero_grad(); loss_q.backward(); opt_q.step()

        # Policy: advantage-weighted regression toward the logged action.
        with torch.no_grad():
            adv = torch.min(q1(sab), q2(sab)) - vnet(sb)
            weight = torch.clamp(torch.exp(cfg.beta * adv), max=cfg.adv_clip)
        pred = policy(sb)
        loss_p = (weight * (pred - ab).pow(2)).mean()
        opt_p.zero_grad(); loss_p.backward(); opt_p.step()

        with torch.no_grad():
            for tp, sp in zip(q1_t.parameters(), q1.parameters()):
                tp.mul_(1 - cfg.polyak).add_(cfg.polyak * sp)
            for tp, sp in zip(q2_t.parameters(), q2.parameters()):
                tp.mul_(1 - cfg.polyak).add_(cfg.polyak * sp)

    return _extract_artifact(policy, norm, lo, hi, dataset.feature_names)


def _extract_artifact(policy, norm, lo: float, hi: float, feature_names) -> PolicyArtifact:
    """Pull the Linear layers out of the torch policy into a numpy artifact."""
    layers: list[tuple[np.ndarray, np.ndarray]] = []
    for m in policy:
        if isinstance(m, nn.Linear):
            W = m.weight.detach().cpu().numpy().astype(np.float32)
            b = m.bias.detach().cpu().numpy().astype(np.float32)
            layers.append((W, b))
    return PolicyArtifact(
        layers=layers,
        norm_mean=np.asarray(norm.mean, dtype=np.float32),
        norm_std=np.asarray(norm.std, dtype=np.float32),
        action_lo=float(lo),
        action_hi=float(hi),
        feature_names=tuple(feature_names),
    )
