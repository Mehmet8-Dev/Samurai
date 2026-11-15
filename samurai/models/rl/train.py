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
    import torch.nn.functional as F
except ImportError:  # pragma: no cover - optional training dependency
    torch = None
    nn = None
    F = None


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
    a_dim = dataset.action_dim
    norm = dataset.normalizer
    S = norm.transform(dataset.states)
    S2 = norm.transform(dataset.next_states)

    # Per-dim action normalization to [0,1] using the data-derived bounds that also
    # travel to serving, so the exported policy de-normalizes each dim identically.
    # The critic (Q/V) always consumes the a_dim scalar action embedding; only the
    # policy *head* splits continuous vs categorical dims.
    lo = np.asarray(dataset.action_lo, dtype=np.float32)
    hi = np.asarray(dataset.action_hi, dtype=np.float32)
    span = np.where(hi <= lo, 1.0, hi - lo)
    A = ((dataset.actions - lo) / span).clip(0.0, 1.0).reshape(-1, a_dim)

    # Per-dim head layout. A continuous dim owns one output (regressed to A[:,k]); a
    # categorical dim owns len(cats) logits (classified to the logged category
    # index). heads[k] = ("continuous", col) or ("categorical", col, width, cats).
    kinds = dataset.action_kinds or ("continuous",) * a_dim
    categories = dataset.action_categories or (None,) * a_dim
    heads: list[tuple] = []
    cat_targets = np.zeros((dataset.actions.shape[0], a_dim), dtype=np.int64)
    col = 0
    for k in range(a_dim):
        if kinds[k] == "categorical":
            cats = np.asarray(categories[k], dtype=np.float32)
            width = int(cats.size)
            # Map each logged raw value to its nearest category index.
            diffs = np.abs(dataset.actions[:, k][:, None] - cats[None, :])
            cat_targets[:, k] = np.argmin(diffs, axis=1)
            heads.append(("categorical", col, width, cats))
            col += width
        else:
            heads.append(("continuous", col))
            col += 1
    out_width = col

    dev = torch.device("cpu")
    s = torch.tensor(S, dtype=torch.float32, device=dev)
    s2 = torch.tensor(S2, dtype=torch.float32, device=dev)
    a = torch.tensor(A, dtype=torch.float32, device=dev)
    ct = torch.tensor(cat_targets, dtype=torch.long, device=dev)
    r = torch.tensor(dataset.rewards.reshape(-1, 1), dtype=torch.float32, device=dev)
    done = torch.tensor(dataset.dones.reshape(-1, 1), dtype=torch.float32, device=dev)

    qnet = lambda: _mlp([feat_dim + a_dim, *cfg.hidden_dims, 1]).to(dev)
    q1, q2 = qnet(), qnet()
    q1_t, q2_t = qnet(), qnet()
    q1_t.load_state_dict(q1.state_dict())
    q2_t.load_state_dict(q2.state_dict())
    vnet = _mlp([feat_dim, *cfg.hidden_dims, 1]).to(dev)
    policy = _mlp([feat_dim, *cfg.hidden_dims, out_width]).to(dev)

    opt_q = torch.optim.Adam([*q1.parameters(), *q2.parameters()], lr=cfg.lr)
    opt_v = torch.optim.Adam(vnet.parameters(), lr=cfg.lr)
    opt_p = torch.optim.Adam(policy.parameters(), lr=cfg.lr)

    n = s.shape[0]
    bs = min(cfg.batch_size, n)

    for _ in range(cfg.steps):
        idx = torch.randint(0, n, (bs,), device=dev)
        sb, s2b, ab, rb, db, ctb = s[idx], s2[idx], a[idx], r[idx], done[idx], ct[idx]
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

        # Policy: advantage-weighted imitation of the logged action. Continuous dims
        # are regressed (MSE); categorical dims are classified (cross-entropy) toward
        # the logged category — so a WAF-blocked variant gets *down*-weighted, not
        # averaged in. Both share the same AWR weight exp(beta*adv).
        with torch.no_grad():
            adv = torch.min(q1(sab), q2(sab)) - vnet(sb)
            w = torch.clamp(torch.exp(cfg.beta * adv), max=cfg.adv_clip).squeeze(1)  # (B,)
        pred = policy(sb)
        loss_p = pred.new_zeros(())
        for k, head in enumerate(heads):
            if head[0] == "categorical":
                _, c0, width, _ = head
                logits = pred[:, c0:c0 + width]
                ce = F.cross_entropy(logits, ctb[:, k], reduction="none")  # (B,)
                loss_p = loss_p + (w * ce).mean()
            else:
                c0 = head[1]
                loss_p = loss_p + (w * (pred[:, c0] - ab[:, k]).pow(2)).mean()
        opt_p.zero_grad(); loss_p.backward(); opt_p.step()

        with torch.no_grad():
            for tp, sp in zip(q1_t.parameters(), q1.parameters()):
                tp.mul_(1 - cfg.polyak).add_(cfg.polyak * sp)
            for tp, sp in zip(q2_t.parameters(), q2.parameters()):
                tp.mul_(1 - cfg.polyak).add_(cfg.polyak * sp)

    return _extract_artifact(policy, norm, lo, hi, dataset.feature_names,
                             dataset.action_spec.names, kinds, categories)


def _extract_artifact(policy, norm, lo, hi, feature_names, action_names,
                      action_kinds=(), action_categories=()) -> PolicyArtifact:
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
        action_lo=np.asarray(lo, dtype=np.float32),
        action_hi=np.asarray(hi, dtype=np.float32),
        feature_names=tuple(feature_names),
        action_names=tuple(action_names),
        action_kinds=tuple(action_kinds),
        action_categories=tuple(action_categories),
    )
