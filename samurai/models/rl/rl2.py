"""RL² — the recurrent, in-context policy (the Mahoraga wheel made the network).

The feedforward policy (``train.py``) reacts to one window; its only cross-window
memory is the hand-rolled LeverShield/ban EWMA appended as state features. RL²
replaces that with a *learned* memory: a GRU whose hidden state is carried across
the episode, so the SAME frozen weights produce a different action as the trajectory
unfolds — the wheel turns during the fight, no weight update needed. On a target
whose defense the fixed levers can't crack, the recurrent policy can shift strategy
purely from the pattern of reactions it has already seen this episode.

Design (kept deliberately stable and small for the noisy off-policy corpus):

  * Critic: a feedforward IQL critic (Q1/Q2/V) over (single-window state, action),
    identical to ``train.py`` — it supplies per-transition advantages A(s,a).
  * Actor: GRUCell context encoder + MLP head, trained by advantage-weighted
    regression *over episode sequences*. At window i the head consumes
    [standardized state_i, hidden_i] where hidden_i integrates windows < i; the GRU
    is advanced by the token [standardized state, applied action (normalized)]. This
    is exactly the recurrence ``rl_policy.cpp`` runs online (nn.GRU is a stack of the
    same GRUCell math), so the exported v4 artifact serves op-for-op.

RL² trains on the BASE state (no block/ban features): the GRU subsumes that memory,
which is the whole point. The serving LeverShield can still bound the proposal as a
safety net, but the adaptation now lives in the network.

torch is an optional dependency (see requirements-ml.txt); import fails loudly only
when you actually train.
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
class RL2Config:
    hidden_dim: int = 32          # GRU context width (the carried episode memory)
    head_dims: tuple[int, ...] = (64,)  # MLP head hidden layers over [state, hidden]
    critic_dims: tuple[int, ...] = (64, 64)
    lr: float = 3e-4
    gamma: float = 0.99
    tau: float = 0.7              # IQL expectile
    beta: float = 3.0            # AWR temperature
    adv_clip: float = 100.0
    polyak: float = 0.005
    critic_steps: int = 2000     # feedforward critic pretrain
    actor_steps: int = 2000      # recurrent AWR fit
    episode_batch: int = 16      # episodes per actor step
    seed: int = 0


def _mlp(sizes: list[int]):
    layers = []
    for i in range(len(sizes) - 1):
        layers.append(nn.Linear(sizes[i], sizes[i + 1]))
        if i < len(sizes) - 2:
            layers.append(nn.ReLU())
    return nn.Sequential(*layers)


def _expectile_loss(diff, tau: float):
    weight = torch.where(diff > 0, tau, 1.0 - tau)
    return (weight * diff.pow(2)).mean()


def _require_torch() -> None:
    if torch is None:  # pragma: no cover
        raise ImportError(
            "RL² training requires torch (pip install -r requirements-ml.txt); "
            "serving/export/OPE of a loaded policy do not."
        )


def _episode_slices(episode_ids: np.ndarray) -> list[tuple[int, int]]:
    """Contiguous [start, end) index ranges per episode (built in-order by the
    dataset, so equal ids are already contiguous and window-ordered)."""
    slices: list[tuple[int, int]] = []
    if episode_ids.size == 0:
        return slices
    start = 0
    for i in range(1, len(episode_ids)):
        if episode_ids[i] != episode_ids[i - 1]:
            slices.append((start, i))
            start = i
    slices.append((start, len(episode_ids)))
    return slices


def _train_critic(cfg: RL2Config, s, a, s2, r, done, feat_dim, a_dim):
    """Feedforward IQL critic -> per-transition advantage A(s,a) = min(Q) - V(s)."""
    qnet = lambda: _mlp([feat_dim + a_dim, *cfg.critic_dims, 1])
    q1, q2, q1_t, q2_t = qnet(), qnet(), qnet(), qnet()
    q1_t.load_state_dict(q1.state_dict())
    q2_t.load_state_dict(q2.state_dict())
    vnet = _mlp([feat_dim, *cfg.critic_dims, 1])
    opt_q = torch.optim.Adam([*q1.parameters(), *q2.parameters()], lr=cfg.lr)
    opt_v = torch.optim.Adam(vnet.parameters(), lr=cfg.lr)

    n = s.shape[0]
    bs = min(256, n)
    for _ in range(cfg.critic_steps):
        idx = torch.randint(0, n, (bs,))
        sb, s2b, ab, rb, db = s[idx], s2[idx], a[idx], r[idx], done[idx]
        sab = torch.cat([sb, ab], dim=1)
        with torch.no_grad():
            q_target = torch.min(q1_t(sab), q2_t(sab))
        loss_v = _expectile_loss(q_target - vnet(sb), cfg.tau)
        opt_v.zero_grad(); loss_v.backward(); opt_v.step()
        with torch.no_grad():
            td = rb + cfg.gamma * (1.0 - db) * vnet(s2b)
        loss_q = ((q1(sab) - td).pow(2) + (q2(sab) - td).pow(2)).mean()
        opt_q.zero_grad(); loss_q.backward(); opt_q.step()
        with torch.no_grad():
            for tp, sp in zip(q1_t.parameters(), q1.parameters()):
                tp.mul_(1 - cfg.polyak).add_(cfg.polyak * sp)
            for tp, sp in zip(q2_t.parameters(), q2.parameters()):
                tp.mul_(1 - cfg.polyak).add_(cfg.polyak * sp)

    with torch.no_grad():
        sab = torch.cat([s, a], dim=1)
        adv = (torch.min(q1(sab), q2(sab)) - vnet(s)).squeeze(1)  # (N,)
    return adv


def train_rl2(dataset: Dataset, cfg: RL2Config | None = None) -> PolicyArtifact:
    """Train an RL² recurrent policy on the corpus -> torch-free v4 artifact.

    ``dataset`` must be built on the BASE state (no variant-block / ban features);
    the GRU learns that cross-window memory itself. Categorical action dims use a
    softmax head exactly like the feedforward trainer.
    """
    _require_torch()
    cfg = cfg or RL2Config()
    if len(dataset) == 0:
        raise ValueError("empty dataset — capture a corpus first")
    if dataset.block_present() or dataset.ban_present():
        raise ValueError(
            "RL² trains on the base state; build the dataset with "
            "variant_block_features=False and ban_state_features=False")

    torch.manual_seed(cfg.seed)
    np.random.seed(cfg.seed)

    feat_dim = dataset.states.shape[1]
    a_dim = dataset.action_dim
    norm = dataset.normalizer
    S = norm.transform(dataset.states)
    S2 = norm.transform(dataset.next_states)
    lo = np.asarray(dataset.action_lo, dtype=np.float32)
    hi = np.asarray(dataset.action_hi, dtype=np.float32)
    span = np.where(hi <= lo, 1.0, hi - lo)
    A = ((dataset.actions - lo) / span).clip(0.0, 1.0).reshape(-1, a_dim)

    # Per-dim head layout (shared with train.py): continuous -> one regressed output;
    # categorical -> len(cats) logits classified to the logged category index.
    kinds = dataset.action_kinds or ("continuous",) * a_dim
    categories = dataset.action_categories or (None,) * a_dim
    heads: list[tuple] = []
    cat_targets = np.zeros((dataset.actions.shape[0], a_dim), dtype=np.int64)
    col = 0
    for k in range(a_dim):
        if kinds[k] == "categorical":
            cats = np.asarray(categories[k], dtype=np.float32)
            width = int(cats.size)
            diffs = np.abs(dataset.actions[:, k][:, None] - cats[None, :])
            cat_targets[:, k] = np.argmin(diffs, axis=1)
            heads.append(("categorical", col, width, cats))
            col += width
        else:
            heads.append(("continuous", col))
            col += 1
    out_width = col

    s = torch.tensor(S, dtype=torch.float32)
    s2 = torch.tensor(S2, dtype=torch.float32)
    a = torch.tensor(A, dtype=torch.float32)
    ct = torch.tensor(cat_targets, dtype=torch.long)
    r = torch.tensor(dataset.rewards.reshape(-1, 1), dtype=torch.float32)
    done = torch.tensor(dataset.dones.reshape(-1, 1), dtype=torch.float32)

    adv = _train_critic(cfg, s, a, s2, r, done, feat_dim, a_dim)
    w_all = torch.clamp(torch.exp(cfg.beta * adv), max=cfg.adv_clip)  # (N,)

    # --- Pad episodes into (B, Lmax, ...) tensors for the recurrent actor ---
    slices = _episode_slices(dataset.episode_ids)
    lengths = [e - b for b, e in slices]
    Lmax = max(lengths)
    B = len(slices)
    token_dim = feat_dim + a_dim
    S_pad = torch.zeros(B, Lmax, feat_dim)
    A_pad = torch.zeros(B, Lmax, a_dim)
    CT_pad = torch.zeros(B, Lmax, a_dim, dtype=torch.long)
    W_pad = torch.zeros(B, Lmax)
    mask = torch.zeros(B, Lmax)
    for bi, (b0, e0) in enumerate(slices):
        L = e0 - b0
        S_pad[bi, :L] = s[b0:e0]
        A_pad[bi, :L] = a[b0:e0]
        CT_pad[bi, :L] = ct[b0:e0]
        W_pad[bi, :L] = w_all[b0:e0]
        mask[bi, :L] = 1.0

    gru = nn.GRUCell(token_dim, cfg.hidden_dim)
    head = _mlp([feat_dim + cfg.hidden_dim, *cfg.head_dims, out_width])
    opt = torch.optim.Adam([*gru.parameters(), *head.parameters()], lr=cfg.lr)

    def rollout(Sb, Ab):
        """Head hidden per window: hidden_i integrates tokens < i (h_0 = 0)."""
        Bn, Ln, _ = Sb.shape
        h = Sb.new_zeros(Bn, cfg.hidden_dim)
        hid = []
        for i in range(Ln):
            hid.append(h)  # hidden BEFORE consuming token_i -> used with state_i
            token = torch.cat([Sb[:, i, :], Ab[:, i, :]], dim=1)
            h = gru(token, h)
        return torch.stack(hid, dim=1)  # (B, L, hidden)

    for _ in range(cfg.actor_steps):
        bidx = torch.randint(0, B, (min(cfg.episode_batch, B),))
        Sb, Ab, CTb, Wb, Mb = S_pad[bidx], A_pad[bidx], CT_pad[bidx], W_pad[bidx], mask[bidx]
        hid = rollout(Sb, Ab)
        head_in = torch.cat([Sb, hid], dim=2)
        out = head(head_in)  # (B, L, out_width)
        loss = out.new_zeros(())
        denom = Mb.sum().clamp_min(1.0)
        for k, hd in enumerate(heads):
            if hd[0] == "categorical":
                _, c0, width, _ = hd
                logits = out[..., c0:c0 + width].reshape(-1, width)
                ce = F.cross_entropy(logits, CTb[..., k].reshape(-1), reduction="none")
                ce = ce.reshape(Sb.shape[0], Sb.shape[1])
                loss = loss + (Wb * Mb * ce).sum() / denom
            else:
                c0 = hd[1]
                se = (out[..., c0] - Ab[..., k]).pow(2)
                loss = loss + (Wb * Mb * se).sum() / denom
        opt.zero_grad(); loss.backward(); opt.step()

    return _extract_recurrent_artifact(
        gru, head, norm, lo, hi, dataset.feature_names,
        dataset.action_spec.names, kinds, categories)


def _extract_recurrent_artifact(gru, head, norm, lo, hi, feature_names, action_names,
                                action_kinds, action_categories) -> PolicyArtifact:
    layers: list[tuple[np.ndarray, np.ndarray]] = []
    for m in head:
        if isinstance(m, nn.Linear):
            layers.append((m.weight.detach().cpu().numpy().astype(np.float32),
                           m.bias.detach().cpu().numpy().astype(np.float32)))
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
        gru_w_ih=gru.weight_ih.detach().cpu().numpy().astype(np.float32),
        gru_w_hh=gru.weight_hh.detach().cpu().numpy().astype(np.float32),
        gru_b_ih=gru.bias_ih.detach().cpu().numpy().astype(np.float32),
        gru_b_hh=gru.bias_hh.detach().cpu().numpy().astype(np.float32),
    )
