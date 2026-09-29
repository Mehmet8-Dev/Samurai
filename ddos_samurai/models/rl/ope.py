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
from .shield import HONORED_SUCCESS_FLOOR, best_success_from_states, govern_batch

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
    # Score the SHIELDED policy, not the bare one. Serving wraps the policy in the
    # LeverShield (see shield.py), which vetoes a request_mix variant the target
    # path-blocks; evaluating the raw policy overstates what actually ships. Applied
    # only when the corpus carries variant-block features and request_mix is an
    # action dim; otherwise the shield is inert and this is a no-op.
    shielded: bool = True
    shield_honored_floor: float = HONORED_SUCCESS_FLOOR
    # Trajectory-wide value instead of the initial-state anchor. The bare FQE scores
    # Q(s0, pi(s0)) at each episode's ZERO-CONTEXT first window, which structurally
    # under-credits a recurrent (RL²) policy whose advantage only materializes once
    # its context has warmed mid/late-episode. With `trajectory_value`, we instead
    # score the policy's value-to-go at EVERY visited state — Q(s_t, pi(s_t|ctx_t)) for
    # the recurrent in-context action — and pair it against the behavior return-to-go
    # from the same t. Averaged per episode, this credits the late-window adaptation a
    # meta-RL policy is trained for, while a stateless (FF) policy gets no such lift
    # (its action does not depend on ctx_t). The s0-anchored score remains available by
    # setting this False.
    trajectory_value: bool = True


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
    # True when the shield actually governed the evaluated action (block features
    # present + request_mix action dim). False => the bare policy was scored.
    shielded: bool = False
    # True when the value was scored trajectory-wide (value-to-go at every visited
    # state, crediting late-window recurrent context) rather than at the s0 anchor.
    trajectory_value: bool = False

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


def behavior_returns_to_go(dataset: Dataset, gamma: float,
                           slices: list[tuple[int, int]]) -> np.ndarray:
    """Per-transition discounted return-to-go G_t = sum_{k>=t} gamma^(k-t) r_k, computed
    within each episode. This is the behavior baseline's value-to-go from every visited
    state, the natural pairing target for a trajectory-wide (not just s0) policy value."""
    rewards = dataset.rewards
    g_all = np.zeros(rewards.shape[0], dtype=np.float64)
    for b0, e0 in slices:
        g = 0.0
        for i in range(e0 - 1, b0 - 1, -1):
            g = float(rewards[i]) + gamma * g
            g_all[i] = g
    return g_all


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


def _block_variant_count(feature_names: tuple[str, ...]) -> int:
    """How many request_mix variants the corpus carries block features for (0 if the
    variant-block feature is off). Counts the trailing ``variant{i}_block`` names."""
    return sum(1 for n in feature_names
               if n.startswith("variant") and n.endswith("_block"))


def _request_mix_col(dataset: Dataset) -> int:
    """Index of the request_mix action dim, or -1 if the action space lacks it."""
    spec = getattr(dataset, "action_spec", None)
    if spec is None or "request_mix" not in spec.names:
        return -1
    return spec.names.index("request_mix")


def _shielded_action_norm(artifact: PolicyArtifact, states_raw: np.ndarray,
                          lo: np.ndarray, hi: np.ndarray, col: int, n_variant: int,
                          floor: float, warm: np.ndarray | None) -> np.ndarray:
    """Like ``_policy_action_norm`` but with the LeverShield veto applied to the
    request_mix column, using each state's own block-feature memory (optionally
    warm-started from ``warm``) — the action the master actually applies at serving."""
    act = artifact.act_batch(states_raw)  # (N, A) de-normalized
    best = best_success_from_states(states_raw, n_variant)  # (N, n) memory snapshot
    if warm is not None:
        for v in range(min(warm.shape[0], best.shape[1])):
            if warm[v] >= 0.0:  # LeverShield::Warm — a known prior raises, never lowers
                best[:, v] = np.maximum(best[:, v], warm[v])
    proposed = np.rint(act[:, col]).astype(np.int64)
    act[:, col] = govern_batch(proposed, best, floor).astype(act.dtype)
    span = np.where(hi <= lo, 1.0, hi - lo)
    return ((act - lo) / span).clip(0.0, 1.0)


def _episode_slices(episode_ids: np.ndarray) -> list[tuple[int, int]]:
    """Contiguous [start, end) ranges per episode (built in-order by the dataset)."""
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


def _recurrent_actions_norm(artifact: PolicyArtifact, dataset: Dataset,
                            lo: np.ndarray, hi: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Policy actions at (s, s') for every transition, in the [0,1] space Q is fit on,
    computed by rolling the recurrent policy per episode with the logged trajectory as
    context — exactly the history the serving loop would have observed."""
    span = np.where(hi <= lo, 1.0, hi - lo)
    a_dim = dataset.action_dim
    A = ((dataset.actions - lo) / span).clip(0.0, 1.0).reshape(-1, a_dim)
    n = dataset.states.shape[0]
    a_s = np.zeros((n, a_dim), dtype=np.float32)
    a_s2 = np.zeros((n, a_dim), dtype=np.float32)
    for b0, e0 in _episode_slices(dataset.episode_ids):
        act_s, act_s2 = artifact.act_sequence(
            dataset.states[b0:e0], A[b0:e0], next_states_raw=dataset.next_states[b0:e0])
        a_s[b0:e0] = ((act_s - lo) / span).clip(0.0, 1.0)
        a_s2[b0:e0] = ((act_s2 - lo) / span).clip(0.0, 1.0)
    return a_s, a_s2


def evaluate_policy(dataset: Dataset, artifact: PolicyArtifact,
                    cfg: FQEConfig | None = None,
                    warm_start: list[float] | None = None) -> OPEResult:
    """FQE value of ``artifact`` vs the behavior return. Gate = learned >= behavior.

    By default scores the SHIELDED policy — the raw action passed through the
    LeverShield veto that runs at serving — so the gate measures what ships, not the
    bare policy. ``warm_start`` optionally seeds the shield with the per-target
    fingerprint prior (the ``--cl-variant-memory`` warm start) so the score reflects
    the exact served configuration. The shield is inert (and this reduces to the bare
    FQE) when the corpus has no variant-block features or no request_mix action dim.
    """
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

    # Shield decision: only govern when the corpus carries variant-block features AND
    # request_mix is a controlled dim; otherwise the shield has nothing to act on.
    n_variant = _block_variant_count(dataset.feature_names)
    mix_col = _request_mix_col(dataset)
    shield_on = cfg.shielded and n_variant > 0 and mix_col >= 0
    warm = np.asarray(warm_start, dtype=np.float64) if (shield_on and warm_start) else None

    # Recurrent (RL²) policies carry episode context, so their action at a state
    # depends on the trajectory so far — scored by a per-episode rollout rather than
    # a stateless per-row forward. RL² datasets have no block features, so the shield
    # is inert here; the bare recurrent rollout is what ships.
    recurrent = getattr(artifact, "recurrent", False)
    rec_a_s = rec_a_s2 = None
    if recurrent:
        rec_a_s, rec_a_s2 = _recurrent_actions_norm(artifact, dataset, lo, hi)

    def policy_act(states_raw: np.ndarray) -> np.ndarray:
        if shield_on:
            return _shielded_action_norm(artifact, states_raw, lo, hi, mix_col,
                                         n_variant, cfg.shield_honored_floor, warm)
        return _policy_action_norm(artifact, states_raw, lo, hi)

    S = norm.transform(dataset.states)
    S2 = norm.transform(dataset.next_states)
    A = ((dataset.actions - lo) / span).clip(0.0, 1.0).reshape(-1, a_dim)
    # (Shielded) policy's action at s' (for the FQE bootstrap) and at initial states.
    A2_pi = rec_a_s2 if recurrent else policy_act(dataset.next_states)

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

    eids = dataset.episode_ids
    slices = _episode_slices(eids)

    if cfg.trajectory_value:
        # Trajectory-wide value: Q(s_t, pi(s_t|ctx_t)) at EVERY visited state, using the
        # policy's in-context action there (rec_a_s already rolls the recurrent context
        # through the logged trajectory; a stateless policy is context-free). We pair it
        # against the behavior return-to-go from the same t, then average per episode so
        # the bootstrap still resamples whole episodes 1:1. A recurrent policy's late-t
        # rows carry warmed context — the memory advantage the s0 anchor cannot see.
        a_all = rec_a_s if recurrent else policy_act(dataset.states)
        with torch.no_grad():
            sa_all = torch.cat(
                [s, torch.tensor(a_all, dtype=torch.float32, device=dev)], dim=1)
            q_all = q(sa_all).squeeze(-1).cpu().numpy().astype(np.float64)
        g_all = behavior_returns_to_go(dataset, cfg.gamma, slices)
        fqe_per_ep = np.array([q_all[b0:e0].mean() for b0, e0 in slices], dtype=np.float64)
        base_per_ep = np.array([g_all[b0:e0].mean() for b0, e0 in slices], dtype=np.float64)
        n_anchor = len(dataset)
    else:
        # Value estimate: Q(s0, pi(s0)) at each episode's initial state (per-episode, so
        # it pairs 1:1 with beh_per_ep for the bootstrap; np.unique gives the same order).
        first_idx = [int(np.where(eids == e)[0][0]) for e in np.unique(eids)]
        s0_raw = dataset.states[first_idx]
        # A recurrent policy's initial-state action is its first-window action (zero
        # context), which is exactly rec_a_s at each episode's first index.
        a0 = rec_a_s[first_idx] if recurrent else policy_act(s0_raw)
        with torch.no_grad():
            s0 = torch.tensor(norm.transform(s0_raw), dtype=torch.float32, device=dev)
            s0a0 = torch.cat([s0, torch.tensor(a0, dtype=torch.float32, device=dev)], dim=1)
            fqe_per_ep = q(s0a0).squeeze(-1).cpu().numpy().astype(np.float64)
        base_per_ep = beh_per_ep
        n_anchor = len(first_idx)

    fqe = float(fqe_per_ep.mean())
    base = float(base_per_ep.mean()) if base_per_ep.size else base

    imp_lo, imp_hi = _paired_bootstrap_ci(
        fqe_per_ep, base_per_ep, cfg.n_bootstrap, cfg.ci_alpha, cfg.seed)
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
        n_initial_states=n_anchor,
        improvement_ci_low=imp_lo,
        improvement_ci_high=imp_hi,
        fqe_ci_low=fqe_lo,
        fqe_ci_high=fqe_hi,
        effective_horizon=eff_h,
        mean_episode_len=mean_len,
        shielded=shield_on,
        trajectory_value=cfg.trajectory_value,
    )
