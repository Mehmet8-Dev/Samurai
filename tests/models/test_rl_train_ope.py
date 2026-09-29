"""IQL training -> export -> FQE evaluation, end to end (needs torch).

Uses a synthetic corpus shaped like real closed-loop data (episodes that climb rps
through SLO-green windows, then breach) to exercise the full offline half without a
live target. Learning *quality* on toy data is not asserted; the mechanics,
determinism, the export handshake on trained weights, and the OPE gate are.
"""

from __future__ import annotations

import json

import numpy as np
import pytest

torch = pytest.importorskip("torch")

from ddos_samurai.models.rl import ActionSpec, build_dataset, load_policy, save_policy
from ddos_samurai.models.rl.ope import FQEConfig, behavior_return, evaluate_policy
from ddos_samurai.models.rl.train import IQLConfig, train_iql


def _corpus(path, *, episodes: int = 8, windows: int = 10, max_rps: float = 2000.0):
    rng = np.random.default_rng(0)
    with open(path, "w", encoding="utf-8") as fh:
        for ep in range(episodes):
            rps = 100.0
            ceiling = 800.0 + 400.0 * rng.random()  # per-run sustainable ceiling
            prev = 0.0
            for w in range(windows):
                action = rps
                healthy = rps <= ceiling
                error_pct = 0.0 if healthy else min(20.0, (rps - ceiling) / ceiling * 30.0)
                s2_rps = rps if healthy else ceiling
                rec = {
                    "run_id": f"cl-{ep}", "win": w, "ts_ms": 1_700_000_000_000 + w,
                    "strategy": "aimd", "min_rps": 50.0, "max_rps": max_rps, "window_s": 5,
                    "slo": {"max_error_pct": 2.0, "max_loss_pct": 0.0,
                            "min_rate_accuracy_pct": 0.0, "max_latency_ms": 0.0},
                    "action_rps": action,
                    "action": {"rps": action, "pacing_mode": 1, "concurrency": -1,
                               "connections": -1, "request_mix": -1, "source_rotation": -1},
                    "s_valid": w > 0,
                    "s": _state(prev), "s2": _state(s2_rps, error_pct=error_pct),
                    "healthy": healthy, "phase": "probe", "done": w == windows - 1,
                }
                fh.write(json.dumps(rec) + "\n")
                prev = s2_rps
                # AIMD-ish behavior: additive climb while green, back off on breach.
                rps = rps + 120.0 if healthy else rps * 0.5
    return path


def _state(rps, *, error_pct: float = 0.0):
    return {
        "valid": True, "rps": rps, "attempted": max(rps, 1.0) * 5,
        "errors": max(rps, 1.0) * 5 * error_pct / 100.0,
        "error_pct": error_pct, "loss_pct": -1.0, "rate_accuracy_pct": -1.0,
        "p99_ms": -1.0, "defense": {},
    }


def test_train_export_reload_evaluate(tmp_path):
    ds = build_dataset(_corpus(tmp_path / "c.ndjson"))
    assert len(ds) > 0

    art = train_iql(ds, IQLConfig(steps=400, batch_size=128, seed=0))
    # Artifact shape: input matches feature count, output is 1-D (rps), bounds sane.
    assert art.input_dim == ds.states.shape[1]
    assert art.layers[-1][0].shape[0] == 1
    assert art.action_hi > art.action_lo

    # Actions are in-range for every logged state.
    acts = art.act_batch(ds.states)
    assert np.all(acts >= art.action_lo - 1e-3)
    assert np.all(acts <= art.action_hi + 1e-3)

    # Export handshake is lossless on trained weights.
    p = tmp_path / "policy.srlp"
    save_policy(art, p)
    back = load_policy(p)
    assert np.allclose(art.act_batch(ds.states), back.act_batch(ds.states), atol=1e-5)

    # OPE returns finite numbers and a well-formed gate. Default is trajectory-wide:
    # the value is anchored at every visited state, not just the 8 episode starts.
    res = evaluate_policy(ds, art, FQEConfig(steps=400, batch_size=128, seed=0))
    assert np.isfinite(res.fqe_value)
    assert np.isfinite(res.behavior_return)
    assert isinstance(res.gate_pass, bool)
    assert res.n_episodes == 8
    assert res.trajectory_value is True
    assert res.n_initial_states == len(ds)
    # Bootstrap CI brackets the point estimate, and the default gate is pessimistic:
    # it passes iff the improvement's lower confidence bound clears zero.
    assert res.improvement_ci_low <= res.improvement_ci_high
    assert res.fqe_ci_low <= res.fqe_value <= res.fqe_ci_high
    assert res.gate_pass == (res.improvement_ci_low >= 0.0)

    # Disabling pessimism recovers the legacy point-estimate gate.
    legacy = evaluate_policy(
        ds, art, FQEConfig(steps=400, batch_size=128, seed=0, pessimistic_gate=False))
    assert legacy.gate_pass == (legacy.fqe_value >= legacy.behavior_return)

    # The s0-anchored mode is still available and pins the value to the 8 episode
    # starts (zero-context first window) — the legacy instrument.
    s0mode = evaluate_policy(
        ds, art, FQEConfig(steps=400, batch_size=128, seed=0, trajectory_value=False))
    assert s0mode.trajectory_value is False
    assert s0mode.n_initial_states == 8

    # The horizon diagnostic is exposed: gamma=0.99 => effective horizon ~100, well
    # over these ~10-window episodes, so the mismatch flag fires.
    assert res.effective_horizon > 2.0 * res.mean_episode_len
    assert res.horizon_mismatch


def test_multidim_mahoraga_action_end_to_end(tmp_path):
    from ddos_samurai.models.rl import ActionSpec, load_policy, save_policy

    # Corpus where BOTH rps and concurrency vary, so a 2-D policy is learnable.
    rng = np.random.default_rng(0)
    p = tmp_path / "m.ndjson"
    with open(p, "w", encoding="utf-8") as fh:
        for ep in range(6):
            rps = 100.0
            for w in range(10):
                conc = int(rng.integers(1, 64))
                rec = {
                    "run_id": f"cl-{ep}", "win": w, "ts_ms": w, "strategy": "aimd",
                    "min_rps": 50.0, "max_rps": 2000.0, "window_s": 5,
                    "slo": {"max_error_pct": 2.0, "max_loss_pct": 0.0,
                            "min_rate_accuracy_pct": 0.0, "max_latency_ms": 0.0},
                    "action_rps": rps,
                    "action": {"rps": rps, "pacing_mode": 1, "concurrency": conc,
                               "connections": -1, "request_mix": -1, "source_rotation": -1},
                    "s_valid": w > 0,
                    "s": _state(rps - 100), "s2": _state(rps),
                    "healthy": True, "phase": "probe", "done": w == 9,
                }
                fh.write(json.dumps(rec) + "\n")
                rps += 100.0

    spec = ActionSpec(("rps", "concurrency"))
    ds = build_dataset(p, action_spec=spec)
    assert ds.action_dim == 2
    assert ds.actions.shape[1] == 2

    art = train_iql(ds, IQLConfig(steps=300, seed=0))
    assert art.action_dim == 2  # policy outputs rps + concurrency
    assert art.action_names == ("rps", "concurrency")

    # SRLP v2 round-trips the multi-dim action bounds losslessly.
    fp = tmp_path / "m.srlp"
    save_policy(art, fp)
    back = load_policy(fp, action_names=("rps", "concurrency"))
    assert np.allclose(art.act_batch(ds.states), back.act_batch(ds.states), atol=1e-5)

    # Proposed concurrency stays within the data-derived bound for every state.
    acts = art.act_batch(ds.states)
    assert np.all(acts[:, 1] >= art.action_lo[1] - 1e-3)
    assert np.all(acts[:, 1] <= art.action_hi[1] + 1e-3)

    res = evaluate_policy(ds, art, FQEConfig(steps=300, seed=0))
    assert np.isfinite(res.fqe_value)


def _categorical_corpus(path, *, episodes: int = 12, windows: int = 8):
    """Corpus where request_mix is categorical: variant 2 is WAF-blocked (mostly
    4xx, low success) and the others are honored. A continuous head would regress
    request_mix to the mean of the good variants {0,1,3,4} == 2.0 (the blocked one);
    a categorical head must be able to avoid it."""
    rng = np.random.default_rng(1)
    with open(path, "w", encoding="utf-8") as fh:
        for ep in range(episodes):
            variant = ep % 5  # cycle 0..4 so every category is logged
            rps = 300.0
            prev = 0.0
            for w in range(windows):
                blocked = variant == 2
                succ = 0.1 if blocked else 0.95
                resp = max(rps, 1.0) * 5
                rec = {
                    "run_id": f"cl-{ep}", "win": w, "ts_ms": 1_700_000_000_000 + w,
                    "strategy": "explore", "min_rps": 50.0, "max_rps": 2000.0, "window_s": 5,
                    "slo": {"max_error_pct": 100.0, "max_loss_pct": 0.0,
                            "min_rate_accuracy_pct": 0.0, "max_latency_ms": 0.0},
                    "action_rps": rps,
                    "action": {"rps": rps, "pacing_mode": 1, "concurrency": 4,
                               "connections": -1, "request_mix": variant, "source_rotation": -1},
                    "s_valid": w > 0,
                    "s": _state(prev),
                    "s2": {
                        "valid": True, "rps": rps, "attempted": resp, "errors": 0.0,
                        "error_pct": 0.0, "loss_pct": -1.0, "rate_accuracy_pct": -1.0,
                        "p99_ms": -1.0,
                        "defense": {
                            "responses_total": resp,
                            "status_2xx": resp * succ,
                            "status_4xx": resp * (1.0 - succ) if blocked else 0.0,
                            "status_5xx": 0.0,
                        },
                    },
                    "healthy": True, "phase": "explore", "done": w == windows - 1,
                }
                fh.write(json.dumps(rec) + "\n")
                prev = rps
    return path


def test_categorical_head_can_avoid_blocked_variant(tmp_path):
    from ddos_samurai.models.rl import EffectiveThroughputReward, MAHORAGA
    from ddos_samurai.models.rl.config import RLConfig

    spec = ActionSpec(("rps", "request_mix"), categorical_names=("request_mix",))
    cfg = RLConfig(rps_scale=1000.0)
    ds = build_dataset(
        _categorical_corpus(tmp_path / "cat.ndjson"),
        cfg, reward_fn=EffectiveThroughputReward(cfg), action_spec=spec,
    )
    assert ds.action_kinds == ("continuous", "categorical")
    assert tuple(ds.action_categories[1]) == (0.0, 1.0, 2.0, 3.0, 4.0)

    art = train_iql(ds, IQLConfig(steps=1500, seed=0))
    acts = art.act_batch(ds.states)
    # Discreteness: every proposed request_mix is exactly one of the categories.
    assert np.all(np.isin(acts[:, 1], ds.action_categories[1]))
    # Learning: the blocked variant 2 is proposed on a minority of states (a
    # continuous head would collapse to exactly 2.0 everywhere).
    assert np.mean(acts[:, 1] == 2.0) < 0.5

    # v3 export round-trips the categorical head losslessly.
    fp = tmp_path / "cat.srlp"
    save_policy(art, fp)
    back = load_policy(fp, action_names=("rps", "request_mix"))
    assert np.array_equal(art.act_batch(ds.states), back.act_batch(ds.states))

    res = evaluate_policy(ds, art, FQEConfig(steps=300, seed=0))
    assert np.isfinite(res.fqe_value)


def test_ope_scores_shielded_policy(tmp_path):
    """The OPE gate scores the SHIELDED policy: the request_mix veto that runs at
    serving is applied to the evaluated action (with block features present)."""
    from ddos_samurai.models.rl import EffectiveThroughputReward
    from ddos_samurai.models.rl.config import RLConfig
    from ddos_samurai.models.rl.shield import best_success_from_states, govern_batch

    spec = ActionSpec(("rps", "request_mix"), categorical_names=("request_mix",))
    cfg = RLConfig(rps_scale=1000.0, variant_block_features=True)
    ds = build_dataset(
        _categorical_corpus(tmp_path / "cat.ndjson"),
        cfg, reward_fn=EffectiveThroughputReward(cfg), action_spec=spec)
    assert any(n.endswith("_block") for n in ds.feature_names)  # block features exist

    art = train_iql(ds, IQLConfig(steps=500, seed=0))

    shielded = evaluate_policy(ds, art, FQEConfig(steps=300, seed=0))  # default shielded
    bare = evaluate_policy(ds, art, FQEConfig(steps=300, seed=0, shielded=False))
    assert shielded.shielded is True and bare.shielded is False
    assert np.isfinite(shielded.fqe_value) and np.isfinite(bare.fqe_value)

    # Deterministic invariant of the exact warm+govern path OPE feeds through: with a
    # prior marking variant 0 honored (so an honored option always exists), the shield
    # must never APPLY a known-blocked variant — every governed choice is honored
    # (best >= floor) or an unobserved probe (best < 0). This is what --cl-variant-
    # memory buys at serving; here it rides the same code the FQE actions go through.
    warm = [0.9, 0.0, 0.0, 0.0, 0.0]
    col = spec.names.index("request_mix")
    best = best_success_from_states(ds.states, cfg.request_variant_count)
    for v, wv in enumerate(warm):
        if wv >= 0.0:
            best[:, v] = np.maximum(best[:, v], wv)
    proposed = np.rint(art.act_batch(ds.states)[:, col]).astype(np.int64)
    gov = govern_batch(proposed, best, 0.10)
    chosen = best[np.arange(gov.shape[0]), gov]
    assert np.all((chosen < 0.0) | (chosen >= 0.10))  # never a known-blocked variant

    # The warm-started evaluation runs and stays finite.
    warmed = evaluate_policy(ds, art, FQEConfig(steps=200, seed=0), warm_start=warm)
    assert warmed.shielded is True and np.isfinite(warmed.fqe_value)


def test_ope_shield_inert_without_block_features(tmp_path):
    """No variant-block features -> the shield has no memory to read, so it stays off
    (shielded=False) even with a request_mix dim; the score is the bare policy's."""
    from ddos_samurai.models.rl import EffectiveThroughputReward
    from ddos_samurai.models.rl.config import RLConfig

    spec = ActionSpec(("rps", "request_mix"), categorical_names=("request_mix",))
    cfg = RLConfig(rps_scale=1000.0)  # variant_block_features=False (default)
    ds = build_dataset(
        _categorical_corpus(tmp_path / "cat.ndjson"),
        cfg, reward_fn=EffectiveThroughputReward(cfg), action_spec=spec)
    art = train_iql(ds, IQLConfig(steps=200, seed=0))
    res = evaluate_policy(ds, art, FQEConfig(steps=200, seed=0))  # default shielded=True
    assert res.shielded is False


def test_training_is_deterministic(tmp_path):
    ds = build_dataset(_corpus(tmp_path / "c.ndjson"))
    a1 = train_iql(ds, IQLConfig(steps=200, seed=7))
    a2 = train_iql(ds, IQLConfig(steps=200, seed=7))
    for (W1, b1), (W2, b2) in zip(a1.layers, a2.layers):
        assert np.array_equal(W1, W2)
        assert np.array_equal(b1, b2)


def test_returns_to_go_matches_manual(tmp_path):
    """behavior_returns_to_go computes, per transition, the discounted return from that
    step to the episode's end — the pairing target for the trajectory-wide value."""
    from ddos_samurai.models.rl.ope import _episode_slices, behavior_returns_to_go

    ds = build_dataset(_corpus(tmp_path / "c.ndjson", episodes=2, windows=4))
    gamma = 0.9
    slices = _episode_slices(ds.episode_ids)
    g = behavior_returns_to_go(ds, gamma, slices)
    assert g.shape[0] == len(ds)
    # Recompute independently within each episode: G_t = r_t + gamma*G_{t+1}.
    for b0, e0 in slices:
        acc = 0.0
        for i in range(e0 - 1, b0 - 1, -1):
            acc = float(ds.rewards[i]) + gamma * acc
            assert abs(g[i] - acc) < 1e-6
    # And the first index of each episode equals the full discounted episode return.
    from ddos_samurai.models.rl.ope import behavior_returns_per_episode
    per_ep = behavior_returns_per_episode(ds, gamma)
    for (b0, _e0), ret in zip(slices, per_ep):
        assert abs(g[b0] - ret) < 1e-6


def test_trajectory_value_credits_recurrent_memory(tmp_path):
    """The whole point of trajectory-wide OPE: score the policy's value-to-go at every
    visited state (crediting warmed late-window context), not just the zero-context s0.
    For a recurrent RL² policy on a within-episode regime-shift corpus, the trajectory
    anchor set spans all transitions and both modes stay finite — the s0 anchor sees
    only the cold first window."""
    pytest.importorskip("torch")
    from ddos_samurai.models.rl.rl2 import RL2Config, train_rl2
    from ddos_samurai.models.rl.ope import FQEConfig, evaluate_policy

    # Mid-episode shift: the sustainable ceiling drops halfway, so late windows carry
    # information the cold start cannot — exactly what recurrent context exploits.
    p = tmp_path / "shift.ndjson"
    rng = np.random.default_rng(3)
    with open(p, "w", encoding="utf-8") as fh:
        for ep in range(10):
            rps, prev = 100.0, 0.0
            for w in range(12):
                ceiling = 1400.0 if w < 6 else 500.0  # regime shift at the midpoint
                healthy = rps <= ceiling
                err = 0.0 if healthy else min(20.0, (rps - ceiling) / ceiling * 30.0)
                s2 = rps if healthy else ceiling
                fh.write(json.dumps({
                    "run_id": f"cl-{ep}", "win": w, "ts_ms": w, "strategy": "aimd",
                    "min_rps": 50.0, "max_rps": 2000.0, "window_s": 5,
                    "slo": {"max_error_pct": 2.0, "max_loss_pct": 0.0,
                            "min_rate_accuracy_pct": 0.0, "max_latency_ms": 0.0},
                    "action_rps": rps, "action": {"rps": rps, "pacing_mode": 1},
                    "s_valid": w > 0, "s": _state(prev), "s2": _state(s2, error_pct=err),
                    "healthy": healthy, "phase": "probe", "done": w == 11,
                }) + "\n")
                prev = s2
                rps = rps + 120.0 if healthy else rps * 0.5

    ds = build_dataset(p)
    art = train_rl2(ds, RL2Config(hidden_dim=8, critic_steps=200, actor_steps=200, seed=0))

    traj = evaluate_policy(ds, art, FQEConfig(steps=300, seed=0))  # default trajectory
    s0 = evaluate_policy(ds, art, FQEConfig(steps=300, seed=0, trajectory_value=False))

    assert traj.trajectory_value is True and s0.trajectory_value is False
    # Trajectory mode anchors on every visited state; s0 mode only on episode starts.
    assert traj.n_initial_states == len(ds)
    assert s0.n_initial_states == 10
    assert np.isfinite(traj.fqe_value) and np.isfinite(s0.fqe_value)
    assert isinstance(traj.gate_pass, bool)


def test_behavior_return_matches_manual(tmp_path):
    ds = build_dataset(_corpus(tmp_path / "c.ndjson", episodes=2, windows=3))
    # Discounted MC return, computed independently, must match the OPE baseline.
    gamma = 0.99
    eids = ds.episode_ids
    manual = []
    for e in np.unique(eids):
        rs = ds.rewards[eids == e]
        g = 0.0
        for rr in reversed(rs):
            g = rr + gamma * g
        manual.append(g)
    assert abs(behavior_return(ds, gamma) - float(np.mean(manual))) < 1e-6
