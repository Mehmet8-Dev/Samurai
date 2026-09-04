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

from ddos_samurai.models.rl import build_dataset, load_policy, save_policy
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

    # OPE returns finite numbers and a well-formed gate.
    res = evaluate_policy(ds, art, FQEConfig(steps=400, batch_size=128, seed=0))
    assert np.isfinite(res.fqe_value)
    assert np.isfinite(res.behavior_return)
    assert isinstance(res.gate_pass, bool)
    assert res.n_episodes == 8
    assert res.n_initial_states == 8
    assert res.gate_pass == (res.fqe_value >= res.behavior_return)


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


def test_training_is_deterministic(tmp_path):
    ds = build_dataset(_corpus(tmp_path / "c.ndjson"))
    a1 = train_iql(ds, IQLConfig(steps=200, seed=7))
    a2 = train_iql(ds, IQLConfig(steps=200, seed=7))
    for (W1, b1), (W2, b2) in zip(a1.layers, a2.layers):
        assert np.array_equal(W1, W2)
        assert np.array_equal(b1, b2)


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
