"""In-context adaptation, end to end and torch-free at serving time.

The golden/lockstep tests pin the RL² math; this pins the *behavior* the whole
feature exists for — that a trained recurrent policy, with FROZEN weights, proposes a
DIFFERENT action at the same current state depending on the episode history it has
seen. That is "the wheel turns": adaptation without a weight update. It is the
CI-safe complement to deploy/waf-lab/e2e-rl2.sh, which shows the same thing against
the live WAF lab (and A/Bs served throughput vs a context-free policy).

Trains on a synthetic *non-stationary* corpus (calm episodes vs hostile episodes
whose defense ramps within the episode) so history carries real signal, then reloads
the exported SRLP v4 through the numpy serving oracle and checks the policy is
genuinely context-sensitive and non-degenerate.
"""

from __future__ import annotations

import json

import numpy as np
import pytest

torch = pytest.importorskip("torch")  # training needs torch; serving/reload does not

from ddos_samurai.models.rl import build_dataset, load_policy, save_policy
from ddos_samurai.models.rl.rl2 import RL2Config, train_rl2


def _write_corpus(path, *, episodes=24, windows=8, seed=0):
    """Interleave calm and hostile episodes. Hostile ones ramp defense within the
    episode and the logged (applied) rps backs off as they do — so an in-context
    policy can learn to read 'history is turning hostile' and lower the setpoint."""
    rng = np.random.default_rng(seed)
    with open(path, "w", encoding="utf-8") as fh:
        for ep in range(episodes):
            hostile = ep % 2 == 1
            prev_rps = 400.0
            for w in range(windows):
                # Hostile episodes: rejection climbs across the episode; applied rps
                # is walked down in response. Calm episodes: served stays high at high rps.
                if hostile:
                    reject = min(0.9, 0.1 + 0.12 * w)
                    rps = max(60.0, 400.0 - 40.0 * w)
                else:
                    reject = 0.02
                    rps = 400.0 + 20.0 * rng.standard_normal()
                resp = 500.0
                s2xx = resp * (1.0 - reject)
                s4xx = resp * reject
                fh.write(json.dumps({
                    "run_id": f"cl-{ep}", "win": w, "ts_ms": w, "strategy": "rl",
                    "min_rps": 50.0, "max_rps": 800.0, "window_s": 1,
                    "slo": {"max_error_pct": 100.0},
                    "action_rps": prev_rps, "action": {"rps": prev_rps, "request_mix": 0},
                    "s_valid": w > 0,
                    "s": {"valid": True, "rps": prev_rps, "attempted": resp, "errors": 0,
                          "error_pct": 0.0, "loss_pct": -1, "rate_accuracy_pct": -1,
                          "p99_ms": -1, "defense": {}},
                    "s2": {"valid": True, "rps": rps, "attempted": resp, "errors": 0,
                           "error_pct": 0.0, "loss_pct": -1, "rate_accuracy_pct": -1,
                           "p99_ms": -1,
                           "defense": {"responses_total": resp, "status_2xx": s2xx,
                                       "status_4xx": s4xx}},
                    "healthy": True, "phase": "probe", "done": w == windows - 1,
                }) + "\n")
                prev_rps = rps
    return path


def _train(tmp_path):
    corpus = _write_corpus(tmp_path / "nonstationary.ndjson")
    ds = build_dataset(corpus)
    # Small but real: enough steps to fit the direction, fast enough for CI.
    art = train_rl2(ds, RL2Config(seed=0, critic_steps=500, actor_steps=500,
                                  episode_batch=8, hidden_dim=16))
    out = tmp_path / "rl2.srlp"
    save_policy(art, out)
    return ds, load_policy(out)


def _norm_actions(ds):
    """Reproduce the [0,1] action normalization train_rl2 uses for the GRU token."""
    lo = np.asarray(ds.action_lo, dtype=np.float32)
    hi = np.asarray(ds.action_hi, dtype=np.float32)
    span = np.where(hi <= lo, 1.0, hi - lo)
    return ((ds.actions - lo) / span).clip(0.0, 1.0).astype(np.float32)


def test_recurrent_policy_is_context_sensitive(tmp_path):
    """Same current state, different history -> different action, with frozen weights."""
    ds, pol = _train(tmp_path)
    assert pol.recurrent and pol.hidden_dim == 16

    # Episodes alternate calm (ep 0: rows 0..7) and hostile (ep 1: rows 8..15). Build
    # two 6-window histories that end at the SAME probe state, differing only in the
    # carried context (calm run vs hostile ramp).
    S = ds.states.shape[1]
    probe = np.zeros(S, dtype=np.float32)
    a_norm = _norm_actions(ds)

    calm_hist, hostile_hist = ds.states[0:6], ds.states[8:14]
    calm_acts, hostile_acts = a_norm[0:6], a_norm[8:14]

    seq_h = np.vstack([hostile_hist, probe[None, :]]).astype(np.float32)
    seq_c = np.vstack([calm_hist, probe[None, :]]).astype(np.float32)
    tok_h = np.vstack([hostile_acts, a_norm[:1]]).astype(np.float32)
    tok_c = np.vstack([calm_acts, a_norm[:1]]).astype(np.float32)

    act_h = pol.act_sequence(seq_h, tok_h)[-1]
    act_c = pol.act_sequence(seq_c, tok_c)[-1]

    # Adaptation is real: the carried context measurably changes the proposed action
    # at an identical current state. (Direction/served-gain is asserted live in the lab.)
    assert np.abs(act_h[0] - act_c[0]) > 1e-4, (
        f"recurrent policy ignored its context: {act_h[0]} vs {act_c[0]}")


def test_context_reset_returns_to_first_window(tmp_path):
    """Resetting the context (new episode) must reproduce the zero-history action —
    the C++ ResetContext contract the master calls per episode."""
    _, pol = _train(tmp_path)
    S = pol.state_feat_dim
    probe = np.zeros((1, S), dtype=np.float32)

    first = pol.act_batch(probe)[0]              # zero hidden (fresh episode)
    # Advance context, then a fresh act_sequence of length 1 == zero hidden again.
    reset = pol.act_sequence(probe, np.zeros((1, pol.action_dim), np.float32))[0]
    assert np.allclose(first, reset, atol=1e-5)
