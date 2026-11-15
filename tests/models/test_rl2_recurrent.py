"""RL² recurrent policy — artifact rollout, v4 export handshake, and the C++ golden.

The torch-free tests pin the recurrence math and the SRLP v4 byte layout that
``rl_policy.cpp`` serves. The golden artifact here is byte-for-byte the one the C++
selftest builds by hand, so the two forwards are cross-checked on identical weights
(Python ``act_sequence`` <-> C++ ``ProposeFor``). The torch tests exercise training.
"""

from __future__ import annotations

import json

import numpy as np
import pytest

from samurai.models.rl import PolicyArtifact, build_dataset, load_policy, save_policy


def _golden_recurrent() -> PolicyArtifact:
    """The exact artifact the C++ selftest pins: state_dim=20, hidden=1, 1 cont dim.

    MLP = one linear layer over [state(20), hidden(1)] with W picking state[0]
    (rps_norm) and the hidden, b=0 => out = clamp(rps_norm + hidden). GRU new-gate
    reads token[0] (rps_norm) with weight 10; everything else is zero.
    """
    w_ih = np.zeros((3, 21), dtype=np.float32)
    w_ih[2, 0] = 10.0  # new-gate on token[0] = rps_norm
    w_hh = np.zeros((3, 1), dtype=np.float32)
    b_ih = np.zeros(3, dtype=np.float32)
    b_hh = np.zeros(3, dtype=np.float32)
    W = np.zeros((1, 21), dtype=np.float32)
    W[0, 0] = 1.0   # rps_norm
    W[0, 20] = 1.0  # hidden
    b = np.zeros(1, dtype=np.float32)
    return PolicyArtifact(
        layers=[(W, b)],
        norm_mean=np.zeros(20, dtype=np.float32),
        norm_std=np.ones(20, dtype=np.float32),
        action_lo=np.array([0.0], dtype=np.float32),
        action_hi=np.array([1.0], dtype=np.float32),
        feature_names=tuple(f"f{i}" for i in range(20)),
        action_names=("rps",),
        action_kinds=("continuous",),
        action_categories=(None,),
        gru_w_ih=w_ih, gru_w_hh=w_hh, gru_b_ih=b_ih, gru_b_hh=b_hh,
    )


def test_recurrent_flags_and_dims():
    art = _golden_recurrent()
    assert art.recurrent is True
    assert art.hidden_dim == 1
    assert art.state_feat_dim == 20
    assert art.input_dim == 21  # MLP input = state + hidden
    assert art.action_dim == 1


def test_golden_rollout_matches_cpp():
    """Two identical windows: window1 = rps_norm (zero context), window2 shifts because
    the GRU carried context. h1 = 0.5*tanh(3.0) = 0.497527; out2 = 0.3 + 0.497527."""
    art = _golden_recurrent()
    states = np.zeros((2, 20), dtype=np.float32)
    states[:, 0] = 0.3  # rps_norm both windows
    actions_norm = np.array([[0.3], [0.3]], dtype=np.float32)

    a_s = art.act_sequence(states, actions_norm)
    assert a_s.shape == (2, 1)
    assert abs(a_s[0, 0] - 0.3) < 1e-4          # window1: zero context
    assert abs(a_s[1, 0] - 0.797527) < 1e-3     # window2: the wheel turned


def test_context_free_forward_equals_act_batch():
    """A recurrent policy scored context-free (act_batch, zero hidden) equals the
    first window of a rollout — the invariant the C++ Propose() vs ProposeFor() pins."""
    art = _golden_recurrent()
    states = np.zeros((3, 20), dtype=np.float32)
    states[:, 0] = [0.1, 0.3, 0.5]
    ff = art.act_batch(states)
    # First window of an isolated rollout has zero context, so equals the FF forward.
    for i in range(3):
        row = np.zeros((1, 20), dtype=np.float32)
        row[0, 0] = states[i, 0]
        a = art.act_sequence(row, np.zeros((1, 1), dtype=np.float32))
        assert abs(a[0, 0] - ff[i, 0]) < 1e-5


def test_v4_export_roundtrip_is_exact(tmp_path):
    art = _golden_recurrent()
    p = tmp_path / "rec.srlp"
    save_policy(art, p)
    assert p.read_bytes()[:4] == b"SRLP"
    assert p.read_bytes()[4:8] == (4).to_bytes(4, "little")  # version 4

    back = load_policy(p, action_names=("rps",))
    assert back.recurrent and back.hidden_dim == 1 and back.state_feat_dim == 20
    assert np.array_equal(back.gru_w_ih, art.gru_w_ih)
    assert np.array_equal(back.gru_w_hh, art.gru_w_hh)
    assert np.array_equal(back.gru_b_ih, art.gru_b_ih)
    assert np.array_equal(back.gru_b_hh, art.gru_b_hh)

    states = np.zeros((4, 20), dtype=np.float32)
    states[:, 0] = [0.1, 0.2, 0.3, 0.4]
    actions = np.full((4, 1), 0.3, dtype=np.float32)
    assert np.allclose(art.act_sequence(states, actions),
                       back.act_sequence(states, actions), atol=1e-6)


def test_numpy_gru_step_matches_torch():
    torch = pytest.importorskip("torch")
    rng = np.random.default_rng(0)
    H, T = 4, 7
    cell = torch.nn.GRUCell(T, H)
    art = PolicyArtifact(
        layers=[(np.zeros((1, 20 + H), dtype=np.float32), np.zeros(1, dtype=np.float32))],
        norm_mean=np.zeros(20, dtype=np.float32), norm_std=np.ones(20, dtype=np.float32),
        action_lo=np.array([0.0], dtype=np.float32), action_hi=np.array([1.0], dtype=np.float32),
        action_kinds=("continuous",), action_categories=(None,),
        gru_w_ih=cell.weight_ih.detach().numpy().astype(np.float32),
        gru_w_hh=cell.weight_hh.detach().numpy().astype(np.float32),
        gru_b_ih=cell.bias_ih.detach().numpy().astype(np.float32),
        gru_b_hh=cell.bias_hh.detach().numpy().astype(np.float32),
    )
    h = rng.normal(size=(1, H)).astype(np.float32)
    x = rng.normal(size=(1, T)).astype(np.float32)
    got = art._gru_step(h, x)
    with torch.no_grad():
        want = cell(torch.tensor(x), torch.tensor(h)).numpy()
    assert np.allclose(got, want, atol=1e-5)


# --- torch-only training path -------------------------------------------------

def _state(rps, *, error_pct=0.0):
    return {"valid": True, "rps": rps, "attempted": max(rps, 1.0) * 5,
            "errors": max(rps, 1.0) * 5 * error_pct / 100.0,
            "error_pct": error_pct, "loss_pct": -1.0, "rate_accuracy_pct": -1.0,
            "p99_ms": -1.0, "defense": {}}


def _corpus(path, *, episodes=8, windows=10):
    rng = np.random.default_rng(0)
    with open(path, "w", encoding="utf-8") as fh:
        for ep in range(episodes):
            rps, ceiling, prev = 100.0, 800.0 + 400.0 * rng.random(), 0.0
            for w in range(windows):
                healthy = rps <= ceiling
                err = 0.0 if healthy else min(20.0, (rps - ceiling) / ceiling * 30.0)
                s2 = rps if healthy else ceiling
                fh.write(json.dumps({
                    "run_id": f"cl-{ep}", "win": w, "ts_ms": w, "strategy": "aimd",
                    "min_rps": 50.0, "max_rps": 2000.0, "window_s": 5,
                    "slo": {"max_error_pct": 2.0, "max_loss_pct": 0.0,
                            "min_rate_accuracy_pct": 0.0, "max_latency_ms": 0.0},
                    "action_rps": rps,
                    "action": {"rps": rps, "pacing_mode": 1},
                    "s_valid": w > 0, "s": _state(prev), "s2": _state(s2, error_pct=err),
                    "healthy": healthy, "phase": "probe", "done": w == windows - 1,
                }) + "\n")
                prev = s2
                rps = rps + 120.0 if healthy else rps * 0.5
    return path


def test_train_rl2_exports_and_evaluates(tmp_path):
    pytest.importorskip("torch")
    from samurai.models.rl.rl2 import RL2Config, train_rl2
    from samurai.models.rl.ope import FQEConfig, evaluate_policy

    ds = build_dataset(_corpus(tmp_path / "c.ndjson"))
    assert not ds.block_present() and not ds.ban_present()  # base state for RL²

    art = train_rl2(ds, RL2Config(hidden_dim=8, critic_steps=150, actor_steps=150, seed=0))
    assert art.recurrent and art.hidden_dim == 8
    assert art.input_dim == ds.states.shape[1] + 8

    # v4 export handshake is lossless on trained weights (rollout matches).
    p = tmp_path / "rl2.srlp"
    save_policy(art, p)
    back = load_policy(p, action_names=art.action_names)
    eids = ds.episode_ids
    b0 = int(np.where(eids == eids[0])[0][0])
    e0 = int(np.max(np.where(eids == eids[0])[0])) + 1
    A = ((ds.actions - art.action_lo) / np.maximum(art.action_hi - art.action_lo, 1e-9)).clip(0, 1)
    got = art.act_sequence(ds.states[b0:e0], A[b0:e0].astype(np.float32))
    got2 = back.act_sequence(ds.states[b0:e0], A[b0:e0].astype(np.float32))
    assert np.allclose(got, got2, atol=1e-5)

    # The OPE gate scores the recurrent rollout and stays finite.
    res = evaluate_policy(ds, art, FQEConfig(steps=150, seed=0))
    assert np.isfinite(res.fqe_value) and np.isfinite(res.behavior_return)
    assert isinstance(res.gate_pass, bool)


def test_train_rl2_rejects_block_dataset(tmp_path):
    pytest.importorskip("torch")
    from samurai.models.rl.config import RLConfig
    from samurai.models.rl.rl2 import train_rl2

    cfg = RLConfig(variant_block_features=True)
    ds = build_dataset(_corpus(tmp_path / "c.ndjson"), cfg)
    with pytest.raises(ValueError, match="base state"):
        train_rl2(ds)
