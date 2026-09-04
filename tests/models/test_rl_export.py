"""Policy artifact + flat-file export contract (torch-free).

This is the exact byte layout ``rl_policy.cpp`` will read, so the round-trip and
the numpy forward pin the C++ serving contract from the Python side.
"""

from __future__ import annotations

import numpy as np

from ddos_samurai.models.rl import PolicyArtifact, load_policy, save_policy


def _artifact() -> PolicyArtifact:
    # 3-in -> 2-hidden (ReLU) -> 1-out (linear, clamped). Known weights.
    W1 = np.array([[1.0, 0.0, -1.0], [0.5, 0.5, 0.0]], dtype=np.float32)
    b1 = np.array([0.1, -0.2], dtype=np.float32)
    W2 = np.array([[2.0, -1.0]], dtype=np.float32)
    b2 = np.array([0.05], dtype=np.float32)
    return PolicyArtifact(
        layers=[(W1, b1), (W2, b2)],
        norm_mean=np.array([0.0, 0.0, 0.0], dtype=np.float32),
        norm_std=np.array([1.0, 1.0, 1.0], dtype=np.float32),
        action_lo=100.0,
        action_hi=1100.0,
        feature_names=("a", "b", "c"),
    )


def test_numpy_forward_matches_hand_computation():
    art = _artifact()
    x = np.array([1.0, 2.0, 0.5], dtype=np.float32)
    # layer1: [1*1+0*2-1*0.5+0.1, 0.5*1+0.5*2+0-0.2] = [0.6, 1.3] -> relu -> [0.6,1.3]
    # layer2: 2*0.6 - 1*1.3 + 0.05 = -0.05 -> clamp[0,1] -> 0.0 -> lo = 100
    assert art.act(x) == 100.0

    # A state that drives the output above 0: pick x so out in (0,1).
    x2 = np.array([2.0, 3.0, 0.0], dtype=np.float32)
    # l1: [2.1, 2.3] relu -> l2: 2*2.1 - 2.3 + 0.05 = 1.95 -> clamp -> 1.0 -> hi
    assert art.act(x2) == 1100.0


def test_save_load_roundtrip_is_exact(tmp_path):
    art = _artifact()
    p = tmp_path / "policy.srlp"
    save_policy(art, p)
    back = load_policy(p, feature_names=art.feature_names)

    assert len(back.layers) == len(art.layers)
    for (W, b), (W2, b2) in zip(art.layers, back.layers):
        assert np.array_equal(W, W2)
        assert np.array_equal(b, b2)
    assert back.action_lo == art.action_lo
    assert back.action_hi == art.action_hi
    assert np.array_equal(back.norm_mean, art.norm_mean)
    assert back.feature_names == art.feature_names

    states = np.random.default_rng(0).normal(size=(16, 3)).astype(np.float32)
    assert np.allclose(art.act_batch(states), back.act_batch(states))


def test_magic_and_dims_header(tmp_path):
    art = _artifact()
    p = tmp_path / "policy.srlp"
    save_policy(art, p)
    raw = p.read_bytes()
    assert raw[:4] == b"SRLP"
    # in_dim carried so the C++ loader can size its input buffer.
    assert load_policy(p).input_dim == 3
    assert load_policy(p).hidden_dims == (2,)


def test_normalizer_applied_in_forward(tmp_path):
    art = _artifact()
    shifted = PolicyArtifact(
        layers=art.layers,
        norm_mean=np.array([1.0, 2.0, 0.5], dtype=np.float32),
        norm_std=np.array([2.0, 2.0, 2.0], dtype=np.float32),
        action_lo=art.action_lo,
        action_hi=art.action_hi,
        feature_names=art.feature_names,
    )
    # With mean/std applied, the raw input equal to the mean maps to z=0.
    at_mean = np.array([1.0, 2.0, 0.5], dtype=np.float32)
    # z=0 -> l1 = b1 = [0.1,-0.2] relu -> [0.1,0] -> l2 = 2*0.1 - 0 + 0.05 = 0.25
    # -> rps = 100 + 0.25*1000 = 350
    assert abs(shifted.act(at_mean) - 350.0) < 1e-4
