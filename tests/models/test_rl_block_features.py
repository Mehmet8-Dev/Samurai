"""Path-aware variant-block state features (no torch required).

These pin the causal semantics the serving side (rl_policy BuildFeatures + the
master's LeverShield snapshot) must mirror: the STATE conditions only on windows
strictly before it, the NEXT_STATE folds in the current window's reaction, and the
memory resets per episode. Get this wrong and Python training and C++ serving see
different states for the same situation.
"""

from __future__ import annotations

import json

import numpy as np

from samurai.models.rl import build_dataset
from samurai.models.rl.config import RLConfig

# Feature layout with mask bits on: 11 base + 9 mask = 20, then 2*V block features.
_BASE = 20
_V = 5


def _fixed_variant_corpus(path, *, episodes, variant, windows=3, succ=0.1):
    """Every window of every episode applies the same request_mix `variant` with the
    same observed success `succ`. Window 0 is s_valid=False (dropped as leading)."""
    with open(path, "w", encoding="utf-8") as fh:
        for ep in range(episodes):
            prev = 0.0
            rps = 300.0
            for w in range(windows):
                resp = rps * 5
                rec = {
                    "run_id": f"cl-{ep}", "win": w, "ts_ms": 1_700_000_000_000 + w,
                    "strategy": "explore", "min_rps": 50.0, "max_rps": 2000.0,
                    "window_s": 5,
                    "slo": {"max_error_pct": 100.0, "max_loss_pct": 0.0,
                            "min_rate_accuracy_pct": 0.0, "max_latency_ms": 0.0},
                    "action_rps": rps,
                    "action": {"rps": rps, "pacing_mode": 1, "concurrency": 4,
                               "connections": -1, "request_mix": variant,
                               "source_rotation": -1},
                    "s_valid": w > 0,
                    "s": {"valid": True, "rps": prev, "attempted": prev * 5,
                          "errors": 0.0, "error_pct": 0.0, "loss_pct": -1.0,
                          "rate_accuracy_pct": -1.0, "p99_ms": -1.0},
                    "s2": {
                        "valid": True, "rps": rps, "attempted": resp, "errors": 0.0,
                        "error_pct": 0.0, "loss_pct": -1.0, "rate_accuracy_pct": -1.0,
                        "p99_ms": -1.0,
                        "defense": {
                            "responses_total": resp,
                            "status_2xx": resp * succ,
                            "status_4xx": resp * (1.0 - succ),
                            "status_5xx": 0.0,
                        },
                    },
                    "healthy": True, "phase": "explore", "done": w == windows - 1,
                }
                fh.write(json.dumps(rec) + "\n")
                prev = rps
    return path


def test_block_features_disabled_by_default(tmp_path):
    cfg = RLConfig()
    assert cfg.block_feature_count == 0
    ds = build_dataset(_fixed_variant_corpus(tmp_path / "c.ndjson", episodes=2, variant=2), cfg)
    assert ds.states.shape[1] == _BASE
    assert not any(n.startswith("variant") for n in ds.feature_names)


def test_block_features_widen_state_and_name_in_order(tmp_path):
    cfg = RLConfig(variant_block_features=True, request_variant_count=_V)
    assert cfg.block_feature_count == 2 * _V
    assert cfg.state_dim == _BASE + 2 * _V
    ds = build_dataset(_fixed_variant_corpus(tmp_path / "c.ndjson", episodes=2, variant=2), cfg)
    assert ds.states.shape[1] == _BASE + 2 * _V
    assert ds.normalizer.mean.shape[0] == _BASE + 2 * _V
    # Ratios first, then known bits — the wire order BuildFeatures must match.
    assert ds.feature_names[_BASE:] == (
        "variant0_block", "variant1_block", "variant2_block", "variant3_block",
        "variant4_block", "variant0_known", "variant1_known", "variant2_known",
        "variant3_known", "variant4_known",
    )


def test_block_memory_is_causal_and_resets_per_episode(tmp_path):
    cfg = RLConfig(variant_block_features=True, request_variant_count=_V)
    # variant 2, success 0.1 => block ratio 0.9 once observed.
    ds = build_dataset(
        _fixed_variant_corpus(tmp_path / "c.ndjson", episodes=2, variant=2, windows=3, succ=0.1),
        cfg,
    )
    ratio2, known2 = _BASE + 2, _BASE + _V + 2  # variant 2's ratio / known columns

    # Two episodes, each contributes windows [1,2] (window 0 dropped as leading).
    eids = ds.episode_ids
    assert set(eids.tolist()) == {0, 1}
    for e in (0, 1):
        rows = np.where(eids == e)[0]
        assert len(rows) == 2
        first, second = rows[0], rows[1]
        # First kept window: nothing observed BEFORE it -> unknown, ratio imputed 0.
        assert ds.states[first, known2] == 0.0
        assert ds.states[first, ratio2] == 0.0
        # Its next_state folds in this window's block reaction.
        assert ds.next_states[first, known2] == 1.0
        assert abs(ds.next_states[first, ratio2] - 0.9) < 1e-6
        # Second kept window's STATE now carries the block learned last window.
        assert ds.states[second, known2] == 1.0
        assert abs(ds.states[second, ratio2] - 0.9) < 1e-6
        # Other variants stay unobserved (known 0) the whole episode.
        for v in (0, 1, 3, 4):
            assert ds.states[second, _BASE + _V + v] == 0.0


def test_block_ratio_reflects_honored_variant(tmp_path):
    cfg = RLConfig(variant_block_features=True, request_variant_count=_V)
    # variant 0, success 0.95 => block ratio ~0.05 (honored, not blocked).
    ds = build_dataset(
        _fixed_variant_corpus(tmp_path / "c.ndjson", episodes=1, variant=0, windows=3, succ=0.95),
        cfg,
    )
    ratio0, known0 = _BASE + 0, _BASE + _V + 0
    rows = np.where(ds.episode_ids == 0)[0]
    second = rows[1]
    assert ds.states[second, known0] == 1.0
    assert abs(ds.states[second, ratio0] - 0.05) < 1e-6
