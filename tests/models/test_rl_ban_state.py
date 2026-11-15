"""Persistent-ban (ban_pressure) state feature — the union-corpus non-stationarity fix.

A fail2ban/IPS ban persists across windows and episodes; the single-window
conn_drop_ratio can't tell a transient drop from a sustained ban. build_dataset folds
conn_drop into a causal EWMA (ban_pressure) + a known bit, appended AFTER the block
features. These lock the encoding + causal semantics the C++ serving path mirrors.
"""

from __future__ import annotations

import json

import numpy as np

from samurai.models.rl import ActionSpec, build_dataset
from samurai.models.rl.config import RLConfig


def _rec(win, conn_drop, *, rps=300.0, s_valid=True, done=False):
    # conn_drop_ratio = max(0, 1 - established/attempted): pick att=100 to set it.
    att, est = 100.0, 100.0 * (1.0 - conn_drop)
    base_s = {"valid": True, "rps": rps, "attempted": rps * 5, "errors": 0.0,
              "error_pct": 0.0, "loss_pct": -1.0, "rate_accuracy_pct": -1.0,
              "p99_ms": -1.0, "defense": {}}
    s2 = dict(base_s)
    s2["defense"] = {"responses_total": rps * 5, "status_2xx": rps * 5,
                     "l7_conn_attempted": att, "l7_conn_established": est}
    return {
        "run_id": "cl-0", "win": win, "ts_ms": 1_700_000_000_000 + win,
        "strategy": "aimd", "min_rps": 50.0, "max_rps": 2000.0, "window_s": 5,
        "slo": {"max_error_pct": 100.0, "max_loss_pct": 0.0,
                "min_rate_accuracy_pct": 0.0, "max_latency_ms": 0.0},
        "action_rps": rps,
        "action": {"rps": rps, "pacing_mode": 1, "concurrency": 4,
                   "connections": -1, "request_mix": 0, "source_rotation": -1},
        "s_valid": s_valid, "s": base_s, "s2": s2,
        "healthy": True, "phase": "probe", "done": done,
    }


def _write(tmp_path, recs):
    p = tmp_path / "ban.ndjson"
    with open(p, "w", encoding="utf-8") as fh:
        for r in recs:
            fh.write(json.dumps(r) + "\n")
    return p


def _ban_cols(ds):
    return ds.feature_names.index("ban_pressure"), ds.feature_names.index("ban_known")


def test_ban_feature_off_by_default():
    cfg = RLConfig()
    assert cfg.ban_feature_count == 0
    assert cfg.ban_feature_names() == ()
    assert "ban_pressure" not in cfg.block_feature_names()


def test_ban_feature_widens_state_and_names(tmp_path):
    recs = [_rec(w, 0.0, s_valid=(w > 0), done=(w == 5)) for w in range(6)]
    base = build_dataset(_write(tmp_path, recs), RLConfig())
    cfg = RLConfig(ban_state_features=True)
    withban = build_dataset(_write(tmp_path, recs), cfg)
    assert withban.states.shape[1] == base.states.shape[1] + 2
    assert withban.feature_names[-2:] == ("ban_pressure", "ban_known")


def test_ban_pressure_is_causal_and_persists(tmp_path):
    # Sustained ban: conn_drop=0.8 every window. ban_pressure starts unknown (known=0,
    # pressure=0 before any fold), then — the EWMA seeds on the first sample — sits at
    # the sustained 0.8 and stays there (a persistent ban does not decay).
    recs = [_rec(w, 0.8, s_valid=(w > 0), done=(w == 6)) for w in range(7)]
    cfg = RLConfig(ban_state_features=True)
    ds = build_dataset(_write(tmp_path, recs), cfg)
    pc, kc = _ban_cols(ds)
    order = np.argsort(ds.episode_ids, kind="stable")  # windows in captured order
    pressure = ds.states[order, pc]
    known = ds.states[order, kc]
    # First kept window: nothing folded yet -> unknown.
    assert known[0] == 0.0 and pressure[0] == 0.0
    # Thereafter known and pinned at the sustained level (never exceeds it).
    assert np.all(known[1:] == 1.0)
    assert np.allclose(pressure[1:], 0.8, atol=1e-6)


def test_ban_pressure_ramps_toward_a_rising_ban(tmp_path):
    # A ban that tightens window-over-window: EWMA climbs monotonically and lags the
    # instantaneous drop (persistence smoothing), so pressure < the latest conn_drop.
    drops = [0.1, 0.3, 0.5, 0.7, 0.9]
    recs = [_rec(w, d, s_valid=(w > 0), done=(w == len(drops) - 1))
            for w, d in enumerate(drops)]
    cfg = RLConfig(ban_state_features=True)
    ds = build_dataset(_write(tmp_path, recs), cfg)
    pc, _ = _ban_cols(ds)
    order = np.argsort(ds.episode_ids, kind="stable")
    pressure = ds.states[order, pc]
    known_rising = pressure[1:]  # windows with a folded value
    assert np.all(np.diff(known_rising) > 0)  # strictly climbing
    assert known_rising[-1] < 0.9  # lags the instantaneous drop


def test_ban_pressure_decays_after_transient(tmp_path):
    # One-window spike then clean: EWMA must decay, not latch (distinguishes a
    # transient drop from a persistent ban).
    drops = [0.0, 0.9, 0.0, 0.0, 0.0, 0.0]
    recs = [_rec(w, d, s_valid=(w > 0), done=(w == len(drops) - 1))
            for w, d in enumerate(drops)]
    cfg = RLConfig(ban_state_features=True)
    ds = build_dataset(_write(tmp_path, recs), cfg)
    pc, _ = _ban_cols(ds)
    order = np.argsort(ds.episode_ids, kind="stable")
    pressure = ds.states[order, pc]
    peak = pressure.max()
    assert peak > 0.2  # the spike registered
    assert pressure[-1] < 0.5 * peak  # ...but decayed well below it


def test_ban_appended_after_block_features(tmp_path):
    # With both features on, order is [...base+mask, block ratios, block known, ban].
    recs = [_rec(w, 0.3, s_valid=(w > 0), done=(w == 5)) for w in range(6)]
    spec = ActionSpec(("rps", "request_mix"), categorical_names=("request_mix",))
    cfg = RLConfig(variant_block_features=True, ban_state_features=True,
                   request_variant_count=5)
    ds = build_dataset(_write(tmp_path, recs), cfg, action_spec=spec)
    names = ds.feature_names
    assert names[-2:] == ("ban_pressure", "ban_known")
    assert names.index("ban_pressure") > names.index("variant4_known")
    assert ds.states.shape[1] == cfg.state_dim
