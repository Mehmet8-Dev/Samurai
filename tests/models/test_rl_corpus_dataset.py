"""RL corpus -> dataset pipeline contract.

Mirrors the exact NDJSON schema emitted by ``samurai_master --rl-corpus``
(``RlTransitionJson`` in control/daemon/master_main.cpp) so a schema drift on
either side breaks this test rather than silently poisoning training.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from ddos_samurai.models.rl import RLConfig, build_dataset, load_transitions
from ddos_samurai.models.rl.reward import SloProgressReward, slo_overshoot
from ddos_samurai.models.rl.schemas import DefenseSignals, RawState, SloThresholds, Transition


def _rec(
    *,
    win: int,
    action: float,
    s_rps: float,
    s2_rps: float,
    s_valid: bool,
    healthy: bool,
    error_pct: float,
    done: bool = False,
    run_id: str = "cl-1",
    attempted2: float = 1000.0,
    max_rps: float = 10000.0,
    s2_defense: dict | None = None,
) -> dict:
    """One corpus line shaped exactly like the C++ emitter (RlTransitionJson)."""
    return {
        "run_id": run_id,
        "win": win,
        "ts_ms": 1_700_000_000_000 + win,
        "strategy": "aimd",
        "min_rps": 1.0,
        "max_rps": max_rps,
        "window_s": 5,
        "slo": {
            "max_error_pct": 1.0,
            "max_loss_pct": 0.0,
            "min_rate_accuracy_pct": 0.0,
            "max_latency_ms": 0.0,
        },
        "action_rps": action,
        "action": {
            "rps": action,
            "pacing_mode": 1,
            "concurrency": -1,
            "connections": -1,
            "request_mix": -1,
            "source_rotation": -1,
        },
        "s_valid": s_valid,
        "s": {
            "valid": True,
            "rps": s_rps,
            "attempted": 1000.0,
            "errors": 0.0,
            "error_pct": 0.0,
            "loss_pct": -1.0,
            "rate_accuracy_pct": -1.0,
            "p99_ms": -1.0,
            "defense": {},
        },
        "s2": {
            "valid": True,
            "rps": s2_rps,
            "attempted": attempted2,
            "errors": attempted2 * error_pct / 100.0,
            "error_pct": error_pct,
            "loss_pct": -1.0,
            "rate_accuracy_pct": -1.0,
            "p99_ms": -1.0,
            "defense": s2_defense if s2_defense is not None else {},
        },
        "healthy": healthy,
        "phase": "probe" if not done else "converged",
        "done": done,
    }


def _write(tmp_path: Path, records: list[dict]) -> Path:
    p = tmp_path / "corpus.ndjson"
    with p.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    return p


def test_transition_roundtrip_matches_schema():
    rec = _rec(win=1, action=100.0, s_rps=90.0, s2_rps=95.0, s_valid=True, healthy=True, error_pct=0.0)
    t = Transition.from_json(rec)
    assert t.run_id == "cl-1"
    assert t.action_rps == 100.0
    assert t.s.rps == 90.0 and t.s2.rps == 95.0
    assert t.slo.max_error_pct == 1.0
    # loss/rate/latency unknown -> carried through as -1.
    assert t.s2.loss_pct == -1.0


def test_leading_and_no_traffic_windows_dropped(tmp_path):
    recs = [
        _rec(win=0, action=100.0, s_rps=0.0, s2_rps=100.0, s_valid=False, healthy=True, error_pct=0.0),
        _rec(win=1, action=200.0, s_rps=100.0, s2_rps=200.0, s_valid=True, healthy=True, error_pct=0.0),
        _rec(win=2, action=300.0, s_rps=200.0, s2_rps=0.0, s_valid=True, healthy=False,
             error_pct=0.0, attempted2=0.0),  # no traffic -> dropped
    ]
    ds = build_dataset(_write(tmp_path, recs))
    assert len(ds) == 1  # leading (s_valid=False) and no-traffic windows removed
    assert ds.actions[0] == 200.0


def test_reward_rewards_healthy_progress_and_penalizes_breach(tmp_path):
    cfg = RLConfig()
    reward = SloProgressReward(cfg)

    # Healthy climb big enough to clear the flat step cost -> net positive.
    good = Transition.from_json(
        _rec(win=1, action=600.0, s_rps=100.0, s2_rps=600.0, s_valid=True, healthy=True, error_pct=0.0)
    )
    r_good = reward(good)
    assert r_good == (600.0 - 100.0) / 10000.0 - cfg.step_cost
    assert r_good > 0.0

    # A tiny healthy step is net-negative: step_cost dominates marginal progress,
    # discouraging dithering near the ceiling (a deliberate shaping property).
    tiny = Transition.from_json(
        _rec(win=1, action=110.0, s_rps=100.0, s2_rps=110.0, s_valid=True, healthy=True, error_pct=0.0)
    )
    assert reward(tiny) < 0.0

    # SLO breach: error_pct 5% vs 1% cap -> overshoot 4.0, dominates.
    bad = Transition.from_json(
        _rec(win=2, action=400.0, s_rps=200.0, s2_rps=400.0, s_valid=True, healthy=False, error_pct=5.0)
    )
    r_bad = reward(bad)
    assert r_bad < 0.0
    assert r_bad < r_good


def test_slo_overshoot_max_across_rules():
    slo = SloThresholds(max_error_pct=1.0, max_loss_pct=0.0, min_rate_accuracy_pct=0.0, max_latency_ms=100.0)
    s2 = RawState(valid=True, rps=100.0, attempted=1000.0, errors=20.0, error_pct=2.0,
                  loss_pct=-1.0, rate_accuracy_pct=-1.0, p99_ms=400.0)
    # error breach = (2-1)/1 = 1.0 ; latency breach = (400-100)/100 = 3.0 -> worst dominates.
    assert slo_overshoot(s2, slo) == 3.0


def test_defense_signals_derive_mahoraga_ratios():
    # A WAF/rate-limiter window: 60% 2xx, 30% 429 (4xx), 10% 503 (5xx); half the
    # connection attempts refused; 20% of H2 streams reset.
    d = DefenseSignals.from_json(
        {
            "responses_total": 1000.0,
            "status_2xx": 600.0,
            "status_4xx": 300.0,
            "status_5xx": 100.0,
            "l7_conn_attempted": 400.0,
            "l7_conn_established": 200.0,
            "h2_stream_reset_ratio": 0.2,
        }
    )
    assert d.rate_limited_ratio == 0.3
    assert d.overload_ratio == 0.1
    assert d.success_ratio == 0.6
    assert d.conn_drop_ratio == 0.5
    assert d.reset_pressure == 0.2
    # Absent signal -> UNKNOWN, so the extractor can mask it.
    assert d.challenge_rate == -1.0


def test_defense_features_flow_into_state_vector(tmp_path):
    cfg = RLConfig()
    defense = {
        "responses_total": 1000.0,
        "status_2xx": 500.0,
        "status_4xx": 400.0,  # heavy rate-limiting
        "status_5xx": 100.0,
        "l7_conn_attempted": 100.0,
        "l7_conn_established": 100.0,  # no conn drops
        "h2_stream_reset_ratio": 0.0,
    }
    rec = _rec(win=1, action=200.0, s_rps=100.0, s2_rps=180.0, s_valid=True,
               healthy=True, error_pct=0.0, s2_defense=defense)
    ds = build_dataset(_write(tmp_path, [rec]), cfg)
    names = ds.feature_names
    # next_states carries s2's defense reaction; rate_limited_ratio = 400/1000.
    rl_idx = names.index("rate_limited_ratio")
    assert ds.next_states[0, rl_idx] == 0.4
    # challenge_rate was absent -> imputed to 0 and its known-mask bit is 0.
    ch_mask = names.index("challenge_rate_known")
    assert ds.next_states[0, ch_mask] == 0.0
    rl_mask = names.index("rate_limited_ratio_known")
    assert ds.next_states[0, rl_mask] == 1.0


def test_action_vector_parsed():
    rec = _rec(win=1, action=250.0, s_rps=100.0, s2_rps=250.0, s_valid=True,
               healthy=True, error_pct=0.0)
    t = Transition.from_json(rec)
    assert t.action.rps == 250.0
    assert t.action.pacing_mode == 1
    # Undriven Mahoraga levers default to -1 (schema-ready, not yet controlled).
    assert t.action.concurrency == -1
    assert t.action.request_mix == -1


def test_feature_dim_and_normalizer_shape(tmp_path):
    cfg = RLConfig()
    recs = [
        _rec(win=1, action=200.0, s_rps=100.0, s2_rps=200.0, s_valid=True, healthy=True, error_pct=0.0),
        _rec(win=2, action=300.0, s_rps=200.0, s2_rps=280.0, s_valid=True, healthy=True, error_pct=0.5, done=True),
    ]
    ds = build_dataset(_write(tmp_path, recs), cfg)
    assert ds.states.shape == (2, cfg.feature_count)
    assert ds.next_states.shape == (2, cfg.feature_count)
    assert ds.normalizer.mean.shape == (cfg.feature_count,)
    assert np.all(ds.normalizer.std > 0)  # constant features floored, never zero
    # Last window converged -> terminal.
    assert ds.dones[-1] == 1.0
    # feature_names includes the mask bits.
    assert len(ds.feature_names) == cfg.feature_count
