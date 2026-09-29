"""Leave-one-profile-out generalization eval (ddos_samurai/models/rl/generalize.py).

The filename-grouping helpers are torch-free; the LOPO driver needs torch and is
gated. Quality of transfer on toy data is not asserted — the plumbing (profile split,
per-fold train/eval, finite gate) is.
"""

from __future__ import annotations

import json

from ddos_samurai.models.rl import group_by_profile, profile_of


def test_profile_of_parses_capture_filenames():
    assert profile_of("data/rl-corpus/waf-lab-strict-waf-20260905-120000.ndjson") == "strict-waf"
    assert profile_of("waf-lab-rate-only-20260905.ndjson") == "rate-only"
    assert profile_of("/x/waf-lab-waf-heavy-20260830-153000.ndjson") == "waf-heavy"
    # Off-pattern names fall back to the bare stem.
    assert profile_of("custom-corpus.ndjson") == "custom-corpus"


def test_group_by_profile_buckets_and_preserves_order():
    paths = [
        "waf-lab-strict-waf-20260905-120000.ndjson",
        "waf-lab-rate-only-20260905-120000.ndjson",
        "waf-lab-strict-waf-20260906-090000.ndjson",
    ]
    groups = group_by_profile(paths)
    assert set(groups) == {"strict-waf", "rate-only"}
    assert [p.name for p in groups["strict-waf"]] == [
        "waf-lab-strict-waf-20260905-120000.ndjson",
        "waf-lab-strict-waf-20260906-090000.ndjson",
    ]


# --- torch-gated LOPO driver ---

import numpy as np  # noqa: E402
import pytest  # noqa: E402

torch = pytest.importorskip("torch")

from ddos_samurai.models.rl import leave_one_profile_out  # noqa: E402
from ddos_samurai.models.rl.config import RLConfig  # noqa: E402
from ddos_samurai.models.rl.ope import FQEConfig  # noqa: E402
from ddos_samurai.models.rl.train import IQLConfig  # noqa: E402


def _profile_corpus(path, blocked_variant, *, episodes=8, windows=6):
    """Small MAHORAGA-shaped corpus: `blocked_variant` returns mostly 4xx (low
    success), the others are honored. Distinct blocked variant => distinct profile."""
    with open(path, "w", encoding="utf-8") as fh:
        for ep in range(episodes):
            variant = ep % 5
            rps = 300.0
            prev = 0.0
            for w in range(windows):
                blocked = variant == blocked_variant
                succ = 0.1 if blocked else 0.95
                resp = max(rps, 1.0) * 5
                rec = {
                    "run_id": f"cl-{ep}", "win": w, "ts_ms": 1_700_000_000_000 + w,
                    "strategy": "explore", "min_rps": 50.0, "max_rps": 2000.0, "window_s": 5,
                    "slo": {"max_error_pct": 100.0, "max_loss_pct": 0.0,
                            "min_rate_accuracy_pct": 0.0, "max_latency_ms": 0.0},
                    "action_rps": rps,
                    "action": {"rps": rps, "pacing_mode": 1, "concurrency": 4,
                               "connections": -1, "request_mix": variant, "source_rotation": 0},
                    "s_valid": w > 0,
                    "s": {"valid": True, "rps": prev, "attempted": max(prev, 1.0) * 5,
                          "errors": 0.0, "error_pct": 0.0, "loss_pct": -1.0,
                          "rate_accuracy_pct": -1.0, "p99_ms": -1.0, "defense": {}},
                    "s2": {"valid": True, "rps": rps, "attempted": resp, "errors": 0.0,
                           "error_pct": 0.0, "loss_pct": -1.0, "rate_accuracy_pct": -1.0,
                           "p99_ms": -1.0,
                           "defense": {"responses_total": resp, "status_2xx": resp * succ,
                                       "status_4xx": resp * (1.0 - succ) if blocked else 0.0,
                                       "status_5xx": 0.0}},
                    "healthy": True, "phase": "explore", "done": w == windows - 1,
                }
                fh.write(json.dumps(rec) + "\n")
                prev = rps
    return path


def test_leave_one_profile_out_runs_every_fold(tmp_path):
    groups = {
        "strict-waf": [_profile_corpus(tmp_path / "waf-lab-strict-waf-20260905-000000.ndjson", 2)],
        "rate-only": [_profile_corpus(tmp_path / "waf-lab-rate-only-20260905-000000.ndjson", 4)],
        "waf-heavy": [_profile_corpus(tmp_path / "waf-lab-waf-heavy-20260905-000000.ndjson", 1)],
    }
    res = leave_one_profile_out(
        groups, cfg=RLConfig(rps_scale=1000.0),
        iql_config=IQLConfig(steps=120, seed=0),
        fqe_config=FQEConfig(steps=120, seed=0))

    # One fold per profile, each holding out a distinct one.
    assert {f.held_out for f in res.folds} == set(groups)
    assert len(res.folds) == 3
    for f in res.folds:
        assert f.n_train_episodes > 0 and f.n_eval_episodes > 0
        assert np.isfinite(f.transfer.improvement) and np.isfinite(f.in_dist.improvement)
        assert isinstance(f.generalizes, bool)
        assert np.isfinite(f.gap)
    assert np.isfinite(res.mean_transfer_improvement)
    assert "held-out" in res.format_report()


def test_leave_one_profile_out_needs_two_profiles(tmp_path):
    one = {"only": [_profile_corpus(tmp_path / "waf-lab-only-20260905-000000.ndjson", 2)]}
    with pytest.raises(ValueError):
        leave_one_profile_out(one)
