"""Served-gain A/B, torch-free at decision time and deterministic in CI.

test_rl2_adaptation_ab pins that in-context adaptation EXISTS; this pins that it
PAYS — that the recurrent policy serves more throughput than a context-free
(feedforward IQL) policy on the same target. It is the CI-measurable counterpart of
``deploy/waf-lab/e2e-rl2.sh AB=1``, which shows the same gain against the live lab.

The task is the honest shape of what makes in-context adaptation win: an episode has
a hidden capacity ``c`` (the rate limiter). It is disclosed only during an early
PROBE phase (the state reveals ``c``); in the later EXPLOIT phase the state no longer
carries it, and served throughput is scored there. Offering rps ``a`` serves
``min(a,c)`` and wastes the overshoot — maximized by sitting exactly at ``c``. So the
only way to serve well in the exploit phase is to have REMEMBERED ``c`` from the
probe: a recurrent policy carries it in its hidden state; a memoryless feedforward
policy sees an identical exploit-phase state every episode and can only emit the one
marginal constant. Both policies read the identical logged trajectory; only the
carried context differs, and the proposed action is scored against the TRUE ``c``.
Everything is seeded, so the gap is reproducible.
"""

from __future__ import annotations

import json

import numpy as np
import pytest

torch = pytest.importorskip("torch")

from samurai.models.rl import build_dataset, load_policy, save_policy
from samurai.models.rl.rl2 import RL2Config, train_rl2
from samurai.models.rl.train import IQLConfig, train_iql

MIN_RPS, MAX_RPS = 50.0, 500.0
C_LO, C_HI = 140.0, 360.0
WS = 1
RESP = 500.0
OVERSHOOT_PENALTY = 1.0  # wasted-capacity weight; served peaks exactly at a == c


def _served_score(a: np.ndarray, c: float) -> np.ndarray:
    honored = np.minimum(a, c)
    overshoot = np.maximum(0.0, a - c)
    return honored - OVERSHOOT_PENALTY * overshoot


def _write_corpus(path, *, episodes, windows, seed):
    """Probe/exploit episodes. Probe windows disclose c in the state (success_ratio
    proportional to c); exploit windows carry a fixed, c-free state and score served
    throughput, with behavior exploring rps around c so a==c is the high-advantage act."""
    rng = np.random.default_rng(seed)
    half = windows // 2
    caps = {}
    with open(path, "w", encoding="utf-8") as fh:
        for ep in range(episodes):
            c = float(rng.uniform(C_LO, C_HI))
            caps[f"cl-{ep}"] = c
            c_signal = (c - C_LO) / (C_HI - C_LO)  # clean [0,1] disclosure of c
            for w in range(windows):
                probe = w < half
                if probe:
                    # State reveals c; action irrelevant; reward ~flat (no served, no pushback).
                    a = float(rng.uniform(MIN_RPS, MAX_RPS))
                    s_def = {"responses_total": RESP, "status_2xx": RESP * c_signal,
                             "status_4xx": RESP * (1.0 - c_signal)}
                    s2_def = {"responses_total": RESP, "status_2xx": 0.0, "status_4xx": 0.0}
                else:
                    # State is c-free (identical every exploit window/episode); served is
                    # scored here so a==c is optimal — only memory of the probe can hit it.
                    a = float(np.clip(c * rng.uniform(0.5, 1.5), MIN_RPS, MAX_RPS))
                    s_def = {}  # no capacity signal at decision time
                    honored = min(a, c)
                    s2_def = {"responses_total": RESP, "status_2xx": RESP * honored / a,
                              "status_4xx": RESP * max(0.0, a - c) / a}
                fh.write(json.dumps({
                    "run_id": f"cl-{ep}", "win": w, "ts_ms": w, "strategy": "rl",
                    "min_rps": MIN_RPS, "max_rps": MAX_RPS, "window_s": WS,
                    "slo": {"max_error_pct": 100.0},
                    "action_rps": a, "action": {"rps": a, "request_mix": 0},
                    "s_valid": True,
                    "s": {"valid": True, "rps": 0.0, "attempted": RESP, "errors": 0,
                          "error_pct": 0.0, "loss_pct": -1, "rate_accuracy_pct": -1,
                          "p99_ms": -1, "defense": s_def},
                    "s2": {"valid": True, "rps": a, "attempted": RESP, "errors": 0,
                           "error_pct": 0.0, "loss_pct": -1, "rate_accuracy_pct": -1,
                           "p99_ms": -1, "defense": s2_def},
                    "healthy": True, "phase": "probe" if probe else "exploit",
                    "done": w == windows - 1,
                }) + "\n")
    return path, caps


def _norm_actions(ds):
    lo = np.asarray(ds.action_lo, dtype=np.float32)
    hi = np.asarray(ds.action_hi, dtype=np.float32)
    span = np.where(hi <= lo, 1.0, hi - lo)
    return ((ds.actions - lo) / span).clip(0.0, 1.0).astype(np.float32)


def _episode_slices(ids):
    out, start = [], 0
    for i in range(1, len(ids)):
        if ids[i] != ids[i - 1]:
            out.append((start, i)); start = i
    out.append((start, len(ids)))
    return out


def _mean_exploit_served(ds, caps, windows, act_fn):
    """Mean true served over EXPLOIT windows for a policy's proposed rps. Both policies
    see the identical logged states; only the carried context differs."""
    half = windows // 2
    a_norm = _norm_actions(ds)
    caps_ord = [caps[k] for k in sorted(caps, key=lambda s: int(s.split("-")[1]))]
    total, n = 0.0, 0
    for (b, e), c in zip(_episode_slices(ds.episode_ids), caps_ord):
        proposed = np.asarray(act_fn(ds.states[b:e].astype(np.float32), a_norm[b:e]))
        ex = proposed[half:]  # score the exploit phase only
        total += float(_served_score(ex, c).sum())
        n += ex.size
    return total / n if n else 0.0


def test_rl2_serves_more_than_feedforward(tmp_path):
    windows = 8
    train_corpus, _ = _write_corpus(tmp_path / "train.ndjson",
                                    episodes=140, windows=windows, seed=1)
    eval_corpus, eval_caps = _write_corpus(tmp_path / "eval.ndjson",
                                           episodes=48, windows=windows, seed=2)
    train_ds = build_dataset(train_corpus)
    eval_ds = build_dataset(eval_corpus)

    rl2 = train_rl2(train_ds, RL2Config(seed=0, hidden_dim=32,
                                        critic_steps=1500, actor_steps=1500, episode_batch=24))
    ff = train_iql(train_ds, IQLConfig(seed=0))
    save_policy(rl2, tmp_path / "rl2.srlp")
    save_policy(ff, tmp_path / "ff.srlp")
    rl2 = load_policy(tmp_path / "rl2.srlp")   # exercise the torch-free serving path
    ff = load_policy(tmp_path / "ff.srlp")

    served_rl2 = _mean_exploit_served(eval_ds, eval_caps, windows,
                                      lambda s, a: rl2.act_sequence(s, a)[:, 0])
    served_ff = _mean_exploit_served(eval_ds, eval_caps, windows,
                                     lambda s, a: ff.act_batch(s)[:, 0])

    # The recurrent policy carried the probe-phase capacity into the exploit phase and
    # sat near it; the context-free policy saw an identical c-free exploit state every
    # episode and could only emit one marginal constant, serving measurably less.
    assert served_rl2 > served_ff + 5.0, (
        f"in-context adaptation did not pay: RL²={served_rl2:.1f} vs FF={served_ff:.1f} req/s")
