"""Pure-Python LeverShield mirror (samurai/models/rl/shield.py).

These lock the port to the native control/lever_shield.hpp Govern/Blocked logic and
the dataset block-feature encoding it reads at OPE time. Torch-free on purpose — the
shield must stay importable in the serving/eval-only environment.
"""

from __future__ import annotations

import numpy as np

from samurai.models.rl import LeverShield
from samurai.models.rl.schemas import UNKNOWN
from samurai.models.rl.shield import best_success_from_states, govern_batch


def _shield(best, floor=0.10):
    sh = LeverShield(len(best), floor)
    sh.best = list(best)
    return sh


def test_govern_passes_through_unblocked_and_unobserved():
    # Proposal not known-blocked (honored, or never observed) is trusted as-is.
    sh = _shield([0.95, UNKNOWN, 0.05, UNKNOWN, 0.9])
    assert sh.govern(0) == 0       # honored -> unchanged
    assert sh.govern(1) == 1       # unobserved -> first-touch discovery, unchanged
    assert sh.blocked(2) is True   # 0.05 < floor -> path-blocked


def test_govern_substitutes_blocked_with_best_honored():
    # Blocked proposal (2) -> the observed variant with the highest best-success (4).
    sh = _shield([0.6, UNKNOWN, 0.05, UNKNOWN, 0.9])
    assert sh.govern(2) == 4


def test_govern_probes_unobserved_when_no_honored():
    # Blocked proposal, nothing observed above the floor -> probe an unobserved one.
    sh = _shield([0.02, UNKNOWN, 0.05, 0.0, 0.03])
    assert sh.govern(2) == 1  # first index still UNKNOWN


def test_govern_all_blocked_returns_proposal():
    # Everything observed and blocked -> no better option; keep the proposal.
    sh = _shield([0.01, 0.02, 0.05, 0.0, 0.03])
    assert sh.govern(2) == 2


def test_warm_raises_never_lowers():
    sh = _shield([UNKNOWN, 0.2, 0.9])
    sh.warm([0.5, 0.1, 0.4])       # prior
    # unknown -> takes prior; known-lower prior ignored; known-higher current kept.
    assert sh.best == [0.5, 0.2, 0.9]


def test_best_success_from_states_inverts_block_encoding():
    # A raw state row whose trailing 2*n columns are [1-best ratios..., known bits...]
    # (dataset._encode_block). n=3: v0 honored 0.9, v1 unobserved, v2 blocked 0.05.
    base = np.array([0.1, 0.2, 0.3], dtype=np.float32)         # arbitrary base features
    ratios = np.array([1 - 0.9, 0.0, 1 - 0.05], dtype=np.float32)
    known = np.array([1.0, 0.0, 1.0], dtype=np.float32)
    row = np.concatenate([base, ratios, known])[None, :]
    best = best_success_from_states(row, n_variant=3)
    assert best.shape == (1, 3)
    assert best[0, 0] == np.float32(0.9)
    assert best[0, 1] == UNKNOWN
    assert abs(best[0, 2] - 0.05) < 1e-6  # blocked: 1 - (1 - 0.05)


def test_govern_batch_matches_per_row():
    best = np.array([[0.6, UNKNOWN, 0.05, UNKNOWN, 0.9],
                     [0.01, 0.02, 0.05, 0.0, 0.03]], dtype=np.float64)
    proposed = np.array([2, 2], dtype=np.int64)
    out = govern_batch(proposed, best, floor=0.10)
    assert list(out) == [4, 2]  # row0 -> best honored; row1 -> all blocked, unchanged
