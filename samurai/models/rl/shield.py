"""Pure-Python mirror of the native LeverShield (``control/lever_shield.hpp``).

Serving does not run the bare policy: the master wraps it in the C++ LeverShield,
which vetoes a request_mix variant the target path-BLOCKS and substitutes the
best-known honored one (model-free, per episode). Scoring the raw policy in FQE
therefore measures something that never ships. This mirror lets the OPE gate
(``ope.evaluate_policy``) score the SAME shielded action the master will apply.

The ``govern`` / ``blocked`` logic is kept byte-for-byte faithful to the C++
source — if one side changes, change both (the control selftest cross-checks the
block-feature contract this rides on).

Offline, the shield's per-variant memory is not replayed step-by-step; it is read
straight out of the state's own block features (``dataset._encode_block``: the
trailing ``[1-best ratios..., known bits...]`` columns). That IS the memory
snapshot the serving loop fed the policy at that window, so governing on it
reproduces the serving substitution exactly. An optional warm-start vector (the
fingerprint→variant prior) seeds it the way ``--cl-variant-memory`` does live.
"""

from __future__ import annotations

import numpy as np

from .schemas import UNKNOWN

# Best-observed success below this => the variant is path-blocked (a WAF 403 on
# that path), not merely rate-limited. Mirrors LeverShield::Config default and the
# fingerprint block criterion.
HONORED_SUCCESS_FLOOR = 0.10


class LeverShield:
    """Per-episode reaction memory for the request_mix lever (C++ port)."""

    def __init__(self, variant_count: int = 5,
                 honored_success_floor: float = HONORED_SUCCESS_FLOOR):
        self.floor = honored_success_floor
        n = variant_count if variant_count > 0 else 1
        self.best: list[float] = [UNKNOWN] * n

    def observe(self, variant: int, success_ratio: float) -> None:
        if variant < 0 or variant >= len(self.best):
            return
        if success_ratio < 0.0:
            return
        if success_ratio > self.best[variant]:
            self.best[variant] = success_ratio

    def blocked(self, variant: int) -> bool:
        if variant < 0 or variant >= len(self.best):
            return False
        b = self.best[variant]
        return b >= 0.0 and b < self.floor

    def govern(self, proposed: int) -> int:
        """Map a proposal to the variant to actually apply — see the C++ Govern."""
        if not self.blocked(proposed):
            return proposed
        best, best_val = -1, self.floor
        for v in range(len(self.best)):
            if self.best[v] > best_val:
                best_val, best = self.best[v], v
        if best >= 0:
            return best
        for v in range(len(self.best)):
            if self.best[v] < 0.0:
                return v  # unobserved — probe it
        return proposed

    def warm(self, best: list[float]) -> None:
        for v in range(min(len(best), len(self.best))):
            if best[v] >= 0.0 and best[v] > self.best[v]:
                self.best[v] = best[v]


def best_success_from_states(states_raw: np.ndarray, n_variant: int) -> np.ndarray:
    """Invert ``dataset._encode_block``: recover the (N, n) per-variant best-success
    the block features encode. The trailing 2*n columns are ``[1-best ratios...,
    known bits...]``; where the known bit is 0 the variant is UNKNOWN (-1)."""
    n2 = 2 * n_variant
    ratios = states_raw[:, -n2:-n_variant]
    known = states_raw[:, -n_variant:]
    return np.where(known > 0.5, 1.0 - ratios, UNKNOWN).astype(np.float64)


def govern_batch(proposed: np.ndarray, best_success: np.ndarray,
                 floor: float = HONORED_SUCCESS_FLOOR) -> np.ndarray:
    """Apply ``LeverShield.govern`` row-wise: proposed (N,), best_success (N, n)."""
    out = np.array(proposed, dtype=np.int64)
    n_variant = best_success.shape[1]
    sh = LeverShield(n_variant, floor)
    for i in range(out.shape[0]):
        sh.best = best_success[i].tolist()
        out[i] = sh.govern(int(out[i]))
    return out
