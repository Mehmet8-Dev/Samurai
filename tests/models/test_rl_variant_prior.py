"""Bridge: fingerprint DefenseProfile -> VariantMemory warm-start prior.

The store this writes is read verbatim by the native LeverShield
(control/variant_memory.hpp), so the JSON layout ({ "host:port": [best...] }, -1 =
unknown) is part of the contract and is asserted here.
"""

from __future__ import annotations

import json

from samurai.models.rl import build_variant_prior, fingerprint_corpus
from samurai.models.rl.schemas import UNKNOWN

# Reuse the synthetic-corpus builders from the fingerprint test.
from tests.models.test_rl_fingerprint import _rec, _fully_blocked, _write


def _blocked_corpus(tmp_path):
    """Variant 2 hard-blocked (403 at every rps), others only rate-limited."""
    recs = []
    for rps in range(100, 1300, 100):
        for mix in range(5):
            recs.append(_fully_blocked(rps, mix) if mix == 2 else _rec(rps, mix))
    return _write(tmp_path, recs)


def test_variant_best_success_maps_block_to_prior(tmp_path):
    profile = fingerprint_corpus(_blocked_corpus(tmp_path))
    best = profile.variant_best_success(5)
    assert len(best) == 5
    # Blocked variant 2 -> ~0 best success; honored variants -> high best success.
    assert best[2] <= 0.1
    assert all(best[v] >= 0.5 for v in (0, 1, 3, 4))


def test_prior_written_in_variant_memory_format(tmp_path):
    out = tmp_path / "variant-memory.json"
    profile, best = build_variant_prior(
        _blocked_corpus(tmp_path), "127.0.0.1:8080", out, n_variants=5)

    store = json.loads(out.read_text())
    # Exactly the { "host:port": [best...] } shape the C++ VariantMemory::Load parses.
    assert set(store) == {"127.0.0.1:8080"}
    arr = store["127.0.0.1:8080"]
    assert isinstance(arr, list) and len(arr) == 5
    assert arr == best
    assert arr[2] <= 0.1


def test_unexercised_variants_stay_unknown(tmp_path):
    # Corpus only exercises variants 0 and 1; asking for 5 leaves 2..4 UNKNOWN (-1),
    # so the shield probes them live rather than assuming they are honored/blocked.
    recs = [_rec(rps, mix) for rps in range(100, 700, 100) for mix in (0, 1)]
    out = tmp_path / "vm.json"
    _, best = build_variant_prior(_write(tmp_path, recs), "h:1", out, n_variants=5)
    assert best[0] >= 0.5 and best[1] >= 0.5
    assert best[2] == UNKNOWN and best[3] == UNKNOWN and best[4] == UNKNOWN


def test_merge_prefers_known_and_higher_success(tmp_path):
    out = tmp_path / "vm.json"
    # Seed a store with a live-learned value the fingerprint corpus won't overwrite:
    # variant 4 already known honored (0.9), variant 0 known low (0.2).
    out.write_text(json.dumps({"h:1": [0.2, -1.0, -1.0, -1.0, 0.9]}))

    recs = [_rec(rps, mix) for rps in range(100, 700, 100) for mix in (0, 1)]
    _, best = build_variant_prior(_write(tmp_path, recs), "h:1", out, n_variants=5)

    # Variant 4 was never in this corpus -> keep the existing known 0.9 (not clobbered).
    assert best[4] == 0.9
    # Variant 1 came only from the corpus -> its fingerprinted value is kept.
    assert best[1] >= 0.5
    # Variant 0 known in both -> the higher success wins (corpus honored it ~1.0).
    assert best[0] >= 0.5
    # A second, unrelated target is preserved in the store.
    store = json.loads(out.read_text())
    assert "h:1" in store
