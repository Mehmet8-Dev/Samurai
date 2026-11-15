"""Bridge the passive DefenseProfile into the serving loop's per-target memory.

The fingerprint (``fingerprint.py``) discovers which request_mix variants a target
path-blocks. This module writes that discovery as a warm-start prior into the SAME
JSON store the native ``LeverShield`` reads (``control/variant_memory.hpp``), keyed
by target identity ("host:port"):

    { "host:port": [best0, best1, ...], ... }   # best = success in [0,1], -1 = unknown

A fresh serving episode then starts from the discovered walls — the shield vetoes a
path-blocked variant on window 1 instead of paying a rejected window to relearn it,
and a block-aware policy (in_dim 30) sees the block-state feature pre-seeded. Crucially
this touches NO feature in the frozen SRLP contract: it only populates the same memory
the serving loop already warm-starts from.

CLI:
    python -m samurai.models.rl.variant_prior \
        --corpus data/rl-corpus/strict-waf.ndjson --target 127.0.0.1:8080 \
        --variants 5 --out artifacts/rl/variant-memory.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .fingerprint import fingerprint_corpus
from .schemas import UNKNOWN


def _merge_best(prior: list[float], existing: list[float]) -> list[float]:
    """Element-wise merge, mirroring LeverShield::Warm — a known value always beats
    UNKNOWN (-1), and two known values resolve to the higher success. So a live store
    that already learned a variant is honored is never clobbered by a corpus that
    happened not to exercise it."""
    out = list(prior)
    for i in range(min(len(out), len(existing))):
        a, b = out[i], float(existing[i])
        if a < 0.0:
            out[i] = b
        elif b >= 0.0:
            out[i] = max(a, b)
    return out


def _load_store(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {}
    return obj if isinstance(obj, dict) else {}


def build_variant_prior(
    corpus_paths: str | Path | Iterable[str | Path],
    target_key: str,
    out_path: str | Path,
    n_variants: int = 5,
    *,
    merge: bool = True,
):
    """Fingerprint ``corpus_paths`` and write/merge a warm-start prior for ``target_key``
    into the VariantMemory JSON store at ``out_path``.

    Returns ``(DefenseProfile, best_success_list)``. Writes atomically (temp + rename)
    with sorted keys, matching ``VariantMemory::Save`` so the native side reads it back
    identically.
    """
    profile = fingerprint_corpus(corpus_paths)
    best = profile.variant_best_success(n_variants)

    out = Path(out_path)
    store = _load_store(out) if merge else {}
    prev = store.get(target_key)
    if merge and isinstance(prev, list):
        best = _merge_best(best, prev)
    store[target_key] = best

    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_text(json.dumps(store, sort_keys=True), encoding="utf-8")
    tmp.replace(out)
    return profile, best


def _main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--corpus", nargs="+", required=True,
                    help="one or more NDJSON corpus files to fingerprint")
    ap.add_argument("--target", required=True,
                    help='target key "host:port" (must match the serving --target/--port)')
    ap.add_argument("--out", required=True, help="VariantMemory JSON store to write/merge")
    ap.add_argument("--variants", type=int, default=5, help="request_mix cardinality")
    ap.add_argument("--no-merge", action="store_true",
                    help="overwrite the target entry instead of merging with any existing")
    args = ap.parse_args(argv)

    profile, best = build_variant_prior(
        args.corpus, args.target, args.out, args.variants, merge=not args.no_merge)
    print(profile.format_report())
    shown = ", ".join(f"v{i}={'?' if b == UNKNOWN or b < 0 else f'{b:.2f}'}"
                      for i, b in enumerate(best))
    print(f"\n>> warm-start prior for {args.target}: [{shown}]")
    print(f">> wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
