"""Open-vocabulary defense detection — the offline scan that names what the frozen
feature space could not.

``fingerprint.py`` explains a target's defense along the KNOWN axes (rate limit,
overload, conn-drop, reset, WAF challenge). This module is its complement: it finds
the windows those axes CANNOT explain — where traffic is failing (success well below
1) but no known signal accounts for it — the tell-tale of a defense mechanism outside
the dictionary (a silent tarpit, a slow-drip, a 200-with-wrong-body content block).

The math mirrors, value-for-value, the native serving-time ``NoveltyDetector``
(``control/novelty_detector.hpp``): per window,

    unexplained = max(0, (1 - success_ratio) - sum(known defense shares))

A window is novel when its unexplained loss clears a threshold; each novel window is
labelled with an open-vocabulary SIGNATURE, and the set of signatures discovered
across the corpus is the "new axes" the fixed representation was blind to.

CLI:
    python -m samurai.models.rl.novelty --corpus data/rl-corpus/*.ndjson
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .corpus import iter_transitions
from .schemas import Transition

DEFAULT_RESIDUAL_THRESHOLD = 0.35


def _share(v: float) -> float:
    return v if v > 0.0 else 0.0


def unexplained_loss(defense) -> float | None:
    """Success loss the known defense axes cannot account for, or None if there is no
    success signal to judge. Mirrors NoveltyDetector::Observe."""
    succ = defense.success_ratio
    if succ < 0.0:
        return None
    explained = min(1.0, _share(defense.rate_limited_ratio) + _share(defense.overload_ratio)
                    + _share(defense.conn_drop_ratio) + _share(defense.reset_pressure)
                    + _share(defense.challenge_rate))
    return max(0.0, (1.0 - succ) - explained)


def signature(defense) -> str:
    """Open-vocabulary label for a novel window (mirrors NoveltyDetector::Signature)."""
    explained = (_share(defense.rate_limited_ratio) + _share(defense.overload_ratio)
                 + _share(defense.conn_drop_ratio) + _share(defense.reset_pressure)
                 + _share(defense.challenge_rate))
    if explained < 0.10:
        return "silent-success-loss"
    axes = {
        "rate_limit": _share(defense.rate_limited_ratio),
        "overload": _share(defense.overload_ratio),
        "conn_drop": _share(defense.conn_drop_ratio),
        "reset": _share(defense.reset_pressure),
        "challenge": _share(defense.challenge_rate),
    }
    dom = max(axes, key=axes.get)
    return f"under-explained:{dom}"


@dataclass
class NoveltyReport:
    n_windows: int = 0
    n_judged: int = 0          # windows with a success signal (so unexplained is defined)
    n_novel: int = 0
    residual_threshold: float = DEFAULT_RESIDUAL_THRESHOLD
    vocabulary: dict[str, int] = field(default_factory=dict)
    worst: list[tuple[float, float, str]] = field(default_factory=list)  # (rps, unexplained, sig)

    @property
    def novelty_rate(self) -> float:
        return self.n_novel / self.n_judged if self.n_judged else 0.0

    def format_report(self) -> str:
        L: list[str] = []
        L.append("=== Open-vocabulary defense detection (novelty scan) ===")
        L.append(f"windows        : {self.n_windows} ({self.n_judged} with a success signal)")
        L.append(f"novel windows  : {self.n_novel}  ({100.0 * self.novelty_rate:.1f}% of judged)"
                 f"  [threshold unexplained >= {self.residual_threshold:.2f}]")
        if not self.vocabulary:
            L.append("discovered     : none — every failing window is explained by a known "
                     "defense axis (rate-limit / overload / conn-drop / reset / challenge)")
        else:
            L.append("discovered new axes (open vocabulary):")
            for sig, cnt in sorted(self.vocabulary.items(), key=lambda kv: -kv[1]):
                L.append(f"  * {sig:<28} x{cnt}")
            L.append("worst offenders (offered rps, unexplained loss, signature):")
            for rps, ux, sig in self.worst:
                L.append(f"  - {rps:8.0f} rps  unexplained={ux:.2f}  {sig}")
        return "\n".join(L)


def scan(transitions: Iterable[Transition],
         residual_threshold: float = DEFAULT_RESIDUAL_THRESHOLD,
         top_k: int = 5) -> NoveltyReport:
    rep = NoveltyReport(residual_threshold=residual_threshold)
    flagged: list[tuple[float, float, str]] = []
    for t in transitions:
        rep.n_windows += 1
        ux = unexplained_loss(t.s2.defense)
        if ux is None:
            continue
        rep.n_judged += 1
        if ux >= residual_threshold:
            rep.n_novel += 1
            sig = signature(t.s2.defense)
            rep.vocabulary[sig] = rep.vocabulary.get(sig, 0) + 1
            flagged.append((float(t.action.rps), ux, sig))
    flagged.sort(key=lambda x: -x[1])
    rep.worst = flagged[:top_k]
    return rep


def scan_corpus(paths, residual_threshold: float = DEFAULT_RESIDUAL_THRESHOLD) -> NoveltyReport:
    if isinstance(paths, (str, Path)):
        paths = [paths]
    txs: list[Transition] = []
    for p in paths:
        txs.extend(iter_transitions(p))
    return scan(txs, residual_threshold)


def _main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--corpus", nargs="+", required=True,
                    help="one or more NDJSON corpus files to scan")
    ap.add_argument("--threshold", type=float, default=DEFAULT_RESIDUAL_THRESHOLD,
                    help="unexplained-loss threshold for flagging a window as novel")
    args = ap.parse_args(argv)
    print(scan_corpus(args.corpus, args.threshold).format_report())
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
