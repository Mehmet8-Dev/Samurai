"""Corpus I/O — isolated so the rest of the pipeline never touches the filesystem.

The corpus is append-only NDJSON emitted by ``samurai_master --rl-corpus``: one
JSON object per closed-loop window (see ``Transition``). Keeping read/parse here
means features/reward/dataset stay pure functions over ``Transition`` objects and
are trivially unit-testable with hand-built records.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path

from .schemas import Transition


def iter_transitions(path: str | Path) -> Iterator[Transition]:
    """Yield every well-formed transition in one NDJSON corpus file.

    Blank lines and lines that fail to parse are skipped rather than aborting the
    read — a truncated final line (crash mid-flush) must not poison a whole corpus.
    """
    p = Path(path)
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield Transition.from_json(obj)


def load_transitions(paths: str | Path | Iterable[str | Path]) -> list[Transition]:
    """Load one or many corpus files into a flat, order-preserving list."""
    if isinstance(paths, (str, Path)):
        paths = [paths]
    out: list[Transition] = []
    for p in paths:
        out.extend(iter_transitions(p))
    return out


def group_episodes(transitions: Iterable[Transition]) -> dict[str, list[Transition]]:
    """Group transitions by run_id, preserving per-episode window order.

    Off-policy evaluation and any return/advantage computation are per-episode, so
    the dataset must be able to reconstruct trajectories from a flat corpus.
    """
    episodes: dict[str, list[Transition]] = {}
    for t in transitions:
        episodes.setdefault(t.run_id, []).append(t)
    for eps in episodes.values():
        eps.sort(key=lambda t: t.win)
    return episodes
