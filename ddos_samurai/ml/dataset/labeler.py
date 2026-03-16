from __future__ import annotations

from typing import List

from .pcap_events import NormalizedWireEvent


def infer_label(events: List[NormalizedWireEvent]) -> str:
    retry_total = sum(int(max(0, ev.retry_count)) for ev in events)
    reset_total = sum(1 for ev in events if str(ev.event_type) in {"reset", "retry"})
    mutation_total = sum(1 for ev in events if str(ev.mutation_flags or "").strip())
    if retry_total >= 3 or reset_total >= 3:
        return "aggressive"
    if mutation_total >= 1:
        return "evasive"
    return "benign"

