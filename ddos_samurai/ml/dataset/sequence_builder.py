from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from .pcap_events import NormalizedWireEvent


def events_to_sessions(events: List[NormalizedWireEvent]) -> Dict[str, List[NormalizedWireEvent]]:
    grouped: Dict[str, List[NormalizedWireEvent]] = defaultdict(list)
    for ev in events:
        grouped[str(ev.session_id)].append(ev)
    for sid in list(grouped.keys()):
        grouped[sid] = sorted(grouped[sid], key=lambda e: int(e.event_index))
    return dict(grouped)

