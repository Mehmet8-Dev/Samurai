from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List


@dataclass(frozen=True)
class NormalizedWireEvent:
    trace_id: str
    session_id: str
    event_index: int
    timestamp_rel_ms: int
    protocol: str
    event_type: str
    label: str
    src_role: str
    method: str
    path: str
    status_class: str
    payload_class: str
    header_profile: str
    mutation_flags: str
    tls_profile: str
    h2_profile: str
    quic_mode: str
    response_time_bucket: str
    retry_count: int
    close_reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def pcap_to_normalized_events(_pcap_path: str, _protocol_profile: str = "") -> List[NormalizedWireEvent]:
    # v1 placeholder extractor intentionally conservative.
    # Full PCAP reconstruction is expected to be implemented incrementally.
    return []

