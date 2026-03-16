from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from .types import SessionEvent
from .vocab import Vocab


@dataclass
class FeatureCodec:
    event_vocab: Vocab
    method_vocab: Vocab

    @classmethod
    def default(cls) -> "FeatureCodec":
        return cls(
            event_vocab=Vocab.build(
                [
                    "connect_open",
                    "tls_client_hello",
                    "http_request",
                    "http2_headers",
                    "ws_open",
                    "ws_frame",
                    "quic_open",
                    "quic_request",
                    "idle_wait",
                    "retry",
                    "reset",
                    "close",
                ]
            ),
            method_vocab=Vocab.build(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]),
        )

    def encode_event(self, event: SessionEvent) -> Dict[str, int]:
        return {
            "step_index": int(event.step_index),
            "event_type_id": int(self.event_vocab.encode(event.event_type)),
            "delay_ms": int(max(0, event.delay_ms)),
            "method_id": int(self.method_vocab.encode((event.method or "").upper(), default=-1)),
            "mutation_count": int(len(event.mutation_flags)),
        }

    def decode_event(self, payload: Dict[str, int]) -> SessionEvent:
        method_id = int(payload.get("method_id", -1))
        method = None if method_id < 0 else self.method_vocab.decode(method_id)
        return SessionEvent(
            step_index=int(payload.get("step_index", 0)),
            event_type=self.event_vocab.decode(int(payload.get("event_type_id", -1))),
            delay_ms=int(payload.get("delay_ms", 0)),
            method=method,
            mutation_flags=["mut"] * int(max(0, payload.get("mutation_count", 0))),
        )

    def encode_events(self, events: List[SessionEvent]) -> List[Dict[str, int]]:
        return [self.encode_event(ev) for ev in events]

    def decode_events(self, payloads: List[Dict[str, int]]) -> List[SessionEvent]:
        return [self.decode_event(p) for p in payloads]

