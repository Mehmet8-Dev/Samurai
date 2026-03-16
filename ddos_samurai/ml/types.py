from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Literal, Optional

SUPPORTED_PROTOCOLS = {"http1", "http2", "websocket", "quic"}
SUPPORTED_LABELS = {"benign", "evasive", "aggressive"}
SUPPORTED_EVENT_TYPES = {
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
}


@dataclass(frozen=True)
class SessionEvent:
    step_index: int
    event_type: str
    delay_ms: int = 0
    method: Optional[str] = None
    path: Optional[str] = None
    header_profile: Optional[str] = None
    payload_class: Optional[str] = None
    mutation_flags: List[str] = field(default_factory=list)
    expect_response_class: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionEvent":
        return cls(
            step_index=int(data.get("step_index", 0)),
            event_type=str(data.get("event_type", "")),
            delay_ms=int(data.get("delay_ms", 0)),
            method=(str(data["method"]) if data.get("method") is not None else None),
            path=(str(data["path"]) if data.get("path") is not None else None),
            header_profile=(
                str(data["header_profile"]) if data.get("header_profile") is not None else None
            ),
            payload_class=(str(data["payload_class"]) if data.get("payload_class") is not None else None),
            mutation_flags=[str(x) for x in list(data.get("mutation_flags", []) or [])],
            expect_response_class=(
                str(data["expect_response_class"])
                if data.get("expect_response_class") is not None
                else None
            ),
        )


@dataclass(frozen=True)
class SessionPlan:
    session_id: str
    protocol: Literal["http1", "http2", "websocket", "quic"]
    label: Literal["benign", "evasive", "aggressive"]
    events: List[SessionEvent]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "protocol": self.protocol,
            "label": self.label,
            "events": [ev.to_dict() for ev in self.events],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionPlan":
        return cls(
            session_id=str(data.get("session_id", "")),
            protocol=str(data.get("protocol", "http1")),  # type: ignore[arg-type]
            label=str(data.get("label", "benign")),  # type: ignore[arg-type]
            events=[SessionEvent.from_dict(ev) for ev in list(data.get("events", []) or [])],
        )


@dataclass(frozen=True)
class TrafficPlan:
    plan_id: str
    model_name: str
    checkpoint_id: str
    seed: int
    session_plans: List[SessionPlan]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "model_name": self.model_name,
            "checkpoint_id": self.checkpoint_id,
            "seed": int(self.seed),
            "session_plans": [sp.to_dict() for sp in self.session_plans],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TrafficPlan":
        return cls(
            plan_id=str(data.get("plan_id", "")),
            model_name=str(data.get("model_name", "")),
            checkpoint_id=str(data.get("checkpoint_id", "")),
            seed=int(data.get("seed", 0)),
            session_plans=[SessionPlan.from_dict(sp) for sp in list(data.get("session_plans", []) or [])],
        )


@dataclass(frozen=True)
class PlanRequest:
    session_count: int
    session_len: int
    seed: int
    protocols: List[str]
    label_mix: Dict[str, float] = field(default_factory=dict)

