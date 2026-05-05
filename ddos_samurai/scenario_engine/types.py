from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TypeAlias

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]


class StepType(str, Enum):
    REQUEST = "request"
    PAUSE = "pause"
    BRANCH = "branch"
    LOOP = "loop"
    ASSERT = "assert"
    END_SESSION = "end_session"
    TCP_CONNECT = "tcp_connect"
    TCP_SEND = "tcp_send"
    TCP_EXPECT = "tcp_expect"
    TCP_CLOSE = "tcp_close"


class OnFailurePolicy(str, Enum):
    RETRY = "retry"
    SKIP = "skip"
    ABORT = "abort"


@dataclass(frozen=True)
class ThinkTimeSpec:
    min_ms: int = 0
    max_ms: int = 0
    distribution: str = "uniform"
    mean_ms: int = 0
    stddev_ms: int = 0


@dataclass(frozen=True)
class StepSpec:
    step_type: StepType
    method: str = "GET"
    path: str = "/"
    body_template: str = ""
    flow: str = ""
    repeat: int = 1
    probability: float = 1.0
    on_failure: OnFailurePolicy = OnFailurePolicy.RETRY
    conditions: JsonObject = field(default_factory=dict)
    dst_port: int = 0
    payload_template: str = ""
    condition: str = ""
    timeout_ms: int = 0
    think_time: ThinkTimeSpec = field(default_factory=ThinkTimeSpec)


@dataclass(frozen=True)
class PersonaSpec:
    name: str
    device_profile: str
    headers: dict[str, str]
    cookies: dict[str, str]
    retry_policy: JsonObject
    timeout_policy: JsonObject
    weight: float = 1.0


@dataclass(frozen=True)
class FlowSpec:
    name: str
    persona: str
    steps: list[StepSpec]


@dataclass(frozen=True)
class LoadModelSpec:
    concurrent_vus: int
    ramp_seconds: int
    max_session_seconds: int
    backend: str


@dataclass(frozen=True)
class SlaGateSpec:
    min_completion_rate: float
    max_step_fail_ratio: float
    max_latency_p95_ms: float | None = None
    per_flow: dict[str, dict[str, float | None]] = field(default_factory=dict)


@dataclass(frozen=True)
class ScenarioSpec:
    schema_version: int
    personas: dict[str, PersonaSpec]
    flows: dict[str, FlowSpec]
    load_model: LoadModelSpec
    sla: SlaGateSpec
