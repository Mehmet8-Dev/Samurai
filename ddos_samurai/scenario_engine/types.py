from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ThinkTimeSpec:
    min_ms: int = 0
    max_ms: int = 0


@dataclass(frozen=True)
class StepSpec:
    step_type: str
    method: str = "GET"
    path: str = "/"
    flow: str = ""
    repeat: int = 1
    probability: float = 1.0
    conditions: dict[str, Any] = field(default_factory=dict)
    think_time: ThinkTimeSpec = field(default_factory=ThinkTimeSpec)


@dataclass(frozen=True)
class PersonaSpec:
    name: str
    device_profile: str
    headers: dict[str, str]
    cookies: dict[str, str]
    retry_policy: dict[str, Any]
    timeout_policy: dict[str, Any]
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


@dataclass(frozen=True)
class ScenarioSpec:
    schema_version: int
    personas: dict[str, PersonaSpec]
    flows: dict[str, FlowSpec]
    load_model: LoadModelSpec
    sla: SlaGateSpec
