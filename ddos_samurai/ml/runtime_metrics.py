from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict


@dataclass
class PlannerRuntimeMetrics:
    planner_load_ms: float = 0.0
    planner_generate_ms: float = 0.0
    planner_validate_ms: float = 0.0
    planner_timeout_hit: int = 0
    planner_fallback_used: int = 0
    planner_session_count: int = 0
    planner_event_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

