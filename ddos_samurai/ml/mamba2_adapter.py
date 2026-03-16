from __future__ import annotations

import random
import uuid
from dataclasses import dataclass
from typing import Optional

from .fallback_profiles import generate_deterministic_plan
from .types import PlanRequest, TrafficPlan


@dataclass
class Mamba2Adapter:
    checkpoint_path: str
    device: str = "cpu"
    loaded: bool = False

    @classmethod
    def load(cls, checkpoint_path: str, device: str = "cpu") -> "Mamba2Adapter":
        adapter = cls(checkpoint_path=str(checkpoint_path), device=str(device), loaded=True)
        return adapter

    def generate(self, request: PlanRequest) -> TrafficPlan:
        # v1 adapter fallback implementation: deterministic synthetic generation.
        # Real Mamba-2 inference can replace this body without changing planner API.
        seed = int(request.seed)
        ckpt = str(self.checkpoint_path or "none")
        _ = random.Random(seed ^ hash(ckpt))
        plan = generate_deterministic_plan(
            request,
            model_name="mamba2",
            checkpoint_id=ckpt,
        )
        return TrafficPlan(
            plan_id=f"m2-{uuid.uuid4().hex[:12]}",
            model_name="mamba2",
            checkpoint_id=ckpt,
            seed=plan.seed,
            session_plans=plan.session_plans,
        )

