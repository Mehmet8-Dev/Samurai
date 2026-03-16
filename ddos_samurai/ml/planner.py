from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Dict

from .mamba2_adapter import Mamba2Adapter
from .types import PlanRequest, TrafficPlan


class PlannerError(RuntimeError):
    pass


@dataclass
class MambaPlanner:
    adapter: Mamba2Adapter
    device: str = "cpu"

    @classmethod
    def load(cls, checkpoint_path: str, device: str = "cpu") -> "MambaPlanner":
        dev = str(device or "cpu").strip().lower()
        if dev != "cpu":
            raise PlannerError(f"v1 only supports device=cpu, got: {device}")
        ckpt = str(checkpoint_path or "").strip()
        if not ckpt:
            raise PlannerError("checkpoint_path is required")
        if not os.path.exists(ckpt):
            raise PlannerError(f"checkpoint file not found: {ckpt}")
        adapter = Mamba2Adapter.load(checkpoint_path=ckpt, device=dev)
        return cls(adapter=adapter, device=dev)

    def generate(self, plan_request: PlanRequest) -> TrafficPlan:
        t0 = time.perf_counter()
        plan = self.adapter.generate(plan_request)
        if not plan.session_plans:
            raise PlannerError("planner emitted empty plan")
        _ = time.perf_counter() - t0
        return plan

