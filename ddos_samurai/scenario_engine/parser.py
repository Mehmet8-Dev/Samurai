from __future__ import annotations

from typing import Any

import yaml

from .compiler import scenario_spec_from_dict
from .schema import validate_with_json_schema
from .types import ScenarioSpec
from .validator import validate_raw_schema


def load_raw_scenario(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    validate_with_json_schema(raw)
    validate_raw_schema(raw)
    return dict(raw)


def load_scenario_spec(path: str) -> ScenarioSpec:
    raw = load_raw_scenario(path)
    return scenario_spec_from_dict(raw)
