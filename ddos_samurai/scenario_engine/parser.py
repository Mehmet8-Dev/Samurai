from __future__ import annotations

import os
import re
from typing import Any

import yaml

from .compiler import scenario_spec_from_dict
from .schema import validate_with_json_schema
from .types import ScenarioSpec
from .validator import validate_raw_schema

_VAR_RE = re.compile(r"\$\{([^}]+)\}")


def _resolve_string_vars(text: str, variables: dict[str, str]) -> str:
    def _replace(match: re.Match[str]) -> str:
        key = str(match.group(1) or "").strip()
        if key.startswith("ENV:"):
            return str(os.getenv(key[4:], ""))
        return str(variables.get(key, match.group(0)))
    return _VAR_RE.sub(_replace, text)


def _resolve_vars(node: Any, variables: dict[str, str]) -> Any:
    if isinstance(node, str):
        return _resolve_string_vars(node, variables)
    if isinstance(node, list):
        return [_resolve_vars(x, variables) for x in node]
    if isinstance(node, dict):
        return {str(k): _resolve_vars(v, variables) for k, v in node.items()}
    return node


def load_raw_scenario(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    variables = {str(k): str(v) for k, v in dict((raw or {}).get("variables") or {}).items()}
    if variables:
        raw = _resolve_vars(raw, variables)
    validate_with_json_schema(raw)
    validate_raw_schema(raw)
    return dict(raw)


def load_scenario_spec(path: str) -> ScenarioSpec:
    raw = load_raw_scenario(path)
    return scenario_spec_from_dict(raw)
