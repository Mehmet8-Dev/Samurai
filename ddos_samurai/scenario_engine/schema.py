from __future__ import annotations

from typing import Any

try:
    import jsonschema  # type: ignore
except Exception:  # pragma: no cover
    jsonschema = None


SCENARIO_SCHEMA_V1: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["schema_version", "personas", "flows", "load_model", "sla"],
    "properties": {
        "schema_version": {"type": "integer", "minimum": 1},
        "personas": {
            "type": "object",
            "minProperties": 1,
            "additionalProperties": {
                "type": "object",
                "required": ["device_profile", "headers", "cookies", "retry_policy", "timeout_policy"],
                "properties": {
                    "device_profile": {"type": "string"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                    "cookies": {"type": "object", "additionalProperties": {"type": "string"}},
                    "retry_policy": {"type": "object"},
                    "timeout_policy": {"type": "object"},
                    "weight": {"type": "number", "exclusiveMinimum": 0},
                },
                "additionalProperties": True,
            },
        },
        "flows": {
            "type": "object",
            "minProperties": 1,
            "additionalProperties": {
                "type": "object",
                "required": ["persona", "steps"],
                "properties": {
                    "persona": {"type": "string"},
                    "steps": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "type": "object",
                            "required": ["type"],
                            "properties": {
                                "type": {"type": "string"},
                                "method": {"type": "string"},
                                "path": {"type": "string"},
                                "flow": {"type": "string"},
                                "repeat": {"type": "integer", "minimum": 1},
                                "probability": {"type": "number", "minimum": 0, "maximum": 1},
                                "conditions": {"type": "object"},
                                "think_time": {
                                    "type": "object",
                                    "properties": {
                                        "min_ms": {"type": "integer", "minimum": 0},
                                        "max_ms": {"type": "integer", "minimum": 0},
                                    },
                                    "additionalProperties": True,
                                },
                            },
                            "additionalProperties": True,
                        },
                    },
                },
                "additionalProperties": True,
            },
        },
        "load_model": {
            "type": "object",
            "required": ["concurrent_vus", "ramp_seconds", "max_session_seconds", "backend"],
            "properties": {
                "concurrent_vus": {"type": "integer", "minimum": 1},
                "ramp_seconds": {"type": "integer", "minimum": 0},
                "max_session_seconds": {"type": "integer", "minimum": 1},
                "backend": {"type": "string", "enum": ["http", "http2"]},
            },
            "additionalProperties": True,
        },
        "sla": {
            "type": "object",
            "required": ["min_completion_rate", "max_step_fail_ratio"],
            "properties": {
                "min_completion_rate": {"type": "number", "minimum": 0, "maximum": 1},
                "max_step_fail_ratio": {"type": "number", "minimum": 0, "maximum": 1},
                "max_latency_p95_ms": {"type": ["number", "null"], "minimum": 0},
            },
            "additionalProperties": True,
        },
    },
    "additionalProperties": True,
}


def validate_with_json_schema(raw: dict[str, Any]) -> None:
    if jsonschema is None:
        return
    jsonschema.validate(instance=raw, schema=SCENARIO_SCHEMA_V1)
