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
                                "body_template": {"type": "string"},
                                "flow": {"type": "string"},
                                "repeat": {"type": "integer", "minimum": 1},
                                "probability": {"type": "number", "minimum": 0, "maximum": 1},
                                "on_failure": {"type": "string", "enum": ["retry", "skip", "abort"]},
                                "conditions": {"type": "object"},
                                "think_time": {
                                    "type": "object",
                                    "properties": {
                                        "min_ms": {"type": "integer", "minimum": 0},
                                        "max_ms": {"type": "integer", "minimum": 0},
                                        "distribution": {"type": "string", "enum": ["uniform", "gaussian"]},
                                        "mean_ms": {"type": "integer", "minimum": 0},
                                        "stddev_ms": {"type": "integer", "minimum": 0},
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
                "per_flow": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "object",
                        "properties": {
                            "min_completion_rate": {"type": "number", "minimum": 0, "maximum": 1},
                            "max_step_fail_ratio": {"type": "number", "minimum": 0, "maximum": 1},
                            "max_latency_p95_ms": {"type": ["number", "null"], "minimum": 0},
                        },
                        "additionalProperties": True,
                    },
                },
            },
            "additionalProperties": True,
        },
    },
    "additionalProperties": True,
}

SCENARIO_SCHEMA_V2_PATCH: dict[str, Any] = {
    "type": "object",
    "properties": {
        "schema_version": {"type": "integer", "minimum": 1},
        "variables": {"type": "object", "additionalProperties": {"type": "string"}},
        "flows": {
            "type": "object",
            "additionalProperties": {
                "type": "object",
                "properties": {
                    "steps": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "extract": {"type": "object", "additionalProperties": {"type": "string"}},
                                "assertions": {"type": "array"},
                                "condition": {"type": "string"},
                            },
                            "additionalProperties": True,
                        },
                    },
                },
                "additionalProperties": True,
            },
        },
    },
    "additionalProperties": True,
}


def validate_with_json_schema(raw: dict[str, Any]) -> None:
    if jsonschema is None:
        return
    schema_version = int((raw or {}).get("schema_version", 1) or 1)
    if schema_version <= 1:
        jsonschema.validate(instance=raw, schema=SCENARIO_SCHEMA_V1)
        return
    merged = dict(SCENARIO_SCHEMA_V1)
    merged["properties"] = dict(SCENARIO_SCHEMA_V1.get("properties", {}))
    merged["properties"].update(dict(SCENARIO_SCHEMA_V2_PATCH.get("properties", {})))
    jsonschema.validate(instance=raw, schema=merged)
