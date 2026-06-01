from __future__ import annotations

from typing import Any
from copy import deepcopy

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

SCENARIO_SCHEMA_V3_PATCH: dict[str, Any] = {
    "type": "object",
    "properties": {
        "schema_version": {"type": "integer", "minimum": 1},
        "personas": {
            "type": "object",
            "additionalProperties": {
                "type": "object",
                "properties": {
                    "tcp_mimicry": {
                        "type": "object",
                        "properties": {
                            "window": {"type": "integer", "minimum": 1},
                            "mss": {"type": "integer", "minimum": 1},
                            "ttl": {"type": "integer", "minimum": 1, "maximum": 255},
                        },
                        "additionalProperties": True,
                    }
                },
                "additionalProperties": True,
            },
        },
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
                                "dst_port": {"type": "integer", "minimum": 1, "maximum": 65535},
                                "payload_template": {"type": "string"},
                                "timeout_ms": {"type": "integer", "minimum": 1},
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
            "properties": {
                "backend": {"type": "string", "enum": ["http", "http2", "l4_tcp"]},
            },
            "additionalProperties": True,
        },
        "sla": {
            "type": "object",
            "properties": {
                "max_connect_timeout_ratio": {"type": "number", "minimum": 0, "maximum": 1},
                "max_retransmit_ratio": {"type": "number", "minimum": 0, "maximum": 1},
            },
            "additionalProperties": True,
        },
    },
    "allOf": [
        {
            "if": {
                "properties": {
                    "load_model": {
                        "type": "object",
                        "properties": {"backend": {"const": "l4_tcp"}},
                        "required": ["backend"],
                    }
                },
                "required": ["load_model"],
            },
            "then": {
                "properties": {
                    "personas": {
                        "type": "object",
                        "additionalProperties": {
                            "type": "object",
                            "required": ["tcp_mimicry"],
                        },
                    }
                },
                "required": ["personas"],
            },
        }
    ],
    "additionalProperties": True,
}


def validate_with_json_schema(raw: dict[str, Any]) -> None:
    if jsonschema is None:
        return
    schema_version = int((raw or {}).get("schema_version", 1) or 1)
    try:
        if schema_version <= 1:
            jsonschema.validate(instance=raw, schema=SCENARIO_SCHEMA_V1)
            return
        merged = dict(SCENARIO_SCHEMA_V1)
        merged["properties"] = dict(SCENARIO_SCHEMA_V1.get("properties", {}))
        merged["properties"].update(dict(SCENARIO_SCHEMA_V2_PATCH.get("properties", {})))
        if schema_version >= 3:
            merged["properties"].update(dict(SCENARIO_SCHEMA_V3_PATCH.get("properties", {})))
            merged_allof = list(merged.get("allOf", []) or [])
            merged_allof.extend(list(SCENARIO_SCHEMA_V3_PATCH.get("allOf", []) or []))
            if merged_allof:
                merged["allOf"] = merged_allof
        jsonschema.validate(instance=raw, schema=merged)
    except jsonschema.exceptions.ValidationError as exc:
        raise ValueError(f"Schema validation failed: {exc}") from exc


def migrate_schema(raw: dict[str, Any], *, target_version: int = 3) -> dict[str, Any]:
    obj = deepcopy(dict(raw or {}))
    cur = int(obj.get("schema_version", 1) or 1)
    tgt = max(1, int(target_version or 1))
    if cur >= tgt:
        return obj
    if cur < 2 <= tgt:
        flows = dict(obj.get("flows") or {})
        for _, flow in flows.items():
            steps = list((flow or {}).get("steps") or [])
            for step in steps:
                if not isinstance(step, dict):
                    continue
                st = str(step.get("type", "") or "").strip().lower()
                if st == "request" and "on_failure" not in step:
                    step["on_failure"] = "retry"
                if st in {"pause", "think_time"} and "think_time" in step:
                    tt = step.get("think_time")
                    if isinstance(tt, dict):
                        tt.setdefault("distribution", "uniform")
                        tt.setdefault("mean_ms", 0)
                        tt.setdefault("stddev_ms", 0)
        obj["schema_version"] = 2
        cur = 2
    if cur < 3 <= tgt:
        flows = dict(obj.get("flows") or {})
        personas = dict(obj.get("personas") or {})
        has_l4_steps = False
        for _, flow in flows.items():
            steps = list((flow or {}).get("steps") or [])
            for step in steps:
                if not isinstance(step, dict):
                    continue
                st = str(step.get("type", "") or "").strip().lower()
                if st in {"tcp_connect", "tcp_send", "tcp_expect", "tcp_close"}:
                    has_l4_steps = True
                    if st == "tcp_expect":
                        step["timeout_ms"] = max(1, int(step.get("timeout_ms", 1000) or 1000))
        lm = dict(obj.get("load_model") or {})
        backend = str(lm.get("backend", "http") or "http").strip().lower()
        if has_l4_steps and backend in {"http", "http2", ""}:
            lm["backend"] = "l4_tcp"
        elif backend == "":
            lm["backend"] = "http"
        if str(lm.get("backend", "http") or "http").strip().lower() == "l4_tcp":
            for _pname, _pdata in personas.items():
                if not isinstance(_pdata, dict):
                    continue
                tm = dict(_pdata.get("tcp_mimicry") or {})
                tm.setdefault("window", 64240)
                tm.setdefault("mss", 1460)
                tm.setdefault("ttl", 64)
                _pdata["tcp_mimicry"] = tm
            obj["personas"] = personas
        obj["load_model"] = lm
        obj["schema_version"] = 3
    return obj
