from __future__ import annotations

from typing import Any, Dict


def normalize_vector_spec(spec: Dict[str, Any] | None) -> Dict[str, Any]:
    raw = dict(spec or {})
    mode = str(raw.get("mode", "program") or "program").strip().lower()
    if mode not in {"program", "pcap", "mixed"}:
        raise ValueError("mode must be one of: program|pcap|mixed")
    methods = [str(x or "").strip() for x in list(raw.get("methods") or ["GET"]) if str(x or "").strip()]
    paths = [str(x or "").strip() for x in list(raw.get("paths") or ["/"]) if str(x or "").strip()]
    header_profiles = [
        str(x or "").strip() for x in list(raw.get("header_profiles") or ["default"]) if str(x or "").strip()
    ]
    body_profiles = [
        str(x or "").strip() for x in list(raw.get("body_profiles") or ["none"]) if str(x or "").strip()
    ]
    max_steps = int(raw.get("max_steps", 4) or 4)
    if max_steps <= 0:
        raise ValueError("max_steps must be > 0")
    return {
        "mode": mode,
        "methods": methods,
        "paths": paths,
        "header_profiles": header_profiles,
        "body_profiles": body_profiles,
        "max_steps": max_steps,
    }

