from __future__ import annotations

from typing import Any


_ALIASES = {
    "h3": "h3_stateful",
    "h3_native": "h3_stateful",
    "native_h3": "h3_stateful",
    "h3_stateful_native": "h3_stateful",
    "h3_py": "h3_stateful_py",
    "h3_bridge": "h3_stateful_py",
    "py_bridge": "h3_stateful_py",
    "h3_stateful_bridge": "h3_stateful_py",
    "probe": "probe_udp",
    "udp_probe": "probe_udp",
}

_KNOWN = {"h3_stateful", "h3_stateful_py", "probe_udp", "unavailable"}


def normalize(value: Any) -> str:
    raw = str(value or "unavailable").strip().lower()
    if not raw:
        return "unavailable"
    mode = _ALIASES.get(raw, raw)
    if mode in _KNOWN:
        return mode
    return "unavailable"


def is_h3_stateful(mode: Any) -> bool:
    normalized = normalize(mode)
    return normalized in {"h3_stateful", "h3_stateful_py"}


def is_native_h3_stateful(mode: Any) -> bool:
    return normalize(mode) == "h3_stateful"


def is_bridge_h3_stateful(mode: Any) -> bool:
    return normalize(mode) == "h3_stateful_py"
