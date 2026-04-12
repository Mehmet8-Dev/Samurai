from __future__ import annotations

from typing import Any


_ALIASES = {
    "custom_native": "custom_native",
    "native_custom": "custom_native",
    "h3": "custom_native",
    "h3_native": "custom_native",
    "native_h3": "custom_native",
    "h3_stateful_native": "custom_native",
    "h3_py": "h3_stateful_py",
    "h3_bridge": "h3_stateful_py",
    "py_bridge": "h3_stateful_py",
    "h3_stateful_bridge": "h3_stateful_py",
    "probe": "probe_udp",
    "udp_probe": "probe_udp",
    # Backward compatibility: old native mode aliases map to new canonical mode.
    "h3_stateful": "custom_native",
    "h3_native_stateful": "custom_native",
}

_KNOWN = {"custom_native", "h3_stateful_py", "probe_udp", "unavailable"}


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
    return normalized in {"custom_native", "h3_stateful_py"}


def is_native_h3_stateful(mode: Any) -> bool:
    return normalize(mode) == "custom_native"


def is_bridge_h3_stateful(mode: Any) -> bool:
    return normalize(mode) == "h3_stateful_py"
