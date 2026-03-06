from __future__ import annotations

from . import policy
from .types import L7RouteDecision, L7RouteRequest

_C_ENGINE_PATHS = {
    "http1": "C_STATE_HTTP1",
    "ws": "C_STATE_WS",
    "http2": "C_STATE_H2",
    "quic": "C_STATE_QUIC",
}

_PY_ENGINE_PATHS = {
    "http1": "PY_HTTP1",
    "ws": "PY_WS",
    "http2": "PY_HTTP2",
    "quic": "PY_QUIC",
}


def resolve_protocol_engine(*, protocol: str, l7_engine: str, protocol_engine: str) -> str:
    proto = str(protocol or "").strip().lower()
    global_engine = policy.normalize_engine(l7_engine, allow_auto=False, default="python")

    if proto in {"http1", "ws"}:
        return global_engine

    requested = policy.normalize_engine(protocol_engine, allow_auto=True, default="auto")
    if requested == "auto":
        # V2 default prefers C dataplane; policy decides whether Python fallback is allowed.
        return "c_state"
    return requested


def build_route_decision(req: L7RouteRequest) -> L7RouteDecision:
    protocol_name = str(req.protocol or "").strip().lower()
    fallback_policy = policy.normalize_fallback_policy(req.fallback_policy)
    strict = policy.resolve_capability_strict(
        capability_strict=bool(req.capability_strict),
        lab_profile=req.lab_profile,
    )
    engine = resolve_protocol_engine(
        protocol=protocol_name,
        l7_engine=req.l7_engine,
        protocol_engine=req.protocol_engine,
    )

    # http1/ws fallback uses explicit legacy gate; http2/quic fallback policy is global.
    if protocol_name in {"http1", "ws"}:
        allow_fallback = policy.allow_python_fallback(
            fallback_policy=fallback_policy,
            capability_strict=strict,
            legacy_path_enable=bool(req.legacy_path_enable),
        )
    else:
        allow_fallback = policy.allow_python_fallback(
            fallback_policy=fallback_policy,
            capability_strict=strict,
            legacy_path_enable=True,
        )

    path_map = _C_ENGINE_PATHS if engine == "c_state" else _PY_ENGINE_PATHS
    return L7RouteDecision(
        protocol=protocol_name,
        engine=engine,
        fallback_policy=fallback_policy,
        capability_strict=bool(strict),
        allow_python_fallback=bool(allow_fallback),
        legacy_path_enable=bool(req.legacy_path_enable),
        l7_engine_path_used=str(path_map.get(protocol_name, "PY_UNKNOWN")),
    )

