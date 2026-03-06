from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass(frozen=True)
class L7RouteRequest:
    protocol: str
    l7_engine: str = "python"
    protocol_engine: str = "auto"
    fallback_policy: str = "allow"
    capability_strict: bool = False
    legacy_path_enable: bool = False
    lab_profile: str = "off"


@dataclass(frozen=True)
class L7RouteDecision:
    protocol: str
    engine: str
    fallback_policy: str
    capability_strict: bool
    allow_python_fallback: bool
    legacy_path_enable: bool
    l7_engine_path_used: str

    def as_stats(self) -> Dict[str, Any]:
        return {
            "l7_engine_path_used": str(self.l7_engine_path_used),
            "sender_fallback_policy": str(self.fallback_policy),
            "l7_capability_strict": int(bool(self.capability_strict)),
        }


@dataclass
class L7NormalizedResult:
    attempted: int = 0
    sent: int = 0
    errors: int = 0
    sender_path: str = ""
    sender_fallback_reason: str = "none"
    l7_engine_path_used: str = ""
    l7_fallback_reason: str = "none"
    extra: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        out = {
            "attempted": int(self.attempted),
            "sent": int(self.sent),
            "errors": int(self.errors),
            "sender_path": str(self.sender_path or ""),
            "sender_fallback_reason": str(self.sender_fallback_reason or "none"),
            "l7_engine_path_used": str(self.l7_engine_path_used or ""),
            "l7_fallback_reason": str(self.l7_fallback_reason or "none"),
        }
        for k, v in dict(self.extra or {}).items():
            if isinstance(v, bool):
                out[str(k)] = int(v)
            elif isinstance(v, (int, float, str)):
                out[str(k)] = v
        return out

