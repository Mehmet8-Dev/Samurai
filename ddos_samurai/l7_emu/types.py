from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class FlowOpcode(str, Enum):
    CONNECT = "CONNECT"
    SEND_HEADERS = "SEND_HEADERS"
    SEND_BODY = "SEND_BODY"
    EXPECT_STATUS = "EXPECT_STATUS"
    EXPECT_HEADER = "EXPECT_HEADER"
    EXPECT_BODY_SUBSTRING = "EXPECT_BODY_SUBSTRING"
    CAPTURE_HEADER = "CAPTURE_HEADER"
    CAPTURE_COOKIE = "CAPTURE_COOKIE"
    THINK_TIME = "THINK_TIME"
    LOOP = "LOOP"
    CLOSE = "CLOSE"


@dataclass(frozen=True)
class Expectation:
    kind: str
    name: str = ""
    value: str = ""
    status_min: int = 0
    status_max: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": str(self.kind),
            "name": str(self.name),
            "value": str(self.value),
            "status_min": int(self.status_min),
            "status_max": int(self.status_max),
        }


@dataclass(frozen=True)
class FlowOp:
    opcode: FlowOpcode
    method: str = ""
    path: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    expect: Optional[Expectation] = None
    capture_name: str = ""
    capture_source: str = ""
    think_time_ms: int = 0
    loop_count: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "opcode": str(self.opcode.value),
            "method": str(self.method),
            "path": str(self.path),
            "headers": dict(self.headers),
            "body": bytes(self.body or b""),
            "expect": None if self.expect is None else self.expect.as_dict(),
            "capture_name": str(self.capture_name),
            "capture_source": str(self.capture_source),
            "think_time_ms": int(self.think_time_ms),
            "loop_count": int(self.loop_count),
        }


@dataclass(frozen=True)
class FlowProgram:
    ops: List[FlowOp]

    def as_dict(self) -> Dict[str, Any]:
        return {"ops": [op.as_dict() for op in self.ops]}


@dataclass(frozen=True)
class ConnectionTemplate:
    protocol: str
    target_ip: str
    target_port: int
    scheme: str
    host_header: str
    transport_backend: str = "kernel_socket"
    stateful_runtime_backend: str = "afxdp"
    stateful_runtime_strict: bool = False
    legacy_mode: bool = False
    verify: bool = True
    tls_profile_name: str = "none"
    max_connections: int = 1
    max_streams_per_connection: int = 1
    session_repeats: int = 1
    keepalive: bool = True
    timeout_ms: int = 5000

    def as_dict(self) -> Dict[str, Any]:
        return {
            "protocol": str(self.protocol),
            "target_ip": str(self.target_ip),
            "target_port": int(self.target_port),
            "scheme": str(self.scheme),
            "host_header": str(self.host_header),
            "transport_backend": str(self.transport_backend),
            "stateful_runtime_backend": str(self.stateful_runtime_backend),
            "stateful_runtime_strict": int(bool(self.stateful_runtime_strict)),
            "legacy_mode": int(bool(self.legacy_mode)),
            "verify": int(bool(self.verify)),
            "tls_profile_name": str(self.tls_profile_name),
            "max_connections": int(self.max_connections),
            "max_streams_per_connection": int(self.max_streams_per_connection),
            "session_repeats": int(self.session_repeats),
            "keepalive": int(bool(self.keepalive)),
            "timeout_ms": int(self.timeout_ms),
        }


@dataclass(frozen=True)
class L7EmuProfile:
    protocol: str
    sender_path: str
    template_mode: str
    compat_mode: str
    flow_attempted: int
    flow_program: FlowProgram
    connection_template: ConnectionTemplate

    def as_dict(self) -> Dict[str, Any]:
        return {
            "protocol": str(self.protocol),
            "sender_path": str(self.sender_path),
            "template_mode": str(self.template_mode),
            "compat_mode": str(self.compat_mode),
            "flow_attempted": int(self.flow_attempted),
            "flow_program": self.flow_program.as_dict(),
            "connection_template": self.connection_template.as_dict(),
        }


@dataclass(frozen=True)
class RuntimeConfig:
    concurrency: int
    stateful_runtime_backend: str = "afxdp"
    stateful_runtime_strict: bool = False
    legacy_mode: bool = False
    live_progress: bool = False
    live_sent: bool = False
    live_errors: bool = False
    profile_l7: bool = False
    profile_sample_limit: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "concurrency": int(self.concurrency),
            "stateful_runtime_backend": str(self.stateful_runtime_backend),
            "stateful_runtime_strict": int(bool(self.stateful_runtime_strict)),
            "legacy_mode": int(bool(self.legacy_mode)),
            "live_progress": int(bool(self.live_progress)),
            "live_sent": int(bool(self.live_sent)),
            "live_errors": int(bool(self.live_errors)),
            "profile_l7": int(bool(self.profile_l7)),
            "profile_sample_limit": int(self.profile_sample_limit),
        }


@dataclass(frozen=True)
class RunResult:
    stats: Dict[str, Any]

    def as_dict(self) -> Dict[str, Any]:
        return dict(self.stats)
