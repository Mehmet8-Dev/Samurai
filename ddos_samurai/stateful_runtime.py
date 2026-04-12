from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from .l7_emu import run_l7_profile as _run_l7_profile
from .l7_emu.types import L7EmuProfile, RunResult, RuntimeConfig


def _normalize_runtime_backend(value: Any) -> str:
    backend = str(value or "afxdp").strip().lower()
    if backend not in {"afxdp", "dpdk"}:
        return "afxdp"
    return backend


@dataclass(frozen=True)
class StatefulRuntimeSessionConfig:
    concurrency: int = 1
    stateful_runtime_backend: str = "afxdp"
    stateful_runtime_strict: bool = False
    legacy_mode: bool = False
    live_progress: bool = False
    live_sent: bool = False
    live_errors: bool = False
    profile_l7: bool = False
    profile_sample_limit: int = 0

    def to_runtime_config(self) -> RuntimeConfig:
        return RuntimeConfig(
            concurrency=max(1, int(self.concurrency or 1)),
            stateful_runtime_backend=_normalize_runtime_backend(self.stateful_runtime_backend),
            stateful_runtime_strict=bool(self.stateful_runtime_strict),
            legacy_mode=bool(self.legacy_mode),
            live_progress=bool(self.live_progress),
            live_sent=bool(self.live_sent),
            live_errors=bool(self.live_errors),
            profile_l7=bool(self.profile_l7),
            profile_sample_limit=max(0, int(self.profile_sample_limit or 0)),
        )


class StatefulRuntimeSession:
    def __init__(self, config: StatefulRuntimeSessionConfig):
        self._config = config
        self._profile: Optional[L7EmuProfile] = None
        self._last_result: Dict[str, Any] = {}
        self._closed = False

    def load_profile(self, compiled_profile: L7EmuProfile) -> None:
        if self._closed:
            raise RuntimeError("stateful runtime session is closed")
        self._profile = compiled_profile

    async def run(self) -> RunResult:
        if self._closed:
            raise RuntimeError("stateful runtime session is closed")
        if self._profile is None:
            raise RuntimeError("stateful runtime session requires a loaded profile")
        result = await _run_l7_profile(self._profile, self._config.to_runtime_config())
        self._last_result = dict(result.as_dict())
        return result

    def snapshot(self) -> Dict[str, Any]:
        profile = self._profile
        conn = getattr(profile, "connection_template", None)
        runtime_backend = _normalize_runtime_backend(
            self._config.stateful_runtime_backend or getattr(conn, "stateful_runtime_backend", "afxdp")
        )
        transport_backend = str(getattr(conn, "transport_backend", "kernel_socket") or "kernel_socket")
        legacy_mode = bool(self._config.legacy_mode)
        runtime_hot_path_level = "phase1_hybrid_afxdp"
        if runtime_backend == "afxdp":
            runtime_hot_path_level = "phase1_hybrid_afxdp"
        elif runtime_backend == "dpdk":
            runtime_hot_path_level = "phase1_stub_dpdk"
        if transport_backend == "custom_tcp":
            runtime_hot_path_level = f"{runtime_hot_path_level}_custom_tcp"
        return {
            "runtime_backend": runtime_backend,
            "stateful_runtime_backend": runtime_backend,
            "runtime_hot_path_level": runtime_hot_path_level,
            "legacy_path_used": int(legacy_mode),
            "runtime_transport_backend": transport_backend,
            "runtime_session_open": int(not self._closed),
            "runtime_profile_loaded": int(profile is not None),
        }

    def close(self) -> None:
        self._closed = True


def open_session(config: StatefulRuntimeSessionConfig | Dict[str, Any] | None = None) -> StatefulRuntimeSession:
    if isinstance(config, StatefulRuntimeSessionConfig):
        session_config = config
    else:
        raw = dict(config or {})
        session_config = StatefulRuntimeSessionConfig(
            concurrency=max(1, int(raw.get("concurrency", 1) or 1)),
            stateful_runtime_backend=_normalize_runtime_backend(raw.get("stateful_runtime_backend", "afxdp")),
            stateful_runtime_strict=bool(raw.get("stateful_runtime_strict", False)),
            legacy_mode=bool(raw.get("legacy_mode", False)),
            live_progress=bool(raw.get("live_progress", False)),
            live_sent=bool(raw.get("live_sent", False)),
            live_errors=bool(raw.get("live_errors", False)),
            profile_l7=bool(raw.get("profile_l7", False)),
            profile_sample_limit=max(0, int(raw.get("profile_sample_limit", 0) or 0)),
        )
    return StatefulRuntimeSession(session_config)


@dataclass(frozen=True)
class HotPathContractResult:
    status: str
    violation_reason: str
    sender_path_single_required: int
    sender_fallback_reason: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "hot_path_contract_status": str(self.status or "failed"),
            "hot_path_contract_violation_reason": str(self.violation_reason or "unknown"),
            "sender_path_single_required": int(self.sender_path_single_required),
            "sender_fallback_reason": str(self.sender_fallback_reason or "none"),
        }


def evaluate_hot_path_contract(
    *,
    attack_vector: str,
    sender_path: str,
    sender_fallback_reason: str,
    fallback_count: int = 0,
    runtime_transport_backend: str = "",
    custom_tcp_bridge_backend_used: str = "",
) -> HotPathContractResult:
    vec = str(attack_vector or "basic").strip().lower()
    path = str(sender_path or "").strip().upper()
    fallback_reason = str(sender_fallback_reason or "none").strip().lower() or "none"
    fallback_count_i = int(fallback_count or 0)
    rt_backend = str(runtime_transport_backend or "").strip().lower()
    bridge_backend = str(custom_tcp_bridge_backend_used or "").strip().lower()

    if path == "MIXED":
        return HotPathContractResult("failed", "sender_path_mixed_forbidden", 1, fallback_reason)
    if fallback_reason not in {"none", ""} or fallback_count_i > 0:
        return HotPathContractResult("failed", "sender_fallback_forbidden", 1, fallback_reason or "unknown")

    is_l7 = vec in {"http", "http2", "quic", "websocket", "slowloris", "slow-post", "slow-read"}
    if is_l7:
        if rt_backend != "custom_tcp":
            return HotPathContractResult("failed", "l7_runtime_transport_must_be_custom_tcp", 1, "none")
        if bridge_backend and bridge_backend != "xdp":
            return HotPathContractResult("failed", "l7_custom_tcp_bridge_backend_must_be_xdp", 1, "none")
        return HotPathContractResult("passed", "none", 1, "none")

    if path and path != "DP_TX_RING":
        return HotPathContractResult("failed", "l4_sender_path_must_be_dp_tx_ring", 1, "none")
    return HotPathContractResult("passed", "none", 1, "none")
