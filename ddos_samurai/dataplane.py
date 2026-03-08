from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

try:
    from . import dataplane_core as _dp_core
except Exception:
    _dp_core = None


@dataclass
class DataplaneConfig:
    backend: str = "auto"
    fallback_policy: str = "allow"
    core_mode: str = "off"
    lab_profile: str = "off"
    queue_strategy: str = "rr"
    queue_id: int = 0
    interface: str = ""
    xdp_enable: bool = False
    afpacket_hugepage_mode: str = "off"
    afpacket_hugepage_size_kb: int = 2048
    afpacket_ring_target_mb: int = 64
    afpacket_mlock_ring: bool = False
    afpacket_prefault_ring: bool = True
    use_core: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        out = {
            "backend": str(self.backend or "auto"),
            "fallback_policy": str(self.fallback_policy or "allow"),
            "core_mode": str(self.core_mode or "off"),
            "lab_profile": str(self.lab_profile or "off"),
            "queue_strategy": str(self.queue_strategy or "rr"),
            "queue_id": int(self.queue_id or 0),
            "interface": str(self.interface or ""),
            "xdp_enable": bool(self.xdp_enable),
            "afpacket_hugepage_mode": str(self.afpacket_hugepage_mode or "off"),
            "afpacket_hugepage_size_kb": int(self.afpacket_hugepage_size_kb or 2048),
            "afpacket_ring_target_mb": int(self.afpacket_ring_target_mb or 64),
            "afpacket_mlock_ring": bool(self.afpacket_mlock_ring),
            "afpacket_prefault_ring": bool(self.afpacket_prefault_ring),
            "use_core": bool(self.use_core),
        }
        if self.extra:
            out["extra"] = dict(self.extra)
        return out


@dataclass
class DataplaneResult:
    attempted: int = 0
    sent: int = 0
    errors: int = 0
    bytes_sent_est: int = 0
    sender_path: str = ""
    sender_fallback_reason: str = "none"
    fallback_count: int = 0
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_stats(self) -> Dict[str, Any]:
        stats = {
            "attempted": int(self.attempted),
            "sent": int(self.sent),
            "errors": int(self.errors),
            "bytes_sent_est": int(self.bytes_sent_est),
            "sender_path": str(self.sender_path or ""),
            "sender_fallback_reason": str(self.sender_fallback_reason or "none"),
            "fallback_count": int(self.fallback_count or 0),
        }
        for k, v in dict(self.meta or {}).items():
            if isinstance(v, bool):
                stats[str(k)] = int(v)
            elif isinstance(v, (int, float, str)):
                stats[str(k)] = v
        return stats


class DataplaneSession:
    """Thin Python adapter for in-proc dataplane core.

    Current integration is intentionally conservative:
    - Extension path is only used when `config.use_core` is true.
    - If extension is missing, caller can keep legacy sender path.
    """

    def __init__(self, config: DataplaneConfig):
        self.config = config
        self._handle: Any = None
        self._open_error: str = ""

    @property
    def core_available(self) -> bool:
        return _dp_core is not None

    @property
    def enabled(self) -> bool:
        return bool(self.config.use_core)

    @property
    def open_error(self) -> str:
        return self._open_error

    def open(self) -> bool:
        if not self.enabled:
            return False
        if self._handle is not None:
            return True
        if _dp_core is None:
            self._open_error = "dataplane_core_extension_unavailable"
            return False
        try:
            self._handle = _dp_core.open(self.config.as_dict())
            self._open_error = ""
            return True
        except Exception as exc:
            self._open_error = f"{type(exc).__name__}: {exc}"
            log.warning("DataplaneSession.open failed: %s", self._open_error)
            self._handle = None
            return False

    def send_batch(
        self,
        *,
        packets_buffer: Any,
        packet_size: int,
        count: int,
        target_ip: str,
        target_port: int,
    ) -> Optional[DataplaneResult]:
        if not self.enabled:
            return None
        if count <= 0:
            return DataplaneResult(attempted=0, sent=0, errors=0, bytes_sent_est=0, sender_path="DP_NONE")
        if self._handle is None and not self.open():
            return DataplaneResult(
                attempted=int(count),
                sent=0,
                errors=int(count),
                bytes_sent_est=0,
                sender_path="DP_OPEN_FAILED",
                sender_fallback_reason=str(self._open_error or "dataplane_open_failed"),
                fallback_count=1,
            )
        try:
            raw = _dp_core.send_batch(
                self._handle,
                packets_buffer,
                int(packet_size or 0),
                int(count),
                str(target_ip or ""),
                int(target_port or 0),
            )
        except Exception as exc:
            return DataplaneResult(
                attempted=int(count),
                sent=0,
                errors=int(count),
                bytes_sent_est=0,
                sender_path="DP_SEND_FAILED",
                sender_fallback_reason=f"{type(exc).__name__}:{exc}",
                fallback_count=1,
            )

        if not isinstance(raw, dict):
            return DataplaneResult(
                attempted=int(count),
                sent=0,
                errors=int(count),
                bytes_sent_est=0,
                sender_path="DP_INVALID_RESULT",
                sender_fallback_reason="dataplane_invalid_result",
                fallback_count=1,
            )

        attempted = int(raw.get("attempted", count) or count)
        sent = int(raw.get("sent", 0) or 0)
        errors = int(raw.get("errors", max(0, attempted - sent)) or 0)
        bytes_sent_est = int(raw.get("bytes_sent_est", sent * max(0, int(packet_size or 0))) or 0)
        sender_path = str(raw.get("sender_path", "DP_CORE") or "DP_CORE")
        reason = str(raw.get("sender_fallback_reason", "none") or "none")
        fallback_count = int(raw.get("fallback_count", 0) or 0)

        meta = dict(raw)
        return DataplaneResult(
            attempted=attempted,
            sent=sent,
            errors=errors,
            bytes_sent_est=bytes_sent_est,
            sender_path=sender_path,
            sender_fallback_reason=reason,
            fallback_count=fallback_count,
            meta=meta,
        )

    def snapshot(self) -> Dict[str, Any]:
        if self._handle is None or _dp_core is None:
            return {}
        try:
            snap = _dp_core.snapshot(self._handle)
            return dict(snap or {})
        except Exception:
            return {}

    def close(self) -> None:
        if self._handle is None or _dp_core is None:
            self._handle = None
            return
        try:
            _dp_core.close(self._handle)
        except Exception:
            pass
        finally:
            self._handle = None


def _env_truthy(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    return str(raw).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _normalize_core_mode(value: str | None) -> str:
    raw = str(value or "").strip().lower()
    aliases = {
        "on": "auto",
        "enable": "auto",
        "enabled": "auto",
        "1": "auto",
        "true": "auto",
        "off": "off",
        "disable": "off",
        "disabled": "off",
        "0": "off",
        "false": "off",
        "strict": "required",
        "must": "required",
    }
    mode = aliases.get(raw, raw)
    if mode in {"off", "auto", "required"}:
        return mode
    return "off"


def _normalize_afpacket_hugepage_mode(value: str | None) -> str:
    raw = str(value or "").strip().lower()
    aliases = {
        "on": "auto",
        "enable": "auto",
        "enabled": "auto",
        "1": "auto",
        "true": "auto",
        "off": "off",
        "disable": "off",
        "disabled": "off",
        "0": "off",
        "false": "off",
        "strict": "required",
        "must": "required",
    }
    mode = aliases.get(raw, raw)
    if mode in {"off", "auto", "required"}:
        return mode
    return "off"


def build_dataplane_config(args: Dict[str, Any], queue_id: Optional[int] = None) -> DataplaneConfig:
    backend = str(args.get("sender_backend", "auto") or "auto").strip().lower()
    fallback_policy = str(args.get("sender_fallback_policy", "allow") or "allow").strip().lower()
    lab_profile = str(args.get("lab_profile", "off") or "off").strip().lower()
    core_mode_raw = args.get("dataplane_core_mode", os.environ.get("SAMURAI_DATAPLANE_CORE_MODE", "off"))
    core_mode = _normalize_core_mode(core_mode_raw)
    queue_strategy = str(args.get("dp_queue_strategy", "rr") or "rr").strip().lower()
    qid = int(queue_id if queue_id is not None else (args.get("dp_queue_id", args.get("xdp_queue_id", 0)) or 0))
    interface = str(args.get("xdp_interface", "") or "")
    xdp_enable = bool(args.get("xdp_enable", False))
    afpacket_hugepage_mode = _normalize_afpacket_hugepage_mode(
        args.get("afpacket_hugepage_mode", os.environ.get("SAMURAI_AF_PACKET_HUGEPAGE_MODE", "off"))
    )
    afpacket_hugepage_size_kb = int(
        args.get("afpacket_hugepage_size_kb", os.environ.get("SAMURAI_AF_PACKET_HUGEPAGE_SIZE_KB", 2048)) or 2048
    )
    afpacket_ring_target_mb = int(
        args.get("afpacket_ring_target_mb", os.environ.get("SAMURAI_AF_PACKET_RING_TARGET_MB", 64)) or 64
    )
    afpacket_mlock_ring = bool(
        args.get("afpacket_mlock_ring", _env_truthy("SAMURAI_AF_PACKET_MLOCK_RING", False))
    )
    afpacket_prefault_ring = bool(
        args.get("afpacket_prefault_ring", _env_truthy("SAMURAI_AF_PACKET_PREFAULT_RING", True))
    )
    if "dataplane_core_enable" in args:
        use_core_legacy = bool(args.get("dataplane_core_enable", False))
        if use_core_legacy and core_mode == "off":
            core_mode = "auto"
        elif not use_core_legacy:
            core_mode = "off"
    elif core_mode == "off" and _env_truthy("SAMURAI_DATAPLANE_CORE_ENABLE", False):
        core_mode = "auto"
    if lab_profile == "dedicated" and core_mode != "required":
        core_mode = "required"
    if lab_profile == "dedicated" and backend == "txring" and afpacket_hugepage_mode != "required":
        afpacket_hugepage_mode = "required"
    use_core = core_mode in {"auto", "required"}
    allow_python_fallback = _env_truthy("SAMURAI_DP_ALLOW_PY_FALLBACK", False)
    if core_mode == "required":
        allow_python_fallback = False
    extra = {
        "dp_queues": int(args.get("dp_queues", 1) or 1),
        "dp_queue_map": str(args.get("dp_queue_map", "") or ""),
        "allow_python_fallback": int(1 if allow_python_fallback else 0),
    }
    return DataplaneConfig(
        backend=backend,
        fallback_policy=fallback_policy,
        core_mode=core_mode,
        lab_profile=lab_profile,
        queue_strategy=queue_strategy,
        queue_id=qid,
        interface=interface,
        xdp_enable=xdp_enable,
        afpacket_hugepage_mode=afpacket_hugepage_mode,
        afpacket_hugepage_size_kb=max(1, afpacket_hugepage_size_kb),
        afpacket_ring_target_mb=max(1, afpacket_ring_target_mb),
        afpacket_mlock_ring=afpacket_mlock_ring,
        afpacket_prefault_ring=afpacket_prefault_ring,
        use_core=use_core,
        extra=extra,
    )
