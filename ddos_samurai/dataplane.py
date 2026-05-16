from __future__ import annotations

import logging
import os
import importlib
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

try:
    from . import dataplane_core as _dp_core
except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
    _dp_core = None

def _load_dpdk_module():
    try:
        return importlib.import_module("ddos_samurai.dpdk_pmd_core")
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        return None


def _dpdk_open(config: Dict[str, Any]) -> Any:
    mod = _load_dpdk_module()
    if mod is None or not hasattr(mod, "dpdk_open"):
        raise RuntimeError("dpdk_runtime_unavailable")
    return mod.dpdk_open(dict(config or {}))


def _dpdk_send_batch(handle: Any, packets_buffer: Any, packet_size: int, count: int) -> Dict[str, Any]:
    mod = _load_dpdk_module()
    if mod is None or not hasattr(mod, "dpdk_send_batch"):
        raise RuntimeError("dpdk_runtime_unavailable")
    return dict(mod.dpdk_send_batch(handle, packets_buffer, int(packet_size or 0), int(count or 0)) or {})


def _dpdk_snapshot(handle: Any) -> Dict[str, Any]:
    mod = _load_dpdk_module()
    if mod is None or not hasattr(mod, "dpdk_snapshot"):
        return {}
    return dict(mod.dpdk_snapshot(handle) or {})


def _dpdk_close(handle: Any) -> None:
    mod = _load_dpdk_module()
    if mod is None or not hasattr(mod, "dpdk_close"):
        return
    mod.dpdk_close(handle)


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
    xdp_mode: int = 0
    xdp_mode2_policy: str = "soft"
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
            "xdp_mode": int(self.xdp_mode or 0),
            "xdp_mode2_policy": str(self.xdp_mode2_policy or "soft"),
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
    def _is_dpdk_backend(self) -> bool:
        return str(self.config.backend or "").strip().lower() == "dpdk"

    @property
    def core_available(self) -> bool:
        if self._is_dpdk_backend:
            return _load_dpdk_module() is not None
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
        if self._is_dpdk_backend:
            dpdk_cfg = dict(self.config.extra.get("dpdk", {}) or {})
            if not dpdk_cfg:
                dpdk_cfg = {"enable": 1, "queue_id": int(self.config.queue_id or 0)}
            try:
                self._handle = _dpdk_open(dpdk_cfg)
                self._open_error = ""
                return True
            except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError) as exc:
                self._open_error = f"{type(exc).__name__}: {exc}"
                self._handle = None
                return False
        if _dp_core is None:
            self._open_error = "dataplane_core_extension_unavailable"
            return False
        try:
            self._handle = _dp_core.open(self.config.as_dict())
            self._open_error = ""
            return True
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError) as exc:
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
            if self._is_dpdk_backend:
                raw = _dpdk_send_batch(
                    self._handle,
                    packets_buffer,
                    int(packet_size or 0),
                    int(count),
                )
            else:
                raw = _dp_core.send_batch(
                    self._handle,
                    packets_buffer,
                    int(packet_size or 0),
                    int(count),
                    str(target_ip or ""),
                    int(target_port or 0),
                )
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError) as exc:
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
        if self._handle is None:
            return {}
        if self._is_dpdk_backend:
            return _dpdk_snapshot(self._handle)
        if _dp_core is None:
            return {}
        try:
            snap = _dp_core.snapshot(self._handle)
            return dict(snap or {})
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
            return {}

    def close(self) -> None:
        if self._handle is None:
            self._handle = None
            return
        if self._is_dpdk_backend:
            _dpdk_close(self._handle)
            self._handle = None
            return
        if _dp_core is None:
            self._handle = None
            return
        try:
            _dp_core.close(self._handle)
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
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
    backend = str(args.get("sender_backend", "xdp") or "xdp").strip().lower()
    if backend not in {"xdp", "dpdk", "txring", "auto"}:
        backend = "xdp"
    fallback_policy = str(args.get("sender_fallback_policy", "fail") or "fail").strip().lower()
    lab_profile = str(args.get("lab_profile", "off") or "off").strip().lower()
    core_mode_raw = args.get("dataplane_core_mode", os.environ.get("SAMURAI_DATAPLANE_CORE_MODE", "off"))
    core_mode = _normalize_core_mode(core_mode_raw)
    queue_strategy = str(args.get("dp_queue_strategy", "rr") or "rr").strip().lower()
    qid = int(queue_id if queue_id is not None else (args.get("dp_queue_id", args.get("xdp_queue_id", 0)) or 0))
    interface = str(args.get("xdp_interface", "") or "")
    xdp_enable = bool(args.get("xdp_enable", False))
    xdp_mode = int(args.get("xdp_mode", 0) or 0)
    xdp_mode2_policy = str(
        args.get(
            "xdp_mode2_policy",
            "hard" if fallback_policy == "fail" else "soft",
        )
        or ("hard" if fallback_policy == "fail" else "soft")
    ).strip().lower()
    if xdp_mode2_policy not in {"soft", "hard"}:
        xdp_mode2_policy = "hard" if fallback_policy == "fail" else "soft"
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
    dpdk_queue_raw = args.get("dpdk_queue_id", os.environ.get("SAMURAI_DPDK_QUEUE_ID", qid))
    if dpdk_queue_raw is None or str(dpdk_queue_raw).strip() == "":
        dpdk_queue_raw = qid
    extra = {
        "dp_queues": int(args.get("dp_queues", 1) or 1),
        "dp_queue_map": str(args.get("dp_queue_map", "") or ""),
        "allow_python_fallback": int(1 if allow_python_fallback else 0),
        "dpdk": {
            "enable": int(bool(args.get("dpdk_enable", _env_truthy("SAMURAI_DPDK_ENABLE", False)))),
            "strict": int(bool(args.get("dpdk_strict", _env_truthy("SAMURAI_DPDK_STRICT", False)))),
            "eal_args": str(args.get("dpdk_eal_args", os.environ.get("SAMURAI_DPDK_EAL_ARGS", "")) or ""),
            "port_id": int(args.get("dpdk_port_id", os.environ.get("SAMURAI_DPDK_PORT_ID", 0)) or 0),
            "queue_id": int(dpdk_queue_raw),
            "burst_size": int(args.get("dpdk_burst_size", os.environ.get("SAMURAI_DPDK_BURST_SIZE", 64)) or 64),
            "mempool_size": int(args.get("dpdk_mempool_size", os.environ.get("SAMURAI_DPDK_MEMPOOL_SIZE", 8192)) or 8192),
            "rx_enable": int(bool(args.get("dpdk_rx_enable", _env_truthy("SAMURAI_DPDK_RX_ENABLE", False)))),
        },
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
        xdp_mode=xdp_mode,
        xdp_mode2_policy=xdp_mode2_policy,
        afpacket_hugepage_mode=afpacket_hugepage_mode,
        afpacket_hugepage_size_kb=max(1, afpacket_hugepage_size_kb),
        afpacket_ring_target_mb=max(1, afpacket_ring_target_mb),
        afpacket_mlock_ring=afpacket_mlock_ring,
        afpacket_prefault_ring=afpacket_prefault_ring,
        use_core=use_core,
        extra=extra,
    )
