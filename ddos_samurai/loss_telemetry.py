"""Loss telemetry helpers for sender paths.

This module is Linux-oriented and best-effort. It collects:
- Host counters: `/proc/net/dev`
- Softnet pressure: `/proc/net/softnet_stat`
- Wire egress counters (preferred): `/sys/class/net/<iface>/statistics/*`
  with fallback to `/proc/net/dev` when sysfs counters are unavailable.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Dict, Optional


_DISABLED_VALUES = {"0", "false", "off", "no", "disabled"}
_ENABLED_VALUES = {"1", "true", "on", "yes"}

_WIRE_SYSFS_ROOT = "/sys/class/net"
_WIRE_SOURCE_NONE = "none"
_WIRE_SOURCE_SYSFS = "sysfs_netdev_stats"
_WIRE_SOURCE_PROC = "proc_net_dev_fallback"
_WIRE_CONFIDENCE_SYSFS = 1.0
_WIRE_CONFIDENCE_PROC = 0.65


def _to_int(value) -> int:
    try:
        return int(value)
    except Exception:
        return 0


def _to_float(value) -> float:
    try:
        return float(value)
    except Exception:
        return 0.0


def _normalize_mode(mode: Optional[str] = None) -> str:
    raw = mode
    if raw is None:
        raw = os.environ.get("SAMURAI_LOSS_TELEMETRY", "auto")
    return str(raw or "auto").strip().lower()


def is_enabled(mode: Optional[str] = None, *, proc_net_dev_path: str = "/proc/net/dev") -> bool:
    m = _normalize_mode(mode)
    if m in _DISABLED_VALUES:
        return False
    if m in _ENABLED_VALUES:
        return True
    # auto
    return os.name == "posix" and os.path.exists(proc_net_dev_path)


def _parse_proc_net_dev_text(text: str) -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {}
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        left, right = line.split(":", 1)
        iface = left.strip()
        if not iface or iface.startswith("Inter-") or iface.startswith("face"):
            continue
        cols = right.strip().split()
        if len(cols) < 16:
            continue
        try:
            vals = [int(x) for x in cols[:16]]
        except Exception:
            continue
        out[iface] = {
            "rx_bytes": vals[0],
            "rx_packets": vals[1],
            "rx_errors": vals[2],
            "rx_dropped": vals[3],
            "tx_bytes": vals[8],
            "tx_packets": vals[9],
            "tx_errors": vals[10],
            "tx_dropped": vals[11],
        }
    return out


def _parse_softnet_stat_text(text: str) -> Dict[str, int]:
    dropped = 0
    time_squeeze = 0
    processed = 0
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        cols = line.split()
        if not cols:
            continue
        try:
            processed += int(cols[0], 16) if len(cols) > 0 else 0
            dropped += int(cols[1], 16) if len(cols) > 1 else 0
            time_squeeze += int(cols[2], 16) if len(cols) > 2 else 0
        except Exception:
            continue
    return {
        "processed": int(processed),
        "dropped": int(dropped),
        "time_squeeze": int(time_squeeze),
    }


def read_proc_net_dev(path: str = "/proc/net/dev") -> Dict[str, Dict[str, int]]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return _parse_proc_net_dev_text(f.read())


def read_proc_softnet_stat(path: str = "/proc/net/softnet_stat") -> Dict[str, int]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return _parse_softnet_stat_text(f.read())


def resolve_iface(
    iface: Optional[str] = None,
    *,
    dev_stats: Optional[Dict[str, Dict[str, int]]] = None,
) -> Optional[str]:
    stats = dev_stats if isinstance(dev_stats, dict) else {}

    env_iface = str(os.environ.get("SAMURAI_LOSS_IFACE", "") or "").strip()
    if env_iface:
        if (stats and env_iface in stats) or (not stats and (Path(_WIRE_SYSFS_ROOT) / env_iface).exists()):
            return env_iface

    if iface:
        if (stats and iface in stats) or (not stats and (Path(_WIRE_SYSFS_ROOT) / str(iface)).exists()):
            return str(iface)

    if not stats:
        return None

    candidates = [(name, data) for name, data in stats.items() if name != "lo"]
    if not candidates:
        candidates = list(stats.items())
    if not candidates:
        return None

    candidates.sort(
        key=lambda item: (
            int(item[1].get("tx_packets", 0) or 0),
            int(item[1].get("rx_packets", 0) or 0),
            item[0],
        ),
        reverse=True,
    )
    return str(candidates[0][0])


def _join_reason(parts) -> str:
    out = []
    for p in parts:
        s = str(p or "").strip()
        if s and s not in out:
            out.append(s)
    return ";".join(out)


def _read_sysfs_wire_counters(iface: str, *, sysfs_root: str = _WIRE_SYSFS_ROOT) -> tuple[dict, str]:
    base = Path(sysfs_root) / str(iface) / "statistics"
    if not base.exists():
        return {}, "sysfs_stats_not_found"
    keys = ("tx_packets", "tx_dropped", "tx_errors", "tx_bytes")
    out: Dict[str, int] = {}
    for k in keys:
        p = base / k
        try:
            raw = p.read_text(encoding="utf-8", errors="replace").strip()
            out[k] = int(raw or "0")
        except Exception as exc:
            return {}, f"sysfs_read_failed:{k}:{type(exc).__name__}"
    return out, ""


def _wire_snapshot_from_proc(iface_stats: Dict[str, int]) -> Dict[str, int]:
    return {
        "wire_tx_packets": int(iface_stats.get("tx_packets", 0) or 0),
        "wire_tx_dropped": int(iface_stats.get("tx_dropped", 0) or 0),
        "wire_tx_errors": int(iface_stats.get("tx_errors", 0) or 0),
        "wire_tx_bytes": int(iface_stats.get("tx_bytes", 0) or 0),
    }


def _wire_snapshot_from_sysfs(stats: Dict[str, int]) -> Dict[str, int]:
    return {
        "wire_tx_packets": int(stats.get("tx_packets", 0) or 0),
        "wire_tx_dropped": int(stats.get("tx_dropped", 0) or 0),
        "wire_tx_errors": int(stats.get("tx_errors", 0) or 0),
        "wire_tx_bytes": int(stats.get("tx_bytes", 0) or 0),
    }


def _empty_snapshot(reason: str = "", iface: str = "") -> Dict[str, int | float | str]:
    return {
        "enabled": 0,
        "iface": str(iface or ""),
        "reason": str(reason or ""),
        "ts_ns": int(time.time_ns()),
        "host_tx_packets": 0,
        "host_tx_dropped": 0,
        "host_tx_errors": 0,
        "softnet_dropped": 0,
        "softnet_time_squeeze": 0,
        "wire_counter_available": 0,
        "wire_counter_source": _WIRE_SOURCE_NONE,
        "wire_counter_confidence": 0.0,
        "wire_counter_reason": str(reason or ""),
        "wire_tx_packets": 0,
        "wire_tx_dropped": 0,
        "wire_tx_errors": 0,
        "wire_tx_bytes": 0,
    }


def snapshot(
    iface: Optional[str] = None,
    *,
    proc_net_dev_path: str = "/proc/net/dev",
    softnet_path: str = "/proc/net/softnet_stat",
    sysfs_root: str = _WIRE_SYSFS_ROOT,
) -> Dict[str, int | float | str]:
    if not is_enabled(proc_net_dev_path=proc_net_dev_path):
        return _empty_snapshot(reason="disabled", iface=str(iface or ""))

    dev_stats: Dict[str, Dict[str, int]] = {}
    dev_reason = ""
    try:
        dev_stats = read_proc_net_dev(proc_net_dev_path)
    except Exception as exc:
        dev_reason = f"proc_net_dev_unavailable:{type(exc).__name__}"

    resolved = resolve_iface(iface=iface, dev_stats=dev_stats)
    if not resolved:
        env_iface = str(os.environ.get("SAMURAI_LOSS_IFACE", "") or "").strip()
        candidate = str(env_iface or iface or "").strip()
        if candidate and (Path(sysfs_root) / candidate).exists():
            resolved = candidate
    if not resolved:
        return _empty_snapshot(reason=dev_reason or "iface_not_found", iface=str(iface or ""))

    iface_stats = dev_stats.get(resolved) or {}

    softnet = {"dropped": 0, "time_squeeze": 0}
    softnet_reason = ""
    try:
        softnet = read_proc_softnet_stat(softnet_path)
    except Exception as exc:
        softnet_reason = f"softnet_unavailable:{type(exc).__name__}"

    wire_counter_available = 0
    wire_counter_source = _WIRE_SOURCE_NONE
    wire_counter_confidence = 0.0
    wire_counter_reason = ""
    wire_tx = {
        "wire_tx_packets": 0,
        "wire_tx_dropped": 0,
        "wire_tx_errors": 0,
        "wire_tx_bytes": 0,
    }

    sysfs_stats, sysfs_reason = _read_sysfs_wire_counters(resolved, sysfs_root=sysfs_root)
    if sysfs_stats:
        wire_counter_available = 1
        wire_counter_source = _WIRE_SOURCE_SYSFS
        wire_counter_confidence = _WIRE_CONFIDENCE_SYSFS
        wire_tx = _wire_snapshot_from_sysfs(sysfs_stats)
    elif iface_stats:
        wire_counter_available = 1
        wire_counter_source = _WIRE_SOURCE_PROC
        wire_counter_confidence = _WIRE_CONFIDENCE_PROC
        wire_counter_reason = sysfs_reason or "sysfs_unavailable_using_proc_fallback"
        wire_tx = _wire_snapshot_from_proc(iface_stats)
    else:
        wire_counter_reason = _join_reason([sysfs_reason, dev_reason, "wire_counter_unavailable"])

    reason = _join_reason([dev_reason, softnet_reason])
    return {
        "enabled": 1,
        "iface": str(resolved),
        "reason": reason,
        "ts_ns": int(time.time_ns()),
        "host_tx_packets": int(iface_stats.get("tx_packets", 0) or 0),
        "host_tx_dropped": int(iface_stats.get("tx_dropped", 0) or 0),
        "host_tx_errors": int(iface_stats.get("tx_errors", 0) or 0),
        "softnet_dropped": int(softnet.get("dropped", 0) or 0),
        "softnet_time_squeeze": int(softnet.get("time_squeeze", 0) or 0),
        "wire_counter_available": int(wire_counter_available),
        "wire_counter_source": str(wire_counter_source),
        "wire_counter_confidence": float(wire_counter_confidence),
        "wire_counter_reason": str(wire_counter_reason),
        "wire_tx_packets": int(wire_tx["wire_tx_packets"]),
        "wire_tx_dropped": int(wire_tx["wire_tx_dropped"]),
        "wire_tx_errors": int(wire_tx["wire_tx_errors"]),
        "wire_tx_bytes": int(wire_tx["wire_tx_bytes"]),
    }


def delta(before: Dict[str, int | float | str], after: Dict[str, int | float | str]) -> Dict[str, int | float | str]:
    b = before if isinstance(before, dict) else {}
    a = after if isinstance(after, dict) else {}

    enabled = int(bool(_to_int(b.get("enabled", 0))) and bool(_to_int(a.get("enabled", 0))))
    iface = str(a.get("iface") or b.get("iface") or "")
    reason = str(a.get("reason") or b.get("reason") or "")

    def _d(key: str) -> int:
        v = _to_int(a.get(key, 0)) - _to_int(b.get(key, 0))
        return int(v if v > 0 else 0)

    if enabled == 0:
        return {
            "enabled": 0,
            "iface": iface,
            "reason": reason or "telemetry_unavailable",
            "host_tx_packets_delta": 0,
            "host_tx_dropped_delta": 0,
            "host_tx_errors_delta": 0,
            "softnet_dropped_delta": 0,
            "softnet_time_squeeze_delta": 0,
            "wire_counter_available": 0,
            "wire_counter_source": _WIRE_SOURCE_NONE,
            "wire_counter_confidence": 0.0,
            "wire_counter_reason": reason or "telemetry_unavailable",
            "wire_tx_packets_delta": 0,
            "wire_tx_dropped_delta": 0,
            "wire_tx_errors_delta": 0,
            "wire_tx_bytes_delta": 0,
        }

    before_wire_ok = int(bool(_to_int(b.get("wire_counter_available", 0))))
    after_wire_ok = int(bool(_to_int(a.get("wire_counter_available", 0))))
    source_before = str(b.get("wire_counter_source", "") or "")
    source_after = str(a.get("wire_counter_source", "") or "")
    source_now = source_after or source_before or _WIRE_SOURCE_NONE
    source_changed = source_before and source_after and source_before != source_after

    wire_counter_available = int(bool(before_wire_ok) and bool(after_wire_ok))
    wire_counter_confidence = max(0.0, min(1.0, _to_float(a.get("wire_counter_confidence", 0.0))))
    wire_counter_reason = str(a.get("wire_counter_reason", "") or "")
    if source_changed:
        wire_counter_reason = _join_reason(
            [wire_counter_reason, f"wire_counter_source_changed:{source_before}->{source_after}"]
        )
    if wire_counter_available == 0 and not wire_counter_reason:
        wire_counter_reason = "wire_counter_unavailable"

    return {
        "enabled": 1,
        "iface": iface,
        "reason": reason,
        "host_tx_packets_delta": _d("host_tx_packets"),
        "host_tx_dropped_delta": _d("host_tx_dropped"),
        "host_tx_errors_delta": _d("host_tx_errors"),
        "softnet_dropped_delta": _d("softnet_dropped"),
        "softnet_time_squeeze_delta": _d("softnet_time_squeeze"),
        "wire_counter_available": int(wire_counter_available),
        "wire_counter_source": str(source_now),
        "wire_counter_confidence": float(wire_counter_confidence),
        "wire_counter_reason": str(wire_counter_reason),
        "wire_tx_packets_delta": _d("wire_tx_packets") if wire_counter_available else 0,
        "wire_tx_dropped_delta": _d("wire_tx_dropped") if wire_counter_available else 0,
        "wire_tx_errors_delta": _d("wire_tx_errors") if wire_counter_available else 0,
        "wire_tx_bytes_delta": _d("wire_tx_bytes") if wire_counter_available else 0,
    }
