"""Host/kernel loss telemetry helpers for sender paths.

This module is Linux-oriented and intentionally best-effort:
- `/proc/net/dev` for host interface TX counters
- `/proc/net/softnet_stat` for CPU softnet drop pressure
"""

from __future__ import annotations

import os
import time
from typing import Dict, Optional


_DISABLED_VALUES = {"0", "false", "off", "no", "disabled"}
_ENABLED_VALUES = {"1", "true", "on", "yes"}


def _to_int(value) -> int:
    try:
        return int(value)
    except Exception:
        return 0


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
    if not stats:
        return None

    env_iface = str(os.environ.get("SAMURAI_LOSS_IFACE", "") or "").strip()
    if env_iface and env_iface in stats:
        return env_iface

    if iface and iface in stats:
        return iface

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


def _empty_snapshot(reason: str = "", iface: str = "") -> Dict[str, int | str]:
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
    }


def snapshot(
    iface: Optional[str] = None,
    *,
    proc_net_dev_path: str = "/proc/net/dev",
    softnet_path: str = "/proc/net/softnet_stat",
) -> Dict[str, int | str]:
    if not is_enabled(proc_net_dev_path=proc_net_dev_path):
        return _empty_snapshot(reason="disabled")

    try:
        dev_stats = read_proc_net_dev(proc_net_dev_path)
    except Exception as exc:
        return _empty_snapshot(reason=f"proc_net_dev_unavailable:{type(exc).__name__}")

    resolved = resolve_iface(iface=iface, dev_stats=dev_stats)
    if not resolved:
        return _empty_snapshot(reason="iface_not_found")

    iface_stats = dev_stats.get(resolved) or {}

    softnet = {"dropped": 0, "time_squeeze": 0}
    reason = ""
    try:
        softnet = read_proc_softnet_stat(softnet_path)
    except Exception as exc:
        reason = f"softnet_unavailable:{type(exc).__name__}"

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
    }


def delta(before: Dict[str, int | str], after: Dict[str, int | str]) -> Dict[str, int | str]:
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
        }

    return {
        "enabled": 1,
        "iface": iface,
        "reason": reason,
        "host_tx_packets_delta": _d("host_tx_packets"),
        "host_tx_dropped_delta": _d("host_tx_dropped"),
        "host_tx_errors_delta": _d("host_tx_errors"),
        "softnet_dropped_delta": _d("softnet_dropped"),
        "softnet_time_squeeze_delta": _d("softnet_time_squeeze"),
    }

