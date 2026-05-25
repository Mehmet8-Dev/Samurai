from __future__ import annotations

from typing import Any


def build_empty_stats(*, attempted: int = 0, sent: int = 0, errors: int = 0, bytes_sent_est: int = 0, **extra) -> dict:
    out = {
        "attempted": int(attempted),
        "sent": int(sent),
        "errors": int(errors),
        "bytes_sent_est": int(bytes_sent_est),
        "sender_fallback_reason": "none",
        "actual_rps": 0.0,
        "rate_accuracy_pct": 0.0,
        "jitter_p99_ns": 0.0,
        "ipg_mean_ns": 0.0,
        "sleep_calls": 0,
        "busywait_cycles": 0,
    }
    for k, v in dict(extra or {}).items():
        out[str(k)] = v
    return out


def normalize_l7_stats(raw_stats: dict[str, Any], **extra) -> dict:
    out = build_empty_stats()
    out.update(dict(raw_stats or {}))
    out.update(dict(extra or {}))
    return out


def update_live_counter(val: Any, inc: int) -> None:
    try:
        if val is not None and int(inc) != 0:
            val.value += int(inc)
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        pass


def recompute_loss_metrics(stats: dict[str, Any], *, inplace: bool = False) -> dict:
    d = stats if inplace else dict(stats or {})
    attempted = max(0, int(d.get("attempted", 0) or 0))
    sent = max(0, int(d.get("sent", 0) or 0))
    errors = max(0, int(d.get("errors", 0) or 0))
    if errors <= 0 and attempted > sent:
        errors = attempted - sent
        d["errors"] = int(errors)
    d["wire_loss_est_packets"] = int(max(0, attempted - sent))
    d["wire_loss_est_pct"] = float((100.0 * int(d["wire_loss_est_packets"])) / max(1, attempted))
    return d


def merge_worker_stats(*items: dict[str, Any]) -> dict:
    acc = build_empty_stats()
    for it in items:
        if not isinstance(it, dict):
            continue
        acc["attempted"] += int(it.get("attempted", 0) or 0)
        acc["sent"] += int(it.get("sent", 0) or 0)
        acc["errors"] += int(it.get("errors", 0) or 0)
        acc["bytes_sent_est"] += int(it.get("bytes_sent_est", 0) or 0)
        if float(it.get("actual_rps", 0.0) or 0.0) > 0.0:
            acc["actual_rps"] = float(it.get("actual_rps", 0.0) or 0.0)
        if float(it.get("rate_accuracy_pct", 0.0) or 0.0) > 0.0:
            acc["rate_accuracy_pct"] = float(it.get("rate_accuracy_pct", 0.0) or 0.0)
        if float(it.get("jitter_p99_ns", 0.0) or 0.0) > 0.0:
            acc["jitter_p99_ns"] = float(it.get("jitter_p99_ns", 0.0) or 0.0)
        if float(it.get("ipg_mean_ns", 0.0) or 0.0) > 0.0:
            acc["ipg_mean_ns"] = float(it.get("ipg_mean_ns", 0.0) or 0.0)
        acc["sleep_calls"] += int(it.get("sleep_calls", 0) or 0)
        acc["busywait_cycles"] += int(it.get("busywait_cycles", 0) or 0)
    return recompute_loss_metrics(acc, inplace=True)
