from __future__ import annotations

import asyncio
import importlib
from typing import Any, Dict

_RECOVERABLE_ERRORS = (
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
    AttributeError,
    ImportError,
    KeyError,
    IndexError,
)


def _load_dpdk_module():
    try:
        return importlib.import_module("ddos_samurai.dpdk_pmd_core")
    except _RECOVERABLE_ERRORS:
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


def _dpdk_poll_rx(handle: Any, budget: int) -> list[bytes]:
    mod = _load_dpdk_module()
    if mod is None or not hasattr(mod, "dpdk_poll_rx"):
        return []
    out = mod.dpdk_poll_rx(handle, int(budget or 0))
    if not isinstance(out, list):
        return []
    frames: list[bytes] = []
    for item in out:
        if isinstance(item, (bytes, bytearray, memoryview)):
            frames.append(bytes(item))
    return frames


def _dpdk_close(handle: Any) -> None:
    mod = _load_dpdk_module()
    if mod is None or not hasattr(mod, "dpdk_close"):
        return
    mod.dpdk_close(handle)


def _resolve_dpdk_handle(sender_context: Dict[str, Any] | None, config: Dict[str, Any]) -> Any:
    if isinstance(sender_context, dict):
        cached = sender_context.get("dpdk_handle")
        cached_cfg = dict(sender_context.get("dpdk_handle_cfg") or {})
        if cached is not None and cached_cfg == dict(config):
            return cached
        if cached is not None:
            _dpdk_close(cached)
            sender_context.pop("dpdk_handle", None)
            sender_context.pop("dpdk_handle_cfg", None)
    handle = _dpdk_open(config)
    if isinstance(sender_context, dict):
        sender_context["dpdk_handle"] = handle
        sender_context["dpdk_handle_cfg"] = dict(config)
    return handle


async def send_strided_batch(
    *,
    packets_buffer: Any,
    packet_size: int,
    packet_stride: int,
    count: int,
    sender_context: Dict[str, Any] | None = None,
    dpdk_config: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    del packet_stride
    cfg = dict(dpdk_config or {})
    try:
        handle = _resolve_dpdk_handle(sender_context, cfg)
    except _RECOVERABLE_ERRORS as exc:
        return {
            "attempted": int(count or 0),
            "sent": 0,
            "errors": int(count or 0),
            "bytes_sent_est": 0,
            "sender_path": "DPDK_OPEN_FAILED",
            "sender_fallback_reason": f"dpdk_open_failed:{type(exc).__name__}",
            "fallback_count": 1,
        }

    try:
        result = _dpdk_send_batch(handle, packets_buffer, int(packet_size or 0), int(count or 0))
    except _RECOVERABLE_ERRORS as exc:
        return {
            "attempted": int(count or 0),
            "sent": 0,
            "errors": int(count or 0),
            "bytes_sent_est": 0,
            "sender_path": "DPDK_SEND_FAILED",
            "sender_fallback_reason": f"dpdk_send_failed:{type(exc).__name__}",
            "fallback_count": 1,
        }

    out = dict(result or {})
    attempted = int(out.get("attempted", count) or count)
    sent = int(out.get("sent", 0) or 0)
    out.setdefault("attempted", attempted)
    out.setdefault("sent", sent)
    out.setdefault("errors", max(0, attempted - sent))
    out.setdefault("bytes_sent_est", sent * max(0, int(packet_size or 0)))
    out.setdefault("sender_path", "DPDK_PMD")
    out.setdefault("sender_fallback_reason", "none")
    out.setdefault("fallback_count", 0)
    await asyncio.sleep(0)
    return out


def poll_rx_and_ingest(
    *,
    sender_context: Dict[str, Any] | None = None,
    bridge_api: Any = None,
    budget: int = 64,
) -> Dict[str, Any]:
    if not isinstance(sender_context, dict):
        return {}
    handle = sender_context.get("dpdk_handle")
    if handle is None:
        return {}
    ingest_fn = getattr(bridge_api, "ingest_custom_tcp_rx_frame", None)
    if not callable(ingest_fn):
        ingest_fn = getattr(bridge_api, "ingest_tcp_rx_frame", None)
    if not callable(ingest_fn):
        return {}
    frames = _dpdk_poll_rx(handle, int(budget or 0))
    if not frames:
        return {"dpdk_rx_poll_calls": 1, "dpdk_rx_polled": 0}

    ingested = 0
    for frame in frames:
        try:
            ok = ingest_fn(frame)
        except _RECOVERABLE_ERRORS:
            ok = 0
        ingested += int(ok or 0)
    return {
        "dpdk_rx_poll_calls": 1,
        "dpdk_rx_polled": int(len(frames)),
        "dpdk_rx_ingested": int(ingested),
    }


def close_sender_context(sender_context: Dict[str, Any] | None = None) -> None:
    if not isinstance(sender_context, dict):
        return
    handle = sender_context.pop("dpdk_handle", None)
    sender_context.pop("dpdk_handle_cfg", None)
    if handle is None:
        return
    _dpdk_close(handle)
