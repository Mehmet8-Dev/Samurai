import asyncio
from typing import Any, Dict


def merge_bridge_stats(base: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base or {})
    for key, value in (extra or {}).items():
        if key in {
            "sender_backend_requested",
            "sender_backend_used",
            "sender_fallback_policy",
            "sender_fallback_reason",
            "sender_path",
            "runtime_transport_contract",
            "runtime_transport_service",
        }:
            merged[key] = value
            continue
        if key in {
            "attempted",
            "sent",
            "errors",
            "bytes_sent_est",
            "fallback_count",
            "permission_error_count",
            "buffer_copy_count",
            "buffer_copy_bytes",
            "eagain_retry_count",
            "partial_send_retry_count",
            "buffer_reuse_hits",
        }:
            merged[key] = int(base.get(key, 0) or 0) + int(value or 0)
            continue
        if (
            key.startswith("runtime_")
            or key.startswith("l7_")
            or key.startswith("tcp_")
            or key.startswith("h2_")
            or key.startswith("status_")
            or key in {"responses_total", "l7_engine_path_used"}
        ):
            merged[key] = value
    for key in ("attempted", "sent", "errors"):
        if key in base:
            merged[key] = base[key]
    for key, value in (extra or {}).items():
        if key not in merged:
            merged[key] = value
    for key in (
        "custom_tcp_tx_flush_packets",
        "custom_tcp_tx_flush_bytes",
        "custom_tcp_bridge_backend_requested",
        "custom_tcp_bridge_backend_used",
        "custom_tcp_bridge_backend_match",
        "custom_tcp_bridge_degraded",
        "custom_tcp_bridge_fallback_reason",
        "custom_tcp_bridge_fallback_detail",
        "custom_tcp_bridge_xdp_interface",
        "custom_tcp_bridge_xdp_queue_id",
        "custom_tcp_bridge_xdp_available",
        "custom_tcp_bridge_xdp_enabled",
    ):
        if key in extra:
            merged[key] = extra[key]
        elif key in base:
            merged[key] = base[key]
    for key in ("custom_tcp_tx_flush_packets", "custom_tcp_tx_flush_bytes"):
        merged[key] = int(base.get(key, 0) or 0) + int(extra.get(key, 0) or 0)
    return merged


def extract_contiguous_drain_batch(value: Any) -> tuple[Any, Any, int, int, int]:
    if value is None:
        return None, None, 0, 0, 0

    buffer = None
    owner = None
    count = 0
    packet_size = 0
    uniform = 0

    if isinstance(value, dict):
        buffer = value.get("buffer")
        owner = value.get("owner")
        count = int(value.get("count", 0) or 0)
        packet_size = int(value.get("packet_size", 0) or 0)
        uniform = int(value.get("uniform", 0) or 0)
    elif isinstance(value, (tuple, list)) and len(value) >= 3:
        buffer = value[0]
        count = int(value[1] or 0)
        packet_size = int(value[2] or 0)
        if len(value) >= 4:
            uniform = int(value[3] or 0)

    if buffer is None or count <= 0:
        return None, None, 0, 0, 0

    total_len = len(buffer)
    if packet_size <= 0 and count > 0 and total_len > 0 and (total_len % count == 0):
        packet_size = total_len // count
    if uniform == 0 and packet_size > 0 and (packet_size * count) == total_len:
        uniform = 1

    return buffer, owner, int(count), int(packet_size), int(uniform)


def extract_strided_peek_batch(value: Any) -> tuple[Any, Any, int, int, int, int]:
    if value is None:
        return None, None, 0, 0, 0, 0

    buffer = None
    owner = None
    count = 0
    packet_size = 0
    stride = 0
    uniform = 0

    if isinstance(value, dict):
        buffer = value.get("buffer")
        owner = value.get("owner")
        count = int(value.get("count", 0) or 0)
        packet_size = int(value.get("packet_size", 0) or 0)
        stride = int(value.get("stride", 0) or 0)
        uniform = int(value.get("uniform", 0) or 0)
    elif isinstance(value, (tuple, list)) and len(value) >= 4:
        buffer = value[0]
        count = int(value[1] or 0)
        packet_size = int(value[2] or 0)
        stride = int(value[3] or 0)
        if len(value) >= 5:
            uniform = int(value[4] or 0)

    if buffer is None or count <= 0 or packet_size <= 0 or stride <= 0:
        return None, None, 0, 0, 0, 0
    if stride < packet_size:
        return None, None, 0, 0, 0, 0

    total_len = len(buffer)
    needed = (count - 1) * stride + packet_size
    if total_len < needed:
        return None, None, 0, 0, 0, 0
    if uniform == 0:
        uniform = 1
    return buffer, owner, int(count), int(packet_size), int(stride), int(uniform)


def resolve_custom_tcp_flush_transport(
    *,
    requested_backend: Any = None,
    xdp_interface: Any = None,
    xdp_queue_id: Any = 0,
    resolve_custom_tcp_backend_fn,
    xdp_available_flag: bool,
    check_xdp_available_fn,
) -> Dict[str, Any]:
    backend_requested = resolve_custom_tcp_backend_fn(requested_backend)
    iface = str(xdp_interface or "").strip()
    sender_backend = "txring"
    xdp_enabled = False
    xdp_available = 0
    fallback_reason = "none"
    fallback_detail = ""
    hard_fail_required = False

    if backend_requested == "af_xdp":
        sender_backend = "xdp"
        xdp_enabled = True
        hard_fail_required = True
        if not iface:
            fallback_reason = "custom_tcp_xdp_interface_missing"
            fallback_detail = "custom_tcp_backend=af_xdp but no xdp interface was provided"
        elif not bool(xdp_available_flag):
            fallback_reason = "custom_tcp_xdp_module_unavailable"
            fallback_detail = "AF_XDP sender module is unavailable"
        else:
            available = True
            detail = ""
            if callable(check_xdp_available_fn):
                try:
                    available, detail = check_xdp_available_fn()
                except Exception as exc:
                    available = False
                    detail = str(exc)
            if available:
                xdp_available = 1
            else:
                fallback_reason = "custom_tcp_xdp_unavailable"
                fallback_detail = str(detail or "AF_XDP runtime reported unavailable")

    return {
        "custom_tcp_bridge_backend_requested": backend_requested,
        "custom_tcp_bridge_backend_used": sender_backend,
        "custom_tcp_bridge_backend_match": int(sender_backend == ("xdp" if backend_requested == "af_xdp" else backend_requested)),
        "custom_tcp_bridge_degraded": int(fallback_reason != "none" or sender_backend != ("xdp" if backend_requested == "af_xdp" else backend_requested)),
        "custom_tcp_bridge_fallback_reason": fallback_reason,
        "custom_tcp_bridge_fallback_detail": fallback_detail,
        "custom_tcp_bridge_xdp_interface": iface,
        "custom_tcp_bridge_xdp_queue_id": int(xdp_queue_id or 0),
        "custom_tcp_bridge_xdp_available": int(xdp_available),
        "custom_tcp_bridge_xdp_enabled": int(xdp_enabled),
        "custom_tcp_bridge_hard_fail_required": int(hard_fail_required),
        "sender_backend": sender_backend,
        "xdp_enable": bool(xdp_enabled),
    }


async def flush_custom_tcp_tx_packets(
    *,
    profile: Any,
    verbose: bool,
    pacing_config: Any = None,
    bridge_api: Any = None,
    default_bridge_api: Any = None,
    live_sent: Any = None,
    live_errors: Any = None,
    live_progress: Any = None,
    custom_tcp_backend: Any = None,
    custom_tcp_xdp_interface: Any = None,
    custom_tcp_xdp_queue_id: Any = 0,
    custom_tcp_xdp_mode: Any = 0,
    custom_tcp_bridge_strict: bool = True,
    resolve_transport_fn,
    paced_raw_socket_sender_fn,
    xdp_sender_fn,
    update_live_fn,
    paced_send_xdp_fn,
    pacing_engine_available: bool,
) -> Dict[str, Any]:
    bridge = bridge_api if bridge_api is not None else default_bridge_api
    if bridge is None:
        return {}
    target_ip = str(getattr(profile.connection_template, "target_ip", "") or "")
    target_port = int(getattr(profile.connection_template, "target_port", 0) or 0)
    xdp_interface = str(custom_tcp_xdp_interface or "").strip()
    transport_plan = resolve_transport_fn(
        requested_backend=custom_tcp_backend,
        xdp_interface=xdp_interface,
        xdp_queue_id=custom_tcp_xdp_queue_id,
    )

    tx_buffer = None
    tx_buffer_owner = None
    packet_count = 0
    packet_size = 0

    if int(transport_plan.get("custom_tcp_bridge_hard_fail_required", 0) or 0) == 1 and int(
        transport_plan.get("custom_tcp_bridge_degraded", 0) or 0
    ) == 1:
        if not bool(custom_tcp_bridge_strict):
            transport_plan = dict(transport_plan)
            transport_plan["sender_backend"] = "txring"
            transport_plan["xdp_enable"] = False
            transport_plan["custom_tcp_bridge_backend_used"] = "txring"
            transport_plan["custom_tcp_bridge_xdp_enabled"] = 0
            transport_plan["custom_tcp_bridge_backend_match"] = 0
        else:
            reason = str(transport_plan.get("custom_tcp_bridge_fallback_reason", "custom_tcp_bridge_unavailable") or "custom_tcp_bridge_unavailable")
            detail = str(transport_plan.get("custom_tcp_bridge_fallback_detail", "") or "custom_tcp bridge strict transport preflight failed")
            return {
                "attempted": 0,
                "sent": 0,
                "errors": 0,
                "sender_fallback_reason": reason,
                "custom_tcp_tx_flush_packets": 0,
                "custom_tcp_tx_flush_bytes": 0,
                "custom_tcp_bridge_fallback_reason": reason,
                "custom_tcp_bridge_fallback_detail": detail,
                "custom_tcp_bridge_degraded": 1,
                "custom_tcp_bridge_backend_requested": transport_plan.get("custom_tcp_bridge_backend_requested", "af_xdp"),
                "custom_tcp_bridge_backend_used": transport_plan.get("custom_tcp_bridge_backend_used", "xdp"),
                "custom_tcp_bridge_backend_match": 0,
                "custom_tcp_bridge_xdp_interface": transport_plan.get("custom_tcp_bridge_xdp_interface", ""),
                "custom_tcp_bridge_xdp_queue_id": int(transport_plan.get("custom_tcp_bridge_xdp_queue_id", 0) or 0),
                "custom_tcp_bridge_xdp_available": int(transport_plan.get("custom_tcp_bridge_xdp_available", 0) or 0),
                "custom_tcp_bridge_xdp_enabled": int(transport_plan.get("custom_tcp_bridge_xdp_enabled", 0) or 0),
                "runtime_transport_contract": "custom_tcp_runtime_bridge",
            }

    if str(transport_plan.get("sender_backend", "")) == "xdp":
        peek_fn = getattr(bridge, "peek_custom_tcp_tx_buffer_strided", None)
        if peek_fn is None:
            peek_fn = getattr(bridge, "peek_tcp_tx_buffer_strided", None)
        consume_fn = getattr(bridge, "consume_custom_tcp_tx_packets", None)
        if consume_fn is None:
            consume_fn = getattr(bridge, "consume_tcp_tx_packets", None)
        if callable(peek_fn) and callable(consume_fn):
            try:
                sx_buf, sx_owner, sx_count, sx_pkt_size, sx_stride, sx_uniform = extract_strided_peek_batch(peek_fn())
            except Exception:
                sx_buf, sx_owner, sx_count, sx_pkt_size, sx_stride, sx_uniform = (None, None, 0, 0, 0, 0)
            if sx_buf is not None and sx_count > 0 and sx_uniform == 1:
                send_stats = await xdp_sender_fn(
                    packets_buffer=sx_buf,
                    target_ip=target_ip,
                    target_port=target_port,
                    count=sx_count,
                    verbose=verbose,
                    interface=xdp_interface,
                    queue_id=int(custom_tcp_xdp_queue_id or 0),
                    xdp_mode=int(custom_tcp_xdp_mode or 0),
                    sender_fallback_policy="fail" if bool(custom_tcp_bridge_strict) else "allow",
                    fallback_backend="python",
                    sender_context=None,
                    pacing_config=pacing_config,
                    paced_send_xdp_fn=paced_send_xdp_fn if pacing_engine_available else None,
                    packet_size_override=sx_pkt_size,
                    packet_stride=sx_stride,
                )
                _ = sx_owner
                send_stats = dict(send_stats or {})
                sent = int(send_stats.get("sent", 0) or 0)
                consumed = 0
                if sent > 0:
                    try:
                        consumed = int(consume_fn(min(sent, sx_count)) or 0)
                    except Exception:
                        consumed = 0
                if consumed > 0:
                    update_live_fn(live_progress, consumed)
                    update_live_fn(live_sent, consumed)
                if sent < sx_count:
                    update_live_fn(live_errors, max(0, sx_count - sent))
                send_stats["custom_tcp_tx_flush_packets"] = int(consumed)
                send_stats["custom_tcp_tx_flush_bytes"] = int(consumed) * int(sx_pkt_size)
                for key, value in transport_plan.items():
                    if key in {"sender_backend", "xdp_enable"}:
                        continue
                    send_stats.setdefault(key, value)
                return send_stats

    drain_buffer_fn = getattr(bridge, "drain_custom_tcp_tx_buffer", None)
    if drain_buffer_fn is None:
        drain_buffer_fn = getattr(bridge, "drain_tcp_tx_buffer", None)
    if callable(drain_buffer_fn):
        try:
            tx_buffer, tx_buffer_owner, packet_count, packet_size, uniform = extract_contiguous_drain_batch(drain_buffer_fn())
            if uniform == 0:
                tx_buffer = None
                tx_buffer_owner = None
                packet_count = 0
                packet_size = 0
        except Exception:
            tx_buffer = None
            tx_buffer_owner = None
            packet_count = 0
            packet_size = 0

    if tx_buffer is None:
        drain_fn = getattr(bridge, "drain_custom_tcp_tx_packets", None)
        if drain_fn is None:
            drain_fn = getattr(bridge, "drain_tcp_tx_packets", None)
        if drain_fn is None:
            return {}
        try:
            drained = drain_fn()
        except Exception:
            return {}
        if not drained:
            return {}

        packet_count = len(drained)
        packet_size = len(drained[0]) if packet_count > 0 else 0
        if packet_count <= 0 or packet_size <= 0:
            return {}
        tx_buffer = b"".join(bytes(pkt) for pkt in drained)
        tx_buffer_owner = None

    send_stats = await paced_raw_socket_sender_fn(
        packets_buffer=tx_buffer,
        target_ip=target_ip,
        target_port=target_port,
        count=packet_count,
        verbose=verbose,
        pacing_config=pacing_config,
        live_sent=live_sent,
        live_errors=live_errors,
        live_progress=live_progress,
        sender_backend=transport_plan["sender_backend"],
        xdp_enable=bool(transport_plan["xdp_enable"]),
        xdp_interface=xdp_interface if bool(transport_plan["xdp_enable"]) else None,
        xdp_queue_id=int(custom_tcp_xdp_queue_id or 0),
        xdp_mode=int(custom_tcp_xdp_mode or 0),
    )
    _ = tx_buffer_owner
    send_stats = dict(send_stats or {})
    send_stats.setdefault("custom_tcp_tx_flush_packets", packet_count)
    send_stats.setdefault("custom_tcp_tx_flush_bytes", len(tx_buffer))
    for key, value in transport_plan.items():
        if key in {"sender_backend", "xdp_enable"}:
            continue
        send_stats.setdefault(key, value)
    return send_stats


async def service_custom_tcp_runtime(
    stop_event: asyncio.Event,
    *,
    profile: Any,
    verbose: bool,
    bridge_api: Any = None,
    default_bridge_api: Any = None,
    live_sent: Any = None,
    live_errors: Any = None,
    live_progress: Any = None,
    custom_tcp_backend: Any = None,
    custom_tcp_xdp_interface: Any = None,
    custom_tcp_xdp_queue_id: Any = 0,
    custom_tcp_xdp_mode: Any = 0,
    runtime_poll_snapshot_fn,
    flush_fn,
) -> Dict[str, Any]:
    aggregate: Dict[str, Any] = {}
    runtime_api = bridge_api if bridge_api is not None else default_bridge_api
    service_loops = 0
    idle_sleep_s = 0.00005
    idle_sleep_max_s = 0.001
    while not stop_event.is_set():
        service_loops += 1
        did_work = False
        polled = runtime_poll_snapshot_fn(runtime_api)
        if polled:
            polled.setdefault("runtime_transport_service", "native_custom_tcp_runtime_service")
            polled.setdefault("runtime_transport_contract", "custom_tcp_runtime_bridge")
            aggregate = merge_bridge_stats(aggregate, polled)
            did_work = did_work or bool(int(polled.get("runtime_transport_poll_actions", 0) or 0))
        flushed = await flush_fn(
            profile=profile,
            verbose=verbose,
            pacing_config=None,
            bridge_api=bridge_api,
            live_sent=live_sent,
            live_errors=live_errors,
            live_progress=live_progress,
            custom_tcp_backend=custom_tcp_backend,
            custom_tcp_xdp_interface=custom_tcp_xdp_interface,
            custom_tcp_xdp_queue_id=custom_tcp_xdp_queue_id,
            custom_tcp_xdp_mode=custom_tcp_xdp_mode,
        )
        if flushed:
            flushed.setdefault("runtime_transport_service", "native_custom_tcp_runtime_service")
            flushed.setdefault("runtime_transport_contract", "custom_tcp_runtime_bridge")
            aggregate = merge_bridge_stats(aggregate, flushed)
            did_work = did_work or bool(
                int(flushed.get("custom_tcp_tx_flush_packets", 0) or 0)
                or int(flushed.get("sent", 0) or 0)
                or int(flushed.get("attempted", 0) or 0)
            )
            # Ensure cooperative scheduling even when flush path returns
            # immediately (e.g., strict preflight fallback).
            await asyncio.sleep(0)
        if did_work:
            idle_sleep_s = 0.00005
            continue
        await asyncio.sleep(idle_sleep_s)
        idle_sleep_s = min(idle_sleep_max_s, idle_sleep_s * 2.0)

    for _ in range(8):
        service_loops += 1
        polled = runtime_poll_snapshot_fn(runtime_api)
        if polled:
            polled.setdefault("runtime_transport_service", "native_custom_tcp_runtime_service")
            polled.setdefault("runtime_transport_contract", "custom_tcp_runtime_bridge")
            aggregate = merge_bridge_stats(aggregate, polled)
        flushed = await flush_fn(
            profile=profile,
            verbose=verbose,
            pacing_config=None,
            bridge_api=bridge_api,
            live_sent=live_sent,
            live_errors=live_errors,
            live_progress=live_progress,
            custom_tcp_backend=custom_tcp_backend,
            custom_tcp_xdp_interface=custom_tcp_xdp_interface,
            custom_tcp_xdp_queue_id=custom_tcp_xdp_queue_id,
            custom_tcp_xdp_mode=custom_tcp_xdp_mode,
        )
        if not flushed:
            break
        flushed.setdefault("runtime_transport_service", "native_custom_tcp_runtime_service")
        flushed.setdefault("runtime_transport_contract", "custom_tcp_runtime_bridge")
        aggregate = merge_bridge_stats(aggregate, flushed)
    aggregate["runtime_transport_service_loops"] = int(service_loops)
    return aggregate
