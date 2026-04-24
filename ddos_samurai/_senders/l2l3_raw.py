import asyncio
import os
from typing import Any, Dict


async def raw_socket_sender(
    packets_buffer,
    target_ip,
    target_port,
    count,
    verbose,
    live_sent=None,
    live_errors=None,
    live_progress=None,
    force_l2=False,
    sender_backend=None,
    sender_fallback_policy=None,
    sender_context: Dict[str, Any] | None = None,
    xdp_enable: bool = False,
    xdp_interface: str | None = None,
    xdp_queue_id: int = 0,
    xdp_mode: int = 0,
    *,
    resolve_sender_backend_fn,
    resolve_sender_fallback_policy_fn,
    xdp_sender_fn,
    normalize_packets_buffer_fn,
    resolve_loss_iface_fn,
    take_loss_snapshot_fn,
    attach_loss_telemetry_fn,
    update_live_fn,
    stats_fn,
    get_gateway_info_fn,
    FAST_SENDER_AVAILABLE_flag,
    fast_sender_module,
    log_info,
    log_error,
):
    """
    Sends a packet buffer through XDP or dataplane core.
    Legacy Python raw-socket / TX_RING / C_EXT fallback chain is removed.
    """
    _resolve_sender_backend = resolve_sender_backend_fn
    _resolve_sender_fallback_policy = resolve_sender_fallback_policy_fn
    xdp_sender = xdp_sender_fn
    _normalize_packets_buffer = normalize_packets_buffer_fn
    _resolve_loss_iface = resolve_loss_iface_fn
    _take_loss_snapshot = take_loss_snapshot_fn
    _attach_loss_telemetry = attach_loss_telemetry_fn
    _update_live = update_live_fn
    _stats = stats_fn
    get_gateway_info = get_gateway_info_fn
    FAST_SENDER_AVAILABLE = bool(FAST_SENDER_AVAILABLE_flag)
    fast_sender = fast_sender_module

    if sender_backend is None:
        requested_backend = "auto"
    else:
        requested_backend = _resolve_sender_backend(sender_backend)
    if bool(xdp_enable) and requested_backend == "auto":
        requested_backend = "xdp"
    fallback_policy = _resolve_sender_fallback_policy(sender_fallback_policy)

    if requested_backend == "xdp":
        return await xdp_sender(
            packets_buffer=packets_buffer,
            target_ip=target_ip,
            target_port=target_port,
            count=count,
            verbose=verbose,
            interface=xdp_interface,
            queue_id=int(xdp_queue_id or 0),
            xdp_mode=int(xdp_mode or 0),
            sender_fallback_policy=fallback_policy,
            fallback_backend="auto",
            sender_context=sender_context,
        )

    ctx = sender_context if isinstance(sender_context, dict) else None
    _ctx_dp_session = ctx.get("dataplane_session") if ctx else None
    _has_dp_session = bool(_ctx_dp_session is not None and hasattr(_ctx_dp_session, "send_batch"))
    log_info(
        f"Packet sender context initialized. backend={requested_backend}, "
        f"dataplane_session={'on' if _has_dp_session else 'off'}."
    )

    packet_size = len(packets_buffer) // count if count > 0 else 0
    if packet_size == 0 and count > 0:
        log_error("Packet buffer is empty or count is zero, cannot determine packet size.")
        return _stats(
            attempted=count,
            sent=0,
            errors=count,
            sender_path="NONE",
            sender_fallback_reason="invalid_packet_buffer",
            sender_backend_requested=requested_backend,
            sender_fallback_policy=fallback_policy,
            buffer_copy_count=0,
            buffer_copy_bytes=0,
            eagain_retry_count=0,
            partial_send_retry_count=0,
        )
    packets_buffer, normalize_meta = _normalize_packets_buffer(
        packets_buffer,
        required_bytes=packet_size * count,
        pool_key="senders_raw_tx",
        return_meta=True,
    )

    buffer_copy_count = int(normalize_meta.get("buffer_copy_count", 0) or 0)
    buffer_copy_bytes = int(normalize_meta.get("buffer_copy_bytes", 0) or 0)
    loss_iface_hint = _resolve_loss_iface(None)
    loss_before_snapshot = _take_loss_snapshot(loss_iface_hint)
    dp_open_error = ""
    if ctx:
        dp_open_error = str(ctx.get("dataplane_open_error", "") or "").strip()

    dp_session = ctx.get("dataplane_session") if ctx else None
    if dp_session is None or not hasattr(dp_session, "send_batch"):
        _update_live(live_progress, int(count))
        _update_live(live_errors, int(count))
        reason = dp_open_error or "dataplane_session_missing"
        out = _stats(
            attempted=count,
            sent=0,
            errors=count,
            sender_path="DP_UNAVAILABLE",
            permission_error_count=0,
            fallback_count=1,
            sender_fallback_reason=reason,
            sender_backend_requested=requested_backend,
            sender_fallback_policy=fallback_policy,
            buffer_copy_count=buffer_copy_count,
            buffer_copy_bytes=buffer_copy_bytes,
            eagain_retry_count=0,
            partial_send_retry_count=0,
        )
        return _attach_loss_telemetry(out, loss_before_snapshot, preferred_iface=loss_iface_hint)

    try:
        dp_out = dp_session.send_batch(
            packets_buffer=packets_buffer,
            packet_size=packet_size,
            count=count,
            target_ip=target_ip,
            target_port=target_port,
        )
    except Exception as e:
        _update_live(live_progress, int(count))
        _update_live(live_errors, int(count))
        out = _stats(
            attempted=count,
            sent=0,
            errors=count,
            sender_path="DP_SEND_FAILED",
            permission_error_count=0,
            fallback_count=1,
            sender_fallback_reason=f"dataplane_exception:{type(e).__name__}",
            sender_backend_requested=requested_backend,
            sender_fallback_policy=fallback_policy,
            buffer_copy_count=buffer_copy_count,
            buffer_copy_bytes=buffer_copy_bytes,
            eagain_retry_count=0,
            partial_send_retry_count=0,
        )
        return _attach_loss_telemetry(out, loss_before_snapshot, preferred_iface=loss_iface_hint)

    if dp_out is None:
        _update_live(live_progress, int(count))
        _update_live(live_errors, int(count))
        out = _stats(
            attempted=count,
            sent=0,
            errors=count,
            sender_path="DP_SEND_FAILED",
            permission_error_count=0,
            fallback_count=1,
            sender_fallback_reason="dataplane_returned_none",
            sender_backend_requested=requested_backend,
            sender_fallback_policy=fallback_policy,
            buffer_copy_count=buffer_copy_count,
            buffer_copy_bytes=buffer_copy_bytes,
            eagain_retry_count=0,
            partial_send_retry_count=0,
        )
        return _attach_loss_telemetry(out, loss_before_snapshot, preferred_iface=loss_iface_hint)

    if hasattr(dp_out, "to_stats"):
        dp_stats = dict(dp_out.to_stats() or {})
    elif isinstance(dp_out, dict):
        dp_stats = dict(dp_out or {})
    else:
        dp_stats = {}

    dp_attempted = int(dp_stats.get("attempted", count) or count)
    dp_sent = int(dp_stats.get("sent", 0) or 0)
    dp_errors = int(dp_stats.get("errors", max(0, dp_attempted - dp_sent)) or 0)
    _update_live(live_progress, int(dp_attempted))
    _update_live(live_sent, int(dp_sent))
    _update_live(live_errors, int(max(dp_errors, dp_attempted - dp_sent)))
    out = _stats(
        attempted=dp_attempted,
        sent=dp_sent,
        errors=max(dp_errors, dp_attempted - dp_sent),
        bytes_sent_est=int(dp_stats.get("bytes_sent_est", int(dp_sent) * int(max(0, int(packet_size or 0)))) or 0),
        sender_path=str(dp_stats.get("sender_path", "DP_CORE") or "DP_CORE"),
        fallback_count=max(int(dp_stats.get("fallback_count", 0) or 0), 0),
        sender_fallback_reason=str(dp_stats.get("sender_fallback_reason", "none") or "none"),
        sender_backend_requested=requested_backend,
        sender_fallback_policy=fallback_policy,
        buffer_copy_count=buffer_copy_count,
        buffer_copy_bytes=buffer_copy_bytes,
        eagain_retry_count=0,
        partial_send_retry_count=0,
    )
    for k, v in dp_stats.items():
        if k in {"attempted", "sent", "errors", "bytes_sent_est"}:
            continue
        if isinstance(v, bool):
            out[k] = int(v)
        elif isinstance(v, (int, float, str)):
            out[k] = v
    return _attach_loss_telemetry(out, loss_before_snapshot, preferred_iface=loss_iface_hint)


async def paced_raw_socket_sender(
    packets_buffer,
    target_ip,
    target_port,
    count,
    verbose,
    pacing_config=None,
    force_l2=False,
    live_sent=None,
    live_errors=None,
    live_progress=None,
    sender_backend=None,
    sender_fallback_policy=None,
    sender_context: Dict[str, Any] | None = None,
    xdp_enable: bool = False,
    xdp_interface: str | None = None,
    xdp_queue_id: int = 0,
    xdp_mode: int = 0,
    *,
    resolve_sender_backend_fn,
    resolve_sender_fallback_policy_fn,
    xdp_sender_fn,
    raw_socket_sender_fn,
    normalize_packets_buffer_fn,
    resolve_loss_iface_fn,
    take_loss_snapshot_fn,
    attach_loss_telemetry_fn,
    update_live_fn,
    stats_fn,
    apply_pacing_stats_fn,
    run_paced_send_with_live_progress_fn,
    PacedSendRuntimeError_cls,
    get_gateway_info_fn,
    FAST_SENDER_AVAILABLE_flag,
    PACING_ENGINE_AVAILABLE_flag,
    reset_stats_fn,
    paced_send_l2_fn,
    paced_send_xdp_fn,
    paced_send_fn,
    get_stats_fn,
    format_stats_fn,
    cleanup_l2_fn,
    log_info,
    log_error,
    log_warning,
):
    _resolve_sender_backend = resolve_sender_backend_fn
    _resolve_sender_fallback_policy = resolve_sender_fallback_policy_fn
    xdp_sender = xdp_sender_fn
    raw_socket_sender = raw_socket_sender_fn
    _normalize_packets_buffer = normalize_packets_buffer_fn
    _resolve_loss_iface = resolve_loss_iface_fn
    _take_loss_snapshot = take_loss_snapshot_fn
    _attach_loss_telemetry = attach_loss_telemetry_fn
    _update_live = update_live_fn
    _stats = stats_fn
    _apply_pacing_stats = apply_pacing_stats_fn
    _run_paced_send_with_live_progress = run_paced_send_with_live_progress_fn
    _PacedSendRuntimeError = PacedSendRuntimeError_cls
    get_gateway_info = get_gateway_info_fn
    FAST_SENDER_AVAILABLE = bool(FAST_SENDER_AVAILABLE_flag)
    PACING_ENGINE_AVAILABLE = bool(PACING_ENGINE_AVAILABLE_flag)
    reset_stats = reset_stats_fn
    paced_send_l2 = paced_send_l2_fn
    paced_send_xdp = paced_send_xdp_fn
    paced_send = paced_send_fn
    get_stats = get_stats_fn
    format_stats = format_stats_fn
    cleanup_l2 = cleanup_l2_fn

    requested_backend = _resolve_sender_backend(sender_backend)
    if bool(xdp_enable) and requested_backend == "auto":
        requested_backend = "xdp"
    fallback_policy = _resolve_sender_fallback_policy(sender_fallback_policy)

    if requested_backend == "xdp":
        def _xdp_pacing_v2_enabled() -> bool:
            raw = str(os.environ.get("SAMURAI_XDP_PACING_V2", "0") or "0").strip().lower()
            return raw not in {"0", "false", "no", "off", ""}

        def _xdp_pacing_fail_reason(detail: str) -> str:
            d = str(detail or "").strip().lower()
            if "xdp_mode2_hard_probe_not_supported" in d:
                return "xdp_mode2_hard_probe_not_supported"
            if "xdp_init" in d:
                return "xdp_init_failed"
            if "xdp_send" in d:
                return "xdp_send_failed"
            return "xdp_paced_send_failed"

        pacing_active = (
            pacing_config is not None
            and int(getattr(pacing_config, "pacing_mode", 0) or 0) != 0
        )
        pacing_via_xdp = (
            pacing_active
            and PACING_ENGINE_AVAILABLE
            and callable(paced_send_xdp)
        )
        pacing_v2_active = pacing_via_xdp and _xdp_pacing_v2_enabled()

        if pacing_v2_active:
            packet_size = len(packets_buffer) // count if count > 0 else 0
            if packet_size == 0:
                log_error("[Pacing][XDP] Invalid packet buffer (size=0)")
                return _stats(
                    attempted=count,
                    sent=0,
                    errors=count,
                    sender_fallback_reason="invalid_packet_buffer",
                    sender_backend_requested=requested_backend,
                    sender_fallback_policy=fallback_policy,
                    buffer_copy_count=0,
                    buffer_copy_bytes=0,
                    eagain_retry_count=0,
                    partial_send_retry_count=0,
                )

            packets_buffer, normalize_meta = _normalize_packets_buffer(
                packets_buffer,
                required_bytes=packet_size * count,
                pool_key="senders_pacing_xdp_tx",
                return_meta=True,
            )
            buffer_copy_count = int(normalize_meta.get("buffer_copy_count", 0) or 0)
            buffer_copy_bytes = int(normalize_meta.get("buffer_copy_bytes", 0) or 0)

            iface = str(xdp_interface or "").strip()
            if not iface:
                try:
                    iface, _gw_mac = get_gateway_info(target_ip)
                    iface = str(iface or "").strip()
                except Exception:
                    iface = ""

            if callable(reset_stats):
                try:
                    reset_stats()
                except Exception:
                    pass

            if not iface:
                reason = "xdp_interface_unresolved"
                detail = "could not resolve interface for paced XDP path"
                if fallback_policy == "fail":
                    return _stats(
                        attempted=count,
                        sent=0,
                        errors=count,
                        sender_path="XDP_UNAVAILABLE",
                        fallback_count=1,
                        sender_fallback_reason=reason,
                        sender_fallback_reason_detail=detail,
                        sender_backend_requested="xdp",
                        sender_fallback_policy=fallback_policy,
                        buffer_copy_count=buffer_copy_count,
                        buffer_copy_bytes=buffer_copy_bytes,
                        eagain_retry_count=0,
                        partial_send_retry_count=0,
                    )
                out = await xdp_sender(
                    packets_buffer=packets_buffer,
                    target_ip=target_ip,
                    target_port=target_port,
                    count=count,
                    verbose=verbose,
                    interface=xdp_interface,
                    queue_id=int(xdp_queue_id or 0),
                    xdp_mode=int(xdp_mode or 0),
                    sender_fallback_policy=fallback_policy,
                    fallback_backend="c_ext_l3",
                    sender_context=sender_context,
                    pacing_config=None,
                    paced_send_xdp_fn=None,
                )
                out = dict(out or {})
                out["fallback_count"] = int(out.get("fallback_count", 0) or 0) + 1
                existing_reason = str(out.get("sender_fallback_reason", "none") or "none").strip().lower()
                if existing_reason in {"", "none"}:
                    out["sender_fallback_reason"] = reason
                out["sender_fallback_reason_detail"] = detail
                return out

            mode2_policy = "hard" if fallback_policy == "fail" else "soft"
            progress_reported = 0

            send_call = lambda: paced_send_xdp(
                iface,
                packets_buffer,
                packet_size,
                count,
                config=pacing_config,
                queue_id=int(xdp_queue_id or 0),
                xdp_mode=int(xdp_mode or 0),
                xdp_mode2_policy=mode2_policy,
            )

            try:
                if callable(_run_paced_send_with_live_progress):
                    total_sent, progress_reported = await _run_paced_send_with_live_progress(
                        send_call,
                        pacing_config=pacing_config,
                        progress_budget=count,
                        live_progress=live_progress,
                    )
                else:
                    total_sent = int(send_call() or 0)
            except _PacedSendRuntimeError as exc:
                progress_reported = int(getattr(exc, "progress_emitted", 0) or 0)
                _update_live(live_sent, progress_reported)
                _update_live(live_errors, max(0, count - progress_reported))
                detail = str(getattr(exc, "cause", exc) or exc)
                reason = _xdp_pacing_fail_reason(detail)
                if fallback_policy == "fail":
                    return _stats(
                        attempted=count,
                        sent=progress_reported,
                        errors=max(0, count - progress_reported),
                        bytes_sent_est=progress_reported * packet_size,
                        sender_path="PACED_XDP",
                        fallback_count=1,
                        sender_fallback_reason=reason,
                        sender_fallback_reason_detail=detail,
                        sender_backend_requested="xdp",
                        sender_fallback_policy=fallback_policy,
                        buffer_copy_count=buffer_copy_count,
                        buffer_copy_bytes=buffer_copy_bytes,
                        eagain_retry_count=0,
                        partial_send_retry_count=0,
                    )
                out = await xdp_sender(
                    packets_buffer=packets_buffer,
                    target_ip=target_ip,
                    target_port=target_port,
                    count=count,
                    verbose=verbose,
                    interface=iface,
                    queue_id=int(xdp_queue_id or 0),
                    xdp_mode=int(xdp_mode or 0),
                    sender_fallback_policy=fallback_policy,
                    fallback_backend="c_ext_l3",
                    sender_context=sender_context,
                    pacing_config=None,
                    paced_send_xdp_fn=None,
                )
                out = dict(out or {})
                out["fallback_count"] = int(out.get("fallback_count", 0) or 0) + 1
                existing_reason = str(out.get("sender_fallback_reason", "none") or "none").strip().lower()
                if existing_reason in {"", "none"}:
                    out["sender_fallback_reason"] = reason
                out["sender_fallback_reason_detail"] = detail
                return out
            except Exception as exc:
                detail = str(exc)
                reason = _xdp_pacing_fail_reason(detail)
                _update_live(live_sent, progress_reported)
                _update_live(live_errors, max(0, count - progress_reported))
                if fallback_policy == "fail":
                    return _stats(
                        attempted=count,
                        sent=progress_reported,
                        errors=max(0, count - progress_reported),
                        bytes_sent_est=progress_reported * packet_size,
                        sender_path="PACED_XDP",
                        fallback_count=1,
                        sender_fallback_reason=reason,
                        sender_fallback_reason_detail=detail,
                        sender_backend_requested="xdp",
                        sender_fallback_policy=fallback_policy,
                        buffer_copy_count=buffer_copy_count,
                        buffer_copy_bytes=buffer_copy_bytes,
                        eagain_retry_count=0,
                        partial_send_retry_count=0,
                    )
                out = await xdp_sender(
                    packets_buffer=packets_buffer,
                    target_ip=target_ip,
                    target_port=target_port,
                    count=count,
                    verbose=verbose,
                    interface=iface,
                    queue_id=int(xdp_queue_id or 0),
                    xdp_mode=int(xdp_mode or 0),
                    sender_fallback_policy=fallback_policy,
                    fallback_backend="c_ext_l3",
                    sender_context=sender_context,
                    pacing_config=None,
                    paced_send_xdp_fn=None,
                )
                out = dict(out or {})
                out["fallback_count"] = int(out.get("fallback_count", 0) or 0) + 1
                existing_reason = str(out.get("sender_fallback_reason", "none") or "none").strip().lower()
                if existing_reason in {"", "none"}:
                    out["sender_fallback_reason"] = reason
                out["sender_fallback_reason_detail"] = detail
                return out

            _update_live(live_sent, total_sent)
            _update_live(live_errors, max(0, count - total_sent))
            out = _stats(
                attempted=count,
                sent=total_sent,
                errors=max(0, count - total_sent),
                bytes_sent_est=total_sent * packet_size,
                sender_path="PACED_XDP",
                sender_backend_requested=requested_backend,
                sender_fallback_policy=fallback_policy,
                fallback_count=0,
                sender_fallback_reason="none",
                buffer_copy_count=buffer_copy_count,
                buffer_copy_bytes=buffer_copy_bytes,
                eagain_retry_count=0,
                partial_send_retry_count=0,
            )
            if callable(get_stats):
                try:
                    stats = get_stats()
                    if stats:
                        out = _apply_pacing_stats(out, stats)
                except Exception:
                    pass
            return out

        if pacing_active and not pacing_via_xdp:
            log_warning("[Pacing] sender-backend=xdp selected; C pacing is bypassed for this path.")
        elif pacing_active and not pacing_v2_active:
            log_info("[Pacing][XDP] SAMURAI_XDP_PACING_V2=0, legacy XDP pacing route active.")

        if pacing_via_xdp and callable(reset_stats):
            try:
                reset_stats()
            except Exception:
                pass
        out = await xdp_sender(
            packets_buffer=packets_buffer,
            target_ip=target_ip,
            target_port=target_port,
            count=count,
            verbose=verbose,
            interface=xdp_interface,
            queue_id=int(xdp_queue_id or 0),
            xdp_mode=int(xdp_mode or 0),
            sender_fallback_policy=fallback_policy,
            fallback_backend="c_ext_l3",
            sender_context=sender_context,
            pacing_config=pacing_config if pacing_via_xdp else None,
            paced_send_xdp_fn=paced_send_xdp if pacing_via_xdp else None,
        )
        out = dict(out or {})
        if pacing_via_xdp and callable(get_stats):
            try:
                stats = get_stats()
                if stats:
                    out = _apply_pacing_stats(out, stats)
            except Exception:
                pass
        elif pacing_active:
            out["pacing_bypassed_for_xdp"] = 1
        return out

    if pacing_config is None or pacing_config.pacing_mode == 0 or not PACING_ENGINE_AVAILABLE:
        return await raw_socket_sender(
            packets_buffer,
            target_ip,
            target_port,
            count,
            verbose,
            live_sent=live_sent,
            live_errors=live_errors,
            live_progress=live_progress,
            force_l2=force_l2,
            sender_backend=requested_backend,
            sender_fallback_policy=fallback_policy,
            sender_context=sender_context,
            xdp_enable=xdp_enable,
            xdp_interface=xdp_interface,
            xdp_queue_id=xdp_queue_id,
            xdp_mode=xdp_mode,
        )

    packet_size = len(packets_buffer) // count if count > 0 else 0
    if packet_size == 0:
        log_error("[Pacing] Invalid packet buffer (size=0)")
        return _stats(
            attempted=count,
            sent=0,
            errors=count,
            sender_fallback_reason="invalid_packet_buffer",
            sender_backend_requested=requested_backend,
            sender_fallback_policy=fallback_policy,
            buffer_copy_count=0,
            buffer_copy_bytes=0,
            eagain_retry_count=0,
            partial_send_retry_count=0,
        )
    packets_buffer, normalize_meta = _normalize_packets_buffer(
        packets_buffer,
        required_bytes=packet_size * count,
        pool_key="senders_pacing_tx",
        return_meta=True,
    )
    buffer_copy_count = int(normalize_meta.get("buffer_copy_count", 0) or 0)
    buffer_copy_bytes = int(normalize_meta.get("buffer_copy_bytes", 0) or 0)
    loss_iface_hint = _resolve_loss_iface(None)
    loss_before_snapshot = _take_loss_snapshot(loss_iface_hint)
    progress_reported = 0
    fallback_count = 0
    fallback_reasons = []

    def _register_fallback(reason: str) -> None:
        nonlocal fallback_count
        fallback_count += 1
        r = str(reason or "").strip()
        if r and r not in fallback_reasons:
            fallback_reasons.append(r)

    log_info(
        f"[Pacing] C engine: mode={pacing_config.pacing_mode.name}, "
        f"rps={pacing_config.target_rps:.0f}, ipg={pacing_config.ipg_ns}ns, "
        f"burst={pacing_config.burst_size}, jitter={pacing_config.jitter_model.name} "
        f"±{pacing_config.jitter_pct*100:.0f}%"
    )

    if FAST_SENDER_AVAILABLE and requested_backend in {"auto", "txring"}:
        try:
            iface, gateway_mac = get_gateway_info(target_ip)
            if iface and gateway_mac and len(gateway_mac) == 6:
                if not str(os.environ.get("SAMURAI_LOSS_IFACE", "") or "").strip():
                    loss_iface_hint = str(iface)
                    loss_before_snapshot = _take_loss_snapshot(loss_iface_hint)
                log_info(f"[Pacing] Using L2 paced sender on {iface}")
                try:
                    if callable(reset_stats):
                        reset_stats()
                except Exception:
                    pass
                progress_budget = max(0, int(count) - int(progress_reported))
                try:
                    sent, progress_emitted = await _run_paced_send_with_live_progress(
                        lambda: paced_send_l2(
                            iface,
                            packets_buffer,
                            packet_size,
                            count,
                            gateway_mac,
                            config=pacing_config,
                        ),
                        pacing_config=pacing_config,
                        progress_budget=progress_budget,
                        live_progress=live_progress,
                    )
                    progress_reported += int(progress_emitted)
                except _PacedSendRuntimeError as exc:
                    progress_reported += int(exc.progress_emitted)
                    raise exc.cause
                stats = get_stats()
                if stats:
                    log_info(
                        f"[Pacing] L2 done: {sent:,} pkts, "
                        f"rate={stats.get('actual_rps',0):,.0f} pps, "
                        f"accuracy={stats.get('rate_accuracy_pct',0):.1f}%, "
                        f"jitter_p99={stats.get('jitter_p99_ns',0):,.0f}ns"
                    )
                    if verbose:
                        log_info(f"\n{format_stats(stats)}")
                cleanup_l2()
                progress_tail = max(0, int(count) - int(progress_reported))
                _update_live(live_progress, progress_tail)
                progress_reported += int(progress_tail)
                _update_live(live_sent, int(sent or 0))
                _update_live(live_errors, max(0, count - int(sent or 0)))

                out = _stats(
                    attempted=count,
                    sent=int(sent or 0),
                    errors=max(0, count - int(sent or 0)),
                    bytes_sent_est=int(sent or 0) * packet_size,
                    sender_path="PACED_L2",
                    fallback_count=fallback_count,
                    sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "none",
                    sender_backend_requested=requested_backend,
                    sender_fallback_policy=fallback_policy,
                    buffer_copy_count=buffer_copy_count,
                    buffer_copy_bytes=buffer_copy_bytes,
                    eagain_retry_count=0,
                    partial_send_retry_count=0,
                )
                if stats:
                    out = _apply_pacing_stats(out, stats)
                return _attach_loss_telemetry(out, loss_before_snapshot, preferred_iface=loss_iface_hint)
            else:
                _register_fallback("paced_l2_gateway_not_found")
        except Exception as e:
            try:
                cleanup_l2()
            except Exception:
                pass
            _register_fallback("paced_l2_error")
            if verbose:
                log_error(f"[Pacing] L2 paced send failed, falling back to L3: {e}")

    if bool(force_l2) or (requested_backend == "txring" and fallback_policy == "fail"):
        _update_live(live_progress, int(count))
        _update_live(live_errors, int(count))
        return _stats(
            attempted=count,
            sent=0,
            errors=count,
            sender_path="L2_UNAVAILABLE",
            fallback_count=max(1, fallback_count),
            sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "l2_unavailable",
            sender_backend_requested=requested_backend,
            sender_fallback_policy=fallback_policy,
            buffer_copy_count=buffer_copy_count,
            buffer_copy_bytes=buffer_copy_bytes,
            eagain_retry_count=0,
            partial_send_retry_count=0,
        )

    try:
        log_info("[Pacing] Using L3 paced sender")
        try:
            if callable(reset_stats):
                reset_stats()
        except Exception:
            pass
        progress_budget = max(0, int(count) - int(progress_reported))
        try:
            sent, progress_emitted = await _run_paced_send_with_live_progress(
                lambda: paced_send(
                    packets_buffer,
                    target_ip,
                    target_port,
                    packet_size,
                    count,
                    config=pacing_config,
                ),
                pacing_config=pacing_config,
                progress_budget=progress_budget,
                live_progress=live_progress,
            )
            progress_reported += int(progress_emitted)
        except _PacedSendRuntimeError as exc:
            progress_reported += int(exc.progress_emitted)
            raise exc.cause
        stats = get_stats()
        progress_tail = max(0, int(count) - int(progress_reported))
        _update_live(live_progress, progress_tail)
        progress_reported += int(progress_tail)
        _update_live(live_sent, int(sent or 0))
        _update_live(live_errors, max(0, count - int(sent or 0)))

        out = _stats(
            attempted=count,
            sent=int(sent or 0),
            errors=max(0, count - int(sent or 0)),
            bytes_sent_est=int(sent or 0) * packet_size,
            sender_path="PACED_L3",
            fallback_count=fallback_count,
            sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "none",
            sender_backend_requested=requested_backend,
            sender_fallback_policy=fallback_policy,
            buffer_copy_count=buffer_copy_count,
            buffer_copy_bytes=buffer_copy_bytes,
            eagain_retry_count=0,
            partial_send_retry_count=0,
        )
        if stats:
            out = _apply_pacing_stats(out, stats)
        return _attach_loss_telemetry(out, loss_before_snapshot, preferred_iface=loss_iface_hint)
    except PermissionError:
        log_error("[Pacing] Raw socket requires root. Falling back to unpaced.")
        fallback_live_progress = None if progress_reported > 0 else live_progress
        out = await raw_socket_sender(
            packets_buffer,
            target_ip,
            target_port,
            count,
            verbose,
            live_sent=live_sent,
            live_errors=live_errors,
            live_progress=fallback_live_progress,
            force_l2=force_l2,
            sender_backend=requested_backend,
            sender_fallback_policy=fallback_policy,
            sender_context=sender_context,
            xdp_enable=xdp_enable,
            xdp_interface=xdp_interface,
            xdp_queue_id=xdp_queue_id,
            xdp_mode=xdp_mode,
        )
        if progress_reported > 0:
            _update_live(live_progress, max(0, int(count) - int(progress_reported)))
        return out
    except Exception as e:
        log_error(f"[Pacing] L3 paced send failed: {e}. Falling back to unpaced.")
        fallback_live_progress = None if progress_reported > 0 else live_progress
        out = await raw_socket_sender(
            packets_buffer,
            target_ip,
            target_port,
            count,
            verbose,
            live_sent=live_sent,
            live_errors=live_errors,
            live_progress=fallback_live_progress,
            force_l2=force_l2,
            sender_backend=requested_backend,
            sender_fallback_policy=fallback_policy,
            sender_context=sender_context,
            xdp_enable=xdp_enable,
            xdp_interface=xdp_interface,
            xdp_queue_id=xdp_queue_id,
            xdp_mode=xdp_mode,
        )
        if progress_reported > 0:
            _update_live(live_progress, max(0, int(count) - int(progress_reported)))
        return out
