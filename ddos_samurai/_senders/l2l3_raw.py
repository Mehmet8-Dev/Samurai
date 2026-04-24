import asyncio
import os
import socket
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
    Sends a buffer of pre-created raw packets using native senders.
    Fallback chain: TX_RING (L2) -> C_EXT_L3.
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

    s = None
    owns_socket = False
    ctx = sender_context if isinstance(sender_context, dict) else None
    try:
        cached_socket = None
        if isinstance(ctx, dict):
            cached_socket = ctx.get("raw_socket")
            if cached_socket is not None and getattr(cached_socket, "fileno", lambda: -1)() < 0:
                cached_socket = None
                ctx.pop("raw_socket", None)
        if cached_socket is not None:
            s = cached_socket
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            owns_socket = True
            if isinstance(ctx, dict):
                ctx["raw_socket"] = s
    except PermissionError:
        log_error("Raw socket creation failed. Please run the script with sudo/root privileges.")
        return _stats(
            attempted=count,
            sent=0,
            errors=count,
            sender_path="NONE",
            permission_error_count=1,
            fallback_count=0,
            sender_fallback_reason="raw_socket_permission_denied",
            sender_backend_requested=requested_backend,
            sender_fallback_policy=fallback_policy,
            buffer_copy_count=0,
            buffer_copy_bytes=0,
            eagain_retry_count=0,
            partial_send_retry_count=0,
        )
    except Exception as e:
        log_error(f"Failed to create raw socket: {e}")
        return _stats(
            attempted=count,
            sent=0,
            errors=count,
            sender_path="NONE",
            permission_error_count=0,
            fallback_count=0,
            sender_fallback_reason="raw_socket_init_failed",
            sender_backend_requested=requested_backend,
            sender_fallback_policy=fallback_policy,
            buffer_copy_count=0,
            buffer_copy_bytes=0,
            eagain_retry_count=0,
            partial_send_retry_count=0,
        )

    _ctx_dp_session = ctx.get("dataplane_session") if isinstance(ctx, dict) else None
    _has_dp_session = bool(_ctx_dp_session is not None and hasattr(_ctx_dp_session, "send_batch"))
    log_info(
        f"Packet sender context initialized. backend={requested_backend}, "
        f"dataplane_session={'on' if _has_dp_session else 'off'}."
    )

    packet_size = len(packets_buffer) // count if count > 0 else 0
    if packet_size == 0 and count > 0:
        log_error("Packet buffer is empty or count is zero, cannot determine packet size.")
        if owns_socket and s is not None:
            s.close()
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

    fallback_count = 0
    fallback_reasons = []
    permission_error_count = 0
    eagain_retry_count = 0
    partial_send_retry_count = 0
    buffer_copy_count = int(normalize_meta.get("buffer_copy_count", 0) or 0)
    buffer_copy_bytes = int(normalize_meta.get("buffer_copy_bytes", 0) or 0)
    txring_flush_call_count = 0
    txring_flush_error_count = 0
    txring_flush_eagain_count = 0
    txring_flush_enobufs_count = 0
    txring_flush_ebusy_count = 0
    txring_flush_other_errno_count = 0
    txring_flush_last_errno = 0
    txring_flush_last_errno_name = "NONE"
    txring_frame_wait_ns = 0
    txring_poll_count = 0
    flush_mode = "unknown"
    txring_tp_packets = 0
    txring_tp_drops = 0
    txring_tp_freeze_q_cnt = 0
    txring_packet_version = 0
    txring_packet_version_name = "TPACKET_UNKNOWN"
    afpacket_hugepage_mode = "off"
    afpacket_hugepage_effective = 0
    afpacket_hugepage_reason = "none"
    afpacket_hugepage_size_kb = 0
    afpacket_madvise_hugepage_ok = 0
    afpacket_mlock_ok = 0
    afpacket_prefault_pages = 0
    afpacket_smaps_kernel_page_kb = 0
    afpacket_smaps_anon_hugepages_kb = 0
    afpacket_ring_block_size = 0
    afpacket_ring_block_nr = 0
    afpacket_ring_size_bytes = 0
    txring_batch_target = 0
    txring_backoff_ns = 0
    buffer_reuse_hits = 0

    def _register_fallback(reason: str) -> None:
        nonlocal fallback_count
        fallback_count += 1
        r = str(reason or "").strip()
        if r and r not in fallback_reasons:
            fallback_reasons.append(r)

    loss_iface_hint = _resolve_loss_iface(None)
    loss_before_snapshot = _take_loss_snapshot(loss_iface_hint)

    allow_fallback = fallback_policy == "allow"
    dp_hot_path_only = bool(isinstance(ctx, dict) and ctx.get("dataplane_hot_path_only", False))
    dp_open_error = ""
    if isinstance(ctx, dict):
        dp_open_error = str(ctx.get("dataplane_open_error", "") or "").strip()

    dp_session = ctx.get("dataplane_session") if isinstance(ctx, dict) else None
    if dp_session is not None and hasattr(dp_session, "send_batch"):
        dp_out = None
        try:
            dp_out = dp_session.send_batch(
                packets_buffer=packets_buffer,
                packet_size=packet_size,
                count=count,
                target_ip=target_ip,
                target_port=target_port,
            )
        except Exception as e:
            _register_fallback(f"dataplane_exception:{type(e).__name__}")
            if dp_hot_path_only:
                if owns_socket and s is not None:
                    s.close()
                _update_live(live_progress, int(count))
                _update_live(live_errors, int(count))
                return _stats(
                    attempted=count,
                    sent=0,
                    errors=count,
                    sender_path="DP_SEND_FAILED",
                    permission_error_count=0,
                    fallback_count=max(1, int(fallback_count)),
                    sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "dataplane_exception",
                    sender_backend_requested=requested_backend,
                    sender_fallback_policy=fallback_policy,
                    buffer_copy_count=buffer_copy_count,
                    buffer_copy_bytes=buffer_copy_bytes,
                    eagain_retry_count=0,
                    partial_send_retry_count=0,
                )
        if dp_out is not None:
            if hasattr(dp_out, "to_stats"):
                dp_stats = dict(dp_out.to_stats() or {})
            elif isinstance(dp_out, dict):
                dp_stats = dict(dp_out or {})
            else:
                dp_stats = {}
            dp_attempted = int(dp_stats.get("attempted", count) or count)
            dp_sent = int(dp_stats.get("sent", 0) or 0)
            dp_errors = int(dp_stats.get("errors", max(0, dp_attempted - dp_sent)) or 0)
            dp_reason = str(dp_stats.get("sender_fallback_reason", "none") or "none").strip()
            if dp_reason and dp_reason.lower() != "none":
                _register_fallback(dp_reason)
            if owns_socket and s is not None:
                s.close()
            _update_live(live_progress, int(dp_attempted))
            _update_live(live_sent, int(dp_sent))
            _update_live(live_errors, int(max(dp_errors, dp_attempted - dp_sent)))
            out = _stats(
                attempted=dp_attempted,
                sent=dp_sent,
                errors=max(dp_errors, dp_attempted - dp_sent),
                bytes_sent_est=int(
                    dp_stats.get("bytes_sent_est", int(dp_sent) * int(max(0, int(packet_size or 0)))) or 0
                ),
                sender_path=str(dp_stats.get("sender_path", "DP_CORE") or "DP_CORE"),
                fallback_count=max(int(dp_stats.get("fallback_count", 0) or 0), int(fallback_count or 0)),
                sender_fallback_reason=(
                    ";".join(fallback_reasons) if fallback_reasons else str(dp_reason or "none")
                ),
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
    elif dp_hot_path_only:
        if owns_socket and s is not None:
            s.close()
        _update_live(live_progress, int(count))
        _update_live(live_errors, int(count))
        reason = dp_open_error or "dataplane_session_missing"
        return _stats(
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

    try_txring = bool(force_l2) or requested_backend in {"auto", "txring"}
    try_c_ext_l3 = requested_backend in {"auto", "txring", "c_ext_l3"}
    try_c_ext_l3 = requested_backend in {"auto", "txring", "c_ext_l3"}
    if not allow_fallback:
        if requested_backend in {"auto", "txring"}:
            try_c_ext_l3 = False

    if bool(force_l2) and not FAST_SENDER_AVAILABLE:
        _register_fallback("txring_unavailable")
        if not allow_fallback:
            if owns_socket and s is not None:
                s.close()
            _update_live(live_progress, int(count))
            _update_live(live_errors, int(count))
            return _stats(
                attempted=count,
                sent=0,
                errors=count,
                sender_path="L2_UNAVAILABLE",
                permission_error_count=0,
                fallback_count=fallback_count,
                sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "txring_unavailable",
                sender_backend_requested=requested_backend,
                sender_fallback_policy=fallback_policy,
                buffer_copy_count=buffer_copy_count,
                buffer_copy_bytes=buffer_copy_bytes,
                eagain_retry_count=0,
                partial_send_retry_count=0,
            )

    if FAST_SENDER_AVAILABLE and try_txring and hasattr(fast_sender, "send_ring_optimized"):
        try:
            iface, gateway_mac = get_gateway_info(target_ip)
            if iface and gateway_mac:
                if not str(os.environ.get("SAMURAI_LOSS_IFACE", "") or "").strip():
                    loss_iface_hint = str(iface)
                    loss_before_snapshot = _take_loss_snapshot(loss_iface_hint)
                if len(gateway_mac) != 6:
                    log_error(f"Invalid MAC address length: {len(gateway_mac)} (expected 6)")
                    _register_fallback("txring_invalid_gateway_mac")
                else:
                    log_info(f"[TX_RING] Starting zero-copy L2 send with MAC: {gateway_mac.hex()}")
                    if hasattr(fast_sender, "send_ring_optimized_ex"):
                        tx_result = fast_sender.send_ring_optimized_ex(
                            iface, packets_buffer, packet_size, count, gateway_mac
                        )
                        if isinstance(tx_result, dict):
                            sent = int(tx_result.get("sent", 0) or 0)
                            _tx_reason = str(tx_result.get("sender_fallback_reason", "none") or "none").strip()
                            if _tx_reason and _tx_reason.lower() != "none":
                                _register_fallback(_tx_reason)
                            fallback_count = max(int(fallback_count or 0), int(tx_result.get("fallback_count", 0) or 0))
                            txring_flush_call_count += int(tx_result.get("txring_flush_call_count", 0) or 0)
                            txring_flush_error_count += int(tx_result.get("txring_flush_error_count", 0) or 0)
                            txring_flush_eagain_count += int(tx_result.get("txring_flush_eagain_count", 0) or 0)
                            txring_flush_enobufs_count += int(tx_result.get("txring_flush_enobufs_count", 0) or 0)
                            txring_flush_ebusy_count += int(tx_result.get("txring_flush_ebusy_count", 0) or 0)
                            txring_flush_other_errno_count += int(tx_result.get("txring_flush_other_errno_count", 0) or 0)
                            txring_flush_last_errno = int(tx_result.get("txring_flush_last_errno", 0) or 0)
                            txring_flush_last_errno_name = str(
                                tx_result.get("txring_flush_last_errno_name", "NONE") or "NONE"
                            )
                            txring_frame_wait_ns += int(tx_result.get("txring_frame_wait_ns", 0) or 0)
                            txring_poll_count += int(tx_result.get("txring_poll_count", 0) or 0)
                            _tx_flush_mode = str(tx_result.get("flush_mode", "") or "").strip()
                            if _tx_flush_mode:
                                if flush_mode in ("", "unknown"):
                                    flush_mode = _tx_flush_mode
                                elif flush_mode != _tx_flush_mode:
                                    flush_mode = "mixed"
                            txring_tp_packets += int(tx_result.get("txring_tp_packets", 0) or 0)
                            txring_tp_drops += int(tx_result.get("txring_tp_drops", 0) or 0)
                            txring_tp_freeze_q_cnt += int(tx_result.get("txring_tp_freeze_q_cnt", 0) or 0)
                            txring_packet_version = int(tx_result.get("txring_packet_version", 0) or 0)
                            txring_packet_version_name = str(
                                tx_result.get("txring_packet_version_name", "TPACKET_UNKNOWN") or "TPACKET_UNKNOWN"
                            )
                            afpacket_hugepage_mode = str(tx_result.get("afpacket_hugepage_mode", afpacket_hugepage_mode) or afpacket_hugepage_mode)
                            afpacket_hugepage_effective = int(
                                tx_result.get("afpacket_hugepage_effective", afpacket_hugepage_effective) or afpacket_hugepage_effective
                            )
                            afpacket_hugepage_reason = str(
                                tx_result.get("afpacket_hugepage_reason", afpacket_hugepage_reason) or afpacket_hugepage_reason
                            )
                            afpacket_hugepage_size_kb = int(
                                tx_result.get("afpacket_hugepage_size_kb", afpacket_hugepage_size_kb) or afpacket_hugepage_size_kb
                            )
                            afpacket_madvise_hugepage_ok = int(
                                tx_result.get("afpacket_madvise_hugepage_ok", afpacket_madvise_hugepage_ok) or afpacket_madvise_hugepage_ok
                            )
                            afpacket_mlock_ok = int(tx_result.get("afpacket_mlock_ok", afpacket_mlock_ok) or afpacket_mlock_ok)
                            afpacket_prefault_pages += int(tx_result.get("afpacket_prefault_pages", 0) or 0)
                            afpacket_smaps_kernel_page_kb = max(
                                int(afpacket_smaps_kernel_page_kb or 0), int(tx_result.get("afpacket_smaps_kernel_page_kb", 0) or 0)
                            )
                            afpacket_smaps_anon_hugepages_kb = max(
                                int(afpacket_smaps_anon_hugepages_kb or 0), int(tx_result.get("afpacket_smaps_anon_hugepages_kb", 0) or 0)
                            )
                            afpacket_ring_block_size = max(
                                int(afpacket_ring_block_size or 0), int(tx_result.get("afpacket_ring_block_size", 0) or 0)
                            )
                            afpacket_ring_block_nr = max(
                                int(afpacket_ring_block_nr or 0), int(tx_result.get("afpacket_ring_block_nr", 0) or 0)
                            )
                            afpacket_ring_size_bytes = max(
                                int(afpacket_ring_size_bytes or 0), int(tx_result.get("afpacket_ring_size_bytes", 0) or 0)
                            )
                            txring_batch_target = int(tx_result.get("txring_batch_target", 0) or 0)
                            txring_backoff_ns += int(tx_result.get("txring_backoff_ns", 0) or 0)
                        else:
                            sent = int(tx_result or 0)
                    else:
                        sent = int(fast_sender.send_ring_optimized(iface, packets_buffer, packet_size, count, gateway_mac) or 0)
                    log_info(f"Fast Sender (TX_RING L2) finished. Sent {sent} packets via {iface}.")
                    if owns_socket and s is not None:
                        s.close()
                    sent_total = int(sent or 0)
                    _update_live(live_progress, count)
                    _update_live(live_sent, sent_total)
                    _update_live(live_errors, max(0, count - sent_total))
                    out = _stats(
                        attempted=count,
                        sent=sent_total,
                        errors=max(0, count - sent_total),
                        bytes_sent_est=sent_total * packet_size,
                        sender_path="TX_RING_L2",
                        permission_error_count=0,
                        fallback_count=fallback_count,
                        sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "none",
                        sender_backend_requested=requested_backend,
                        sender_fallback_policy=fallback_policy,
                        buffer_copy_count=buffer_copy_count,
                        buffer_copy_bytes=buffer_copy_bytes,
                        eagain_retry_count=eagain_retry_count,
                        partial_send_retry_count=partial_send_retry_count,
                        buffer_reuse_hits=buffer_reuse_hits,
                        txring_flush_call_count=txring_flush_call_count,
                        txring_flush_error_count=txring_flush_error_count,
                        txring_flush_eagain_count=txring_flush_eagain_count,
                        txring_flush_enobufs_count=txring_flush_enobufs_count,
                        txring_flush_ebusy_count=txring_flush_ebusy_count,
                        txring_flush_other_errno_count=txring_flush_other_errno_count,
                        txring_flush_last_errno=txring_flush_last_errno,
                        txring_flush_last_errno_name=txring_flush_last_errno_name,
                        txring_frame_wait_ns=txring_frame_wait_ns,
                        txring_poll_count=txring_poll_count,
                        flush_mode=flush_mode,
                        txring_tp_packets=txring_tp_packets,
                        txring_tp_drops=txring_tp_drops,
                        txring_tp_freeze_q_cnt=txring_tp_freeze_q_cnt,
                        txring_packet_version=txring_packet_version,
                        txring_packet_version_name=txring_packet_version_name,
                        afpacket_hugepage_mode=afpacket_hugepage_mode,
                        afpacket_hugepage_effective=afpacket_hugepage_effective,
                        afpacket_hugepage_reason=afpacket_hugepage_reason,
                        afpacket_hugepage_size_kb=afpacket_hugepage_size_kb,
                        afpacket_madvise_hugepage_ok=afpacket_madvise_hugepage_ok,
                        afpacket_mlock_ok=afpacket_mlock_ok,
                        afpacket_prefault_pages=afpacket_prefault_pages,
                        afpacket_smaps_kernel_page_kb=afpacket_smaps_kernel_page_kb,
                        afpacket_smaps_anon_hugepages_kb=afpacket_smaps_anon_hugepages_kb,
                        afpacket_ring_block_size=afpacket_ring_block_size,
                        afpacket_ring_block_nr=afpacket_ring_block_nr,
                        afpacket_ring_size_bytes=afpacket_ring_size_bytes,
                        txring_batch_target=txring_batch_target,
                        txring_backoff_ns=txring_backoff_ns,
                    )
                    return _attach_loss_telemetry(out, loss_before_snapshot, preferred_iface=loss_iface_hint)
            else:
                _register_fallback("txring_gateway_not_found")
                if verbose:
                    log_error("Gateway MAC not found for TX_RING, falling back to L3.")
        except Exception as e:
            _register_fallback("txring_error")
            if verbose:
                log_error(f"TX_RING failed, falling back to L3: {e}")
    elif try_txring and requested_backend == "txring":
        _register_fallback("txring_unavailable")

    if requested_backend == "auto" and (not allow_fallback) and fallback_count > 0:
        if owns_socket and s is not None:
            s.close()
        _update_live(live_progress, int(count))
        _update_live(live_errors, int(count))
        return _stats(
            attempted=count,
            sent=0,
            errors=count,
            sender_path="AUTO_PRIMARY_FAILED",
            permission_error_count=0,
            fallback_count=max(1, fallback_count),
            sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "auto_primary_failed",
            sender_backend_requested=requested_backend,
            sender_fallback_policy=fallback_policy,
            buffer_copy_count=buffer_copy_count,
            buffer_copy_bytes=buffer_copy_bytes,
            eagain_retry_count=eagain_retry_count,
            partial_send_retry_count=partial_send_retry_count,
            buffer_reuse_hits=buffer_reuse_hits,
        )

    if bool(force_l2) or requested_backend == "txring":
        if not allow_fallback:
            if owns_socket and s is not None:
                s.close()
            _update_live(live_progress, int(count))
            _update_live(live_errors, int(count))
            return _stats(
                attempted=count,
                sent=0,
                errors=count,
                sender_path="L2_UNAVAILABLE",
                permission_error_count=0,
                fallback_count=max(1, fallback_count),
                sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "l2_unavailable",
                sender_backend_requested=requested_backend,
                sender_fallback_policy=fallback_policy,
                buffer_copy_count=buffer_copy_count,
                buffer_copy_bytes=buffer_copy_bytes,
                eagain_retry_count=eagain_retry_count,
                partial_send_retry_count=partial_send_retry_count,
                buffer_reuse_hits=buffer_reuse_hits,
            )
        try_c_ext_l3 = True

    if FAST_SENDER_AVAILABLE and try_c_ext_l3 and hasattr(fast_sender, "send_optimized"):
        try:
            cext_result = fast_sender.send_optimized(
                s.fileno(), packets_buffer, target_ip, target_port, packet_size, count
            )
            if isinstance(cext_result, dict):
                sent = int(cext_result.get("sent", 0) or 0)
                eagain_retry_count += int(cext_result.get("eagain_retry_count", 0) or 0)
                partial_send_retry_count += int(cext_result.get("partial_send_retry_count", 0) or 0)
            else:
                sent = int(cext_result or 0)
            log_info(f"Fast Sender (C Ext L3) finished. Sent {sent} packets.")
            if owns_socket and s is not None:
                s.close()
            sent_total = sent
            _update_live(live_progress, count)
            _update_live(live_sent, sent_total)
            _update_live(live_errors, max(0, count - sent_total))
            out = _stats(
                attempted=count,
                sent=sent_total,
                errors=max(0, count - sent_total),
                bytes_sent_est=sent_total * packet_size,
                sender_path="C_EXT_L3",
                permission_error_count=0,
                fallback_count=fallback_count,
                sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "none",
                sender_backend_requested=requested_backend,
                sender_fallback_policy=fallback_policy,
                buffer_copy_count=buffer_copy_count,
                buffer_copy_bytes=buffer_copy_bytes,
                eagain_retry_count=eagain_retry_count,
                partial_send_retry_count=partial_send_retry_count,
                buffer_reuse_hits=buffer_reuse_hits,
            )
            return _attach_loss_telemetry(out, loss_before_snapshot, preferred_iface=loss_iface_hint)
        except Exception as e:
            _register_fallback("c_ext_l3_error")
            log_error(f"Fast Sender failed: {e}")
    elif try_c_ext_l3 and requested_backend == "c_ext_l3":
        _register_fallback("c_ext_l3_unavailable")
        if not allow_fallback:
            if owns_socket and s is not None:
                s.close()
            _update_live(live_progress, int(count))
            _update_live(live_errors, int(count))
            return _stats(
                attempted=count,
                sent=0,
                errors=count,
                sender_path="C_EXT_UNAVAILABLE",
                permission_error_count=0,
                fallback_count=max(1, fallback_count),
                sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "c_ext_l3_unavailable",
                sender_backend_requested=requested_backend,
                sender_fallback_policy=fallback_policy,
                buffer_copy_count=buffer_copy_count,
                buffer_copy_bytes=buffer_copy_bytes,
                eagain_retry_count=eagain_retry_count,
                partial_send_retry_count=partial_send_retry_count,
                buffer_reuse_hits=buffer_reuse_hits,
            )

    if owns_socket and s is not None:
        s.close()
    if FAST_SENDER_AVAILABLE and hasattr(fast_sender, "cleanup_ring"):
        fast_sender.cleanup_ring()
    _update_live(live_progress, int(count))
    _update_live(live_errors, int(count))
    out = _stats(
        attempted=count,
        sent=0,
        errors=count,
        bytes_sent_est=0,
        sender_path="C_EXT_UNAVAILABLE",
        permission_error_count=permission_error_count,
        fallback_count=max(1, int(fallback_count)),
        sender_fallback_reason=";".join(fallback_reasons) if fallback_reasons else "c_ext_l3_unavailable",
        sender_backend_requested=requested_backend,
        sender_fallback_policy=fallback_policy,
        buffer_copy_count=buffer_copy_count,
        buffer_copy_bytes=buffer_copy_bytes,
        eagain_retry_count=eagain_retry_count,
        partial_send_retry_count=partial_send_retry_count,
        buffer_reuse_hits=0,
        txring_flush_call_count=txring_flush_call_count,
        txring_flush_error_count=txring_flush_error_count,
        txring_flush_eagain_count=txring_flush_eagain_count,
        txring_flush_enobufs_count=txring_flush_enobufs_count,
        txring_flush_ebusy_count=txring_flush_ebusy_count,
        txring_flush_other_errno_count=txring_flush_other_errno_count,
        txring_flush_last_errno=txring_flush_last_errno,
        txring_flush_last_errno_name=txring_flush_last_errno_name,
        txring_frame_wait_ns=txring_frame_wait_ns,
        txring_poll_count=txring_poll_count,
        flush_mode=flush_mode,
        txring_tp_packets=txring_tp_packets,
        txring_tp_drops=txring_tp_drops,
        txring_tp_freeze_q_cnt=txring_tp_freeze_q_cnt,
        txring_packet_version=txring_packet_version,
        txring_packet_version_name=txring_packet_version_name,
        txring_batch_target=txring_batch_target,
        txring_backoff_ns=txring_backoff_ns,
    )
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
