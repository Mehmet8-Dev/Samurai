import time
from typing import Any, Dict


def get_gateway_info(
    target_ip,
    *,
    gateway_cache: Dict[str, Any],
    gateway_cache_ttl_sec: float,
    scapy_getter,
    log_info,
    log_error,
):
    """Resolve output interface and gateway MAC for target IP."""
    cached = gateway_cache.get(target_ip)
    if cached is not None:
        ts, iface, mac_bytes = cached
        if (time.monotonic() - ts) <= gateway_cache_ttl_sec:
            return iface, mac_bytes
    try:
        scapy = scapy_getter()
        conf = scapy.conf
        getmacbyip = scapy.getmacbyip
        # conf.route.route(target_ip) returns (iface, gw_ip, src_ip)
        res = conf.route.route(target_ip)
        iface = res[0]
        gw_ip = res[1]

        # Resolve gateway MAC
        mac_str = getmacbyip(gw_ip)

        if not mac_str:
            # Fallback: /proc/net/arp
            try:
                with open("/proc/net/arp", "r") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] == gw_ip:
                            mac_str = parts[3]
                            if mac_str != "00:00:00:00:00:00":
                                break
                            mac_str = None
            except Exception:
                pass

        if not mac_str:
            # Fallback: local network target MAC
            mac_str = getmacbyip(target_ip)

        if not mac_str:
            log_error(f"Could not resolve MAC for gateway {gw_ip} or target {target_ip}")
            return iface, None

        mac_bytes = bytes.fromhex(mac_str.replace(":", ""))
        log_info(f"Gateway MAC resolved: {mac_str} ({len(mac_bytes)} bytes) on {iface}")
        gateway_cache[target_ip] = (time.monotonic(), iface, mac_bytes)
        return iface, mac_bytes
    except Exception as e:
        # ScapyUnavailableError and generic failures are handled uniformly here.
        log_error(f"get_gateway_info error: {e}")
        return None, None


async def xdp_sender(
    packets_buffer: bytes,
    target_ip: str,
    target_port: int,
    count: int,
    verbose: bool = False,
    interface: str = None,
    queue_id: int = 0,
    xdp_mode: int = 0,
    batch_size: int = 64,
    sender_fallback_policy: str = "allow",
    fallback_backend: str = "python",
    sender_context: Dict[str, Any] | None = None,
    *,
    resolve_sender_fallback_policy_fn,
    resolve_sender_backend_fn,
    raw_socket_sender_fn,
    normalize_packets_buffer_fn,
    stats_fn,
    log_info,
    log_warning,
    log_error,
    XDP_AVAILABLE: bool,
    XDPSender,
    check_xdp_available,
) -> dict:
    """
    Send packets using AF_XDP (copy mode compatibility path) with fallback.
    """
    fallback_policy = resolve_sender_fallback_policy_fn(sender_fallback_policy)
    fallback_backend = resolve_sender_backend_fn(fallback_backend)
    xdp_mode = int(xdp_mode or 0)

    async def _fallback(reason: str, details: str = "") -> dict:
        if details:
            log_warning(f"[XDP] {details}")
        if fallback_policy == "fail":
            return stats_fn(
                attempted=count,
                sent=0,
                errors=count,
                sender_path="XDP_UNAVAILABLE",
                fallback_count=1,
                sender_fallback_reason=str(reason),
                sender_backend_requested="xdp",
                sender_fallback_policy=fallback_policy,
            )
        out = await raw_socket_sender_fn(
            packets_buffer,
            target_ip,
            target_port,
            count,
            verbose,
            sender_backend=fallback_backend,
            sender_fallback_policy=fallback_policy,
            sender_context=sender_context,
        )
        out = dict(out or {})
        out["sender_backend_requested"] = "xdp"
        out["sender_fallback_policy"] = fallback_policy
        out["fallback_count"] = int(out.get("fallback_count", 0) or 0) + 1
        if not str(out.get("sender_fallback_reason", "") or "").strip():
            out["sender_fallback_reason"] = str(reason)
        elif str(out.get("sender_fallback_reason", "")).strip().lower() == "none":
            out["sender_fallback_reason"] = str(reason)
        return out

    if not XDP_AVAILABLE:
        return await _fallback(
            reason="xdp_module_unavailable",
            details="AF_XDP module not available. Build with: python setup.py build_ext --inplace",
        )

    available, msg = check_xdp_available()
    if not available:
        return await _fallback(reason="xdp_unavailable", details=f"Not available: {msg}")

    packet_size = len(packets_buffer) // count if count > 0 else 0
    if packet_size == 0:
        log_error("[XDP] Invalid packet buffer")
        return stats_fn(
            attempted=count,
            sent=0,
            errors=count,
            sender_path="XDP_INVALID_BUFFER",
            sender_fallback_reason="xdp_invalid_buffer",
            sender_backend_requested="xdp",
            sender_fallback_policy=fallback_policy,
        )
    packets_buffer, normalize_meta = normalize_packets_buffer_fn(
        packets_buffer,
        required_bytes=packet_size * count,
        pool_key="senders_xdp_tx",
        return_meta=True,
    )
    first_packet = memoryview(packets_buffer)[:packet_size] if packet_size > 0 else memoryview(b"")
    has_l2_ipv4 = (
        packet_size >= 34
        and ((int(first_packet[14]) >> 4) in (4, 6))
    )
    l3_only_candidate = (
        packet_size >= 20
        and ((int(first_packet[0]) >> 4) in (4, 6))
        and not has_l2_ipv4
    )
    if l3_only_candidate:
        return await _fallback(
            reason="xdp_l2_header_missing",
            details=(
                "AF_XDP TX yolu Ethernet(L2) frame bekliyor; gelen buffer L3-only görünüyor. "
                "Raw sender fallback uygulanıyor."
            ),
        )

    log_info(f"[XDP] Initializing AF_XDP sender for {target_ip}:{target_port}")
    log_info(
        f"[XDP] Packets: {count}, Packet Size: {packet_size} bytes, "
        f"Batch Size: {batch_size}, Mode: {xdp_mode}"
    )

    total_sent = 0
    sender_path = "XDP_L2"
    fallback_reason = "none"
    fallback_count = 0
    mode2_policy = "hard" if fallback_policy == "fail" else "soft"
    persistent_sender = False
    sender = None

    try:
        if isinstance(sender_context, dict):
            cached = sender_context.get("xdp_sender_instance")
            cached_cfg = dict(sender_context.get("xdp_sender_cfg") or {})
            wanted_cfg = {
                "interface": str(interface or ""),
                "queue_id": int(queue_id or 0),
                "mode": int(xdp_mode or 0),
                "batch_size": int(batch_size or 64),
            }
            if cached is not None and hasattr(cached, "is_running"):
                if (
                    cached_cfg.get("interface") == wanted_cfg["interface"]
                    and int(cached_cfg.get("queue_id", -1)) == wanted_cfg["queue_id"]
                    and int(cached_cfg.get("mode", -1)) == wanted_cfg["mode"]
                    and int(cached_cfg.get("batch_size", -1)) == wanted_cfg["batch_size"]
                ):
                    sender = cached
                    if not bool(getattr(sender, "is_running", False)):
                        sender.start()
                    persistent_sender = True
                else:
                    try:
                        cached.stop()
                    except Exception:
                        pass
                    sender_context.pop("xdp_sender_instance", None)
                    sender_context.pop("xdp_sender_cfg", None)

            if sender is None:
                sender = XDPSender(
                    interface=interface,
                    queue_id=int(queue_id or 0),
                    mode=int(xdp_mode or 0),
                    batch_size=batch_size,
                    auto_fallback=True,
                    mode2_policy=mode2_policy,
                )
                sender.start()
                sender_context["xdp_sender_instance"] = sender
                sender_context["xdp_sender_cfg"] = wanted_cfg
                persistent_sender = True
        else:
            sender = XDPSender(
                interface=interface,
                queue_id=int(queue_id or 0),
                mode=int(xdp_mode or 0),
                batch_size=batch_size,
                auto_fallback=True,
                mode2_policy=mode2_policy,
            )
            sender.start()

        if sender.is_using_xdp:
            log_info(f"[XDP] Using AF_XDP on interface: {sender.interface}")
        else:
            log_info(f"[XDP] Using fallback mode on interface: {sender.interface}")
            sender_path = "XDP_INTERNAL_FALLBACK"
            fallback_reason = "xdp_internal_fallback"
            fallback_count = 1
            if fallback_policy == "fail":
                if not persistent_sender:
                    sender.stop()
                return stats_fn(
                    attempted=count,
                    sent=0,
                    errors=count,
                    sender_path="XDP_UNAVAILABLE",
                    fallback_count=1,
                    sender_fallback_reason=fallback_reason,
                    sender_backend_requested="xdp",
                    sender_fallback_policy=fallback_policy,
                    buffer_copy_count=int(normalize_meta.get("buffer_copy_count", 0) or 0),
                    buffer_copy_bytes=int(normalize_meta.get("buffer_copy_bytes", 0) or 0),
                )

        if hasattr(sender, "send_buffer"):
            sent = sender.send_buffer(packets_buffer, packet_size, count)
            total_sent = int(sent or 0)
        else:
            mv = memoryview(packets_buffer)
            needs_bytes = False
            batch_start = 0
            while batch_start < count:
                batch_end = min(batch_start + batch_size, count)
                batch_views = []
                for i in range(batch_start, batch_end):
                    start = i * packet_size
                    end = start + packet_size
                    batch_views.append(mv[start:end])

                if needs_bytes:
                    sent = sender.send([bytes(v) for v in batch_views])
                else:
                    try:
                        sent = sender.send(batch_views)
                    except TypeError:
                        needs_bytes = True
                        sent = sender.send([bytes(v) for v in batch_views])

                total_sent += sent

                if verbose and total_sent % 10000 < batch_size:
                    stats = sender.get_stats()
                    log_info(
                        f"[XDP] Progress: {total_sent}/{count} packets, "
                        f"{stats.packets_per_second:.0f} pps, {stats.mbps:.2f} Mbps"
                    )
                batch_start = batch_end

        stats = sender.get_stats()
        log_info(
            f"[XDP] Completed: {stats.tx_packets:,} packets, "
            f"{stats.tx_bytes:,} bytes, "
            f"{stats.packets_per_second:,.0f} pps, "
            f"{stats.mbps:.2f} Mbps"
        )
        if not persistent_sender:
            sender.stop()

    except Exception as e:
        log_error(f"[XDP] Error: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        if sender is not None and not persistent_sender:
            try:
                sender.stop()
            except Exception:
                pass
        return await _fallback(reason="xdp_runtime_error", details=f"Runtime error: {e}")

    return stats_fn(
        attempted=count,
        sent=total_sent,
        errors=max(0, count - total_sent),
        bytes_sent_est=total_sent * packet_size,
        sender_path=sender_path,
        fallback_count=fallback_count,
        sender_fallback_reason=fallback_reason,
        sender_backend_requested="xdp",
        sender_fallback_policy=fallback_policy,
        buffer_copy_count=int(normalize_meta.get("buffer_copy_count", 0) or 0),
        buffer_copy_bytes=int(normalize_meta.get("buffer_copy_bytes", 0) or 0),
        eagain_retry_count=0,
        partial_send_retry_count=0,
    )
