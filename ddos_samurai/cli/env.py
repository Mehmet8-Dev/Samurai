"""Environment helpers and runtime env synchronization."""

from __future__ import annotations

import os

from .helpers import _normalize_afpacket_hugepage_mode, _normalize_dataplane_core_mode


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)) or default)
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        return int(default)


def _env_flag(name: str, default: str = "0") -> bool:
    raw = str(os.environ.get(name, default) or default).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def sync_runtime_env(args) -> dict[str, object]:
    os.environ["SAMURAI_LOSS_TELEMETRY"] = str(getattr(args, "loss_telemetry", "auto"))
    os.environ["SAMURAI_LOSS_FAIL_PCT"] = str(float(getattr(args, "loss_fail_pct", 5.0) or 5.0))
    loss_iface = str(getattr(args, "loss_iface", "") or "").strip()
    if loss_iface:
        os.environ["SAMURAI_LOSS_IFACE"] = loss_iface
    else:
        os.environ.pop("SAMURAI_LOSS_IFACE", None)
    loss_report_out = str(getattr(args, "loss_report_out", "") or "").strip()
    if loss_report_out:
        os.environ["SAMURAI_LOSS_REPORT_OUT"] = loss_report_out
    else:
        os.environ.pop("SAMURAI_LOSS_REPORT_OUT", None)

    os.environ["SAMURAI_GPU_TEMPLATE_POOL_SIZE_L4"] = str(int(getattr(args, "gpu_template_pool_size_l4", 10) or 10))
    os.environ["SAMURAI_GPU_TEMPLATE_POOL_SIZE_L7"] = str(int(getattr(args, "gpu_template_pool_size_l7", 50) or 50))
    os.environ["SAMURAI_GPU_RING_CAPACITY"] = str(int(getattr(args, "gpu_ring_capacity", 3) or 3))
    os.environ["SAMURAI_GPU_BATCH"] = str(int(getattr(args, "gpu_batch_size", 100000) or 100000))
    os.environ["SAMURAI_GPU_STREAMS"] = str(int(getattr(args, "gpu_stream_count", 3) or 3))
    os.environ["SAMURAI_GPU_PIPELINE_DEPTH"] = str(int(getattr(args, "gpu_pipeline_depth", 2) or 2))
    os.environ["SAMURAI_GPU_FULL_VARIATION"] = "1" if bool(getattr(args, "gpu_full_variation", True)) else "0"
    os.environ["SAMURAI_GPU_PINNED_MAX_MB"] = str(int(getattr(args, "gpu_pinned_max_mb", 512) or 512))
    os.environ["SAMURAI_GPU_PACKET_ZEROCOPY_OUTPUT"] = "1" if bool(getattr(args, "gpu_packet_zerocopy_output", False)) else "0"
    gpu_kernel_mode = str(getattr(args, "gpu_kernel_mode", "batch") or "batch").strip().lower()
    if gpu_kernel_mode not in {"batch", "persistent"}:
        gpu_kernel_mode = "batch"
    gpu_stream_api = str(getattr(args, "gpu_stream_api", "compat") or "compat").strip().lower()
    if gpu_stream_api not in {"compat", "stream"}:
        gpu_stream_api = "compat"
    os.environ["SAMURAI_GPU_KERNEL_MODE"] = gpu_kernel_mode
    os.environ["SAMURAI_GPU_STREAM_API"] = gpu_stream_api
    gpu_tx_backend = str(os.environ.get("SAMURAI_GPU_TX_BACKEND", getattr(args, "gpu_tx_backend", "auto")) or "auto").strip().lower()
    gpu_tx_backend_strict = _env_flag("SAMURAI_GPU_TX_BACKEND_STRICT", "0")
    if gpu_kernel_mode == "persistent" and gpu_stream_api == "stream":
        if gpu_tx_backend in {"", "auto", "noop"}:
            gpu_tx_backend = "af_xdp"
        gpu_tx_backend_strict = True
    os.environ["SAMURAI_GPU_TX_BACKEND"] = gpu_tx_backend
    os.environ["SAMURAI_GPU_TX_BACKEND_STRICT"] = "1" if gpu_tx_backend_strict else "0"
    os.environ["SAMURAI_GPU_EPOCH_MS"] = str(int(getattr(args, "gpu_epoch_ms", 50) or 50))
    os.environ["SAMURAI_GPU_QUEUE_COUNT"] = str(int(getattr(args, "gpu_queue_count", 1) or 1))
    os.environ["SAMURAI_GPU_HEARTBEAT_MS"] = str(int(getattr(args, "gpu_heartbeat_ms", 500) or 500))
    os.environ["SAMURAI_GPU_NO_PROGRESS_MS"] = str(int(getattr(args, "gpu_no_progress_ms", 2000) or 2000))
    os.environ["SAMURAI_GPU_RNG_SEED"] = str(int(getattr(args, "gpu_rng_seed", 1234) or 0))
    gpu_defense_mode = str(getattr(args, "gpu_defense_mode", "off") or "off").strip().lower()
    if gpu_defense_mode not in {"on", "off"}:
        gpu_defense_mode = "off"
    os.environ["SAMURAI_GPU_DEFENSE_MODE"] = gpu_defense_mode
    os.environ["SAMURAI_GPU_CLASSIFIER_RUNTIME"] = str(getattr(args, "gpu_classifier_runtime", "tensorrt") or "tensorrt")
    os.environ["SAMURAI_GPU_CLASSIFIER_ENGINE_PATH"] = str(getattr(args, "gpu_classifier_engine_path", "") or "")
    gpu_rdma_mode = str(getattr(args, "gpu_rdma_mode", "auto") or "auto").strip().lower()
    if gpu_rdma_mode not in {"auto", "direct", "host_staging"}:
        gpu_rdma_mode = "auto"
    os.environ["SAMURAI_GPU_RDMA_MODE"] = gpu_rdma_mode
    os.environ["SAMURAI_GPU_RDMA_STRICT"] = "1" if bool(getattr(args, "gpu_rdma_strict", False)) else "0"
    os.environ["SAMURAI_GPU_BATCH_MAX"] = str(int(getattr(args, "gpu_batch_max", 1024) or 1024))
    os.environ["SAMURAI_GPU_BATCH_FLUSH_TIMEOUT_MS"] = str(int(getattr(args, "gpu_batch_flush_timeout_ms", 2) or 2))
    gpu_rx_pipeline = str(getattr(args, "gpu_rx_pipeline", "off") or "off").strip().lower()
    if gpu_rx_pipeline not in {"on", "off"}:
        gpu_rx_pipeline = "off"
    os.environ["SAMURAI_GPU_RX_PIPELINE"] = gpu_rx_pipeline
    os.environ["SAMURAI_GPU_RX_IFACE"] = str(getattr(args, "gpu_rx_iface", "") or "")
    os.environ["SAMURAI_GPU_RX_DURATION_S"] = str(int(getattr(args, "gpu_rx_duration_s", 10) or 10))
    os.environ["SAMURAI_GPU_RX_BATCH_SIZE"] = str(int(getattr(args, "gpu_rx_batch_size", 256) or 256))
    os.environ["SAMURAI_GPU_RX_MAX_PACKETS"] = str(int(getattr(args, "gpu_rx_max_packets", 100000) or 100000))
    os.environ["SAMURAI_GPU_RX_SNAPLEN"] = str(int(getattr(args, "gpu_rx_snaplen", 2048) or 2048))
    os.environ["SAMURAI_STATE_TABLE_SIZE"] = str(int(getattr(args, "state_table_size", 65536) or 65536))
    os.environ["SAMURAI_STATE_LOCK_COUNT"] = str(int(getattr(args, "state_lock_count", 256) or 256))
    os.environ["SAMURAI_STATE_TIMEOUT_SEC"] = str(int(getattr(args, "state_timeout_sec", 60) or 60))
    os.environ["SAMURAI_STATE_SWEEP_INTERVAL_MS"] = str(int(getattr(args, "state_sweep_interval_ms", 1000) or 1000))
    os.environ["SAMURAI_SENDER_BACKEND"] = str(getattr(args, "sender_backend", "auto") or "auto")
    os.environ["SAMURAI_SENDER_FALLBACK_POLICY"] = str(getattr(args, "sender_fallback_policy", "allow") or "allow")

    dp_mode = _normalize_dataplane_core_mode(getattr(args, "dataplane_core_mode", "off"))
    os.environ["SAMURAI_DATAPLANE_CORE_MODE"] = dp_mode
    os.environ["SAMURAI_DATAPLANE_CORE_ENABLE"] = "1" if dp_mode in {"auto", "required"} else "0"

    afpacket_hp_mode = _normalize_afpacket_hugepage_mode(getattr(args, "afpacket_hugepage_mode", "off"))
    os.environ["SAMURAI_AF_PACKET_HUGEPAGE_MODE"] = afpacket_hp_mode
    os.environ["SAMURAI_AF_PACKET_HUGEPAGE_SIZE_KB"] = str(int(getattr(args, "afpacket_hugepage_size_kb", 2048) or 2048))
    os.environ["SAMURAI_AF_PACKET_RING_TARGET_MB"] = str(int(getattr(args, "afpacket_ring_target_mb", 64) or 64))
    os.environ["SAMURAI_AF_PACKET_BLOCK_SIZE_KB"] = str(int(getattr(args, "afpacket_block_size_kb", 0) or 0))
    os.environ["SAMURAI_AF_PACKET_FRAME_SIZE"] = str(int(getattr(args, "afpacket_frame_size", 0) or 0))
    os.environ["SAMURAI_AF_PACKET_FRAMES_PER_BLOCK"] = str(int(getattr(args, "afpacket_frames_per_block", 64) or 64))
    os.environ["SAMURAI_AF_PACKET_POLL_TIMEOUT_MS"] = str(int(getattr(args, "afpacket_poll_timeout_ms", 1) or 1))
    os.environ["SAMURAI_AF_PACKET_SPIN_LIMIT"] = str(int(getattr(args, "afpacket_spin_limit", 2000) or 2000))
    os.environ["SAMURAI_AF_PACKET_BUSY_POLL_US"] = str(int(getattr(args, "afpacket_busy_poll_us", 0) or 0))
    os.environ["SAMURAI_AF_PACKET_QDISC_BYPASS"] = "1" if bool(getattr(args, "afpacket_qdisc_bypass", True)) else "0"
    os.environ["SAMURAI_AF_PACKET_MLOCK_RING"] = "1" if bool(getattr(args, "afpacket_mlock_ring", False)) else "0"
    os.environ["SAMURAI_AF_PACKET_PREFAULT_RING"] = "1" if bool(getattr(args, "afpacket_prefault_ring", True)) else "0"

    os.environ["SAMURAI_LAB_PROFILE"] = str(getattr(args, "lab_profile", "off") or "off")
    os.environ["SAMURAI_DP_QUEUE_STRATEGY"] = str(getattr(args, "dp_queue_strategy", "rr") or "rr")
    os.environ["SAMURAI_DP_QUEUES"] = str(int(getattr(args, "dp_queues", 1) or 1))
    os.environ["SAMURAI_DP_QUEUE_MAP"] = str(getattr(args, "dp_queue_map", "") or "")
    os.environ["SAMURAI_XDP_ENABLE"] = "1" if bool(getattr(args, "xdp_enable", False)) else "0"
    os.environ["SAMURAI_XDP_INTERFACE"] = str(getattr(args, "xdp_interface", "") or "")
    os.environ["SAMURAI_XDP_QUEUE_ID"] = str(int(getattr(args, "xdp_queue_id", 0) or 0))
    os.environ["SAMURAI_XDP_MODE"] = str(int(getattr(args, "xdp_mode", 0) or 0))
    os.environ["SAMURAI_XDP_ATTACH_BPF"] = "1" if bool(getattr(args, "xdp_attach_bpf", True)) else "0"
    os.environ["SAMURAI_XDP_BPF_SECTION"] = str(getattr(args, "xdp_bpf_section", "xdp_sock") or "xdp_sock")
    os.environ["SAMURAI_XDP_BPF_OBJ"] = str(getattr(args, "xdp_bpf_obj", "") or "")
    os.environ["SAMURAI_XDP_XSKMAP_PIN"] = str(getattr(args, "xdp_xskmap_pin", "") or "")

    os.environ["SAMURAI_KPI_GATE_PROFILE"] = str(getattr(args, "kpi_gate_profile", "off") or "off")
    os.environ["SAMURAI_KPI_HARD_FAIL"] = "1" if bool(getattr(args, "kpi_hard_fail", False)) else "0"
    os.environ["SAMURAI_L7_ENGINE"] = str(getattr(args, "l7_engine", "python") or "python")
    os.environ["SAMURAI_L7_HTTP2_ENGINE"] = str(getattr(args, "l7_http2_engine", "auto") or "auto")
    os.environ["SAMURAI_L7_QUIC_ENGINE"] = str(getattr(args, "l7_quic_engine", "auto") or "auto")
    os.environ["SAMURAI_L7_QUIC_REQUIRE_NATIVE"] = "1" if bool(getattr(args, "l7_quic_require_native", False)) else "0"
    os.environ["SAMURAI_L7_QUIC_AUTO_BRIDGE"] = "1" if bool(getattr(args, "l7_quic_auto_bridge", False)) else "0"
    os.environ["SAMURAI_L7_QUIC_BRIDGE_AUTOPROMOTE"] = "1" if bool(getattr(args, "l7_quic_bridge_autopromote", False)) else "0"
    os.environ["SAMURAI_L7_FALLBACK_POLICY"] = str(getattr(args, "l7_fallback_policy", "allow") or "allow")
    os.environ["SAMURAI_L7_CAPABILITY_STRICT"] = "1" if bool(getattr(args, "l7_capability_strict", False)) else "0"
    stateful_runtime_backend = str(getattr(args, "stateful_runtime_backend", "afxdp") or "afxdp").strip().lower()
    if stateful_runtime_backend not in {"afxdp", "dpdk"}:
        stateful_runtime_backend = "afxdp"
    os.environ["SAMURAI_STATEFUL_RUNTIME_BACKEND"] = stateful_runtime_backend
    os.environ["SAMURAI_CUSTOM_TCP_MODE"] = str(getattr(args, "custom_tcp_mode", "off") or "off")
    os.environ["SAMURAI_CUSTOM_TCP_BACKEND"] = str(getattr(args, "custom_tcp_backend", "af_xdp") or "af_xdp")

    return {
        "loss_report_out": loss_report_out,
        "loss_iface": loss_iface,
        "dataplane_core_mode": dp_mode,
        "afpacket_hugepage_mode": afpacket_hp_mode,
    }
