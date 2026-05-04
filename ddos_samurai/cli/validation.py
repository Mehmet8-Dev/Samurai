"""CLI validation and preflight checks."""

import argparse
import json
import multiprocessing
import os

from .. import utils
from ..profile_names import PROFILE_NONE
from ..topology_native import parse_compile_topology_spec, topology_tuple_preview
from .helpers import _normalize_afpacket_hugepage_mode, _normalize_dataplane_core_mode
def _validate_pacing_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    mode = str(getattr(args, "pacing_mode", "none") or "none").strip().lower()
    rps = float(getattr(args, "rps", 0.0) or 0.0)
    ipg = int(getattr(args, "ipg", 0) or 0)
    burst_size = int(getattr(args, "burst_size", 64) or 0)
    burst_gap = int(getattr(args, "burst_gap", 0) or 0)
    jitter_pct = float(getattr(args, "jitter_pct", 0.0) or 0.0)

    if mode == "rps" and rps <= 0:
        parser.error("Hata: --pacing-mode rps için --rps > 0 olmalıdır.")
    if mode == "ipg" and ipg <= 0:
        parser.error("Hata: --pacing-mode ipg için --ipg > 0 olmalıdır.")
    if mode == "burst" and burst_size < 1:
        parser.error("Hata: --pacing-mode burst için --burst-size >= 1 olmalıdır.")
    if burst_gap < 0:
        parser.error("Hata: --burst-gap >= 0 olmalıdır.")
    if jitter_pct < 0.0 or jitter_pct > 1.0:
        parser.error("Hata: --jitter-pct 0.0 ile 1.0 aralığında olmalıdır.")

    # Keep legacy auto-promote behavior: --rps without explicit pacing mode.
    if mode == "none" and rps > 0:
        utils.log_info(
            "--rps > 0 ve --pacing-mode none: worker tarafında pacing-mode otomatik rps'e yükseltilecek."
        )


def _validate_hybrid_cuda_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    # Unified sanity checks for new hybrid CUDA + state engine knobs.
    for name in (
        "gpu_template_pool_size_l4",
        "gpu_template_pool_size_l7",
        "gpu_ring_capacity",
        "gpu_batch_size",
        "gpu_stream_count",
        "gpu_pipeline_depth",
        "gpu_pinned_max_mb",
        "state_table_size",
        "state_lock_count",
        "state_timeout_sec",
        "state_sweep_interval_ms",
    ):
        value = int(getattr(args, name, 0) or 0)
        if value <= 0:
            parser.error(f"Hata: --{name.replace('_', '-')} pozitif bir tamsayı olmalıdır.")

    table_size = int(getattr(args, "state_table_size", 65536) or 65536)
    lock_count = int(getattr(args, "state_lock_count", 256) or 256)
    if table_size % lock_count != 0:
        parser.error("Hata: --state-table-size değeri --state-lock-count değerine tam bölünmelidir.")
    rng_seed = int(getattr(args, "gpu_rng_seed", 1234) or 0)
    if rng_seed < 0 or rng_seed > 0xFFFFFFFF:
        parser.error("Hata: --gpu-rng-seed 0..4294967295 aralığında olmalıdır.")


def _validate_sender_route_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    sender_backend = str(getattr(args, "sender_backend", "xdp") or "xdp").strip().lower()
    fallback_policy = str(getattr(args, "sender_fallback_policy", "fail") or "fail").strip().lower()
    dataplane_core_mode = _normalize_dataplane_core_mode(getattr(args, "dataplane_core_mode", "off"))
    afpacket_hugepage_mode = _normalize_afpacket_hugepage_mode(
        getattr(args, "afpacket_hugepage_mode", "off")
    )
    args.afpacket_hugepage_mode = afpacket_hugepage_mode
    xdp_enable = bool(getattr(args, "xdp_enable", False))
    xdp_interface = str(getattr(args, "xdp_interface", "") or "").strip()
    xdp_attach_bpf = bool(getattr(args, "xdp_attach_bpf", True))
    xdp_bpf_section = str(getattr(args, "xdp_bpf_section", "xdp_sock") or "").strip()
    lab_profile = str(getattr(args, "lab_profile", "off") or "off").strip().lower()
    dp_queue_strategy = str(getattr(args, "dp_queue_strategy", "rr") or "rr").strip().lower()
    dp_queue_map = str(getattr(args, "dp_queue_map", "") or "").strip()
    l7_quic_require_native = bool(getattr(args, "l7_quic_require_native", False))
    l7_quic_engine = str(getattr(args, "l7_quic_engine", "auto") or "auto").strip().lower()
    l7_quic_auto_bridge = bool(getattr(args, "l7_quic_auto_bridge", False))
    l7_quic_bridge_autopromote = bool(getattr(args, "l7_quic_bridge_autopromote", False))
    attack_vector = str(getattr(args, "attack_vector", "basic") or "basic").strip().lower()
    scenario_mode = str(getattr(args, "scenario_mode", "off") or "off").strip().lower()
    scenario_file = str(getattr(args, "scenario_file", "") or "").strip()
    l7_template_mode = str(getattr(args, "l7_template_mode", "compat") or "compat").strip().lower()
    runtime_backend = str(getattr(args, "stateful_runtime_backend", "afxdp") or "afxdp").strip().lower()
    topo_spec_json = str(getattr(args, "topo_spec_json", "") or "").strip()
    topo_seed = int(getattr(args, "topo_seed", -1) or -1)
    topo_strict = bool(getattr(args, "topo_strict", True))

    if int(getattr(args, "xdp_queue_id", 0) or 0) < 0:
        parser.error("Hata: --xdp-queue-id >= 0 olmalıdır.")
    if int(getattr(args, "xdp_mode", 0) or 0) not in {0, 1, 2}:
        parser.error("Hata: --xdp-mode 0(SKB), 1(Native), 2(Offload) olmalıdır.")
    if int(getattr(args, "dp_queues", 1) or 0) <= 0:
        parser.error("Hata: --dp-queues >= 1 olmalıdır.")
    if int(getattr(args, "afpacket_hugepage_size_kb", 2048) or 0) <= 0:
        parser.error("Hata: --afpacket-hugepage-size-kb >= 1 olmalıdır.")
    if int(getattr(args, "afpacket_ring_target_mb", 64) or 0) <= 0:
        parser.error("Hata: --afpacket-ring-target-mb >= 1 olmalıdır.")
    if int(getattr(args, "afpacket_block_size_kb", 0) or 0) < 0:
        parser.error("Hata: --afpacket-block-size-kb >= 0 olmalıdır (0=auto).")
    if int(getattr(args, "afpacket_frame_size", 0) or 0) < 0:
        parser.error("Hata: --afpacket-frame-size >= 0 olmalıdır (0=auto).")
    if int(getattr(args, "afpacket_frames_per_block", 64) or 0) <= 0:
        parser.error("Hata: --afpacket-frames-per-block >= 1 olmalıdır.")
    if int(getattr(args, "afpacket_poll_timeout_ms", 1) or 0) < 0:
        parser.error("Hata: --afpacket-poll-timeout-ms >= 0 olmalıdır.")
    if int(getattr(args, "afpacket_spin_limit", 2000) or 0) < 0:
        parser.error("Hata: --afpacket-spin-limit >= 0 olmalıdır.")
    if int(getattr(args, "afpacket_busy_poll_us", 0) or 0) < 0:
        parser.error("Hata: --afpacket-busy-poll-us >= 0 olmalıdır.")
    if int(getattr(args, "http2_connections", 1) or 0) <= 0:
        parser.error("Hata: --http2-connections >= 1 olmalıdır.")
    if int(getattr(args, "http2_streams_per_conn", 100) or 0) <= 0:
        parser.error("Hata: --http2-streams-per-conn >= 1 olmalıdır.")
    if int(getattr(args, "l7_session_repeats", 1) or 0) <= 0:
        parser.error("Hata: --l7-session-repeats >= 1 olmalıdır.")
    if int(getattr(args, "l7_max_active_sessions", 0) or 0) < 0:
        parser.error("Hata: --l7-max-active-sessions >= 0 olmalıdır.")
    if int(getattr(args, "quic_streams_per_conn", 0) or 0) < 0:
        parser.error("Hata: --quic-streams-per-conn >= 0 olmalıdır.")
    if int(getattr(args, "quic_requests_per_conn", 0) or 0) < 0:
        parser.error("Hata: --quic-requests-per-conn >= 0 olmalıdır.")
    if int(getattr(args, "quic_conn_pool_size", 1) or 0) < 1:
        parser.error("Hata: --quic-conn-pool-size >= 1 olmalıdır.")
    q_status_min = int(getattr(args, "quic_expect_status_min", 200) or 0)
    q_status_max = int(getattr(args, "quic_expect_status_max", 399) or 0)
    if q_status_min < 100 or q_status_min > 599:
        parser.error("Hata: --quic-expect-status-min 100..599 aralığında olmalıdır.")
    if q_status_max < 100 or q_status_max > 599:
        parser.error("Hata: --quic-expect-status-max 100..599 aralığında olmalıdır.")
    if q_status_max < q_status_min:
        parser.error("Hata: --quic-expect-status-max, --quic-expect-status-min değerinden küçük olamaz.")
    if int(getattr(args, "quic_min_response_body_bytes", 0) or 0) < 0:
        parser.error("Hata: --quic-min-response-body-bytes >= 0 olmalıdır.")
    if len(str(getattr(args, "quic_expect_header_name", "") or "")) > 63:
        parser.error("Hata: --quic-expect-header-name en fazla 63 karakter olmalıdır.")
    if len(str(getattr(args, "quic_expect_header_value_contains", "") or "")) > 159:
        parser.error("Hata: --quic-expect-header-value-contains en fazla 159 karakter olmalıdır.")
    if len(str(getattr(args, "quic_expect_body_substring", "") or "")) > 159:
        parser.error("Hata: --quic-expect-body-substring en fazla 159 karakter olmalıdır.")
    if sender_backend != "xdp":
        parser.error("Hata: kernel/legacy sender backend kaldırıldı; yalnızca --sender-backend xdp desteklenir.")
    if fallback_policy != "fail":
        parser.error("Hata: fallback kaldırıldı; yalnızca --sender-fallback-policy fail desteklenir.")
    if runtime_backend != "afxdp":
        parser.error("Hata: stateful runtime yalnızca afxdp desteklenir.")
    if xdp_enable and not xdp_interface:
        parser.error("Hata: XDP yolu için --xdp-interface zorunludur.")
    if (xdp_enable or sender_backend == "xdp") and xdp_attach_bpf and not xdp_bpf_section:
        parser.error("Hata: --xdp-attach-bpf açıkken --xdp-bpf-section boş olamaz.")
    if dataplane_core_mode == "required" and fallback_policy != "fail":
        parser.error("Hata: --dataplane-core-mode required için --sender-fallback-policy fail zorunludur.")
    if dp_queue_strategy == "map":
        if not dp_queue_map:
            parser.error("Hata: --dp-queue-strategy map için --dp-queue-map zorunludur.")
        try:
            _ = _parse_dp_queue_map(dp_queue_map)
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError) as exc:
            parser.error(f"Hata: --dp-queue-map formatı geçersiz: {exc}")
    if l7_template_mode not in {"compat", "profile"}:
        parser.error("Hata: --l7-template-mode compat veya profile olmalıdır.")
    if scenario_mode not in {"off", "shadow", "enforce"}:
        parser.error("Hata: --scenario-mode off|shadow|enforce olmalıdır.")
    if scenario_mode != "off":
        if not scenario_file:
            parser.error("Hata: --scenario-mode shadow/enforce için --scenario-file zorunludur.")
        if not os.path.isfile(scenario_file):
            parser.error("Hata: --scenario-file bulunamadı.")
        if attack_vector not in {"http", "http2", "basic"}:
            parser.error("Hata: scenario mode ilk fazda yalnızca HTTP/HTTP2 backend ile desteklenir.")
    if int(getattr(args, "scenario_vus", 0) or 0) < 0:
        parser.error("Hata: --scenario-vus >= 0 olmalıdır.")
    if int(getattr(args, "scenario_ramp_seconds", 0) or 0) < 0:
        parser.error("Hata: --scenario-ramp-seconds >= 0 olmalıdır.")
    if int(getattr(args, "scenario_max_session_seconds", 0) or 0) < 0:
        parser.error("Hata: --scenario-max-session-seconds >= 0 olmalıdır.")
    if topo_spec_json:
        if topo_seed < 0:
            parser.error("Hata: --topo-spec-json ile birlikte --topo-seed zorunludur (>=0).")
        spoof_enabled = bool(getattr(args, "spoof", False)) or bool(getattr(args, "realistic_spoof", False))
        spoof_mode = str(getattr(args, "spoof_mode", "realistic") or "realistic").strip().lower()
        spoof_subnet = str(getattr(args, "spoof_subnet", "") or "").strip()
        spoof_list = str(getattr(args, "spoof_list_file", "") or "").strip()
        spoof_ip = str(getattr(args, "spoof_ip", "") or "").strip()
        if spoof_enabled or spoof_subnet or spoof_list or spoof_ip or spoof_mode != "realistic":
            parser.error("Hata: topology aktifken legacy spoofing argümanları (--spoof*) kullanılamaz.")
        try:
            compiled_topology = parse_compile_topology_spec(
                topo_spec_json=topo_spec_json,
                topo_seed=topo_seed,
                topo_strict=topo_strict,
            )
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError) as exc:
            parser.error(f"Hata: topology spec geçersiz: {exc}")
        args.topology_enabled = True
        args.topology_plan_id = str(compiled_topology.plan_id)
        args.topology_seed = int(compiled_topology.seed)
        args.topology_client_pool_size = int(compiled_topology.client_pool_size)
        args.topology_server_pool_size = int(compiled_topology.server_pool_size)
        args.topology_tuple_alloc_fail = 0
        args.topology_compiled_plan_json = json.dumps(compiled_topology.as_dict(), sort_keys=True)
        args.topology_tuple_preview_json = json.dumps(
            topology_tuple_preview(compiled_topology, sample_size=8),
            sort_keys=True,
        )
    else:
        args.topology_enabled = False
        args.topology_plan_id = ""
        args.topology_seed = -1
        args.topology_client_pool_size = 0
        args.topology_server_pool_size = 0
        args.topology_tuple_alloc_fail = 0
        args.topology_compiled_plan_json = ""
        args.topology_tuple_preview_json = "[]"
    if attack_vector == "websocket":
        parser.error("Hata: unsupported_in_l7_emu_v1 - V1 WebSocket desteği henüz etkin değil.")
    if (
        bool(getattr(args, "kpi_hard_fail", False))
        and str(getattr(args, "kpi_gate_profile", "off") or "off") == "off"
        and lab_profile != "dedicated"
    ):
        parser.error("Hata: --kpi-hard-fail için --kpi-gate-profile off olamaz.")
    if l7_quic_require_native:
        if not bool(getattr(args, "l7_capability_strict", False)) and lab_profile != "dedicated":
            parser.error("Hata: --l7-quic-require-native için --l7-capability-strict zorunludur.")
        if l7_quic_engine == "python":
            parser.error("Hata: --l7-quic-require-native ile --l7-quic-engine python kullanılamaz.")
        if l7_quic_auto_bridge:
            parser.error("Hata: --l7-quic-require-native ile --l7-quic-auto-bridge birlikte kullanılamaz.")
        if l7_quic_bridge_autopromote:
            parser.error("Hata: --l7-quic-require-native ile --l7-quic-bridge-autopromote birlikte kullanılamaz.")
    if lab_profile == "dedicated":
        if sender_backend != "xdp":
            parser.error("Hata: --lab-profile dedicated için yalnızca --sender-backend xdp desteklenir.")
        if fallback_policy != "fail":
            parser.error("Hata: --lab-profile dedicated için --sender-fallback-policy fail zorunludur.")
        if int(getattr(args, "dp_queues", 1) or 1) < 1:
            parser.error("Hata: --lab-profile dedicated için --dp-queues >= 1 zorunludur.")


def _parse_dp_queue_map(raw: str) -> dict[int, int]:
    out: dict[int, int] = {}
    txt = str(raw or "").strip()
    if not txt:
        return out
    for token in txt.split(","):
        item = str(token).strip()
        if not item:
            continue
        if ":" not in item:
            raise ValueError(f"'{item}' 'worker:queue' formatında olmalı")
        worker_s, queue_s = item.split(":", 1)
        worker_id = int(worker_s.strip())
        queue_id = int(queue_s.strip())
        if worker_id <= 0:
            raise ValueError(f"worker_id > 0 olmalı: {worker_id}")
        if queue_id < 0:
            raise ValueError(f"queue_id >= 0 olmalı: {queue_id}")
        out[int(worker_id)] = int(queue_id)
    return out


def _resolve_worker_queue_map(
    *,
    workers: int,
    strategy: str,
    dp_queues: int,
    map_spec: str,
) -> dict[int, int]:
    workers = max(0, int(workers or 0))
    dp_queues = max(1, int(dp_queues or 1))
    strategy = str(strategy or "rr").strip().lower()
    out: dict[int, int] = {}
    if workers <= 0:
        return out
    if strategy == "map":
        parsed = _parse_dp_queue_map(map_spec)
        for wid in range(1, workers + 1):
            if wid not in parsed:
                raise ValueError(f"worker {wid} için queue map eksik")
            qid = int(parsed[wid])
            if qid >= dp_queues:
                raise ValueError(f"worker {wid} queue_id {qid} dp_queues({dp_queues}) sınırını aşıyor")
            out[wid] = qid
        return out
    for wid in range(1, workers + 1):
        if strategy == "pin":
            qid = min(wid - 1, dp_queues - 1)
        else:
            qid = (wid - 1) % dp_queues
        out[wid] = int(qid)
    return out


def _preflight_lab_profile(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    lab_profile = str(getattr(args, "lab_profile", "off") or "off").strip().lower()
    if lab_profile != "dedicated":
        return
    dp_core_mode = _normalize_dataplane_core_mode(getattr(args, "dataplane_core_mode", "off"))
    if dp_core_mode != "required":
        args.dataplane_core_mode = "required"
        utils.log_info("lab-profile=dedicated için --dataplane-core-mode otomatik required olarak ayarlandı.")
    if str(getattr(args, "kpi_gate_profile", "off") or "off").strip().lower() == "off":
        args.kpi_gate_profile = "dedicated_lab"
        utils.log_info("lab-profile=dedicated için --kpi-gate-profile otomatik dedicated_lab olarak ayarlandı.")
    if not bool(getattr(args, "kpi_hard_fail", False)):
        args.kpi_hard_fail = True
        utils.log_info("lab-profile=dedicated için --kpi-hard-fail otomatik etkinleştirildi.")
    if not bool(getattr(args, "l7_capability_strict", False)):
        args.l7_capability_strict = True
        utils.log_info("lab-profile=dedicated için --l7-capability-strict otomatik etkinleştirildi.")
    if str(getattr(args, "stateful_runtime_backend", "afxdp") or "afxdp").strip().lower() != "afxdp":
        args.stateful_runtime_backend = "afxdp"
        utils.log_info(
            "lab-profile=dedicated için --stateful-runtime-backend otomatik afxdp olarak ayarlandı."
        )
    if str(getattr(args, "custom_tcp_mode", "off") or "off").strip().lower() != "required":
        args.custom_tcp_mode = "required"
        utils.log_info("lab-profile=dedicated için --custom-tcp-mode otomatik required olarak ayarlandı.")
    if str(getattr(args, "custom_tcp_backend", "af_xdp") or "af_xdp").strip().lower() != "af_xdp":
        args.custom_tcp_backend = "af_xdp"
        utils.log_info("lab-profile=dedicated için --custom-tcp-backend otomatik af_xdp olarak ayarlandı.")
    if (
        str(getattr(args, "attack_vector", "basic") or "basic").strip().lower() == "quic"
        and not bool(getattr(args, "l7_quic_require_native", False))
    ):
        args.l7_quic_require_native = True
        utils.log_info("lab-profile=dedicated + QUIC için --l7-quic-require-native otomatik etkinleştirildi.")
    if bool(getattr(args, "l7_quic_require_native", False)):
        if bool(getattr(args, "l7_quic_auto_bridge", False)):
            args.l7_quic_auto_bridge = False
            utils.log_info("native QUIC zorunlu olduğu için --l7-quic-auto-bridge kapatıldı.")
        if bool(getattr(args, "l7_quic_bridge_autopromote", False)):
            args.l7_quic_bridge_autopromote = False
            utils.log_info("native QUIC zorunlu olduğu için --l7-quic-bridge-autopromote kapatıldı.")
        quic_build_mode = str(os.environ.get("SAMURAI_QUIC_BUILD_MODE", "auto") or "auto").strip().lower()
        if quic_build_mode != "native_required":
            os.environ["SAMURAI_QUIC_BUILD_MODE"] = "native_required"
            utils.log_info("native QUIC zorunluluğu için SAMURAI_QUIC_BUILD_MODE=native_required ayarlandı.")

    sender_backend = str(getattr(args, "sender_backend", "xdp") or "xdp").strip().lower()
    if sender_backend != "xdp":
        parser.error("Hata: dedicated profilde yalnızca xdp backend desteklenir.")

    workers = int(getattr(args, "workers", multiprocessing.cpu_count()) or 0)
    dp_queues = int(getattr(args, "dp_queues", 1) or 1)
    strategy = str(getattr(args, "dp_queue_strategy", "rr") or "rr")
    map_spec = str(getattr(args, "dp_queue_map", "") or "")
    qmap = _resolve_worker_queue_map(workers=workers, strategy=strategy, dp_queues=dp_queues, map_spec=map_spec)
    if strategy == "map":
        used = list(qmap.values())
        if len(used) != len(set(used)):
            parser.error("Hata: dedicated + map stratejisinde queue çakışmaları yasak (her worker tekil queue).")

    iface = str(getattr(args, "xdp_interface", "") or "").strip()
    if not iface:
        iface = str(getattr(args, "loss_iface", "") or "").strip()
    if not iface:
        parser.error("Hata: --lab-profile dedicated için --xdp-interface (veya --loss-iface) zorunludur.")
    try:
        from ..af_xdp_sender import get_interface_queue_count

        nic_tx_queues = int(get_interface_queue_count(iface) or 1)
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        nic_tx_queues = 1
    if dp_queues > nic_tx_queues:
        parser.error(
            f"Hata: --dp-queues ({dp_queues}) interface {iface} TX queue sayısından ({nic_tx_queues}) büyük olamaz."
        )
    for wid, qid in qmap.items():
        if qid >= nic_tx_queues:
            parser.error(
                f"Hata: worker {wid} queue_id {qid}, interface {iface} TX queue sınırını ({nic_tx_queues - 1}) aşıyor."
            )


def _preflight_persistent_tx_backend(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    gpu_kernel_mode = str(getattr(args, "gpu_kernel_mode", "batch") or "batch").strip().lower()
    gpu_stream_api = str(getattr(args, "gpu_stream_api", "compat") or "compat").strip().lower()
    if gpu_kernel_mode != "persistent" or gpu_stream_api != "stream":
        return

    raw_backend = str(os.environ.get("SAMURAI_GPU_TX_BACKEND", getattr(args, "gpu_tx_backend", "auto")) or "auto")
    backend = raw_backend.strip().lower()
    strict_raw = str(os.environ.get("SAMURAI_GPU_TX_BACKEND_STRICT", "0") or "0").strip().lower()
    strict_enabled = strict_raw in {"1", "true", "yes", "on"}

    # Production bootstrap default: persistent+stream must run a verified backend by default.
    if backend in {"", "auto", "noop"}:
        backend = "af_xdp"
        os.environ["SAMURAI_GPU_TX_BACKEND"] = backend
        utils.log_info(
            "persistent+stream için SAMURAI_GPU_TX_BACKEND doğrulanmış varsayılan olarak af_xdp ayarlandı."
        )

    if backend not in {"af_xdp", "af_packet"}:
        parser.error(
            "Hata: persistent+stream modunda SAMURAI_GPU_TX_BACKEND yalnızca af_xdp veya af_packet olabilir."
        )

    if not strict_enabled:
        os.environ["SAMURAI_GPU_TX_BACKEND_STRICT"] = "1"
        utils.log_info(
            "persistent+stream için SAMURAI_GPU_TX_BACKEND_STRICT=1 otomatik etkinleştirildi (fail-fast preflight)."
        )

    if backend == "af_xdp":
        xdp_iface = str(getattr(args, "xdp_interface", "") or "").strip()
        if not xdp_iface:
            parser.error(
                "Hata: persistent+stream + af_xdp strict backend için --xdp-interface zorunludur."
            )


def _preflight_l7_capabilities(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not bool(getattr(args, "l7_capability_strict", False)):
        return

    attack_vector = str(getattr(args, "attack_vector", "basic") or "basic").strip().lower()
    if attack_vector in {"websocket", "quic"}:
        parser.error("Hata: L7 capability strict yalnızca HTTP/1.1 ve HTTP/2 için kullanılabilir.")

    runtime_backend = str(getattr(args, "stateful_runtime_backend", "afxdp") or "afxdp").strip().lower()
    if runtime_backend != "afxdp":
        parser.error("Hata: --stateful-runtime-backend yalnızca afxdp olabilir.")
    xdp_iface = str(getattr(args, "xdp_interface", "") or "").strip()
    if not xdp_iface:
        parser.error(
            "Hata: stateful-runtime-backend=afxdp + l7-capability-strict için --xdp-interface zorunludur."
        )
    if attack_vector == "http":
        custom_tcp_mode = str(getattr(args, "custom_tcp_mode", "off") or "off").strip().lower()
        if custom_tcp_mode not in {"auto", "required"}:
            parser.error(
                "Hata: HTTP strict AF_XDP runtime için --custom-tcp-mode auto|required olmalıdır."
            )


def _parse_label_mix(raw: str) -> dict:
    out = {}
    text = str(raw or "").strip()
    if not text:
        return out
    for chunk in [x.strip() for x in text.split(",") if x.strip()]:
        if "=" not in chunk:
            raise ValueError(f"invalid label-mix entry: {chunk}")
        k, v = chunk.split("=", 1)
        key = str(k or "").strip().lower()
        val = float(v)
        if val < 0.0:
            raise ValueError(f"negative label weight: {chunk}")
        out[key] = val
    if out:
        s = sum(float(v) for v in out.values())
        if s > 0:
            out = {k: float(v) / float(s) for k, v in out.items()}
    return out


def _traffic_model_protocols_for_attack_vector(attack_vector: str) -> list[str]:
    vec = str(attack_vector or "").strip().lower()
    if vec == "http":
        return ["http1"]
    if vec == "http2":
        return ["http2"]
    if vec == "websocket":
        return ["websocket"]
    if vec == "quic":
        return ["quic"]
    return []
