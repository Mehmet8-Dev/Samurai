from __future__ import annotations

import json
import os
import platform
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


_REPORT_DIAGNOSTIC_RESULT_PREFIXES: Tuple[str, ...] = ("txring_",)
_REPORT_DIAGNOSTIC_RESULT_KEYS = {"flush_mode"}
_REPORT_DIAGNOSTIC_RESULT_EXPOSED_KEYS = {
    "txring_packet_version",
    "txring_packet_version_name",
    "txring_batch_target",
    "txring_backoff_ns",
}


def _sanitize_results_for_report_output(results: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in dict(results or {}).items():
        key = str(k)
        if key in _REPORT_DIAGNOSTIC_RESULT_KEYS:
            continue
        if (
            any(key.startswith(prefix) for prefix in _REPORT_DIAGNOSTIC_RESULT_PREFIXES)
            and key not in _REPORT_DIAGNOSTIC_RESULT_EXPOSED_KEYS
        ):
            continue
        out[key] = v
    return out


def _report_to_output_dict(report: "RunReport") -> Dict[str, Any]:
    d = report.to_dict()
    d["results"] = _sanitize_results_for_report_output(d.get("results", {}) or {})
    return d

def collect_system_snapshot() -> Dict[str, Any]:
    snap: Dict[str, Any] = {
        "timestamp_utc": _utc_now_iso(),
        "cpu_count": os.cpu_count(),
    }

    try:
        la = os.getloadavg()
        snap["loadavg_1_5_15"] = [float(la[0]), float(la[1]), float(la[2])]
    except Exception:
        pass

    # Linux-only best-effort memory info
    try:
        if os.path.exists("/proc/meminfo"):
            mem: Dict[str, int] = {}
            with open("/proc/meminfo", "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if ":" not in line:
                        continue
                    k, rest = line.split(":", 1)
                    parts = rest.strip().split()
                    if not parts:
                        continue
                    try:
                        v = int(parts[0])
                    except Exception:
                        continue
                    unit = parts[1].lower() if len(parts) > 1 else ""
                    # meminfo is typically kB
                    if unit == "kb":
                        v *= 1024
                    mem[k] = v
            # Keep only high-signal keys.
            for k in ("MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached", "SwapTotal", "SwapFree"):
                if k in mem:
                    snap[k] = mem[k]
    except Exception:
        pass

    return snap


def _safe_stat(path: str) -> Dict[str, Any]:
    try:
        st = os.stat(path)
        return {
            "path": path,
            "exists": True,
            "size_bytes": int(st.st_size),
            "mtime_utc": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(timespec="seconds"),
        }
    except Exception:
        return {"path": path, "exists": False}


def _try_maxrss_kb() -> Optional[int]:
    # Works on Linux/macOS. Not available on Windows.
    try:
        import resource  # type: ignore

        r = resource.getrusage(resource.RUSAGE_SELF)
        # ru_maxrss is kilobytes on Linux, bytes on macOS. Detect crudely.
        v = int(getattr(r, "ru_maxrss", 0) or 0)
        if v <= 0:
            return None
        if platform.system().lower() == "darwin":
            return int(v / 1024)
        return v
    except Exception:
        return None


def collect_environment() -> Dict[str, Any]:
    env: Dict[str, Any] = {
        "timestamp_utc": _utc_now_iso(),
        "python": {
            "version": sys.version.split()[0],
            "executable": sys.executable,
            "implementation": platform.python_implementation(),
        },
        "os": {
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "process": {
            "pid": os.getpid(),
            "cwd": os.getcwd(),
            "maxrss_kb": _try_maxrss_kb(),
        },
        "capabilities": {},
    }

    # Optional CUDA/GPU info (best-effort; safe if missing).
    try:
        import cupy as cp  # type: ignore

        try:
            dev = cp.cuda.Device()
            props = cp.cuda.runtime.getDeviceProperties(int(dev.id))
            name = props.get("name", b"")
            if isinstance(name, (bytes, bytearray)):
                name = name.decode(errors="replace")
            env["gpu"] = {
                "available": True,
                "device_id": int(dev.id),
                "name": str(name),
            }
        except Exception:
            env["gpu"] = {"available": True}
    except Exception:
        env["gpu"] = {"available": False}

    try:
        from . import get_capabilities  # type: ignore

        env["capabilities"] = get_capabilities() or {}
    except Exception:
        env["capabilities"] = {}

    return env


@dataclass
class Artifact:
    kind: str
    path: str
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RunReport:
    schema_version: str = "1"
    run_id: str = ""
    started_utc: str = ""
    finished_utc: str = ""
    duration_s: float = 0.0
    mode: str = ""
    metrics: Dict[str, Any] = field(default_factory=dict)
    inputs: Dict[str, Any] = field(default_factory=dict)
    results: Dict[str, Any] = field(default_factory=dict)
    environment: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[Artifact] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Ensure dataclass list items serialize cleanly
        d["artifacts"] = [asdict(a) for a in self.artifacts]
        return d


def write_json(report: RunReport, out_path: str) -> str:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(_report_to_output_dict(report), indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(p)
    return str(p)

def write_text(text: str, out_path: str) -> str:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8", errors="replace")
    tmp.replace(p)
    return str(p)


def _md_kv_table(d: Dict[str, Any]) -> str:
    lines = ["| Key | Value |", "|---|---|"]
    for k, v in d.items():
        vv = json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else str(v)
        lines.append(f"| `{k}` | {vv} |")
    return "\n".join(lines)


def write_markdown(report: RunReport, out_path: str) -> str:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    env = report.environment or {}
    results = _sanitize_results_for_report_output(report.results or {})

    lines: List[str] = []
    lines.append("# Run Report")
    lines.append("")
    lines.append(_md_kv_table({
        "run_id": report.run_id,
        "mode": report.mode,
        "started_utc": report.started_utc,
        "finished_utc": report.finished_utc,
        "duration_s": f"{report.duration_s:.3f}",
    }))
    lines.append("")

    lines.append("## Inputs")
    lines.append("")
    lines.append(_md_kv_table(report.inputs or {}))
    lines.append("")

    lines.append("## Results")
    lines.append("")
    lines.append(_md_kv_table(results))
    lines.append("")

    if report.metrics:
        lines.append("## Metrics")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(report.metrics, indent=2, ensure_ascii=False))
        lines.append("```")
        lines.append("")

    lines.append("## Artifacts")
    lines.append("")
    if report.artifacts:
        lines.append("| Kind | Path | Meta |")
        lines.append("|---|---|---|")
        for a in report.artifacts:
            meta = json.dumps(a.meta, ensure_ascii=False) if a.meta else ""
            lines.append(f"| `{a.kind}` | `{a.path}` | {meta} |")
    else:
        lines.append("_No artifacts_")
    lines.append("")

    lines.append("## Environment")
    lines.append("")
    # Keep environment concise; include a few high-signal fields only.
    env_summary: Dict[str, Any] = {
        "python": env.get("python", {}),
        "os": env.get("os", {}),
        "gpu": env.get("gpu", {}),
        "process": env.get("process", {}),
    }
    lines.append("```json")
    lines.append(json.dumps(env_summary, indent=2, ensure_ascii=False))
    lines.append("```")
    lines.append("")

    if report.warnings:
        lines.append("## Warnings")
        lines.append("")
        for w in report.warnings:
            lines.append(f"- {w}")
        lines.append("")

    p.write_text("\n".join(lines), encoding="utf-8")
    return str(p)

def _metric_name(key: str) -> str:
    # Prometheus metric name sanitization (very small subset).
    out = []
    for ch in str(key):
        if ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ("0" <= ch <= "9") or ch in ("_", ":"):
            out.append(ch)
        else:
            out.append("_")
    s = "".join(out)
    if not s or (not (s[0].isalpha() or s[0] in ("_", ":"))):
        s = "m_" + s
    return s


def _flatten_numbers(d: Any, *, prefix: str, out: Dict[str, float]) -> None:
    if isinstance(d, bool):
        out[prefix] = 1.0 if d else 0.0
        return
    if isinstance(d, (int, float)) and not isinstance(d, bool):
        out[prefix] = float(d)
        return
    if isinstance(d, dict):
        for k, v in d.items():
            if k is None:
                continue
            key = f"{prefix}_{k}" if prefix else str(k)
            _flatten_numbers(v, prefix=key, out=out)
        return
    # Ignore lists/strings/bytes/None/objects by default.


def export_prometheus(report: RunReport, *, prefix: str = "samurai") -> str:
    """Best-effort Prometheus exposition for offline/test monitoring.

    This is intentionally minimal and numeric-only.
    """
    flat: Dict[str, float] = {}
    _flatten_numbers({"duration_s": report.duration_s}, prefix="run", out=flat)
    _flatten_numbers(_sanitize_results_for_report_output(report.results or {}), prefix="results", out=flat)
    _flatten_numbers(report.metrics or {}, prefix="metrics", out=flat)

    lines = []
    for k, v in sorted(flat.items()):
        name = _metric_name(f"{prefix}_{k}")
        # No labels here to avoid high-cardinality in a file-based exporter.
        lines.append(f"{name} {v}")
    lines.append("")
    return "\n".join(lines)


def write_metrics_files(report: RunReport, base_path: str) -> Dict[str, str]:
    """Write additional machine-friendly metrics artifacts next to the run report.

    Files:
    - <base>.metrics.json: structured metrics snapshot
    - <base>.metrics.prom: Prometheus exposition (numeric-only)
    """
    p = Path(base_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    metrics_json = {
        "run_id": report.run_id,
        "mode": report.mode,
        "started_utc": report.started_utc,
        "finished_utc": report.finished_utc,
        "duration_s": report.duration_s,
        "metrics": report.metrics or {},
    }
    out_json = str(p) + ".metrics.json"
    write_text(json.dumps(metrics_json, indent=2, sort_keys=True), out_json)

    out_prom = str(p) + ".metrics.prom"
    write_text(export_prometheus(report), out_prom)

    return {"metrics_json": out_json, "metrics_prom": out_prom}


def build_gpu_pcap_report(
    *,
    cfg: Any,
    pcap_path: str,
    realism: Optional[Dict[str, Any]] = None,
    realism_path: Optional[str] = None,
    duration_s: float,
    metrics: Optional[Dict[str, Any]] = None,
    warnings: Optional[List[str]] = None,
) -> RunReport:
    run_id = f"gpu-pcap-{int(time.time())}"
    inputs = {
        "duration_s": getattr(cfg, "duration_s", None),
        "pps": getattr(cfg, "pps", None),
        "mode": getattr(cfg, "mode", None),
        "src_ip": getattr(cfg, "src_ip", None),
        "dst_ip": getattr(cfg, "dst_ip", None),
        "tcp_dport": getattr(cfg, "tcp_dport", None),
        "udp_dport": getattr(cfg, "udp_dport", None),
        "chunk_size": getattr(cfg, "chunk_size", None),
        "seed": getattr(cfg, "seed", None),
        "flow_count": getattr(cfg, "flow_count", None),
        "realistic": getattr(cfg, "realistic", None),
        "udp_checksum": getattr(cfg, "udp_checksum", None),
        "variable_size": getattr(cfg, "variable_size", None),
        "mtu": getattr(cfg, "mtu", None),
        "size_profile": getattr(cfg, "size_profile", None),
    }

    packets_total = None
    try:
        dur = int(getattr(cfg, "duration_s", 0) or 0)
        pps = int(getattr(cfg, "pps", 0) or 0)
        if dur > 0 and pps > 0:
            packets_total = dur * pps
    except Exception:
        packets_total = None

    pcap_stat = _safe_stat(pcap_path)
    results: Dict[str, Any] = {
        "pcap": pcap_stat,
        "packets_estimated": packets_total,
        "throughput_estimated_pps": (packets_total / duration_s) if (packets_total and duration_s > 0) else None,
        "duration_wall_s": duration_s,
        "system_snapshot": collect_system_snapshot(),
    }
    if realism:
        results["realism"] = realism
    if realism_path:
        results["realism_report"] = _safe_stat(realism_path)

    report = RunReport(
        run_id=run_id,
        started_utc="",  # caller fills for better accuracy
        finished_utc="",
        duration_s=float(duration_s),
        mode="gpu_pcap",
        metrics=dict(metrics or {}),
        inputs=inputs,
        results=results,
        environment=collect_environment(),
        artifacts=[
            Artifact(kind="pcap", path=pcap_path, meta=pcap_stat),
        ],
        warnings=list(warnings or []),
    )
    if realism_path:
        report.artifacts.append(Artifact(kind="realism_json", path=realism_path, meta=_safe_stat(realism_path)))
    return report


def build_dry_run_report(
    *,
    args: Dict[str, Any],
    packet_len: int,
    packet_hex_prefix: str,
    duration_s: float,
    metrics: Optional[Dict[str, Any]] = None,
    warnings: Optional[List[str]] = None,
) -> RunReport:
    run_id = f"dry-run-{int(time.time())}"
    report = RunReport(
        run_id=run_id,
        started_utc="",
        finished_utc="",
        duration_s=float(duration_s),
        mode="dry_run",
        metrics=dict(metrics or {}),
        inputs={"args": args},
        results={
            "sample_packet_len": int(packet_len),
            "sample_packet_hex_prefix": packet_hex_prefix,
            "system_snapshot": collect_system_snapshot(),
        },
        environment=collect_environment(),
        artifacts=[],
        warnings=list(warnings or []),
    )
    return report


def build_self_test_report(
    *,
    summary: Dict[str, Any],
    log_path: Optional[str],
    duration_s: float,
    metrics: Optional[Dict[str, Any]] = None,
    warnings: Optional[List[str]] = None,
) -> RunReport:
    run_id = f"self-test-{int(time.time())}"
    artifacts: List[Artifact] = []
    if log_path:
        artifacts.append(Artifact(kind="self_test_log", path=str(log_path), meta=_safe_stat(str(log_path))))

    report = RunReport(
        run_id=run_id,
        started_utc="",
        finished_utc="",
        duration_s=float(duration_s),
        mode="self_test",
        metrics=dict(metrics or {}),
        inputs={},
        results={
            "tests_run": int(summary.get("tests_run", 0) or 0),
            "failures": int(summary.get("failures", 0) or 0),
            "errors": int(summary.get("errors", 0) or 0),
            "skipped": int(summary.get("skipped", 0) or 0),
            "successful": bool(summary.get("successful", False)),
            "system_snapshot": collect_system_snapshot(),
        },
        environment=collect_environment(),
        artifacts=artifacts,
        warnings=list(warnings or []),
    )
    return report


def build_live_attack_report(
    *,
    args: Dict[str, Any],
    worker_events: List[Dict[str, Any]],
    duration_s: float,
    progress_total: int,
    total_count: int,
    metrics: Optional[Dict[str, Any]] = None,
    warnings: Optional[List[str]] = None,
) -> RunReport:
    run_id = f"live-run-{int(time.time())}"

    workers_total = 0
    workers_ok = 0
    workers_degraded = 0
    workers_failed = 0
    workers_interrupted = 0
    attempted_total = 0
    sent_total = 0
    errors_total = 0
    bytes_sent_est_total = 0
    permission_error_count_total = 0
    fallback_count_total = 0
    sender_fallback_reason = "none"
    buffer_copy_count_total = 0
    buffer_copy_bytes_total = 0
    buffer_reuse_hits_total = 0
    eagain_retry_count_total = 0
    partial_send_retry_count_total = 0
    pacing_weight_total = 0
    actual_rps_weighted_sum = 0.0
    rate_accuracy_weighted_sum = 0.0
    jitter_p99_weighted_sum = 0.0
    ipg_mean_weighted_sum = 0.0
    sleep_calls_total = 0
    busywait_cycles_total = 0
    so_txtime_active_any = 0
    txtime_errors_total = 0
    txring_flush_call_count_total = 0
    txring_flush_error_count_total = 0
    txring_flush_eagain_count_total = 0
    txring_flush_enobufs_count_total = 0
    txring_flush_ebusy_count_total = 0
    txring_flush_other_errno_count_total = 0
    txring_flush_last_errno = 0
    txring_flush_last_errno_name = "NONE"
    txring_frame_wait_ns_total = 0
    txring_poll_count_total = 0
    flush_mode = "unknown"
    txring_tp_packets_total = 0
    txring_tp_drops_total = 0
    txring_tp_freeze_q_cnt_total = 0
    txring_packet_version = 0
    txring_packet_version_name = "TPACKET_UNKNOWN"
    txring_batch_target_max = 0
    txring_backoff_ns_total = 0
    host_tx_packets_delta_total = 0
    host_tx_dropped_delta_total = 0
    host_tx_errors_delta_total = 0
    softnet_dropped_delta_total = 0
    softnet_time_squeeze_delta_total = 0
    wire_counter_available_workers = 0
    wire_counter_missing_workers = 0
    wire_counter_confidence_max = 0.0
    wire_counter_source = "none"
    wire_counter_reason = ""
    wire_tx_packets_delta_total = 0
    wire_tx_dropped_delta_total = 0
    wire_tx_errors_delta_total = 0
    wire_tx_bytes_delta_total = 0
    nicq_counter_available_workers = 0
    nicq_counter_missing_workers = 0
    nicq_counter_confidence_max = 0.0
    nicq_counter_source = "none"
    nicq_counter_reason = ""
    nicq_pressure_delta_total = 0
    nicq_drop_delta_total = 0
    nicq_fifo_delta_total = 0
    nicq_timeout_delta_total = 0
    nicq_restart_delta_total = 0
    nicq_busy_delta_total = 0
    nicq_pressure_status = "unknown"
    wire_tx_accounted_packets_total = 0
    wire_tx_over_attempted_packets_total = 0
    wire_loss_measurement_mode = "unknown"
    wire_loss_est_packets_total = 0
    wire_loss_raw_packets_total = 0
    wire_loss_raw_uncapped_packets_total = 0
    wire_loss_estimation_capped_total = 0
    gpu_template_h2d_copy_count_total = 0
    gpu_template_h2d_copy_bytes_total = 0
    gpu_rng_state_alloc_count_total = 0
    gpu_rng_state_reuse_count_total = 0
    gpu_ring_depth_peak_max = 0
    gpu_ring_block_wait_ns_total = 0
    state_active_entries_max = 0
    state_timeout_evictions_total = 0
    state_overwrites_total = 0
    l7_active_sessions_peak_max = 0
    l7_conn_rate_weighted_sum = 0.0
    l7_conn_rate_weight = 0
    l7_handshake_p99_ms_max = 0.0
    l7_step_fail_ratio_weighted_sum = 0.0
    l7_step_fail_ratio_weight = 0
    session_success_rate_weighted_sum = 0.0
    session_success_rate_weight = 0
    retry_success_rate_weighted_sum = 0.0
    retry_success_rate_weight = 0
    l7_engine_path_used = ""
    l7_fallback_reason = "none"
    l7_capability_status = "ok"
    h2_goaway_count_total = 0
    h2_stream_resets_total = 0
    h2_connections_used_total = 0
    h2_request_plan_used_any = 0
    h2_request_plan_items_total = 0
    h2_stream_reset_ratio_weighted_sum = 0.0
    h2_stream_reset_ratio_weight = 0
    quic_connect_fail_count_total = 0
    quic_connect_timeout_count_total = 0
    quic_tls_fail_count_total = 0
    quic_handshake_timeout_count_total = 0
    quic_stream_fail_count_total = 0
    quic_stream_fail_ratio_weighted_sum = 0.0
    quic_stream_fail_ratio_weight = 0
    quic_handshake_fail_ratio_weighted_sum = 0.0
    quic_handshake_fail_ratio_weight = 0
    dp_queue_ids_used: set[int] = set()
    dp_affinity_cpus_used: set[int] = set()
    dp_queue_strategy = "unknown"
    backlog_peak_max = 0
    sender_paths_used: Dict[str, int] = {}
    by_vector: Dict[str, Dict[str, int]] = {}
    by_backend: Dict[str, Dict[str, int]] = {}
    worker_errors: List[Dict[str, Any]] = []

    for ev in list(worker_events or []):
        if not isinstance(ev, dict):
            continue
        workers_total += 1
        status = str(ev.get("status", "unknown"))
        if status == "ok":
            workers_ok += 1
        elif status == "degraded":
            workers_degraded += 1
        elif status == "interrupted":
            workers_interrupted += 1
        else:
            workers_failed += 1
            if ev.get("error"):
                worker_errors.append(
                    {
                        "worker_id": ev.get("worker_id"),
                        "status": status,
                        "error": str(ev.get("error")),
                    }
                )

        st = ev.get("stats") or {}
        attempted = int(st.get("attempted", 0) or 0)
        sent = int(st.get("sent", 0) or 0)
        errors = int(st.get("errors", 0) or 0)
        bytes_sent = int(st.get("bytes_sent_est", 0) or 0)
        attempted_total += attempted
        sent_total += sent
        errors_total += errors
        bytes_sent_est_total += bytes_sent

        # Aggregate sender path / fallback / permission metrics
        _sp = str(ev.get("sender_path", st.get("sender_path", "unknown")) or "").strip() or "unknown"
        sender_paths_used[_sp] = sender_paths_used.get(_sp, 0) + 1
        permission_error_count_total += int(
            ev.get("permission_error_count", st.get("permission_error_count", 0)) or 0
        )
        fallback_count_total += int(
            ev.get("fallback_count", st.get("fallback_count", 0)) or 0
        )
        _fallback_reason_item = str(
            ev.get("sender_fallback_reason", st.get("sender_fallback_reason", "")) or ""
        ).strip()
        if _fallback_reason_item:
            if sender_fallback_reason in ("", "none"):
                sender_fallback_reason = _fallback_reason_item
            elif sender_fallback_reason != _fallback_reason_item and sender_fallback_reason != "mixed":
                sender_fallback_reason = "mixed"
        buffer_copy_count_total += int(
            ev.get("buffer_copy_count", st.get("buffer_copy_count", 0)) or 0
        )
        buffer_copy_bytes_total += int(
            ev.get("buffer_copy_bytes", st.get("buffer_copy_bytes", 0)) or 0
        )
        buffer_reuse_hits_total += int(
            ev.get("buffer_reuse_hits", st.get("buffer_reuse_hits", 0)) or 0
        )
        eagain_retry_count_total += int(
            ev.get("eagain_retry_count", st.get("eagain_retry_count", 0)) or 0
        )
        partial_send_retry_count_total += int(
            ev.get("partial_send_retry_count", st.get("partial_send_retry_count", 0)) or 0
        )
        _w = int(max(0, attempted))
        _actual_rps = float(ev.get("actual_rps", st.get("actual_rps", 0.0)) or 0.0)
        _rate_accuracy = float(ev.get("rate_accuracy_pct", st.get("rate_accuracy_pct", 0.0)) or 0.0)
        _jitter_p99 = float(ev.get("jitter_p99_ns", st.get("jitter_p99_ns", 0.0)) or 0.0)
        _ipg_mean = float(ev.get("ipg_mean_ns", st.get("ipg_mean_ns", 0.0)) or 0.0)
        if _w > 0:
            pacing_weight_total += _w
            actual_rps_weighted_sum += (_actual_rps * _w)
            rate_accuracy_weighted_sum += (_rate_accuracy * _w)
            jitter_p99_weighted_sum += (_jitter_p99 * _w)
            ipg_mean_weighted_sum += (_ipg_mean * _w)
        sleep_calls_total += int(ev.get("sleep_calls", st.get("sleep_calls", 0)) or 0)
        busywait_cycles_total += int(ev.get("busywait_cycles", st.get("busywait_cycles", 0)) or 0)
        so_txtime_active_any = max(
            int(so_txtime_active_any),
            int(ev.get("so_txtime_active", st.get("so_txtime_active", 0)) or 0),
        )
        txtime_errors_total += int(ev.get("txtime_errors", st.get("txtime_errors", 0)) or 0)
        txring_flush_call_count_total += int(
            ev.get("txring_flush_call_count", st.get("txring_flush_call_count", 0)) or 0
        )
        txring_flush_error_count_total += int(
            ev.get("txring_flush_error_count", st.get("txring_flush_error_count", 0)) or 0
        )
        txring_flush_eagain_count_total += int(
            ev.get("txring_flush_eagain_count", st.get("txring_flush_eagain_count", 0)) or 0
        )
        txring_flush_enobufs_count_total += int(
            ev.get("txring_flush_enobufs_count", st.get("txring_flush_enobufs_count", 0)) or 0
        )
        txring_flush_ebusy_count_total += int(
            ev.get("txring_flush_ebusy_count", st.get("txring_flush_ebusy_count", 0)) or 0
        )
        txring_flush_other_errno_count_total += int(
            ev.get("txring_flush_other_errno_count", st.get("txring_flush_other_errno_count", 0)) or 0
        )
        _flush_last_errno = int(ev.get("txring_flush_last_errno", st.get("txring_flush_last_errno", 0)) or 0)
        _flush_last_errno_name = str(
            ev.get("txring_flush_last_errno_name", st.get("txring_flush_last_errno_name", "")) or ""
        ).strip()
        if _flush_last_errno or _flush_last_errno_name:
            txring_flush_last_errno = _flush_last_errno
            txring_flush_last_errno_name = _flush_last_errno_name or "OTHER"
        txring_frame_wait_ns_total += int(
            ev.get("txring_frame_wait_ns", st.get("txring_frame_wait_ns", 0)) or 0
        )
        txring_poll_count_total += int(
            ev.get("txring_poll_count", st.get("txring_poll_count", 0)) or 0
        )
        _flush_mode_item = str(ev.get("flush_mode", st.get("flush_mode", "")) or "").strip()
        if _flush_mode_item:
            if flush_mode in ("", "unknown"):
                flush_mode = _flush_mode_item
            elif flush_mode != _flush_mode_item:
                flush_mode = "mixed"
        txring_tp_packets_total += int(
            ev.get("txring_tp_packets", st.get("txring_tp_packets", 0)) or 0
        )
        txring_tp_drops_total += int(
            ev.get("txring_tp_drops", st.get("txring_tp_drops", 0)) or 0
        )
        txring_tp_freeze_q_cnt_total += int(
            ev.get("txring_tp_freeze_q_cnt", st.get("txring_tp_freeze_q_cnt", 0)) or 0
        )
        txring_batch_target_max = max(
            int(txring_batch_target_max),
            int(ev.get("txring_batch_target", st.get("txring_batch_target", 0)) or 0),
        )
        txring_backoff_ns_total += int(
            ev.get("txring_backoff_ns", st.get("txring_backoff_ns", 0)) or 0
        )
        _tp_ver = int(ev.get("txring_packet_version", st.get("txring_packet_version", 0)) or 0)
        _tp_ver_name = str(
            ev.get("txring_packet_version_name", st.get("txring_packet_version_name", "")) or ""
        ).strip()
        if _tp_ver > 0:
            if txring_packet_version <= 0:
                txring_packet_version = _tp_ver
                txring_packet_version_name = _tp_ver_name or "TPACKET_UNKNOWN"
            elif txring_packet_version != _tp_ver:
                txring_packet_version = 0
                txring_packet_version_name = "MIXED"
            elif txring_packet_version_name in ("", "TPACKET_UNKNOWN"):
                txring_packet_version_name = _tp_ver_name or "TPACKET_UNKNOWN"
        host_tx_packets_delta_total += int(
            ev.get("host_tx_packets_delta", st.get("host_tx_packets_delta", 0)) or 0
        )
        host_tx_dropped_delta_total += int(
            ev.get("host_tx_dropped_delta", st.get("host_tx_dropped_delta", 0)) or 0
        )
        host_tx_errors_delta_total += int(
            ev.get("host_tx_errors_delta", st.get("host_tx_errors_delta", 0)) or 0
        )
        softnet_dropped_delta_total += int(
            ev.get("softnet_dropped_delta", st.get("softnet_dropped_delta", 0)) or 0
        )
        softnet_time_squeeze_delta_total += int(
            ev.get("softnet_time_squeeze_delta", st.get("softnet_time_squeeze_delta", 0)) or 0
        )
        _legacy_host_tx_packets = int(
            ev.get("host_tx_packets_delta", st.get("host_tx_packets_delta", 0)) or 0
        )
        _legacy_host_tx_dropped = int(
            ev.get("host_tx_dropped_delta", st.get("host_tx_dropped_delta", 0)) or 0
        )
        _legacy_host_tx_errors = int(
            ev.get("host_tx_errors_delta", st.get("host_tx_errors_delta", 0)) or 0
        )
        _wire_tx_packets_delta = int(
            ev.get("wire_tx_packets_delta", st.get("wire_tx_packets_delta", _legacy_host_tx_packets)) or 0
        )
        _wire_tx_dropped_delta = int(
            ev.get("wire_tx_dropped_delta", st.get("wire_tx_dropped_delta", _legacy_host_tx_dropped)) or 0
        )
        _wire_tx_errors_delta = int(
            ev.get("wire_tx_errors_delta", st.get("wire_tx_errors_delta", _legacy_host_tx_errors)) or 0
        )
        _wire_tx_bytes_delta = int(
            ev.get("wire_tx_bytes_delta", st.get("wire_tx_bytes_delta", 0)) or 0
        )
        _wire_counter_available = int(
            ev.get(
                "wire_counter_available",
                st.get(
                    "wire_counter_available",
                    1 if (_wire_tx_packets_delta > 0 or _legacy_host_tx_packets > 0) else 0,
                ),
            )
            or 0
        )
        if _wire_counter_available > 0:
            wire_counter_available_workers += 1
        else:
            wire_counter_missing_workers += 1
        _wire_counter_confidence = float(
            ev.get("wire_counter_confidence", st.get("wire_counter_confidence", 0.0)) or 0.0
        )
        wire_counter_confidence_max = max(float(wire_counter_confidence_max), float(_wire_counter_confidence))
        _wire_counter_source_item = str(
            ev.get("wire_counter_source", st.get("wire_counter_source", "")) or ""
        ).strip()
        if _wire_counter_source_item:
            if wire_counter_source in ("", "none", "unknown"):
                wire_counter_source = _wire_counter_source_item
            elif wire_counter_source != _wire_counter_source_item and wire_counter_source != "mixed":
                wire_counter_source = "mixed"
        _wire_counter_reason_item = str(
            ev.get("wire_counter_reason", st.get("wire_counter_reason", "")) or ""
        ).strip()
        if _wire_counter_reason_item:
            if not wire_counter_reason:
                wire_counter_reason = _wire_counter_reason_item
            elif _wire_counter_reason_item not in wire_counter_reason:
                wire_counter_reason = f"{wire_counter_reason};{_wire_counter_reason_item}"
        _nicq_counter_available = int(
            ev.get(
                "nicq_counter_available",
                st.get(
                    "nicq_counter_available",
                    1 if (
                        int(ev.get("nicq_pressure_delta", st.get("nicq_pressure_delta", 0)) or 0) > 0
                        or int(ev.get("nicq_drop_delta", st.get("nicq_drop_delta", 0)) or 0) > 0
                    ) else 0,
                ),
            )
            or 0
        )
        if _nicq_counter_available > 0:
            nicq_counter_available_workers += 1
        else:
            nicq_counter_missing_workers += 1
        _nicq_counter_confidence = float(
            ev.get("nicq_counter_confidence", st.get("nicq_counter_confidence", 0.0)) or 0.0
        )
        nicq_counter_confidence_max = max(float(nicq_counter_confidence_max), float(_nicq_counter_confidence))
        _nicq_counter_source_item = str(
            ev.get("nicq_counter_source", st.get("nicq_counter_source", "")) or ""
        ).strip()
        if _nicq_counter_source_item:
            if nicq_counter_source in ("", "none", "unknown"):
                nicq_counter_source = _nicq_counter_source_item
            elif nicq_counter_source != _nicq_counter_source_item and nicq_counter_source != "mixed":
                nicq_counter_source = "mixed"
        _nicq_counter_reason_item = str(
            ev.get("nicq_counter_reason", st.get("nicq_counter_reason", "")) or ""
        ).strip()
        if _nicq_counter_reason_item:
            if not nicq_counter_reason:
                nicq_counter_reason = _nicq_counter_reason_item
            elif _nicq_counter_reason_item not in nicq_counter_reason:
                nicq_counter_reason = f"{nicq_counter_reason};{_nicq_counter_reason_item}"
        wire_tx_packets_delta_total += _wire_tx_packets_delta
        wire_tx_dropped_delta_total += _wire_tx_dropped_delta
        wire_tx_errors_delta_total += _wire_tx_errors_delta
        wire_tx_bytes_delta_total += _wire_tx_bytes_delta
        nicq_pressure_delta_total += int(
            ev.get("nicq_pressure_delta", st.get("nicq_pressure_delta", 0)) or 0
        )
        nicq_drop_delta_total += int(
            ev.get("nicq_drop_delta", st.get("nicq_drop_delta", 0)) or 0
        )
        nicq_fifo_delta_total += int(
            ev.get("nicq_fifo_delta", st.get("nicq_fifo_delta", 0)) or 0
        )
        nicq_timeout_delta_total += int(
            ev.get("nicq_timeout_delta", st.get("nicq_timeout_delta", 0)) or 0
        )
        nicq_restart_delta_total += int(
            ev.get("nicq_restart_delta", st.get("nicq_restart_delta", 0)) or 0
        )
        nicq_busy_delta_total += int(
            ev.get("nicq_busy_delta", st.get("nicq_busy_delta", 0)) or 0
        )
        _nicq_status_item = str(
            ev.get("nicq_pressure_status", st.get("nicq_pressure_status", "")) or ""
        ).strip()
        if _nicq_status_item:
            if nicq_pressure_status in ("", "unknown"):
                nicq_pressure_status = _nicq_status_item
            elif nicq_pressure_status != _nicq_status_item and nicq_pressure_status != "mixed":
                nicq_pressure_status = "mixed"
        wire_tx_accounted_packets_total += int(
            ev.get("wire_tx_accounted_packets", st.get("wire_tx_accounted_packets", 0)) or 0
        )
        wire_tx_over_attempted_packets_total += int(
            ev.get("wire_tx_over_attempted_packets", st.get("wire_tx_over_attempted_packets", 0)) or 0
        )
        _wire_measure_mode_item = str(
            ev.get("wire_loss_measurement_mode", st.get("wire_loss_measurement_mode", "")) or ""
        ).strip()
        if _wire_measure_mode_item:
            if wire_loss_measurement_mode in ("", "unknown"):
                wire_loss_measurement_mode = _wire_measure_mode_item
            elif wire_loss_measurement_mode != _wire_measure_mode_item and wire_loss_measurement_mode != "mixed":
                wire_loss_measurement_mode = "mixed"
        wire_loss_est_packets_total += int(
            ev.get("wire_loss_est_packets", st.get("wire_loss_est_packets", 0)) or 0
        )
        _raw_uncapped_ev = int(
            ev.get(
                "wire_loss_raw_uncapped_packets",
                st.get(
                    "wire_loss_raw_uncapped_packets",
                    ev.get("wire_loss_raw_packets", st.get("wire_loss_raw_packets", 0)),
                ),
            )
            or 0
        )
        wire_loss_raw_uncapped_packets_total += _raw_uncapped_ev
        wire_loss_raw_packets_total += int(
            ev.get("wire_loss_raw_packets", st.get("wire_loss_raw_packets", _raw_uncapped_ev)) or 0
        )
        wire_loss_estimation_capped_total += int(
            ev.get("wire_loss_estimation_capped", st.get("wire_loss_estimation_capped", 0)) or 0
        )
        gpu_template_h2d_copy_count_total += int(
            ev.get("gpu_template_h2d_copy_count", st.get("gpu_template_h2d_copy_count", 0)) or 0
        )
        gpu_template_h2d_copy_bytes_total += int(
            ev.get("gpu_template_h2d_copy_bytes", st.get("gpu_template_h2d_copy_bytes", 0)) or 0
        )
        gpu_rng_state_alloc_count_total += int(
            ev.get("gpu_rng_state_alloc_count", st.get("gpu_rng_state_alloc_count", 0)) or 0
        )
        gpu_rng_state_reuse_count_total += int(
            ev.get("gpu_rng_state_reuse_count", st.get("gpu_rng_state_reuse_count", 0)) or 0
        )
        _ring_depth = int(ev.get("gpu_ring_depth_peak", st.get("gpu_ring_depth_peak", 0)) or 0)
        if _ring_depth > gpu_ring_depth_peak_max:
            gpu_ring_depth_peak_max = _ring_depth
        gpu_ring_block_wait_ns_total += int(
            ev.get("gpu_ring_block_wait_ns", st.get("gpu_ring_block_wait_ns", 0)) or 0
        )
        _state_active = int(ev.get("state_active_entries", st.get("state_active_entries", 0)) or 0)
        if _state_active > state_active_entries_max:
            state_active_entries_max = _state_active
        state_timeout_evictions_total += int(
            ev.get("state_timeout_evictions", st.get("state_timeout_evictions", 0)) or 0
        )
        state_overwrites_total += int(
            ev.get("state_overwrites", st.get("state_overwrites", 0)) or 0
        )
        _l7_peak = int(ev.get("l7_active_sessions_peak", st.get("l7_active_sessions_peak", 0)) or 0)
        if _l7_peak > l7_active_sessions_peak_max:
            l7_active_sessions_peak_max = _l7_peak
        _l7_conn_rate = float(ev.get("l7_conn_rate", st.get("l7_conn_rate", 0.0)) or 0.0)
        if _l7_conn_rate > 0.0:
            l7_conn_rate_weighted_sum += (_l7_conn_rate * max(1, attempted))
            l7_conn_rate_weight += max(1, attempted)
        _l7_hs_p99 = float(ev.get("l7_handshake_p99_ms", st.get("l7_handshake_p99_ms", 0.0)) or 0.0)
        l7_handshake_p99_ms_max = max(float(l7_handshake_p99_ms_max), float(_l7_hs_p99))
        _l7_step_fail_ratio = float(ev.get("l7_step_fail_ratio", st.get("l7_step_fail_ratio", 0.0)) or 0.0)
        if _l7_step_fail_ratio > 0.0:
            l7_step_fail_ratio_weighted_sum += (_l7_step_fail_ratio * max(1, attempted))
            l7_step_fail_ratio_weight += max(1, attempted)
        _session_success_rate = float(ev.get("session_success_rate", st.get("session_success_rate", 0.0)) or 0.0)
        if _session_success_rate > 0.0:
            session_success_rate_weighted_sum += (_session_success_rate * max(1, attempted))
            session_success_rate_weight += max(1, attempted)
        _retry_success_rate = float(ev.get("retry_success_rate", st.get("retry_success_rate", 0.0)) or 0.0)
        if _retry_success_rate > 0.0:
            retry_success_rate_weighted_sum += (_retry_success_rate * max(1, attempted))
            retry_success_rate_weight += max(1, attempted)
        _l7_engine_path_item = str(
            ev.get("l7_engine_path_used", st.get("l7_engine_path_used", ""))
            or ""
        ).strip()
        if _l7_engine_path_item:
            if not l7_engine_path_used:
                l7_engine_path_used = _l7_engine_path_item
            elif l7_engine_path_used != _l7_engine_path_item and l7_engine_path_used != "mixed":
                l7_engine_path_used = "mixed"
        _l7_fallback_reason_item = str(
            ev.get("l7_fallback_reason", st.get("l7_fallback_reason", ""))
            or ""
        ).strip()
        if _l7_fallback_reason_item:
            if l7_fallback_reason in ("", "none"):
                l7_fallback_reason = _l7_fallback_reason_item
            elif (
                _l7_fallback_reason_item != "none"
                and l7_fallback_reason != _l7_fallback_reason_item
                and l7_fallback_reason != "mixed"
            ):
                l7_fallback_reason = "mixed"
        _l7_capability_item = str(
            ev.get("l7_capability_status", st.get("l7_capability_status", ""))
            or ""
        ).strip().lower()
        if _l7_capability_item in {"ok", "partial", "missing"}:
            if l7_capability_status == "missing" or _l7_capability_item == "missing":
                l7_capability_status = "missing"
            elif l7_capability_status == "partial" or _l7_capability_item == "partial":
                l7_capability_status = "partial"
            else:
                l7_capability_status = "ok"
        h2_goaway_count_total += int(ev.get("h2_goaway_count", st.get("h2_goaway_count", 0)) or 0)
        h2_stream_resets_total += int(ev.get("h2_stream_resets", st.get("h2_stream_resets", 0)) or 0)
        h2_connections_used_total += int(ev.get("h2_connections_used", st.get("h2_connections_used", 0)) or 0)
        h2_request_plan_used_any = max(
            int(h2_request_plan_used_any),
            int(ev.get("h2_request_plan_used", st.get("h2_request_plan_used", 0)) or 0),
        )
        h2_request_plan_items_total += int(
            ev.get("h2_request_plan_items", st.get("h2_request_plan_items", 0)) or 0
        )
        _h2_stream_reset_ratio = float(
            ev.get("h2_stream_reset_ratio", st.get("h2_stream_reset_ratio", 0.0)) or 0.0
        )
        if attempted > 0:
            h2_stream_reset_ratio_weighted_sum += (_h2_stream_reset_ratio * attempted)
            h2_stream_reset_ratio_weight += attempted
        quic_connect_fail_count_total += int(
            ev.get("quic_connect_fail_count", st.get("quic_connect_fail_count", 0)) or 0
        )
        quic_connect_timeout_count_total += int(
            ev.get("quic_connect_timeout_count", st.get("quic_connect_timeout_count", 0)) or 0
        )
        quic_tls_fail_count_total += int(
            ev.get("quic_tls_fail_count", st.get("quic_tls_fail_count", 0)) or 0
        )
        quic_handshake_timeout_count_total += int(
            ev.get("quic_handshake_timeout_count", st.get("quic_handshake_timeout_count", 0)) or 0
        )
        quic_stream_fail_count_total += int(
            ev.get("quic_stream_fail_count", st.get("quic_stream_fail_count", 0)) or 0
        )
        _quic_stream_fail_ratio = float(
            ev.get("quic_stream_fail_ratio", st.get("quic_stream_fail_ratio", 0.0)) or 0.0
        )
        _quic_handshake_fail_ratio = float(
            ev.get("quic_handshake_fail_ratio", st.get("quic_handshake_fail_ratio", 0.0)) or 0.0
        )
        if attempted > 0:
            quic_stream_fail_ratio_weighted_sum += (_quic_stream_fail_ratio * attempted)
            quic_stream_fail_ratio_weight += attempted
            quic_handshake_fail_ratio_weighted_sum += (_quic_handshake_fail_ratio * attempted)
            quic_handshake_fail_ratio_weight += attempted
        _bp = int(ev.get("queue_backlog_peak", 0) or 0)
        if _bp > backlog_peak_max:
            backlog_peak_max = _bp
        _dp_queue_id = int(ev.get("dp_queue_id", st.get("dp_queue_id", -1)) or -1)
        if _dp_queue_id >= 0:
            dp_queue_ids_used.add(_dp_queue_id)
        _dp_affinity_cpu = int(ev.get("dp_affinity_cpu", st.get("dp_affinity_cpu", -1)) or -1)
        if _dp_affinity_cpu >= 0:
            dp_affinity_cpus_used.add(_dp_affinity_cpu)
        _dp_strategy_item = str(ev.get("dp_queue_strategy", st.get("dp_queue_strategy", "")) or "").strip()
        if _dp_strategy_item:
            if dp_queue_strategy in ("", "unknown"):
                dp_queue_strategy = _dp_strategy_item
            elif dp_queue_strategy != _dp_strategy_item and dp_queue_strategy != "mixed":
                dp_queue_strategy = "mixed"

        vec = str(ev.get("attack_vector", "unknown"))
        be = str(ev.get("compute_backend", "unknown"))

        v = by_vector.setdefault(vec, {"attempted": 0, "sent": 0, "errors": 0, "workers": 0})
        v["attempted"] += attempted
        v["sent"] += sent
        v["errors"] += errors
        v["workers"] += 1

        b = by_backend.setdefault(be, {"attempted": 0, "sent": 0, "errors": 0, "workers": 0})
        b["attempted"] += attempted
        b["sent"] += sent
        b["errors"] += errors
        b["workers"] += 1

    effective_pps = (float(sent_total) / float(duration_s)) if duration_s > 0 else None
    throughput_bps_est = (float(bytes_sent_est_total) * 8.0 / float(duration_s)) if duration_s > 0 else None
    send_success_ratio = (float(sent_total) / float(attempted_total) * 100.0) if attempted_total > 0 else 0.0
    pacing_actual_rps = (
        float(actual_rps_weighted_sum) / float(pacing_weight_total)
    ) if pacing_weight_total > 0 else 0.0
    pacing_rate_accuracy_pct = (
        float(rate_accuracy_weighted_sum) / float(pacing_weight_total)
    ) if pacing_weight_total > 0 else 0.0
    pacing_jitter_p99_ns = (
        float(jitter_p99_weighted_sum) / float(pacing_weight_total)
    ) if pacing_weight_total > 0 else 0.0
    pacing_ipg_mean_ns = (
        float(ipg_mean_weighted_sum) / float(pacing_weight_total)
    ) if pacing_weight_total > 0 else 0.0
    l7_conn_rate = (
        float(l7_conn_rate_weighted_sum) / float(l7_conn_rate_weight)
    ) if l7_conn_rate_weight > 0 else 0.0
    l7_step_fail_ratio = (
        float(l7_step_fail_ratio_weighted_sum) / float(l7_step_fail_ratio_weight)
    ) if l7_step_fail_ratio_weight > 0 else 0.0
    session_success_rate = (
        float(session_success_rate_weighted_sum) / float(session_success_rate_weight)
    ) if session_success_rate_weight > 0 else 0.0
    retry_success_rate = (
        float(retry_success_rate_weighted_sum) / float(retry_success_rate_weight)
    ) if retry_success_rate_weight > 0 else 0.0
    h2_stream_reset_ratio = (
        float(h2_stream_reset_ratio_weighted_sum) / float(h2_stream_reset_ratio_weight)
    ) if h2_stream_reset_ratio_weight > 0 else 0.0
    quic_stream_fail_ratio = (
        float(quic_stream_fail_ratio_weighted_sum) / float(quic_stream_fail_ratio_weight)
    ) if quic_stream_fail_ratio_weight > 0 else 0.0
    quic_handshake_fail_ratio = (
        float(quic_handshake_fail_ratio_weighted_sum) / float(quic_handshake_fail_ratio_weight)
    ) if quic_handshake_fail_ratio_weight > 0 else 0.0
    txring_tp_drops_bounded_total = min(
        int(txring_tp_drops_total),
        int(txring_tp_packets_total),
    ) if int(txring_tp_packets_total) > 0 else int(txring_tp_drops_total)
    wire_counter_available = int(wire_counter_available_workers > 0 and wire_counter_missing_workers == 0)
    wire_counter_partial = int(wire_counter_available_workers > 0 and wire_counter_missing_workers > 0)
    wire_counter_any = int(wire_counter_available_workers > 0)
    nicq_counter_available = int(nicq_counter_available_workers > 0 and nicq_counter_missing_workers == 0)
    nicq_counter_partial = int(nicq_counter_available_workers > 0 and nicq_counter_missing_workers > 0)
    nicq_counter_any = int(nicq_counter_available_workers > 0)
    if nicq_counter_any:
        _nicq_pressure_derived = int(
            max(
                0,
                nicq_pressure_delta_total,
                nicq_drop_delta_total + nicq_fifo_delta_total + nicq_timeout_delta_total
                + nicq_restart_delta_total + nicq_busy_delta_total,
            )
        )
        nicq_pressure_delta_total = _nicq_pressure_derived
    else:
        nicq_pressure_delta_total = 0
        nicq_drop_delta_total = 0
        nicq_fifo_delta_total = 0
        nicq_timeout_delta_total = 0
        nicq_restart_delta_total = 0
        nicq_busy_delta_total = 0
    if wire_counter_any:
        _wire_accounted_derived = int(min(max(0, attempted_total), max(0, wire_tx_packets_delta_total)))
        _wire_over_attempted_derived = int(max(0, wire_tx_packets_delta_total - attempted_total))
        _wire_loss_derived = int(max(0, attempted_total - _wire_accounted_derived))
        wire_tx_accounted_packets_total = int(max(wire_tx_accounted_packets_total, _wire_accounted_derived))
        wire_tx_over_attempted_packets_total = int(
            max(wire_tx_over_attempted_packets_total, _wire_over_attempted_derived)
        )
        wire_loss_raw_uncapped_packets_total = int(
            max(
                0,
                wire_loss_raw_uncapped_packets_total,
                wire_loss_raw_packets_total,
                _wire_loss_derived,
            )
        )
        wire_loss_raw_packets_total = int(wire_loss_raw_uncapped_packets_total)
        wire_loss_est_packets_total = int(
            min(
                max(0, attempted_total),
                max(0, int(wire_loss_est_packets_total), int(wire_loss_raw_packets_total)),
            )
        )
    else:
        # Legacy fallback when explicit wire counters are unavailable.
        wire_loss_raw_uncapped_packets_total = int(
            max(
                0,
                wire_loss_raw_uncapped_packets_total,
                wire_loss_raw_packets_total,
                host_tx_dropped_delta_total,
            )
        )
        wire_loss_raw_packets_total = int(wire_loss_raw_uncapped_packets_total)
        wire_loss_est_packets_total = int(
            min(
                max(0, attempted_total),
                max(0, int(wire_loss_est_packets_total), int(host_tx_dropped_delta_total)),
            )
        )
    wire_loss_est_pct = (float(wire_loss_est_packets_total) * 100.0 / float(max(1, attempted_total)))
    wire_loss_raw_pct = (float(wire_loss_raw_packets_total) * 100.0 / float(max(1, attempted_total)))
    wire_loss_raw_over_attempted_packets = int(max(0, wire_loss_raw_packets_total - attempted_total))
    wire_loss_raw_over_attempted_pct = (
        float(wire_loss_raw_over_attempted_packets) * 100.0 / float(max(1, attempted_total))
    )
    wire_loss_raw_gt_attempted = int(wire_loss_raw_over_attempted_packets > 0)
    txring_drop_ratio_pct = (float(txring_tp_drops_bounded_total) * 100.0 / float(max(1, txring_tp_packets_total)))
    txring_flush_error_ratio_pct = (float(txring_flush_error_count_total) * 100.0 / float(max(1, txring_flush_call_count_total)))
    txring_flush_eagain_ratio_pct = (float(txring_flush_eagain_count_total) * 100.0 / float(max(1, txring_flush_call_count_total)))
    txring_flush_enobufs_ratio_pct = (float(txring_flush_enobufs_count_total) * 100.0 / float(max(1, txring_flush_call_count_total)))
    txring_flush_ebusy_ratio_pct = (float(txring_flush_ebusy_count_total) * 100.0 / float(max(1, txring_flush_call_count_total)))
    txring_flush_other_errno_ratio_pct = (
        float(txring_flush_other_errno_count_total) * 100.0 / float(max(1, txring_flush_call_count_total))
    )
    frame_wait_ratio_pct = (float(txring_frame_wait_ns_total) * 100.0 / float(max(1.0, float(duration_s) * 1e9)))
    poll_ratio_pct = (float(txring_poll_count_total) * 100.0 / float(max(1, sent_total)))
    freeze_ratio_pct = (
        float(txring_tp_freeze_q_cnt_total) * 100.0 / float(max(1, txring_tp_packets_total))
    )
    txring_hold_block_pressure_pct = min(
        100.0,
        max(0.0, frame_wait_ratio_pct + poll_ratio_pct + freeze_ratio_pct),
    )
    wire_loss_estimation_capped = int(wire_loss_raw_packets_total > wire_loss_est_packets_total)
    try:
        loss_fail_pct = float(os.environ.get("SAMURAI_LOSS_FAIL_PCT", "5") or 5.0)
    except Exception:
        loss_fail_pct = 5.0
    wire_loss_policy_pct = max(float(wire_loss_est_pct), float(wire_loss_raw_pct))
    if attempted_total > 0 and (wire_counter_any == 0 or wire_counter_partial == 1):
        wire_loss_status = "unknown"
    elif wire_loss_policy_pct > loss_fail_pct:
        wire_loss_status = "fail"
    elif wire_loss_policy_pct > 0.0:
        wire_loss_status = "warn"
    else:
        wire_loss_status = "ok"
    if attempted_total > 0 and (nicq_counter_any == 0 or nicq_counter_partial == 1):
        nicq_pressure_status = "unknown"
    elif int(nicq_pressure_delta_total) > 0:
        nicq_pressure_status = "warn"
    else:
        nicq_pressure_status = "ok"
    warning_set = {str(w).strip() for w in list(warnings or []) if str(w).strip()}
    if "run_interrupted_by_user" in warning_set or int(workers_interrupted) > 0:
        run_quality = "interrupted"
    elif int(workers_total) <= 0 or int(attempted_total) <= 0:
        run_quality = "invalid_metrics"
    else:
        run_quality = "valid"

    report = RunReport(
        run_id=run_id,
        started_utc="",
        finished_utc="",
        duration_s=float(duration_s),
        mode="live_attack",
        metrics=dict(metrics or {}),
        inputs={"args": dict(args or {})},
        results={
            "target_count": int(total_count),
            "progress_total": int(progress_total),
            "workers_total": int(workers_total),
            "workers_ok": int(workers_ok),
            "workers_degraded": int(workers_degraded),
            "workers_failed": int(workers_failed),
            "workers_interrupted": int(workers_interrupted),
            "attempted_total": int(attempted_total),
            "sent_total": int(sent_total),
            "errors_total": int(errors_total),
            "bytes_sent_est_total": int(bytes_sent_est_total),
            "effective_pps": effective_pps,
            "throughput_bps_est": throughput_bps_est,
            "send_success_ratio_pct": round(send_success_ratio, 2),
            "run_quality": str(run_quality),
            "sender_paths_used": sender_paths_used,
            "permission_error_count": int(permission_error_count_total),
            "fallback_count": int(fallback_count_total),
            "sender_fallback_reason": str(sender_fallback_reason),
            "buffer_copy_count": int(buffer_copy_count_total),
            "buffer_copy_bytes": int(buffer_copy_bytes_total),
            "buffer_reuse_hits": int(buffer_reuse_hits_total),
            "eagain_retry_count": int(eagain_retry_count_total),
            "partial_send_retry_count": int(partial_send_retry_count_total),
            "actual_rps": round(float(pacing_actual_rps), 4),
            "rate_accuracy_pct": round(float(pacing_rate_accuracy_pct), 4),
            "jitter_p99_ns": round(float(pacing_jitter_p99_ns), 4),
            "ipg_mean_ns": round(float(pacing_ipg_mean_ns), 4),
            "sleep_calls": int(sleep_calls_total),
            "busywait_cycles": int(busywait_cycles_total),
            "so_txtime_active": int(so_txtime_active_any),
            "txtime_errors": int(txtime_errors_total),
            "txring_flush_call_count": int(txring_flush_call_count_total),
            "txring_flush_error_count": int(txring_flush_error_count_total),
            "txring_flush_eagain_count": int(txring_flush_eagain_count_total),
            "txring_flush_enobufs_count": int(txring_flush_enobufs_count_total),
            "txring_flush_ebusy_count": int(txring_flush_ebusy_count_total),
            "txring_flush_other_errno_count": int(txring_flush_other_errno_count_total),
            "txring_flush_last_errno": int(txring_flush_last_errno),
            "txring_flush_last_errno_name": str(txring_flush_last_errno_name),
            "txring_frame_wait_ns": int(txring_frame_wait_ns_total),
            "txring_poll_count": int(txring_poll_count_total),
            "flush_mode": str(flush_mode),
            "txring_tp_packets": int(txring_tp_packets_total),
            "txring_tp_drops": int(txring_tp_drops_total),
            "txring_kernel_raw_tp_drops": int(txring_tp_drops_total),
            "txring_tp_freeze_q_cnt": int(txring_tp_freeze_q_cnt_total),
            "txring_batch_target": int(txring_batch_target_max),
            "txring_backoff_ns": int(txring_backoff_ns_total),
            "txring_hold_block_pressure_pct": round(float(txring_hold_block_pressure_pct), 4),
            "txring_hold_block_frame_wait_ratio_pct": round(float(frame_wait_ratio_pct), 4),
            "txring_hold_block_poll_ratio_pct": round(float(poll_ratio_pct), 4),
            "txring_hold_block_freeze_ratio_pct": round(float(freeze_ratio_pct), 4),
            "txring_packet_version": int(txring_packet_version),
            "txring_packet_version_name": str(txring_packet_version_name),
            "host_tx_packets_delta": int(host_tx_packets_delta_total),
            "host_tx_dropped_delta": int(host_tx_dropped_delta_total),
            "host_tx_errors_delta": int(host_tx_errors_delta_total),
            "softnet_dropped_delta": int(softnet_dropped_delta_total),
            "softnet_time_squeeze_delta": int(softnet_time_squeeze_delta_total),
            "wire_counter_available": int(wire_counter_available),
            "wire_counter_partial": int(wire_counter_partial),
            "wire_counter_available_workers": int(wire_counter_available_workers),
            "wire_counter_missing_workers": int(wire_counter_missing_workers),
            "wire_counter_source": str(wire_counter_source),
            "wire_counter_confidence": round(float(wire_counter_confidence_max), 4),
            "wire_counter_reason": str(wire_counter_reason),
            "wire_tx_packets_delta": int(wire_tx_packets_delta_total),
            "wire_tx_dropped_delta": int(wire_tx_dropped_delta_total),
            "wire_tx_errors_delta": int(wire_tx_errors_delta_total),
            "wire_tx_bytes_delta": int(wire_tx_bytes_delta_total),
            "nicq_counter_available": int(nicq_counter_available),
            "nicq_counter_partial": int(nicq_counter_partial),
            "nicq_counter_available_workers": int(nicq_counter_available_workers),
            "nicq_counter_missing_workers": int(nicq_counter_missing_workers),
            "nicq_counter_source": str(nicq_counter_source),
            "nicq_counter_confidence": round(float(nicq_counter_confidence_max), 4),
            "nicq_counter_reason": str(nicq_counter_reason),
            "nicq_pressure_delta": int(nicq_pressure_delta_total),
            "nicq_drop_delta": int(nicq_drop_delta_total),
            "nicq_fifo_delta": int(nicq_fifo_delta_total),
            "nicq_timeout_delta": int(nicq_timeout_delta_total),
            "nicq_restart_delta": int(nicq_restart_delta_total),
            "nicq_busy_delta": int(nicq_busy_delta_total),
            "nicq_pressure_status": str(nicq_pressure_status),
            "wire_tx_accounted_packets": int(wire_tx_accounted_packets_total),
            "wire_tx_over_attempted_packets": int(wire_tx_over_attempted_packets_total),
            "wire_loss_measurement_mode": str(wire_loss_measurement_mode),
            "wire_loss_est_packets": int(wire_loss_est_packets_total),
            "wire_loss_est_pct": round(float(wire_loss_est_pct), 4),
            "wire_loss_raw_packets": int(wire_loss_raw_packets_total),
            "wire_loss_raw_uncapped_packets": int(wire_loss_raw_uncapped_packets_total),
            "wire_loss_raw_pct": round(float(wire_loss_raw_pct), 4),
            "wire_loss_raw_pct_of_attempted": round(float(wire_loss_raw_pct), 4),
            "wire_loss_raw_over_attempted_packets": int(wire_loss_raw_over_attempted_packets),
            "wire_loss_raw_over_attempted_pct": round(float(wire_loss_raw_over_attempted_pct), 4),
            "wire_loss_raw_gt_attempted": int(wire_loss_raw_gt_attempted),
            "wire_loss_estimation_capped": int(wire_loss_estimation_capped),
            "wire_loss_fail_pct": float(loss_fail_pct),
            "wire_loss_status": wire_loss_status,
            "txring_drop_ratio_pct": round(float(txring_drop_ratio_pct), 4),
            "txring_flush_error_ratio_pct": round(float(txring_flush_error_ratio_pct), 4),
            "txring_flush_eagain_ratio_pct": round(float(txring_flush_eagain_ratio_pct), 4),
            "txring_flush_enobufs_ratio_pct": round(float(txring_flush_enobufs_ratio_pct), 4),
            "txring_flush_ebusy_ratio_pct": round(float(txring_flush_ebusy_ratio_pct), 4),
            "txring_flush_other_errno_ratio_pct": round(float(txring_flush_other_errno_ratio_pct), 4),
            "gpu_template_h2d_copy_count": int(gpu_template_h2d_copy_count_total),
            "gpu_template_h2d_copy_bytes": int(gpu_template_h2d_copy_bytes_total),
            "gpu_rng_state_alloc_count": int(gpu_rng_state_alloc_count_total),
            "gpu_rng_state_reuse_count": int(gpu_rng_state_reuse_count_total),
            "gpu_ring_depth_peak": int(gpu_ring_depth_peak_max),
            "gpu_ring_block_wait_ns": int(gpu_ring_block_wait_ns_total),
            "state_active_entries": int(state_active_entries_max),
            "state_timeout_evictions": int(state_timeout_evictions_total),
            "state_overwrites": int(state_overwrites_total),
            "l7_active_sessions_peak": int(l7_active_sessions_peak_max),
            "l7_conn_rate": round(float(l7_conn_rate), 4),
            "l7_handshake_p99_ms": round(float(l7_handshake_p99_ms_max), 4),
            "l7_step_fail_ratio": round(float(l7_step_fail_ratio), 6),
            "session_success_rate": round(float(session_success_rate), 6),
            "retry_success_rate": round(float(retry_success_rate), 6),
            "l7_engine_path_used": str(l7_engine_path_used),
            "l7_fallback_reason": str(l7_fallback_reason),
            "l7_capability_status": str(l7_capability_status),
            "h2_goaway_count": int(h2_goaway_count_total),
            "h2_stream_resets": int(h2_stream_resets_total),
            "h2_connections_used": int(h2_connections_used_total),
            "h2_request_plan_used": int(h2_request_plan_used_any),
            "h2_request_plan_items": int(h2_request_plan_items_total),
            "h2_stream_reset_ratio": round(float(h2_stream_reset_ratio), 6),
            "quic_connect_fail_count": int(quic_connect_fail_count_total),
            "quic_connect_timeout_count": int(quic_connect_timeout_count_total),
            "quic_tls_fail_count": int(quic_tls_fail_count_total),
            "quic_handshake_timeout_count": int(quic_handshake_timeout_count_total),
            "quic_stream_fail_count": int(quic_stream_fail_count_total),
            "quic_stream_fail_ratio": round(float(quic_stream_fail_ratio), 6),
            "quic_handshake_fail_ratio": round(float(quic_handshake_fail_ratio), 6),
            "dp_queue_ids_used": sorted(int(x) for x in list(dp_queue_ids_used)),
            "dp_affinity_cpus_used": sorted(int(x) for x in list(dp_affinity_cpus_used)),
            "dp_queue_strategy": str(dp_queue_strategy or "unknown"),
            "queue_backlog_peak": int(backlog_peak_max),
            "by_vector": by_vector,
            "by_backend": by_backend,
            "worker_errors": worker_errors,
            "system_snapshot": collect_system_snapshot(),
        },
        environment=collect_environment(),
        artifacts=[],
        warnings=list(warnings or []),
    )
    try:
        from . import kpi_gate

        gate_profile = str(
            (args or {}).get("kpi_gate_profile", os.environ.get("SAMURAI_KPI_GATE_PROFILE", "off")) or "off"
        )
        gate_hard_fail = bool(
            (args or {}).get("kpi_hard_fail", str(os.environ.get("SAMURAI_KPI_HARD_FAIL", "0")) in {"1", "true"})
        )
        gate_result = kpi_gate.evaluate(
            report.results,
            profile=gate_profile,
            hard_fail=gate_hard_fail,
        )
        report.results.update(gate_result.as_report_fields())
        report.results["kpi_evaluated_rules"] = list(gate_result.evaluated_rules)
    except Exception:
        report.results.setdefault("kpi_gate_profile", "off")
        report.results.setdefault("kpi_gate_status", "pass")
        report.results.setdefault("kpi_gate_hard_fail", 0)
        report.results.setdefault("kpi_violations", [])
        report.results.setdefault("score_eligible", 1 if str(report.results.get("run_quality", "")) == "valid" else 0)
    return report
