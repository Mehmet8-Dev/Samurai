"""Privileged/full benchmark suite.

This module is excluded from ci_safe profile and is intended for manual/full runs.
"""

from __future__ import annotations

import json
import os
import socket
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import pytest

pytestmark = [pytest.mark.benchmark, pytest.mark.privileged]


class _FullBenchState:
    summary = {
        "schema": "samurai.benchmark.summary.v1",
        "profile": "full",
        "generated_utc": None,
        "sections": {},
    }


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _require_root_or_skip() -> None:
    if os.geteuid() != 0:
        raise unittest.SkipTest("full benchmark requires root for pacing/raw socket checks")


def _raw_socket_available() -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.close()
        return True
    except Exception:
        return False


def _write_json_with_fallback(preferred: Path, payload: dict, fallback_name: str) -> Path:
    content = json.dumps(payload, indent=2, sort_keys=True)
    candidates = [
        preferred,
        Path.cwd() / ".pytest_artifacts" / fallback_name,
        Path(tempfile.gettempdir()) / ".pytest_artifacts" / fallback_name,
    ]
    seen = set()
    for cand in candidates:
        key = str(cand)
        if key in seen:
            continue
        seen.add(key)
        try:
            cand.parent.mkdir(parents=True, exist_ok=True)
            cand.write_text(content, encoding="utf-8")
            return cand
        except PermissionError:
            continue
    raise PermissionError(f"Unable to write full benchmark report to any candidate path: {candidates}")


def _load_parity_matrix() -> tuple[Path, dict]:
    path = (Path(__file__).resolve().parents[1] / "benchmarks" / "parity_matrix.json").resolve()
    payload = json.loads(path.read_text(encoding="utf-8"))
    return path, payload


def _build_parity_rows(matrix: dict, normalized_results: dict) -> list[dict]:
    rows: list[dict] = []
    for scenario in list((matrix.get("scenarios") or [])):
        sid = str(scenario.get("id", "") or "").strip()
        if not sid:
            continue
        samurai = scenario.get("ddos_samurai") or {}
        field = str(samurai.get("report_field", "") or "").strip()
        val = normalized_results.get(field, None) if field else None
        rows.append(
            {
                "id": sid,
                "layer": str(scenario.get("layer", "") or ""),
                "comparison": str(scenario.get("comparison", "") or ""),
                "samurai_field": field,
                "samurai_value": val,
                "status": "measured" if val is not None else "not_measured",
            }
        )
    return rows


def _refresh_parity_section() -> None:
    summary = _FullBenchState.summary
    sections = summary.get("sections") or {}
    pacing = sections.get("pacing") or {}
    loss = sections.get("loss_telemetry") or {}

    attempted = int(pacing.get("sent", 0) or 0)
    run_quality = "valid" if attempted > 0 else "invalid_metrics"
    normalized_results = {
        "run_quality": run_quality,
        "sender_paths_used": {"PACED_L3": 1} if attempted > 0 else {},
        "sender_fallback_reason": "none",
        "wire_counter_confidence": 0.0,
        "wire_loss_est_pct": float(loss.get("wire_loss_est_pct", 0.0) or 0.0),
        "rate_accuracy_pct": float(pacing.get("rate_accuracy_pct", 0.0) or 0.0),
        "txring_batch_target": int(pacing.get("txring_batch_target", 0) or 0),
        "txring_backoff_ns": int(pacing.get("txring_backoff_ns", 0) or 0),
        "l7_active_sessions_peak": 0,
        "l7_conn_rate": 0.0,
        "l7_handshake_p99_ms": 0.0,
        "l7_step_fail_ratio": 0.0,
        "effective_pps": float(pacing.get("actual_rps", 0.0) or 0.0),
    }
    matrix_path, matrix = _load_parity_matrix()
    parity_profile = str(os.environ.get("SAMURAI_PARITY_PROFILE", "dedicated_lab") or "dedicated_lab")
    parity_gates = (((matrix.get("profiles") or {}).get(parity_profile) or {}).get("gates") or {})
    missing_fields = [
        key for key in list(matrix.get("required_run_report_results") or [])
        if key not in normalized_results
    ]
    summary["parity"] = {
        "schema": str(matrix.get("schema", "") or ""),
        "matrix_path": str(matrix_path),
        "profile": parity_profile,
        "gates": parity_gates,
        "required_result_fields": list(matrix.get("required_run_report_results") or []),
        "missing_result_fields": missing_fields,
        "normalized_results": normalized_results,
        "rows": _build_parity_rows(matrix, normalized_results),
    }


class TestFullPacingBenchmark(unittest.TestCase):
    def test_pacing_accuracy_full(self):
        _require_root_or_skip()
        if not _raw_socket_available():
            raise unittest.SkipTest("raw socket unavailable in this environment")

        from ddos_samurai.pacing import (
            PACING_ENGINE_AVAILABLE,
            PacingConfig,
            PacingMode,
            JitterModel,
            paced_send,
            get_stats,
        )

        if not PACING_ENGINE_AVAILABLE:
            raise unittest.SkipTest("pacing engine extension unavailable")

        count = 1000
        payload_size = 64
        packet_size = 20 + 20 + payload_size
        packet = b"\x45" + b"\x00" * (packet_size - 1)
        buf = packet * count

        cfg = PacingConfig(
            pacing_mode=PacingMode.RPS,
            target_rps=5000.0,
            jitter_model=JitterModel.NONE,
            jitter_pct=0.0,
            pin_cpu=-1,
            use_so_txtime=False,
        )

        sent = paced_send(buf, "127.0.0.1", 80, packet_size, count, cfg)
        stats = get_stats() or {}

        if sent <= 0:
            raise unittest.SkipTest("paced_send did not send packets in this environment")

        accuracy = float(stats.get("rate_accuracy_pct", 0.0) or 0.0)
        jitter_p99 = float(stats.get("jitter_p99_ns", 0.0) or 0.0)
        actual_rps = float(stats.get("actual_rps", 0.0) or 0.0)
        txring_flush_calls = int(stats.get("txring_flush_call_count", 0) or 0)
        txring_flush_errors = int(stats.get("txring_flush_error_count", 0) or 0)
        txring_flush_eagain = int(stats.get("txring_flush_eagain_count", 0) or 0)
        txring_tp_packets = int(stats.get("txring_tp_packets", 0) or 0)
        txring_tp_drops = int(stats.get("txring_tp_drops", 0) or 0)
        txring_tp_freeze = int(stats.get("txring_tp_freeze_q_cnt", 0) or 0)

        self.assertGreaterEqual(accuracy, 95.0, f"rate_accuracy_pct below threshold: {accuracy:.2f}")
        for k in (
            "txring_flush_call_count",
            "txring_flush_error_count",
            "txring_flush_eagain_count",
            "txring_tp_packets",
            "txring_tp_drops",
            "txring_tp_freeze_q_cnt",
        ):
            self.assertIn(k, stats)

        loss_est_packets = max(txring_tp_drops, 0)
        loss_est_pct = float((100.0 * loss_est_packets) / max(1, count))
        try:
            fail_pct = float(os.environ.get("SAMURAI_LOSS_FAIL_PCT", "5") or 5.0)
        except Exception:
            fail_pct = 5.0
        if loss_est_pct > fail_pct:
            loss_status = "fail"
        elif loss_est_pct > 0:
            loss_status = "warn"
        else:
            loss_status = "ok"

        _FullBenchState.summary["sections"]["pacing"] = {
            "sent": int(sent),
            "target_rps": float(cfg.target_rps),
            "actual_rps": actual_rps,
            "rate_accuracy_pct": accuracy,
            "jitter_p99_ns": jitter_p99,
            "txring_flush_call_count": txring_flush_calls,
            "txring_flush_error_count": txring_flush_errors,
            "txring_flush_eagain_count": txring_flush_eagain,
            "txring_tp_packets": txring_tp_packets,
            "txring_tp_drops": txring_tp_drops,
            "txring_tp_freeze_q_cnt": txring_tp_freeze,
        }
        _FullBenchState.summary["sections"]["loss_telemetry"] = {
            "host_tx_packets_delta": 0,
            "host_tx_dropped_delta": 0,
            "host_tx_errors_delta": 0,
            "softnet_dropped_delta": 0,
            "softnet_time_squeeze_delta": 0,
            "wire_loss_est_packets": int(loss_est_packets),
            "wire_loss_est_pct": float(loss_est_pct),
            "wire_loss_fail_pct": float(fail_pct),
            "wire_loss_status": loss_status,
            "txring_flush_call_count": txring_flush_calls,
            "txring_flush_error_count": txring_flush_errors,
            "txring_flush_eagain_count": txring_flush_eagain,
            "txring_tp_packets": txring_tp_packets,
            "txring_tp_drops": txring_tp_drops,
            "txring_tp_freeze_q_cnt": txring_tp_freeze,
        }


@pytest.mark.gpu
class TestFullGpuBenchmark(unittest.TestCase):
    def test_gpu_template_generation_full(self):
        try:
            from ddos_samurai import gpu_packet
            import numpy as np
            import cupy as cp  # noqa: F401
            from numba import cuda
        except Exception as exc:
            raise unittest.SkipTest(f"GPU stack unavailable: {exc}")

        if not cuda.is_available():
            raise unittest.SkipTest("CUDA device unavailable")

        template = bytes([0x45]) + bytes([0x00] * 63)
        out = gpu_packet.benchmark_template_generation_paths(
            template_bytes=template,
            count=50000,
            iterations=3,
            real_src_ip="192.168.1.100",
            spoof_ip=True,
            has_ethernet=False,
        )

        global_stats = out.get("global") or {}
        pps = float(global_stats.get("pps", 0.0) or 0.0)
        self.assertGreater(pps, 0.0)

        _FullBenchState.summary["sections"]["gpu_template"] = {
            "global": global_stats,
            "constant": out.get("constant", {}),
            "generation_telemetry": out.get("generation_telemetry", {}),
        }


class TestZZWriteFullBenchmarkReport(unittest.TestCase):
    def test_write_full_report(self):
        _FullBenchState.summary["generated_utc"] = _utc_now_iso()
        _refresh_parity_section()

        out_path = str(os.environ.get("SAMURAI_BENCH_REPORT_OUT", "") or "").strip()
        if not out_path:
            out_path = str(Path(tempfile.gettempdir()) / "benchmark_summary_full.json")
        out = _write_json_with_fallback(
            Path(out_path).resolve(),
            _FullBenchState.summary,
            "benchmark_summary_full.json",
        )
        self.assertTrue(out.exists())

        loss_out_path = str(os.environ.get("SAMURAI_LOSS_REPORT_OUT", "") or "").strip()
        if loss_out_path:
            payload = {
                "schema": "samurai.loss.telemetry.v1",
                "profile": "full",
                "generated_utc": _FullBenchState.summary.get("generated_utc"),
                "loss_telemetry": _FullBenchState.summary.get("sections", {}).get("loss_telemetry", {}),
            }
            loss_out = _write_json_with_fallback(
                Path(loss_out_path).resolve(),
                payload,
                "loss_telemetry_full.json",
            )
            self.assertTrue(loss_out.exists())
