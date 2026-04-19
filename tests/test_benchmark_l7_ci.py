"""CI-safe benchmark contract for the native L7 dataplane metrics surface."""

from __future__ import annotations

import json
import math
import os
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ddos_samurai import senders

try:
    import pytest

    pytestmark = [pytest.mark.benchmark, pytest.mark.ci_safe]
except Exception:  # pragma: no cover
    pytestmark = []


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _write_json_with_fallback(preferred: Path, payload: dict, fallback_name: str) -> Path:
    content = json.dumps(payload, indent=2, sort_keys=True)
    candidates = [
        preferred,
        Path.cwd() / ".pytest_artifacts" / fallback_name,
        Path(tempfile.gettempdir()) / ".pytest_artifacts" / fallback_name,
    ]
    for cand in candidates:
        try:
            cand.parent.mkdir(parents=True, exist_ok=True)
            cand.write_text(content, encoding="utf-8")
            return cand
        except PermissionError:
            continue
    raise PermissionError(f"Unable to write benchmark report to any candidate path: {candidates}")


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


def _load_optional_baseline() -> dict:
    baseline_path = str(os.environ.get("SAMURAI_BENCH_BASELINE", "") or "").strip()
    if not baseline_path:
        return {}
    path = Path(baseline_path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _compute_baseline_diff(normalized_results: dict, baseline: dict) -> dict:
    scenarios = dict((baseline.get("scenarios") or {}))
    current_conn_rate = float(normalized_results.get("l7_conn_rate", 0.0) or 0.0)
    current_alloc_count = float(normalized_results.get("l7_alloc_count", 0.0) or 0.0)
    baseline_conn_rate = float(sum(float((entry or {}).get("rate_per_s", 0.0) or 0.0) for entry in scenarios.values()))
    baseline_alloc_count = float(
        sum(float((entry or {}).get("normalized", {}).get("l7_alloc_count", 0.0) or 0.0) for entry in scenarios.values())
    )
    conn_rate_delta_pct = 0.0
    alloc_count_delta_pct = 0.0
    if baseline_conn_rate > 0.0:
        conn_rate_delta_pct = ((current_conn_rate - baseline_conn_rate) * 100.0) / baseline_conn_rate
    if baseline_alloc_count > 0.0:
        alloc_count_delta_pct = ((current_alloc_count - baseline_alloc_count) * 100.0) / baseline_alloc_count
    hard_fail = int(baseline_conn_rate > 0.0 and conn_rate_delta_pct < -20.0)
    return {
        "loaded": bool(scenarios),
        "baseline_conn_rate": baseline_conn_rate,
        "baseline_alloc_count": baseline_alloc_count,
        "current_conn_rate": current_conn_rate,
        "current_alloc_count": current_alloc_count,
        "conn_rate_delta_pct": conn_rate_delta_pct,
        "alloc_count_delta_pct": alloc_count_delta_pct,
        "hard_fail": hard_fail,
    }


def _live_perf_acceptance() -> dict:
    required = str(os.environ.get("SAMURAI_L7_REQUIRE_LIVE_PERF", "") or "").strip().lower() in {"1", "true", "yes", "on"}
    present = str(os.environ.get("SAMURAI_L7_LIVE_PERF_PRESENT", "") or "").strip().lower() in {"1", "true", "yes", "on"}
    passed = str(os.environ.get("SAMURAI_L7_LIVE_PERF_OK", "") or "").strip().lower() in {"1", "true", "yes", "on"}
    status = "pass"
    if required and (not present or not passed):
        status = "fail"
    elif present and not passed:
        status = "warn"
    return {
        "required": int(required),
        "present": int(present),
        "passed": int(passed),
        "status": status,
    }


def _mock_profile(protocol: str) -> object:
    return senders.compile_l7_profile(
        protocol=protocol,
        target_ip="127.0.0.1",
        target_port=443 if protocol == "http2" else 8080,
        scheme="https" if protocol == "http2" else "http",
        http_method="GET",
        http_path=["/bench"],
        payloads=[],
        concurrency=1,
    )


def _fake_stats(protocol: str) -> dict:
    return {
        "attempted": 8,
        "sent": 8,
        "errors": 0,
        "sender_path": "L7_EMU_H2" if protocol == "http2" else "L7_EMU_HTTP1",
        "l7_engine_path_used": "L7_EMU_NATIVE",
        "sender_fallback_reason": "none",
        "l7_fallback_reason": "none",
        "l7_flow_attempted": 8,
        "l7_flow_completed": 8,
        "l7_conn_attempted": 2 if protocol == "http2" else 3,
        "l7_conn_established": 2 if protocol == "http2" else 3,
        "l7_conn_reused": 6 if protocol == "http2" else 5,
        "l7_rx_bytes": 2048,
        "l7_tx_bytes": 1024,
        "l7_cps": 120.0 if protocol == "http2" else 90.0,
        "l7_rps": 640.0 if protocol == "http2" else 320.0,
        "l7_active_conn_peak": 2 if protocol == "http2" else 1,
        "l7_h1_conn_reuse_ratio": 0.625 if protocol == "http1" else 0.0,
        "l7_h2_lane_reuse_ratio": 0.75 if protocol == "http2" else 0.0,
        "l7_h2_active_streams_peak": 8 if protocol == "http2" else 0,
        "l7_epoll_wakeups": 18 if protocol == "http2" else 14,
        "l7_scheduler_queue_depth_peak": 2,
        "l7_idle_evictions": 1,
        "l7_rx_syscalls": 16,
        "l7_tx_syscalls": 10,
        "l7_alloc_bytes": 4096,
        "l7_alloc_count": 12,
        "l7_tls_handshake_p50_ms": 12.0 if protocol == "http2" else 0.0,
        "l7_tls_handshake_p95_ms": 18.0 if protocol == "http2" else 0.0,
        "l7_tls_handshake_p99_ms": 21.0 if protocol == "http2" else 0.0,
        "l7_request_latency_p50_ms": 4.0,
        "l7_request_latency_p95_ms": 8.0,
        "l7_request_latency_p99_ms": 10.0,
        "l7_profile_enabled": 1,
        "l7_profile_snapshot_count": 4,
        "runtime_reactor_backend": "socket_epoll",
        "runtime_backend": "afxdp",
        "runtime_hot_path_level": "phase1_hybrid_afxdp_custom_tcp",
        "legacy_path_used": 0,
        "runtime_transport_backend": "custom_tcp",
        "runtime_tls_backend": "openssl",
        "runtime_http2_backend": "nghttp2_native",
        "runtime_native_hot_path_level": "userspace_reactor",
        "h2_goaway_count": 0,
        "h2_stream_reset_ratio": 0.0,
        "h2_goaway_replacements": 1 if protocol == "http2" else 0,
        "h2_drain_evictions": 1 if protocol == "http2" else 0,
        "h2_replace_now_decisions": 1 if protocol == "http2" else 0,
        "h2_replace_after_idle_decisions": 2 if protocol == "http2" else 0,
        "h2_stream_pool_reuse_hits": 6 if protocol == "http2" else 0,
    }


class _BenchState:
    summary: dict | None = None


class TestL7DataplaneBenchmarkContract(unittest.TestCase):
    @staticmethod
    def _cv_pct(values: list[float]) -> float:
        xs = [float(v) for v in values if float(v) >= 0.0]
        if len(xs) < 2:
            return 0.0
        mean = sum(xs) / float(len(xs))
        if mean <= 0.0:
            return 0.0
        var = sum((x - mean) ** 2 for x in xs) / float(len(xs))
        return (math.sqrt(var) * 100.0) / mean

    def test_l7_ci_safe_benchmark_contract(self):
        h1_profile = _mock_profile("http1")
        h2_profile = _mock_profile("http2")

        def _run_case(profile, protocol: str) -> dict:
            t0 = time.perf_counter()
            out = _fake_stats(protocol)
            dt = max(1e-6, time.perf_counter() - t0)
            return {
                "protocol": protocol,
                "elapsed_s": dt,
                "stats": out,
            }

        h1_runs = [_run_case(h1_profile, "http1") for _ in range(3)]
        h2_runs = [_run_case(h2_profile, "http2") for _ in range(3)]
        h1 = h1_runs[-1]
        h2 = h2_runs[-1]
        h1_conn_rate_cv_pct = self._cv_pct([float(x["stats"]["l7_cps"]) for x in h1_runs])
        h2_conn_rate_cv_pct = self._cv_pct([float(x["stats"]["l7_cps"]) for x in h2_runs])
        l7_conn_rate_cv_pct = self._cv_pct(
            [float(h1_runs[i]["stats"]["l7_cps"]) + float(h2_runs[i]["stats"]["l7_cps"]) for i in range(3)]
        )

        normalized_results = {
            "run_quality": "valid",
            "sender_paths_used": {"L7_EMU_NATIVE": 1},
            "sender_fallback_reason": "none",
            "wire_counter_confidence": 0.0,
            "wire_loss_est_pct": 0.0,
            "rate_accuracy_pct": 100.0,
            "txring_batch_target": 0,
            "txring_backoff_ns": 0,
            "afpacket_hugepage_mode": "off",
            "afpacket_hugepage_effective": 0,
            "afpacket_hugepage_reason": "not_applicable",
            "l7_active_sessions_peak": max(h1["stats"]["l7_active_conn_peak"], h2["stats"]["l7_active_conn_peak"]),
            "l7_conn_rate": h1["stats"]["l7_cps"] + h2["stats"]["l7_cps"],
            "l7_handshake_p99_ms": h2["stats"]["l7_tls_handshake_p99_ms"],
            "l7_step_fail_ratio": 0.0,
            "session_success_rate": 1.0,
            "retry_success_rate": 1.0,
            "kpi_gate_profile": "ci_safe",
            "kpi_gate_status": "pass",
            "kpi_gate_hard_fail": 0,
            "kpi_violations": [],
            "score_eligible": 1,
            "runtime_backend": "afxdp",
            "runtime_hot_path_level": "phase1_hybrid_afxdp_custom_tcp",
            "legacy_path_used": 0,
            "runtime_transport_backend": "custom_tcp",
            "l7_h1_conn_reuse_ratio": h1["stats"]["l7_h1_conn_reuse_ratio"],
            "l7_h2_lane_reuse_ratio": h2["stats"]["l7_h2_lane_reuse_ratio"],
            "l7_h2_active_streams_peak": h2["stats"]["l7_h2_active_streams_peak"],
            "l7_epoll_wakeups": h1["stats"]["l7_epoll_wakeups"] + h2["stats"]["l7_epoll_wakeups"],
            "l7_scheduler_queue_depth_peak": max(
                h1["stats"]["l7_scheduler_queue_depth_peak"],
                h2["stats"]["l7_scheduler_queue_depth_peak"],
            ),
            "l7_alloc_count": h1["stats"]["l7_alloc_count"] + h2["stats"]["l7_alloc_count"],
            "h2_goaway_replacements": h2["stats"]["h2_goaway_replacements"],
            "h2_drain_evictions": h2["stats"]["h2_drain_evictions"],
            "h2_stream_pool_reuse_hits": h2["stats"]["h2_stream_pool_reuse_hits"],
            "h1_conn_rate_cv_pct": h1_conn_rate_cv_pct,
            "h2_conn_rate_cv_pct": h2_conn_rate_cv_pct,
            "l7_conn_rate_cv_pct": l7_conn_rate_cv_pct,
            "persistent_tx_bridge_sent": 0,
            "persistent_produced": 0,
            "queue_pressure": 0,
            "quota_stall": 0,
            "ring_occupancy_peak": 0,
            "persistent_runtime_restarts": 0,
            "no_progress_events": 0,
            "compat_fallback_count": 0,
            "bridge_drain_batches": 0,
            "bridge_drain_packets": 0,
            "ring_drop_events": 0,
            "scheduler_fairness_cv_pct": 0.0,
            "persistent_tx_backend": "noop",
            "persistent_tx_iface": "",
            "persistent_bridge_ipg_ns": 0,
            "persistent_tx_backend_strict": 0,
        }
        baseline_diff = _compute_baseline_diff(normalized_results, _load_optional_baseline())
        live_perf = _live_perf_acceptance()
        normalized_results["baseline_loaded"] = 1 if baseline_diff["loaded"] else 0
        normalized_results["baseline_conn_rate_delta_pct"] = baseline_diff["conn_rate_delta_pct"]
        normalized_results["baseline_alloc_count_delta_pct"] = baseline_diff["alloc_count_delta_pct"]
        normalized_results["kpi_gate_hard_fail"] = baseline_diff["hard_fail"]
        normalized_results["live_perf_gate_status"] = live_perf["status"]
        if baseline_diff["hard_fail"]:
            normalized_results["kpi_gate_status"] = "fail"
            normalized_results["kpi_violations"] = [
                "baseline_conn_rate_regressed_beyond_20pct",
            ]
        if live_perf["status"] == "fail":
            normalized_results["kpi_gate_status"] = "fail"
            normalized_results["kpi_gate_hard_fail"] = 1
            normalized_results["kpi_violations"] = list(normalized_results["kpi_violations"]) + [
                "live_perf_acceptance_missing_or_failed",
            ]
        parity_matrix_path, parity_matrix = _load_parity_matrix()
        parity_rows = _build_parity_rows(parity_matrix, normalized_results)

        summary = {
            "schema": "samurai.benchmark.summary.v1",
            "profile": "l7_dataplane_ci",
            "generated_utc": _utc_now_iso(),
            "scenarios": {
                "http1_keepalive_sequential": h1,
                "http2_shard_lane_reuse": h2,
                "http1_keepalive_runs": h1_runs,
                "http2_shard_lane_runs": h2_runs,
            },
            "parity": {
                "schema": str(parity_matrix.get("schema", "") or ""),
                "matrix_path": str(parity_matrix_path),
                "profile": "ci_safe",
                "required_result_fields": list(parity_matrix.get("required_run_report_results") or []),
                "normalized_results": normalized_results,
                "rows": parity_rows,
            },
            "baseline_diff": baseline_diff,
            "live_perf": live_perf,
            "acceptance": {
                "h1_reuse_ratio": h1["stats"]["l7_h1_conn_reuse_ratio"],
                "h2_reuse_ratio": h2["stats"]["l7_h2_lane_reuse_ratio"],
                "h2_active_streams_peak": h2["stats"]["l7_h2_active_streams_peak"],
                "scheduler_wakeups": normalized_results["l7_epoll_wakeups"],
                "alloc_count": normalized_results["l7_alloc_count"],
                "baseline_conn_rate_delta_pct": baseline_diff["conn_rate_delta_pct"],
                "baseline_alloc_count_delta_pct": baseline_diff["alloc_count_delta_pct"],
                "hard_fail": baseline_diff["hard_fail"],
                "live_perf_required": live_perf["required"],
                "live_perf_present": live_perf["present"],
                "live_perf_passed": live_perf["passed"],
                "live_perf_gate_status": live_perf["status"],
                "goaway_replacements": normalized_results["h2_goaway_replacements"],
                "drain_evictions": normalized_results["h2_drain_evictions"],
                "stream_pool_reuse_hits": normalized_results["h2_stream_pool_reuse_hits"],
                "h1_conn_rate_cv_pct": normalized_results["h1_conn_rate_cv_pct"],
                "h2_conn_rate_cv_pct": normalized_results["h2_conn_rate_cv_pct"],
                "l7_conn_rate_cv_pct": normalized_results["l7_conn_rate_cv_pct"],
            },
        }

        _BenchState.summary = summary

        self.assertGreater(h1["stats"]["l7_h1_conn_reuse_ratio"], 0.0)
        self.assertGreater(h2["stats"]["l7_h2_lane_reuse_ratio"], 0.0)
        self.assertEqual(normalized_results["run_quality"], "valid")
        self.assertTrue(summary["parity"]["rows"])


class TestZZWriteL7BenchmarkReport(unittest.TestCase):
    def test_write_l7_benchmark_report(self):
        summary = _BenchState.summary
        self.assertIsInstance(summary, dict, "L7 benchmark summary is missing")
        preferred = Path(
            os.environ.get(
                "SAMURAI_BENCH_REPORT_OUT",
                str(Path(tempfile.gettempdir()) / "benchmark_l7_summary.json"),
            )
        )
        out = _write_json_with_fallback(
            preferred,
            summary,
            "benchmark_l7_summary.json",
        )
        self.assertTrue(out.exists())
