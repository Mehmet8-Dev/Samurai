from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .l7 import quic_mode

@dataclass
class KpiGateRule:
    name: str
    metric: str
    op: str
    threshold: Any
    required: bool = True


@dataclass
class KpiGateResult:
    profile: str = "off"
    status: str = "pass"
    hard_fail: int = 0
    violations: List[str] = field(default_factory=list)
    score_eligible: int = 0
    evaluated_rules: List[Dict[str, Any]] = field(default_factory=list)

    def as_report_fields(self) -> Dict[str, Any]:
        return {
            "kpi_gate_profile": str(self.profile),
            "kpi_gate_status": str(self.status),
            "kpi_gate_hard_fail": int(self.hard_fail),
            "kpi_violations": list(self.violations),
            "score_eligible": int(self.score_eligible),
        }


_DEFAULT_PROFILE_GATES: Dict[str, Dict[str, Any]] = {
    "dev": {
        "run_quality": "valid",
        "send_success_ratio_pct_min": 90.0,
        "wire_loss_est_pct_max": 10.0,
        "rate_accuracy_pct_min": 85.0,
        "txring_flush_error_ratio_pct_max": 3.0,
        "txring_flush_eagain_ratio_pct_max": 10.0,
        "txring_hold_block_pressure_pct_max": 80.0,
        "afpacket_hugepage_effective_required": 1,
        "session_success_rate_min": 90.0,
        "retry_success_rate_min": 60.0,
        "l7_step_fail_ratio_max": 0.10,
        "l7_handshake_p99_ms_max": 1000.0,
        "l7_fail_budget_pct_max": 10.0,
        "quic_stream_fail_ratio_max": 0.25,
        "quic_handshake_fail_ratio_max": 0.25,
        "quic_response_validation_fail_ratio_max": 0.25,
        "sender_fallback_reason_required": "none",
        "sender_path_single_required": 1,
        "runtime_backend_required": "afxdp",
        "runtime_hot_path_level_required": "phase1_hybrid_afxdp_custom_tcp",
        "legacy_path_used_required": 0,
        "custom_tcp_bridge_xdp_enabled_required": 1,
        "custom_tcp_bridge_backend_match_required": 1,
        "runtime_transport_backend_required": "custom_tcp",
        "stateful_runtime_status_required": "ready",
    },
    "ci_safe": {
        "run_quality": "valid",
        "send_success_ratio_pct_min": 95.0,
        "wire_loss_est_pct_max": 5.0,
        "rate_accuracy_pct_min": 90.0,
        "txring_flush_error_ratio_pct_max": 2.0,
        "txring_flush_eagain_ratio_pct_max": 5.0,
        "txring_hold_block_pressure_pct_max": 60.0,
        "afpacket_hugepage_effective_required": 1,
        "session_success_rate_min": 95.0,
        "retry_success_rate_min": 70.0,
        "l7_step_fail_ratio_max": 0.05,
        "l7_handshake_p99_ms_max": 750.0,
        "l7_fail_budget_pct_max": 5.0,
        "quic_stream_fail_ratio_max": 0.10,
        "quic_handshake_fail_ratio_max": 0.10,
        "quic_response_validation_fail_ratio_max": 0.10,
        "l7_conn_rate_cv_pct_max": 5.0,
        "sender_fallback_reason_required": "none",
        "sender_path_single_required": 1,
        "runtime_backend_required": "afxdp",
        "runtime_hot_path_level_required": "phase1_hybrid_afxdp_custom_tcp",
        "legacy_path_used_required": 0,
        "custom_tcp_bridge_xdp_enabled_required": 1,
        "custom_tcp_bridge_backend_match_required": 1,
        "runtime_transport_backend_required": "custom_tcp",
        "stateful_runtime_status_required": "ready",
    },
    "developer_fallback": {
        "run_quality": "valid",
        "send_success_ratio_pct_min": 99.0,
        "wire_loss_est_pct_max": 5.0,
        "rate_accuracy_pct_min": 90.0,
        "txring_flush_error_ratio_pct_max": 2.0,
        "txring_flush_eagain_ratio_pct_max": 5.0,
        "txring_hold_block_pressure_pct_max": 60.0,
        "afpacket_hugepage_effective_required": 1,
        "session_success_rate_min": 95.0,
        "retry_success_rate_min": 70.0,
        "l7_step_fail_ratio_max": 0.05,
        "l7_handshake_p99_ms_max": 750.0,
        "l7_fail_budget_pct_max": 5.0,
        "quic_stream_fail_ratio_max": 0.10,
        "quic_handshake_fail_ratio_max": 0.10,
        "quic_response_validation_fail_ratio_max": 0.10,
        "l7_conn_rate_cv_pct_max": 5.0,
        "sender_fallback_reason_required": "none",
        "sender_path_single_required": 1,
        "runtime_backend_required": "afxdp",
        "runtime_hot_path_level_required": "phase1_hybrid_afxdp_custom_tcp",
        "legacy_path_used_required": 0,
        "custom_tcp_bridge_xdp_enabled_required": 1,
        "custom_tcp_bridge_backend_match_required": 1,
        "runtime_transport_backend_required": "custom_tcp",
        "stateful_runtime_status_required": "ready",
    },
    "dedicated_lab": {
        "run_quality": "valid",
        "send_success_ratio_pct_min": 99.0,
        "wire_loss_est_pct_max": 1.0,
        "rate_accuracy_pct_min": 98.0,
        "txring_flush_error_ratio_pct_max": 0.5,
        "txring_flush_eagain_ratio_pct_max": 2.0,
        "txring_hold_block_pressure_pct_max": 35.0,
        "afpacket_hugepage_effective_required": 1,
        "session_success_rate_min": 99.0,
        "retry_success_rate_min": 90.0,
        "l7_step_fail_ratio_max": 0.01,
        "l7_handshake_p99_ms_max": 250.0,
        "l7_fail_budget_pct_max": 1.0,
        "quic_stream_fail_ratio_max": 0.01,
        "quic_handshake_fail_ratio_max": 0.01,
        "quic_response_validation_fail_ratio_max": 0.01,
        "quic_stack_mode_required": "custom_native",
        "sender_fallback_reason_required": "none",
        "sender_path_single_required": 1,
        "runtime_backend_required": "afxdp",
        "runtime_hot_path_level_required": "phase1_hybrid_afxdp_custom_tcp",
        "legacy_path_used_required": 0,
        "custom_tcp_bridge_xdp_enabled_required": 1,
        "custom_tcp_bridge_backend_match_required": 1,
        "runtime_transport_backend_required": "custom_tcp",
        "stateful_runtime_status_required": "ready",
        "l7_conn_rate_cv_pct_max": 5.0,
    },
    "persistent_stream_strict": {
        "run_quality": "valid",
        "send_success_ratio_pct_min": 99.0,
        "wire_loss_est_pct_max": 1.0,
        "rate_accuracy_pct_min": 98.0,
        "sender_fallback_reason_required": "none",
        "sender_path_single_required": 1,
        "persistent_tx_backend_allowed": "af_xdp|af_packet",
        "persistent_tx_backend_strict_required": 1,
        "persistent_tx_iface_required": 1,
        "persistent_tx_bridge_sent_min": 1.0,
        "persistent_produced_min": 1.0,
        "queue_pressure_min": 0.0,
        "quota_stall_min": 0.0,
        "ring_occupancy_peak_min": 0.0,
        "persistent_runtime_restarts_min": 0.0,
        "no_progress_events_min": 0.0,
        "compat_fallback_count_min": 0.0,
        "bridge_drain_batches_min": 0.0,
        "bridge_drain_packets_min": 0.0,
        "ring_drop_events_min": 0.0,
        "scheduler_fairness_cv_pct_max": 25.0,
        "persistent_bridge_ipg_ns_min": 0.0,
    },
}


def _normalize_profile(profile: str | None) -> str:
    p = str(profile or "off").strip().lower()
    if p in {"off", "none", "disabled"}:
        return "off"
    if p in {"dedicated", "dedicated-lab", "dedicated_lab"}:
        return "dedicated_lab"
    if p in {"persistent_stream_strict", "persistent-stream-strict", "persistent_stream_lab_strict"}:
        return "persistent_stream_strict"
    if p in {"ci", "ci-safe", "ci_safe"}:
        return "ci_safe"
    if p in {"developer", "dev", "developer_fallback", "developer-fallback"}:
        return "dev" if p == "dev" else "developer_fallback"
    return "off"


def _load_profile_from_parity(profile: str, parity_matrix_path: Optional[str] = None) -> Dict[str, Any]:
    if profile == "off":
        return {}

    path = Path(parity_matrix_path) if parity_matrix_path else (Path(__file__).resolve().parents[1] / "benchmarks" / "parity_matrix.json")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        profiles = (data.get("profiles") or {}) if isinstance(data, dict) else {}
        gates = ((profiles.get(profile) or {}).get("gates") or {})
        if isinstance(gates, dict) and gates:
            return dict(gates)
    except Exception:
        pass
    return {}


def _merge_gate_defaults(profile: str, parity_matrix_path: Optional[str] = None) -> Dict[str, Any]:
    base = dict(_DEFAULT_PROFILE_GATES.get(profile, {}))
    parity = _load_profile_from_parity(profile, parity_matrix_path=parity_matrix_path)
    if not parity:
        return base

    # Backward compatibility with existing parity_matrix keys.
    if "run_quality" in parity:
        base["run_quality"] = parity["run_quality"]
    if "wire_loss_est_pct_max" in parity:
        base["wire_loss_est_pct_max"] = parity["wire_loss_est_pct_max"]
    if "rate_accuracy_pct_min" in parity:
        base["rate_accuracy_pct_min"] = parity["rate_accuracy_pct_min"]
    if "session_success_rate_min" in parity:
        base["session_success_rate_min"] = parity["session_success_rate_min"]
    if "retry_success_rate_min" in parity:
        base["retry_success_rate_min"] = parity["retry_success_rate_min"]
    if "send_success_ratio_pct_min" in parity:
        base["send_success_ratio_pct_min"] = parity["send_success_ratio_pct_min"]
    if "txring_flush_error_ratio_pct_max" in parity:
        base["txring_flush_error_ratio_pct_max"] = parity["txring_flush_error_ratio_pct_max"]
    if "txring_flush_eagain_ratio_pct_max" in parity:
        base["txring_flush_eagain_ratio_pct_max"] = parity["txring_flush_eagain_ratio_pct_max"]
    if "txring_hold_block_pressure_pct_max" in parity:
        base["txring_hold_block_pressure_pct_max"] = parity["txring_hold_block_pressure_pct_max"]
    if "afpacket_hugepage_effective_required" in parity:
        base["afpacket_hugepage_effective_required"] = parity["afpacket_hugepage_effective_required"]
    if "l7_step_fail_ratio_max" in parity:
        base["l7_step_fail_ratio_max"] = parity["l7_step_fail_ratio_max"]
    if "l7_handshake_p99_ms_max" in parity:
        base["l7_handshake_p99_ms_max"] = parity["l7_handshake_p99_ms_max"]
    if "l7_fail_budget_pct_max" in parity:
        base["l7_fail_budget_pct_max"] = parity["l7_fail_budget_pct_max"]
    if "quic_stream_fail_ratio_max" in parity:
        base["quic_stream_fail_ratio_max"] = parity["quic_stream_fail_ratio_max"]
    if "quic_handshake_fail_ratio_max" in parity:
        base["quic_handshake_fail_ratio_max"] = parity["quic_handshake_fail_ratio_max"]
    if "quic_response_validation_fail_ratio_max" in parity:
        base["quic_response_validation_fail_ratio_max"] = parity["quic_response_validation_fail_ratio_max"]
    if "quic_stack_mode_required" in parity:
        base["quic_stack_mode_required"] = parity["quic_stack_mode_required"]
    if "sender_fallback_reason_required" in parity:
        base["sender_fallback_reason_required"] = parity["sender_fallback_reason_required"]
    if "sender_path_single_required" in parity:
        base["sender_path_single_required"] = parity["sender_path_single_required"]
    if "runtime_backend_required" in parity:
        base["runtime_backend_required"] = parity["runtime_backend_required"]
    if "runtime_hot_path_level_required" in parity:
        base["runtime_hot_path_level_required"] = parity["runtime_hot_path_level_required"]
    if "legacy_path_used_required" in parity:
        base["legacy_path_used_required"] = parity["legacy_path_used_required"]
    if "custom_tcp_bridge_xdp_enabled_required" in parity:
        base["custom_tcp_bridge_xdp_enabled_required"] = parity["custom_tcp_bridge_xdp_enabled_required"]
    if "custom_tcp_bridge_backend_match_required" in parity:
        base["custom_tcp_bridge_backend_match_required"] = parity["custom_tcp_bridge_backend_match_required"]
    if "runtime_transport_backend_required" in parity:
        base["runtime_transport_backend_required"] = parity["runtime_transport_backend_required"]
    if "stateful_runtime_status_required" in parity:
        base["stateful_runtime_status_required"] = parity["stateful_runtime_status_required"]
    if "l7_conn_rate_cv_pct_max" in parity:
        base["l7_conn_rate_cv_pct_max"] = parity["l7_conn_rate_cv_pct_max"]
    if "stateful_runtime_preflight_status_required" in parity:
        base["stateful_runtime_preflight_status_required"] = parity["stateful_runtime_preflight_status_required"]
    if "stateful_runtime_preflight_xdp_enabled_required" in parity:
        base["stateful_runtime_preflight_xdp_enabled_required"] = parity["stateful_runtime_preflight_xdp_enabled_required"]
    for k, v in parity.items():
        base[k] = v
    return base


def _to_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except Exception:
        return None


def _metric_gt_zero(results: Dict[str, Any], key: str) -> bool:
    if not isinstance(results, dict):
        return False
    v = _to_float(results.get(key))
    return bool(v is not None and v > 0.0)


def _by_vector_has_activity(results: Dict[str, Any], vectors: set[str]) -> bool:
    if not isinstance(results, dict):
        return False
    by_vector = results.get("by_vector")
    if not isinstance(by_vector, dict):
        return False
    for vec_name, vec_stats in by_vector.items():
        if str(vec_name or "").strip().lower() not in vectors:
            continue
        if isinstance(vec_stats, dict):
            if (
                _to_float(vec_stats.get("attempted")) not in (None, 0.0)
                or _to_float(vec_stats.get("sent")) not in (None, 0.0)
                or _to_float(vec_stats.get("errors")) not in (None, 0.0)
            ):
                return True
        else:
            v = _to_float(vec_stats)
            if v is not None and v > 0.0:
                return True
    return False


def _sender_path_has(results: Dict[str, Any], token: str) -> bool:
    if not isinstance(results, dict):
        return False
    paths = results.get("sender_paths_used")
    if not isinstance(paths, dict):
        return False
    token_u = str(token or "").strip().upper()
    for name in paths.keys():
        if token_u and token_u in str(name or "").upper():
            return True
    return False


def _infer_quic_scope(results: Dict[str, Any]) -> bool:
    if _by_vector_has_activity(results, {"quic"}):
        return True
    if _sender_path_has(results, "QUIC"):
        return True
    quic_metric_keys = (
        "quic_connection_attempts",
        "quic_connect_fail_count",
        "quic_connect_timeout_count",
        "quic_tls_fail_count",
        "quic_handshake_timeout_count",
        "quic_stream_fail_count",
        "quic_response_headers_ok_count",
        "quic_response_body_ok_count",
        "quic_response_validation_fail_count",
    )
    return any(_metric_gt_zero(results, key) for key in quic_metric_keys)


def _infer_l7_scope(results: Dict[str, Any], quic_scope: bool) -> bool:
    if quic_scope:
        return True
    if _by_vector_has_activity(results, {"http", "http2", "http-stateful", "websocket", "websocket-scenario", "ws"}):
        return True
    if _sender_path_has(results, "C_STATE_") or _sender_path_has(results, "PY_HTTP") or _sender_path_has(results, "PY_WS"):
        return True
    l7_metric_keys = (
        "l7_active_sessions_peak",
        "l7_conn_rate",
        "l7_handshake_p99_ms",
        "l7_step_fail_ratio",
        "session_success_rate",
        "retry_success_rate",
        "h2_connections_used",
        "h2_request_plan_items",
    )
    return any(_metric_gt_zero(results, key) for key in l7_metric_keys)


def _infer_txring_scope(results: Dict[str, Any]) -> bool:
    if _sender_path_has(results, "TX_RING") or _sender_path_has(results, "PACED_L2"):
        return True
    txring_metric_keys = (
        "txring_flush_call_count",
        "txring_tp_packets",
        "txring_packet_version",
        "afpacket_ring_size_bytes",
        "afpacket_ring_block_nr",
    )
    return any(_metric_gt_zero(results, key) for key in txring_metric_keys)


def _infer_persistent_stream_scope(results: Dict[str, Any]) -> bool:
    if not isinstance(results, dict):
        return False
    if str(results.get("gpu_kernel_mode", "") or "").strip().lower() == "persistent" and str(
        results.get("gpu_stream_api_mode", "") or ""
    ).strip().lower() == "stream":
        return True
    persistent_keys = (
        "persistent_tx_bridge_sent",
        "persistent_produced",
        "queue_pressure",
        "quota_stall",
        "ring_occupancy_peak",
        "persistent_runtime_restarts",
        "no_progress_events",
        "compat_fallback_count",
        "bridge_drain_batches",
        "bridge_drain_packets",
        "ring_drop_events",
        "scheduler_fairness_cv_pct",
        "persistent_tx_backend",
        "persistent_tx_iface",
        "persistent_bridge_ipg_ns",
    )
    return any(k in results for k in persistent_keys)


def _build_rules(gates: Dict[str, Any], results: Dict[str, Any], *, profile: str) -> List[KpiGateRule]:
    quic_scope = _infer_quic_scope(results)
    l7_scope = _infer_l7_scope(results, quic_scope=quic_scope)
    txring_scope = _infer_txring_scope(results)
    persistent_stream_scope = _infer_persistent_stream_scope(results) or str(profile).strip().lower() == "persistent_stream_strict"
    dedicated_strict = str(profile or "").strip().lower() != "off"
    rules: List[KpiGateRule] = [
        KpiGateRule("run_quality", "run_quality", "eq", gates.get("run_quality", "valid"), required=True),
        KpiGateRule(
            "send_success_ratio_pct",
            "send_success_ratio_pct",
            "min",
            float(gates.get("send_success_ratio_pct_min", 99.0) or 99.0),
            required=True,
        ),
        KpiGateRule(
            "wire_loss_est_pct",
            "wire_loss_est_pct",
            "max",
            float(gates.get("wire_loss_est_pct_max", 1.0) or 1.0),
            required=True,
        ),
        KpiGateRule(
            "rate_accuracy_pct",
            "rate_accuracy_pct",
            "min",
            float(gates.get("rate_accuracy_pct_min", 98.0) or 98.0),
            required=bool(dedicated_strict),
        ),
        KpiGateRule(
            "txring_flush_error_ratio_pct",
            "txring_flush_error_ratio_pct",
            "max",
            float(gates.get("txring_flush_error_ratio_pct_max", 0.5) or 0.5),
            required=bool(txring_scope and dedicated_strict),
        ),
        KpiGateRule(
            "txring_flush_eagain_ratio_pct",
            "txring_flush_eagain_ratio_pct",
            "max",
            float(gates.get("txring_flush_eagain_ratio_pct_max", 2.0) or 2.0),
            required=bool(txring_scope and dedicated_strict),
        ),
        KpiGateRule(
            "txring_hold_block_pressure_pct",
            "txring_hold_block_pressure_pct",
            "max",
            float(gates.get("txring_hold_block_pressure_pct_max", 35.0) or 35.0),
            required=bool(txring_scope and dedicated_strict),
        ),
        KpiGateRule(
            "afpacket_hugepage_effective",
            "afpacket_hugepage_effective",
            "eq",
            int(gates.get("afpacket_hugepage_effective_required", 1) or 1),
            required=bool(txring_scope),
        ),
        KpiGateRule(
            "session_success_rate",
            "session_success_rate",
            "min",
            float(gates.get("session_success_rate_min", 99.0) or 99.0),
            required=bool(l7_scope),
        ),
        KpiGateRule(
            "retry_success_rate",
            "retry_success_rate",
            "min",
            float(gates.get("retry_success_rate_min", 90.0) or 90.0),
            required=bool(l7_scope),
        ),
        KpiGateRule(
            "l7_step_fail_ratio",
            "l7_step_fail_ratio",
            "max",
            float(gates.get("l7_step_fail_ratio_max", 0.01) or 0.01),
            required=bool(l7_scope),
        ),
        KpiGateRule(
            "l7_handshake_p99_ms",
            "l7_handshake_p99_ms",
            "max",
            float(gates.get("l7_handshake_p99_ms_max", 250.0) or 250.0),
            required=bool(l7_scope),
        ),
        KpiGateRule(
            "l7_fail_budget_pct",
            "l7_fail_budget_pct",
            "max",
            float(gates.get("l7_fail_budget_pct_max", 1.0) or 1.0),
            required=bool(l7_scope),
        ),
        KpiGateRule(
            "quic_stream_fail_ratio",
            "quic_stream_fail_ratio",
            "max",
            float(gates.get("quic_stream_fail_ratio_max", 0.01) or 0.01),
            required=bool(quic_scope),
        ),
        KpiGateRule(
            "quic_handshake_fail_ratio",
            "quic_handshake_fail_ratio",
            "max",
            float(gates.get("quic_handshake_fail_ratio_max", 0.01) or 0.01),
            required=bool(quic_scope),
        ),
        KpiGateRule(
            "quic_response_validation_fail_ratio",
            "quic_response_validation_fail_ratio",
            "max",
            float(gates.get("quic_response_validation_fail_ratio_max", 0.01) or 0.01),
            required=bool(quic_scope),
        ),
    ]
    quic_mode_required = str(gates.get("quic_stack_mode_required", "") or "").strip()
    if quic_mode_required:
        rules.append(
            KpiGateRule(
                "quic_stack_mode",
                "quic_stack_mode",
                "eq",
                quic_mode_required,
                required=bool(quic_scope),
            )
        )
    sender_fallback_required = str(gates.get("sender_fallback_reason_required", "") or "").strip()
    if sender_fallback_required:
        rules.append(
            KpiGateRule(
                "sender_fallback_reason",
                "sender_fallback_reason",
                "eq",
                sender_fallback_required,
                required=bool(dedicated_strict),
            )
        )
    sender_path_single_required = int(gates.get("sender_path_single_required", 0) or 0)
    if sender_path_single_required > 0:
        rules.append(
            KpiGateRule(
                "sender_paths_used",
                "sender_paths_used",
                "single_path",
                "single_path",
                required=bool(dedicated_strict),
            )
        )
    runtime_backend_required = str(gates.get("runtime_backend_required", "") or "").strip()
    if runtime_backend_required:
        rules.append(
            KpiGateRule(
                "runtime_backend",
                "runtime_backend",
                "eq",
                runtime_backend_required,
                required=bool(dedicated_strict and l7_scope),
            )
        )
    runtime_hot_path_level_required = str(gates.get("runtime_hot_path_level_required", "") or "").strip()
    if runtime_hot_path_level_required:
        rules.append(
            KpiGateRule(
                "runtime_hot_path_level",
                "runtime_hot_path_level",
                "eq",
                runtime_hot_path_level_required,
                required=bool(dedicated_strict and l7_scope),
            )
        )
    if "legacy_path_used_required" in gates:
        rules.append(
            KpiGateRule(
                "legacy_path_used",
                "legacy_path_used",
                "eq",
                int(gates.get("legacy_path_used_required", 0) or 0),
                required=bool(dedicated_strict and l7_scope),
            )
        )
    if "custom_tcp_bridge_xdp_enabled_required" in gates:
        rules.append(
            KpiGateRule(
                "custom_tcp_bridge_xdp_enabled",
                "custom_tcp_bridge_xdp_enabled",
                "eq",
                int(gates.get("custom_tcp_bridge_xdp_enabled_required", 0) or 0),
                required=bool(dedicated_strict and l7_scope),
            )
        )
    if "custom_tcp_bridge_backend_match_required" in gates:
        rules.append(
            KpiGateRule(
                "custom_tcp_bridge_backend_match",
                "custom_tcp_bridge_backend_match",
                "eq",
                int(gates.get("custom_tcp_bridge_backend_match_required", 0) or 0),
                required=bool(dedicated_strict and l7_scope),
            )
        )
    preflight_status_required = str(gates.get("stateful_runtime_preflight_status_required", "") or "").strip()
    if preflight_status_required:
        rules.append(
            KpiGateRule(
                "stateful_runtime_preflight_status",
                "stateful_runtime_preflight_status",
                "eq",
                preflight_status_required,
                required=bool(dedicated_strict and l7_scope),
            )
        )
    if "stateful_runtime_preflight_xdp_enabled_required" in gates:
        rules.append(
            KpiGateRule(
                "stateful_runtime_preflight_xdp_enabled",
                "stateful_runtime_preflight_xdp_enabled",
                "eq",
                int(gates.get("stateful_runtime_preflight_xdp_enabled_required", 0) or 0),
                required=bool(dedicated_strict and l7_scope),
            )
        )
    runtime_transport_backend_required = str(gates.get("runtime_transport_backend_required", "") or "").strip()
    if runtime_transport_backend_required:
        rules.append(
            KpiGateRule(
                "runtime_transport_backend",
                "runtime_transport_backend",
                "eq",
                runtime_transport_backend_required,
                required=bool(dedicated_strict and l7_scope),
            )
        )
    stateful_runtime_status_required = str(gates.get("stateful_runtime_status_required", "") or "").strip()
    if stateful_runtime_status_required:
        rules.append(
            KpiGateRule(
                "stateful_runtime_status",
                "stateful_runtime_status",
                "eq",
                stateful_runtime_status_required,
                required=bool(dedicated_strict and l7_scope),
            )
        )
    if "l7_conn_rate_cv_pct_max" in gates:
        rules.append(
            KpiGateRule(
                "l7_conn_rate_cv_pct",
                "l7_conn_rate_cv_pct",
                "max",
                float(gates.get("l7_conn_rate_cv_pct_max", 5.0) or 5.0),
                required=bool(l7_scope),
            )
        )
    persistent_backend_allowed = str(gates.get("persistent_tx_backend_allowed", "") or "").strip()
    if persistent_backend_allowed:
        rules.append(
            KpiGateRule(
                "persistent_tx_backend",
                "persistent_tx_backend",
                "in_set",
                persistent_backend_allowed,
                required=bool(persistent_stream_scope),
            )
        )
    if "persistent_tx_backend_strict_required" in gates:
        rules.append(
            KpiGateRule(
                "persistent_tx_backend_strict",
                "persistent_tx_backend_strict",
                "eq",
                int(gates.get("persistent_tx_backend_strict_required", 1) or 1),
                required=bool(persistent_stream_scope),
            )
        )
    if int(gates.get("persistent_tx_iface_required", 0) or 0) == 1:
        rules.append(
            KpiGateRule(
                "persistent_tx_iface",
                "persistent_tx_iface",
                "non_empty",
                1,
                required=bool(persistent_stream_scope),
            )
        )
    if "persistent_tx_bridge_sent_min" in gates:
        rules.append(
            KpiGateRule(
                "persistent_tx_bridge_sent",
                "persistent_tx_bridge_sent",
                "min",
                float(gates.get("persistent_tx_bridge_sent_min", 0.0) or 0.0),
                required=bool(persistent_stream_scope),
            )
        )
    if "persistent_produced_min" in gates:
        rules.append(
            KpiGateRule(
                "persistent_produced",
                "persistent_produced",
                "min",
                float(gates.get("persistent_produced_min", 0.0) or 0.0),
                required=bool(persistent_stream_scope),
            )
        )
    for gate_key, metric_name in (
        ("queue_pressure_min", "queue_pressure"),
        ("quota_stall_min", "quota_stall"),
        ("ring_occupancy_peak_min", "ring_occupancy_peak"),
        ("persistent_runtime_restarts_min", "persistent_runtime_restarts"),
        ("no_progress_events_min", "no_progress_events"),
        ("compat_fallback_count_min", "compat_fallback_count"),
        ("bridge_drain_batches_min", "bridge_drain_batches"),
        ("bridge_drain_packets_min", "bridge_drain_packets"),
        ("ring_drop_events_min", "ring_drop_events"),
        ("persistent_bridge_ipg_ns_min", "persistent_bridge_ipg_ns"),
    ):
        if gate_key in gates:
            rules.append(
                KpiGateRule(
                    metric_name,
                    metric_name,
                    "min",
                    float(gates.get(gate_key, 0.0) or 0.0),
                    required=bool(persistent_stream_scope),
                )
            )
    if "scheduler_fairness_cv_pct_max" in gates:
        rules.append(
            KpiGateRule(
                "scheduler_fairness_cv_pct",
                "scheduler_fairness_cv_pct",
                "max",
                float(gates.get("scheduler_fairness_cv_pct_max", 25.0) or 25.0),
                required=bool(persistent_stream_scope),
            )
        )
    return rules


def evaluate(
    results: Dict[str, Any],
    *,
    profile: str = "off",
    hard_fail: bool = False,
    parity_matrix_path: Optional[str] = None,
) -> KpiGateResult:
    profile_norm = _normalize_profile(profile)
    run_quality = str((results or {}).get("run_quality", "") or "").strip().lower()

    if profile_norm == "off":
        return KpiGateResult(
            profile="off",
            status="pass",
            hard_fail=0,
            violations=[],
            score_eligible=int(run_quality == "valid"),
            evaluated_rules=[],
        )

    gates = _merge_gate_defaults(profile_norm, parity_matrix_path=parity_matrix_path)
    rules = _build_rules(gates, results or {}, profile=profile_norm)

    violations: List[str] = []
    evaluated: List[Dict[str, Any]] = []

    for rule in rules:
        value = (results or {}).get(rule.metric)
        passed = True
        detail = "ok"

        if value is None:
            if rule.required:
                passed = False
                detail = "missing_metric"
            else:
                detail = "missing_optional_metric"
        elif rule.op == "eq":
            lhs = str(value).strip().lower()
            rhs = str(rule.threshold).strip().lower()
            if rule.metric == "quic_stack_mode":
                lhs = quic_mode.normalize(lhs)
                rhs = quic_mode.normalize(rhs)
            passed = lhs == rhs
            if not passed:
                detail = f"expected={rhs} actual={lhs}"
        elif rule.op == "min":
            fv = _to_float(value)
            if fv is None:
                passed = False
                detail = "non_numeric"
            else:
                passed = fv >= float(rule.threshold)
                if not passed:
                    detail = f"expected>={float(rule.threshold):.6g} actual={fv:.6g}"
        elif rule.op == "max":
            fv = _to_float(value)
            if fv is None:
                passed = False
                detail = "non_numeric"
            else:
                passed = fv <= float(rule.threshold)
                if not passed:
                    detail = f"expected<={float(rule.threshold):.6g} actual={fv:.6g}"
        elif rule.op == "single_path":
            if not isinstance(value, dict):
                passed = False
                detail = "non_dict"
            else:
                active_paths: List[str] = []
                for key, raw_count in value.items():
                    fv = _to_float(raw_count)
                    if fv is None:
                        continue
                    if fv > 0.0:
                        active_paths.append(str(key or "").strip())
                active_paths = [p for p in active_paths if p]
                if len(active_paths) != 1:
                    passed = False
                    detail = f"expected_single_path actual={len(active_paths)}"
                elif str(active_paths[0] or "").strip().upper() == "MIXED":
                    passed = False
                    detail = "drift_mixed"
                else:
                    detail = f"path={active_paths[0]}"
        elif rule.op == "in_set":
            lhs = str(value).strip().lower()
            allowed = {
                str(tok).strip().lower()
                for tok in str(rule.threshold or "").replace(",", "|").split("|")
                if str(tok).strip()
            }
            passed = lhs in allowed
            if not passed:
                detail = f"expected_one_of={sorted(allowed)} actual={lhs}"
        elif rule.op == "non_empty":
            lhs = str(value or "").strip()
            passed = bool(lhs)
            if not passed:
                detail = "empty"

        evaluated.append(
            {
                "name": rule.name,
                "metric": rule.metric,
                "op": rule.op,
                "threshold": rule.threshold,
                "value": value,
                "required": bool(rule.required),
                "passed": bool(passed),
                "detail": detail,
            }
        )

        if not passed:
            violations.append(f"{rule.name}:{detail}")

    strict_fail_profiles = {"dedicated_lab", "persistent_stream_strict"}
    if violations:
        status = "fail" if profile_norm in strict_fail_profiles else "warn"
    else:
        status = "pass"

    hard_fail_flag = int(bool(hard_fail) and profile_norm in strict_fail_profiles and status == "fail")
    score_eligible = int(run_quality == "valid" and status == "pass")

    return KpiGateResult(
        profile=profile_norm,
        status=status,
        hard_fail=hard_fail_flag,
        violations=violations,
        score_eligible=score_eligible,
        evaluated_rules=evaluated,
    )
