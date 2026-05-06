from ddos_samurai.control.master import _apply_distributed_kpi_gate, _distributed_snapshot_to_prometheus


def test_distributed_snapshot_to_prometheus_includes_core_fields_and_gate_status():
    snap = {
        "workers": 3,
        "shards_reported": 12,
        "sent": 100,
        "errors": 2,
        "pending_shards_left": 0,
        "inflight_shards_left": 1,
        "kpi_gate_status": "pass",
    }
    text = _distributed_snapshot_to_prometheus(snap)
    assert "samurai_distributed_workers 3.0" in text
    assert "samurai_distributed_shards_reported 12.0" in text
    assert 'samurai_distributed_kpi_gate_status{status="pass"} 1' in text


def test_apply_distributed_kpi_gate_off_profile_passes():
    snap = {"sent": 10, "errors": 0}
    out = _apply_distributed_kpi_gate(snap, {"kpi_gate_profile": "off", "kpi_hard_fail": True})
    assert out["kpi_gate_profile"] == "off"
    assert out["kpi_gate_status"] == "pass"
    assert int(out["kpi_gate_hard_fail"]) == 0


def test_apply_distributed_kpi_gate_dedicated_profile_emits_fields():
    snap = {
        "run_quality": "valid",
        "send_success_ratio_pct": 100.0,
        "wire_loss_est_pct": 0.0,
        "rate_accuracy_pct": 100.0,
        "txring_flush_error_ratio_pct": 0.0,
        "txring_flush_eagain_ratio_pct": 0.0,
        "txring_hold_block_pressure_pct": 0.0,
        "afpacket_hugepage_effective": 1,
        "session_success_rate": 100.0,
        "retry_success_rate": 100.0,
        "l7_step_fail_ratio": 0.0,
        "l7_handshake_p99_ms": 1.0,
        "l7_fail_budget_pct": 0.0,
        "quic_stream_fail_ratio": 0.0,
        "quic_handshake_fail_ratio": 0.0,
        "quic_response_validation_fail_ratio": 0.0,
        "quic_stack_mode": "custom_native",
        "sender_fallback_reason": "none",
        "sender_path_single_required": 1,
        "runtime_backend": "afxdp",
        "runtime_hot_path_level": "phase1_hybrid_afxdp_custom_tcp",
        "legacy_path_used": 0,
        "custom_tcp_bridge_xdp_enabled": 1,
        "custom_tcp_bridge_backend_match": 1,
        "runtime_transport_backend": "custom_tcp",
        "stateful_runtime_status": "ready",
        "l7_conn_rate_cv_pct": 0.0,
    }
    out = _apply_distributed_kpi_gate(snap, {"kpi_gate_profile": "dedicated_lab", "kpi_hard_fail": True})
    assert out["kpi_gate_profile"] == "dedicated_lab"
    assert out["kpi_gate_status"] in {"pass", "warn", "fail"}
    assert "kpi_gate_hard_fail" in out
