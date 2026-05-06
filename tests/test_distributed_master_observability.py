from ddos_samurai.control.master import (
    _apply_per_shard_kpi_gate,
    _apply_distributed_kpi_gate,
    _distributed_snapshot_to_prometheus,
    _distributed_state_to_prometheus,
)


def test_distributed_snapshot_to_prometheus_includes_core_fields_and_gate_status():
    snap = {
        "workers": 3,
        "shards_reported": 12,
        "sent": 100,
        "errors": 2,
        "pending_shards_left": 0,
        "inflight_shards_left": 1,
        "kpi_gate_status": "pass",
        "per_shard_kpi_status": "pass",
        "per_shard_kpi_failed_count": 0,
    }
    text = _distributed_snapshot_to_prometheus(snap)
    assert "samurai_distributed_workers 3.0" in text
    assert "samurai_distributed_shards_reported 12.0" in text
    assert 'samurai_distributed_kpi_gate_status{status="pass"} 1' in text
    assert 'samurai_distributed_per_shard_kpi_status{status="pass"} 1' in text
    assert "samurai_distributed_per_shard_kpi_failed_count 0.0" in text


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


def test_distributed_state_to_prometheus_includes_worker_shard_and_ha_metrics():
    state = {
        "latest_snapshot": {"workers": 1, "shards_reported": 2, "sent": 11, "errors": 1},
        "workers": [{"worker_id": "w-1", "state": "running", "last_heartbeat_ms": 1234}],
        "shards": [{"shard_id": "s-1", "stats_size_bytes": 96}],
        "ha": {"mode": "static", "is_leader": 1},
    }
    text = _distributed_state_to_prometheus(state)
    assert "samurai_distributed_workers 1.0" in text
    assert "samurai_distributed_workers_live 1.0" in text
    assert 'samurai_distributed_worker_state{worker_id="w-1",state="running"} 1' in text
    assert 'samurai_distributed_shard_stats_size_bytes{shard_id="s-1"} 96.0' in text
    assert 'samurai_distributed_ha_is_leader{mode="static"} 1.0' in text
    assert 'samurai_distributed_ha_leader_epoch{mode="static"} 0.0' in text


def test_apply_per_shard_kpi_gate_flags_exitcode_and_error_rate():
    snap = {
        "top_error_shards": [
            {"shard_id": "s1", "sent": 90, "errors": 20, "last_exitcode": 0},
            {"shard_id": "s2", "sent": 100, "errors": 0, "last_exitcode": 1},
            {"shard_id": "s3", "sent": 100, "errors": 1, "last_exitcode": 0},
        ]
    }
    out = _apply_per_shard_kpi_gate(
        snap,
        {
            "shard_kpi_max_error_rate_pct": 10.0,
            "shard_kpi_fail_on_exitcode": True,
            "kpi_hard_fail": True,
        },
    )
    assert out["per_shard_kpi_status"] == "fail"
    assert int(out["per_shard_kpi_failed_count"]) == 2
    assert int(out["per_shard_kpi_hard_fail"]) == 1
