import importlib

import pytest


def _reload_gpu_packet():
    import ddos_samurai.gpu_packet as gp

    return importlib.reload(gp)


def test_gpu_packet_facade_is_zmq_only():
    gp = _reload_gpu_packet()
    assert gp.get_active_backend_name() == "zmq"
    assert gp.is_native_path_enabled() is False
    assert gp.is_native_library_available() is False
    assert gp.get_native_policy() == "removed"


def test_zero_copy_contract_helpers_are_local_contract_math():
    gp = _reload_gpu_packet()
    assert gp.publication_budget_us(300) == 50
    assert gp.publication_budget_us(9000) == 900
    assert gp.publication_budget_us(50000) == 1000
    assert gp.seqlock_next_versions(8) == (9, 10)
    assert gp.seqlock_next_versions(9) == (11, 12)
    assert gp.descriptor_transition_valid(gp.DESCRIPTOR_STATE_FREE, gp.DESCRIPTOR_STATE_GPU_WRITING)
    assert not gp.descriptor_transition_valid(gp.DESCRIPTOR_STATE_FREE, gp.DESCRIPTOR_STATE_READY_FOR_NIC)

    aff = gp.compute_flow_affinity(block_idx=2, block_dim=256, thread_idx=63, flows_per_warp=32, warp_size=32)
    assert aff["global_tid"] == 575
    assert aff["global_warp_id"] == 17
    assert aff["lane"] == 31
    assert aff["flow_start"] == 544
    assert aff["flow_id"] == 575


def test_sync_packet_generation_bridge_is_removed():
    gp = _reload_gpu_packet()
    with pytest.raises(gp.GPUPacketError, match="Python CUDA bridge is disabled"):
        gp.generate_packets(count=1, target_ip="127.0.0.1", target_port=80)
