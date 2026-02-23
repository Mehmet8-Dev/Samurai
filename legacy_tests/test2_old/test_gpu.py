import pytest
import cupy as cp
import numpy as np
from ddos_samurai import gpu_packet, gpu_payload

# Skip all tests in this module if CUDA is not available
pytestmark = pytest.mark.skipif(not cp.is_available(), reason="CUDA not available")

def test_gpu_payload_engine_init():
    engine = gpu_payload.GPUPayloadEngine(count=100)
    assert engine.count == 100
    assert engine.packets_gpu is not None
    assert engine.rng_states is not None

def test_fused_http_generation():
    count = 64
    engine = gpu_payload.GPUPayloadEngine(count=count)
    target_ip = "1.1.1.1"
    target_port = 80
    real_src_ip = "192.168.1.100"
    
    # Test generation
    packets_gpu, size = engine.generate_fused_http(
        target_ip=target_ip,
        target_port=target_port,
        real_src_ip=real_src_ip,
        gateway_mac=0x001122334455
    )
    
    assert size > 0
    assert packets_gpu.size == count * size
    
    # Download and check first packet basic structure
    first_pkt = packets_gpu[:size].get()
    # Ethernet Dst MAC (first 6 bytes)
    assert first_pkt[0] == 0x00
    assert first_pkt[1] == 0x11
    assert first_pkt[5] == 0x55
    # IP Version (at offset 14)
    assert (first_pkt[14] >> 4) == 4

def test_stateful_packet_generation():
    count = 32
    templates = [b'\x00' * 100] # Dummy template
    target_ip = "8.8.8.8"
    
    seq_list = [1000] * count
    ack_list = [2000] * count
    state_list = [2] * count # ESTABLISHED
    
    packets_gpu, size = gpu_packet.generate_stateful_packets(
        templates_bytes_list=templates,
        count=count,
        target_ip=target_ip,
        seq_list=seq_list,
        ack_list=ack_list,
        state_list=state_list
    )
    
    assert size == 100
    assert packets_gpu.size == count * 100
    
    # Check if seq/ack were patched (at offset 14+20+4 = 38 for TCP)
    # Note: This depends on the template having a TCP header at that offset.
    # Since our dummy template is all zeros, we can check if it's non-zero now.
    first_pkt = packets_gpu[:100].get()
    # TCP Seq is at offset 14+20+4 = 38
    seq_val = (first_pkt[38] << 24) | (first_pkt[39] << 16) | (first_pkt[40] << 8) | first_pkt[41]
    assert seq_val == 1000
