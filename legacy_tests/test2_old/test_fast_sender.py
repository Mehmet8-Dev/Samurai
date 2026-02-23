import pytest
import ctypes
import os
from ddos_samurai import fast_sender

def test_fast_sender_imports():
    assert hasattr(fast_sender, 'get_states_batch')
    assert hasattr(fast_sender, 'set_mimicry_settings')
    assert hasattr(fast_sender, 'get_tcp_state')

def test_mimicry_settings():
    # Test setting and getting mimicry settings
    # Since we can't directly read the global variables from Python,
    # we test if the function accepts the arguments correctly.
    try:
        fast_sender.set_mimicry_settings(65535, 1460, 128)
    except Exception as e:
        pytest.fail(f"set_mimicry_settings failed: {e}")

def test_state_table_batch():
    # Test get_states_batch with dummy data
    src_ip = 0x01020304 # 1.2.3.4
    start_port = 10000
    count = 10
    
    try:
        res = fast_sender.get_states_batch(src_ip, start_port, count)
        assert len(res) == 6 # seq, ack, state, window, mss, ttl
        for i in range(6):
            assert len(res[i]) == count
    except Exception as e:
        pytest.fail(f"get_states_batch failed: {e}")

def test_get_tcp_state_empty():
    # Test getting state for a non-existent entry
    src_ip = 0x0A000001 # 10.0.0.1
    src_port = 12345
    
    res = fast_sender.get_tcp_state(src_ip, src_port)
    assert isinstance(res, dict)
    assert res['state'] == 0 # CLOSED
    assert res['seq'] == 0
    assert res['ack'] == 0
