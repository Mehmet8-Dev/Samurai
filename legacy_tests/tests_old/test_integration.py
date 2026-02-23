import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
import argparse

# Add project root to the Python path
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ddos_samurai import orchestrator
from ddos_samurai import packet

@pytest.mark.asyncio
async def test_worker_process_basic_attack_flow(mocker):
    """
    Integration test to ensure the worker process correctly calls the packet_sender
    with a properly constructed PacketConfig for a basic attack.
    """
    # 1. Mock the sender function
    mock_packet_sender = mocker.patch('ddos_samurai.senders.packet_sender', new_callable=mocker.AsyncMock)

    # 2. Create an `args` dict that mimics the user's command
    args = {
        'target': '192.168.1.1',
        'port': 80,
        'count': 100,
        'attack_vector': 'basic',
        'protocol': 'udp',
        'spoof': True,
        'spoof_mode': 'realistic',
        'spoof_subnet': None,
        'spoof_list_file': None,
        'payloads': [],
        'tcp_flags': 'S',
        'ttl': None,
        'tos': None,
        'window': None,
        'fragment': False,
        'pad': 0,
        'dns_name': 'example.com',
        'dns_qtype': ['A'],
        'dns_edns': False,
        'dns_nord': False,
        'delay': 0,
        'rps': 0,
        'jitter': 0,
        'ramp': 0,
        'metrics_log': '',
        'verbose': False,
        'compute_backend': 'cpu' # Ensure we test the CPU path
    }

    # 3. Call the orchestrator's worker_process
    await orchestrator.worker_process(worker_id=1, args=args, shared_metrics=None, lock=None, ssl_context=None)

    # 4. Assert that our mocked sender was called
    mock_packet_sender.assert_awaited_once()

    # 5. Inspect the arguments
    call_args, call_kwargs = mock_packet_sender.call_args
    packet_config = call_kwargs.get('packet_config')

    assert packet_config is not None
    assert packet_config.target_ip == '192.168.1.1'
    assert packet_config.protocol == 'udp'
    assert packet_config.spoof is True
    assert packet_config.spoof_opts.mode == 'realistic'