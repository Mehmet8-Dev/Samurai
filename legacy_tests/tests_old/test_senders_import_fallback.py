import asyncio
import pytest
import os
from unittest.mock import patch, MagicMock
from scapy.all import IP, TCP

from ddos_samurai.senders import send_packet_async

@pytest.mark.skipif(os.getuid() != 0, reason="This test requires root privileges to create raw sockets.")
@pytest.mark.asyncio
async def test_send_packet_async_calls_sendp(mocker):
    """
    Tests if the core `send_packet_async` function correctly calls scapy's `sendp`.
    This isolates the final step of our packet sending pipeline.
    """
    # 1. Mock the `sendp` function from scapy.all
    mock_sendp = mocker.patch('scapy.all.sendp', return_value=None)
    
    # 2. Create a dummy packet to send
    dummy_packet = IP(dst="127.0.0.1") / TCP()
    
    # 3. Get the current asyncio loop
    loop = asyncio.get_event_loop()
    
    # 4. Call the function we want to test
    await send_packet_async(
        packet=dummy_packet,
        verbose=False,
        packet_no=1,
        loop=loop,
        protocol="tcp"
    )
    
    # 5. Assert that our mocked `sendp` was called exactly once
    mock_sendp.assert_called_once()
    
    # 6. Optional: Check if it was called with the correct packet
    call_args, call_kwargs = mock_sendp.call_args
    sent_packet = call_args[0]
    assert sent_packet == dummy_packet
