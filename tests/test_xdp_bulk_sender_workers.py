import pytest

from ddos_samurai.af_xdp_sender import AFXDPBridgeRemoved, XDPBulkSender


def test_xdp_bulk_sender_direct_send_removed():
    bulk = XDPBulkSender(interface="lo", threads=2, batch_size=8, queue_count=1)
    assert bulk.start() is True
    with pytest.raises(AFXDPBridgeRemoved, match="Python xdp_sender bridge"):
        bulk.send_continuous(packet_generator=lambda: [b"x" * 32], duration=0.1)
    bulk.stop()
