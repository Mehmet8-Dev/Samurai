import asyncio
import unittest
from unittest.mock import Mock, patch


class _DummyPacket:
    def __init__(self, has_ether: bool):
        self._has_ether = bool(has_ether)

    def haslayer(self, name: str) -> bool:
        return bool(self._has_ether and name == "Ether")


class _FakeScapy:
    def __init__(self):
        self.sendp = Mock()
        self.send = Mock()

    def get_working_if(self):
        return "lo"


class TestSendPacketAsync(unittest.IsolatedAsyncioTestCase):
    async def test_send_packet_async_calls_sendp_for_l2_packets(self):
        from ddos_samurai.senders import send_packet_async

        fake = _FakeScapy()
        pkt = _DummyPacket(has_ether=True)

        with patch("ddos_samurai.senders._scapy", return_value=fake):
            loop = asyncio.get_running_loop()
            ok = await send_packet_async(pkt, verbose=False, packet_no=1, loop=loop, protocol="tcp")

        self.assertTrue(ok)
        fake.sendp.assert_called_once()
        fake.send.assert_not_called()

    async def test_send_packet_async_calls_send_for_l3_packets(self):
        from ddos_samurai.senders import send_packet_async

        fake = _FakeScapy()
        pkt = _DummyPacket(has_ether=False)

        with patch("ddos_samurai.senders._scapy", return_value=fake):
            loop = asyncio.get_running_loop()
            ok = await send_packet_async(pkt, verbose=False, packet_no=1, loop=loop, protocol="udp")

        self.assertTrue(ok)
        fake.send.assert_called_once()

