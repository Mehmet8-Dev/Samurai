import asyncio
import unittest
from unittest.mock import patch


class _DummySocket:
    def __init__(self):
        self.sent = []

    def setsockopt(self, *args, **kwargs):
        return None

    def sendto(self, data, addr):
        self.sent.append((bytes(data), addr))
        return len(data)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None


class TestSendPacketAsync(unittest.IsolatedAsyncioTestCase):
    async def test_send_packet_async_sends_raw_ipv4_packet(self):
        from ddos_samurai.senders import send_packet_async
        from ddos_samurai.packet import PacketConfig, create_packet

        pkt = create_packet(PacketConfig(target_ip="127.0.0.1", target_port=80, protocol="udp"))
        dummy_sock = _DummySocket()

        with patch("ddos_samurai._senders.legacy_packet.socket.socket", return_value=dummy_sock):
            loop = asyncio.get_running_loop()
            ok = await send_packet_async(pkt, verbose=False, packet_no=1, loop=loop, protocol="tcp")

        self.assertTrue(ok)
        self.assertEqual(len(dummy_sock.sent), 1)
        self.assertEqual(dummy_sock.sent[0][1][0], "127.0.0.1")

    async def test_send_packet_async_rejects_non_bytes_packet(self):
        from ddos_samurai.senders import send_packet_async

        pkt = object()
        loop = asyncio.get_running_loop()
        ok = await send_packet_async(pkt, verbose=False, packet_no=1, loop=loop, protocol="udp")

        self.assertFalse(ok)
