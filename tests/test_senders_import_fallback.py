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
    async def test_send_packet_async_is_removed(self):
        from ddos_samurai.senders import send_packet_async

        loop = asyncio.get_running_loop()
        with self.assertRaises(RuntimeError):
            await send_packet_async(b"X", verbose=False, packet_no=1, loop=loop, protocol="tcp")

    async def test_send_packet_async_rejects_non_bytes_packet_via_removed_path(self):
        from ddos_samurai.senders import send_packet_async

        pkt = object()
        loop = asyncio.get_running_loop()
        with self.assertRaises(RuntimeError):
            await send_packet_async(pkt, verbose=False, packet_no=1, loop=loop, protocol="udp")
