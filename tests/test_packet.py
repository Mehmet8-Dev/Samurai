import asyncio
import tempfile
import unittest

from ddos_samurai.packet import PacketConfig, SpoofingOptions, create_packet, get_spoofed_ip


def _ip_header(pkt) -> bytes:
    data = bytes(pkt)
    return data[14:] if len(data) >= 34 and data[12:14] == b"\x08\x00" else data


class _DummyPacket:
    def __init__(self, has_ether: bool):
        self._has_ether = bool(has_ether)

    def haslayer(self, name: str) -> bool:
        return bool(self._has_ether and name == "Ether")


class TestSendPacketAsync(unittest.IsolatedAsyncioTestCase):
    async def test_send_packet_async_error_handling(self):
        """send_packet_async should return False when packet bytes are invalid."""
        from ddos_samurai.senders import send_packet_async

        pkt = _DummyPacket(has_ether=True)
        loop = asyncio.get_running_loop()
        ok = await send_packet_async(pkt, verbose=True, packet_no=1, loop=loop, protocol="udp")

        self.assertFalse(ok)


class TestSpoofedIp(unittest.TestCase):
    def test_get_spoofed_ip_from_file(self):
        with tempfile.TemporaryDirectory() as td:
            p = f"{td}/ips.txt"
            with open(p, "w", encoding="utf-8") as f:
                f.write("1.1.1.1\n2.2.2.2\n3.3.3.3\n")

            spoofed_ip = get_spoofed_ip("list", {"file_path": p})
            self.assertIn(spoofed_ip, ["1.1.1.1", "2.2.2.2", "3.3.3.3"])

    def test_get_spoofed_ip_modes(self):
        realistic_ip = get_spoofed_ip("realistic", {})
        self.assertIsInstance(realistic_ip, str)

        random_ip = get_spoofed_ip("random", {})
        self.assertIsInstance(random_ip, str)

        subnet_ip = get_spoofed_ip("subnet", {"subnet": "10.0.0.0/24"})
        self.assertIsInstance(subnet_ip, str)
        self.assertTrue(subnet_ip.startswith("10.0.0."))

        # List mode fallback (file missing) should still return a string.
        list_ip = get_spoofed_ip("list", {"file_path": "non_existent_file.txt"})
        self.assertIsInstance(list_ip, str)


class TestPacketCreationNative(unittest.TestCase):
    def test_create_basic_udp_packet(self):
        config = PacketConfig(target_ip="1.2.3.4", target_port=80, protocol="udp")
        pkt = create_packet(config)
        ip = _ip_header(pkt)
        self.assertEqual(ip[0], 0x45)
        self.assertEqual(ip[9], 17)
        self.assertEqual(ip[16:20], b"\x01\x02\x03\x04")
        self.assertEqual(int.from_bytes(ip[22:24], "big"), 80)

    def test_create_spoofed_udp_packet(self):
        config = PacketConfig(
            target_ip="1.2.3.4",
            target_port=80,
            protocol="udp",
            spoof=True,
            spoof_opts=SpoofingOptions(mode="subnet", subnet="10.20.30.40/32"),
        )
        pkt = create_packet(config)
        ip = _ip_header(pkt)
        self.assertEqual(ip[12:16], b"\x0a\x14\x1e\x28")
        self.assertEqual(ip[16:20], b"\x01\x02\x03\x04")
