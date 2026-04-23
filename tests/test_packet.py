import asyncio
import tempfile
import unittest
from unittest.mock import patch

from ddos_samurai.packet import PacketConfig, SpoofingOptions, create_packet, get_spoofed_ip
from ddos_samurai.scapy_support import is_scapy_available


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


class TestPacketCreationWithScapy(unittest.TestCase):
    def setUp(self):
        if not is_scapy_available():
            self.skipTest("Scapy unavailable; packet creation tests require scapy.")

    def test_create_basic_udp_packet(self):
        from scapy.all import IP, UDP

        config = PacketConfig(target_ip="1.2.3.4", target_port=80, protocol="udp")
        pkt = create_packet(config)

        self.assertTrue(pkt.haslayer(IP))
        self.assertTrue(pkt.haslayer(UDP))
        self.assertEqual(pkt[IP].dst, "1.2.3.4")
        self.assertEqual(pkt[UDP].dport, 80)

    def test_create_spoofed_udp_packet(self):
        from scapy.all import IP

        with patch("ddos_samurai.packet.get_spoofed_ip", return_value="10.20.30.40") as mocked_get_ip:
            spoof_opts = SpoofingOptions(mode="random")
            config = PacketConfig(
                target_ip="1.2.3.4",
                target_port=80,
                protocol="udp",
                spoof=True,
                spoof_opts=spoof_opts,
            )
            pkt = create_packet(config)

        mocked_get_ip.assert_called_once_with(
            spoof_opts.mode,
            {"subnet": spoof_opts.subnet, "file_path": spoof_opts.list_file},
        )

        self.assertTrue(pkt.haslayer(IP))
        self.assertEqual(pkt[IP].src, "10.20.30.40")
        self.assertEqual(pkt[IP].dst, "1.2.3.4")
