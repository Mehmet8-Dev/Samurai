import tempfile
import unittest

from ddos_samurai.packet import PacketConfig, SpoofingOptions, _randomize_http_headers, create_packet
from ddos_samurai.scapy_support import is_scapy_available


class TestPacketExtra(unittest.TestCase):
    def setUp(self):
        if not is_scapy_available():
            self.skipTest("Scapy unavailable; packet creation tests require scapy.")

    def test_build_tcp_packet_minimal(self):
        cfg = PacketConfig(target_ip="127.0.0.1", target_port=8080)
        pkt = create_packet(cfg)
        self.assertIsNotNone(pkt)
        self.assertGreater(len(bytes(pkt)), 0)

    def test_dns_packet_with_edns_and_qtypes(self):
        cfg = PacketConfig(
            target_ip="8.8.8.8",
            target_port=53,
            attack_vector="dns",
            dns_qtype=["A", "AAAA"],
            dns_edns=True,
        )
        pkt = create_packet(cfg)
        self.assertIsNotNone(pkt)
        self.assertGreater(len(bytes(pkt)), 0)

    def test_spoofing_options_list(self):
        with tempfile.TemporaryDirectory() as td:
            p = f"{td}/ips.txt"
            with open(p, "w", encoding="utf-8") as f:
                f.write("10.0.0.1\n10.0.0.2\n")

            spoof_opts = SpoofingOptions(mode="list", list_file=p)
            cfg = PacketConfig(target_ip="192.168.0.1", target_port=80, spoof=True, spoof_opts=spoof_opts)
            pkt = create_packet(cfg)
            self.assertIsNotNone(pkt)

    def test_get_spoofed_ip_modes_smoke(self):
        for mode in ["random", "realistic", "subnet"]:
            spoof_opts = SpoofingOptions(mode=mode, subnet="192.168.1.0/24")
            cfg = PacketConfig(target_ip="192.168.0.1", target_port=80, spoof=True, spoof_opts=spoof_opts)
            pkt = create_packet(cfg)
            self.assertIsNotNone(pkt)

    def test_http_request_line_uses_single_spaces(self):
        payload = _randomize_http_headers("198.51.100.10", path="/rfc", method="GET").decode("ascii", errors="replace")
        first_line = payload.split("\r\n", 1)[0]
        self.assertEqual(first_line, "GET /rfc HTTP/1.1")
