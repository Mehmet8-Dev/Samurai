import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from ddos_samurai._senders import legacy_packet


class _DummySock:
    def __init__(self):
        self.sent = []
        self.opts = []
        self.closed = False

    def setsockopt(self, *args):
        self.opts.append(args)

    def sendto(self, data, addr):
        self.sent.append((bytes(data), addr))
        return len(data)

    def close(self):
        self.closed = True


class TestLegacyPacketCpuPool(unittest.IsolatedAsyncioTestCase):
    async def test_cpu_sender_uses_pool_view_when_not_fragmented(self):
        packet_config = SimpleNamespace(
            target_ip="127.0.0.1",
            target_port=80,
            protocol="tcp",
            spoof=False,
            spoof_opts=None,
            payload=None,
            tcp_flags="S",
            ttl=None,
            tos=None,
            window=None,
            fragment_enabled=False,
            fragment_size=800,
            pad_size=0,
            attack_vector="basic",
            dns_name="example.com",
            dns_qtype="A",
            dns_edns=False,
            dns_recursive=True,
        )
        dummy_sock = _DummySock()
        cpu_packet_engine = SimpleNamespace(
            SpoofingOptions=lambda **kw: SimpleNamespace(**kw),
            PacketConfig=lambda **kw: SimpleNamespace(**kw),
            generate_packet_pool_view=Mock(return_value=(memoryview(b"abcd" * 4), 4)),
            create_packet=Mock(side_effect=AssertionError("create_packet should not be used in pool fast path")),
            fragment_packet=Mock(),
        )

        with patch("ddos_samurai._senders.legacy_packet.socket.socket", return_value=dummy_sock):
            result = await legacy_packet.packet_sender(
                packet_config=packet_config,
                count=4,
                delay=0.0,
                rps=0.0,
                jitter=0.0,
                ramp=0.0,
                verbose=False,
                live_sent=None,
                live_errors=None,
                live_progress=None,
                scapy_getter=Mock(),
                stats_fn=lambda **kw: kw,
                update_live_fn=lambda *args, **kwargs: None,
                log_error=Mock(),
                cpu_packet_engine=cpu_packet_engine,
                packet_utils=Mock(),
                ScapyUnavailableError=RuntimeError,
            )

        self.assertEqual(result["sent"], 4)
        self.assertEqual(len(dummy_sock.sent), 4)
        cpu_packet_engine.generate_packet_pool_view.assert_called_once()

    async def test_cpu_sender_fragmented_path_still_uses_create_packet(self):
        packet_config = SimpleNamespace(
            target_ip="127.0.0.1",
            target_port=80,
            protocol="tcp",
            spoof=False,
            spoof_opts=None,
            payload=None,
            tcp_flags="S",
            ttl=None,
            tos=None,
            window=None,
            fragment_enabled=True,
            fragment_size=64,
            pad_size=0,
            attack_vector="basic",
            dns_name="example.com",
            dns_qtype="A",
            dns_edns=False,
            dns_recursive=True,
        )
        dummy_sock = _DummySock()
        cpu_packet_engine = SimpleNamespace(
            SpoofingOptions=lambda **kw: SimpleNamespace(**kw),
            PacketConfig=lambda **kw: SimpleNamespace(**kw),
            generate_packet_pool_view=Mock(side_effect=AssertionError("pool view should not be used when fragmenting")),
            create_packet=Mock(return_value=b"abcdefgh"),
            fragment_packet=Mock(return_value=[b"abcd", b"efgh"]),
        )

        with patch("ddos_samurai._senders.legacy_packet.socket.socket", return_value=dummy_sock):
            result = await legacy_packet.packet_sender(
                packet_config=packet_config,
                count=2,
                delay=0.0,
                rps=0.0,
                jitter=0.0,
                ramp=0.0,
                verbose=False,
                live_sent=None,
                live_errors=None,
                live_progress=None,
                scapy_getter=Mock(),
                stats_fn=lambda **kw: kw,
                update_live_fn=lambda *args, **kwargs: None,
                log_error=Mock(),
                cpu_packet_engine=cpu_packet_engine,
                packet_utils=Mock(),
                ScapyUnavailableError=RuntimeError,
            )

        self.assertEqual(result["sent"], 4)
        self.assertEqual(cpu_packet_engine.create_packet.call_count, 2)
        self.assertEqual(cpu_packet_engine.fragment_packet.call_count, 2)
