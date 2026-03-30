import ipaddress
import struct
import threading
import time
import unittest

try:
    from ddos_samurai import l4_state_engine as l4se
    L4SE_AVAILABLE = True
except ImportError:
    L4SE_AVAILABLE = False


def _ip_to_int(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))


def _build_tcp_ipv4_frame(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    ttl: int = 64,
    window: int = 64240,
) -> bytes:
    eth = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + b"\x08\x00"

    src_ip_b = ipaddress.IPv4Address(src_ip).packed
    dst_ip_b = ipaddress.IPv4Address(dst_ip).packed
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40,
        0,
        0,
        int(ttl),
        6,
        0,
        src_ip_b,
        dst_ip_b,
    )
    tcp_hdr = struct.pack(
        "!HHLLBBHHH",
        int(src_port),
        int(dst_port),
        int(seq) & 0xFFFFFFFF,
        int(ack) & 0xFFFFFFFF,
        0x50,
        int(flags) & 0xFF,
        int(window) & 0xFFFF,
        0,
        0,
    )
    return eth + ip_hdr + tcp_hdr


class TestL4StateEngine(unittest.TestCase):
    def setUp(self):
        if not L4SE_AVAILABLE:
            self.skipTest("l4_state_engine extension not available/compiled")

    def test_three_way_handshake_transitions(self):
        l4se.configure_state_engine(8192, 64, 5)
        l4se.set_mimicry_settings(62000, 1460, 61)

        local_ip = "10.10.10.2"
        remote_ip = "10.10.10.1"
        local_port = 40000
        remote_port = 443

        syn = _build_tcp_ipv4_frame(local_ip, remote_ip, local_port, remote_port, seq=1000, ack=0, flags=0x02)
        updated = l4se.ingest_tx_packets(syn, len(syn), 1)
        self.assertEqual(updated, 1)

        st = l4se.get_tcp_state(_ip_to_int(local_ip), local_port)
        self.assertEqual(int(st.get("state", 0)), 1)
        self.assertEqual(int(st.get("seq", 0)), 1001)
        self.assertEqual(int(st.get("ack", 0)), 0)

        synack = _build_tcp_ipv4_frame(remote_ip, local_ip, remote_port, local_port, seq=2000, ack=1001, flags=0x12)
        rx_updated = l4se.ingest_rx_frame(synack)
        self.assertEqual(rx_updated, 1)

        st = l4se.get_tcp_state(_ip_to_int(local_ip), local_port)
        self.assertEqual(int(st.get("state", 0)), 2)
        self.assertEqual(int(st.get("seq", 0)), 1001)
        self.assertEqual(int(st.get("ack", 0)), 2001)

        ack = _build_tcp_ipv4_frame(local_ip, remote_ip, local_port, remote_port, seq=1001, ack=2001, flags=0x10)
        updated2 = l4se.ingest_tx_packets(ack, len(ack), 1)
        self.assertEqual(updated2, 1)

        st = l4se.get_tcp_state(_ip_to_int(local_ip), local_port)
        self.assertEqual(int(st.get("state", 0)), 2)
        self.assertEqual(int(st.get("seq", 0)), 1001)
        self.assertEqual(int(st.get("ack", 0)), 2001)

        seq_list, ack_list, state_list, win_list, mss_list, ttl_list = l4se.get_states_batch(
            _ip_to_int(local_ip), local_port, 4
        )
        self.assertEqual(len(seq_list), 4)
        self.assertEqual(int(state_list[0]), 2)
        self.assertEqual(int(seq_list[0]), 1001)
        self.assertEqual(int(ack_list[0]), 2001)
        self.assertTrue(int(win_list[0]) > 0)
        self.assertTrue(int(mss_list[0]) > 0)
        self.assertTrue(int(ttl_list[0]) > 0)

    def test_timeout_sweep_and_stats(self):
        l4se.configure_state_engine(2048, 32, 1)

        local_ip = "192.168.56.2"
        remote_ip = "93.184.216.34"
        local_port = 40123
        remote_port = 80

        syn = _build_tcp_ipv4_frame(local_ip, remote_ip, local_port, remote_port, seq=12345, ack=0, flags=0x02)
        l4se.ingest_tx_packets(syn, len(syn), 1)

        removed = 0
        deadline = time.time() + 3.0
        while time.time() < deadline and int(removed) <= 0:
            time.sleep(0.25)
            removed = l4se.sweep_state_table(2048)
        self.assertGreaterEqual(int(removed), 1)

        stats = l4se.get_state_engine_stats()
        self.assertGreaterEqual(int(stats.get("timeout_evictions", 0)), 1)
        self.assertGreaterEqual(int(stats.get("sweeps", 0)), 1)

    def test_threaded_ingest_stability(self):
        l4se.configure_state_engine(16384, 128, 10)

        local_ip = "172.16.1.10"
        remote_ip = "172.16.1.1"
        remote_port = 443

        packets = []
        for i in range(256):
            packets.append(
                _build_tcp_ipv4_frame(
                    local_ip,
                    remote_ip,
                    30000 + i,
                    remote_port,
                    seq=1000 + i,
                    ack=0,
                    flags=0x02,
                )
            )
        packet_size = len(packets[0])
        batch = b"".join(packets)

        errors = []

        def _worker() -> None:
            try:
                for _ in range(10):
                    l4se.ingest_tx_packets(batch, packet_size, len(packets))
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=_worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        stats = l4se.get_state_engine_stats()
        self.assertGreater(int(stats.get("active_entries", 0)), 0)


if __name__ == "__main__":
    unittest.main()
