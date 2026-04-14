import ipaddress
import struct
import time
import unittest

try:
    from ddos_samurai import custom_tcp_dataplane as tcpdp

    TCPDP_AVAILABLE = True
except ImportError:
    TCPDP_AVAILABLE = False


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
    payload: bytes = b"",
    ttl: int = 64,
    window: int = 64240,
) -> bytes:
    eth = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + b"\x08\x00"
    total_len = 40 + len(payload)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        0,
        0,
        int(ttl),
        6,
        0,
        ipaddress.IPv4Address(src_ip).packed,
        ipaddress.IPv4Address(dst_ip).packed,
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
    return eth + ip_hdr + tcp_hdr + payload


def _drain_packets(tcpdp_module, max_packets: int = 0):
    peek = getattr(tcpdp_module, "peek_tcp_tx_buffer_strided", None)
    consume = getattr(tcpdp_module, "consume_tcp_tx_packets", None)
    if not callable(peek) or not callable(consume):
        raise RuntimeError("custom tcp dataplane requires peek/consume zero-copy api")
    batch = peek(int(max_packets or 0))
    if not isinstance(batch, dict):
        return []
    buf = batch.get("buffer")
    count = int(batch.get("count", 0) or 0)
    pkt_size = int(batch.get("packet_size", 0) or 0)
    stride = int(batch.get("stride", 0) or 0)
    if buf is None or count <= 0 or pkt_size <= 0 or stride < pkt_size:
        return []
    mv = memoryview(buf)
    out = []
    for i in range(count):
        start = i * stride
        out.append(bytes(mv[start : start + pkt_size]))
    consumed = int(consume(count) or 0)
    if consumed < count:
        out = out[:consumed]
    return out


class TestCustomTcpDataplane(unittest.TestCase):
    def setUp(self):
        if not TCPDP_AVAILABLE:
            self.skipTest("custom tcp dataplane extension not available/compiled")
        tcpdp.configure_tcp_dataplane("required", "af_xdp", 50, 3, 250, 500)

    def test_connect_flow_tracks_full_tuple_and_establishes(self):
        flow_id = tcpdp.enqueue_tcp_connect(_ip_to_int("10.0.0.2"), _ip_to_int("10.0.0.1"), 40000, 443)
        tx = _drain_packets(tcpdp)
        self.assertEqual(len(tx), 1)

        flow = tcpdp.get_tcp_flow(flow_id)
        self.assertEqual(int(flow["src_port"]), 40000)
        self.assertEqual(int(flow["dst_port"]), 443)
        self.assertEqual(int(flow["state"]), 1)

        synack = _build_tcp_ipv4_frame(
            "10.0.0.1",
            "10.0.0.2",
            443,
            40000,
            seq=9000,
            ack=int(flow["snd_nxt"]),
            flags=0x12,
        )
        self.assertEqual(tcpdp.ingest_tcp_rx_frame(synack), 1)
        tx = _drain_packets(tcpdp)
        self.assertEqual(len(tx), 1)
        flow = tcpdp.get_tcp_flow(flow_id)
        self.assertEqual(int(flow["state"]), 3)
        self.assertEqual(int(flow["rcv_nxt"]), 9001)

        completions = tcpdp.collect_tcp_completions()
        self.assertTrue(any(item["event"] == "connect_established" for item in completions))

    def test_ack_advances_snd_una_for_payload(self):
        flow_id = tcpdp.enqueue_tcp_connect(_ip_to_int("10.1.0.2"), _ip_to_int("10.1.0.1"), 41000, 80)
        syn_flow = tcpdp.get_tcp_flow(flow_id)
        _drain_packets(tcpdp)
        synack = _build_tcp_ipv4_frame(
            "10.1.0.1", "10.1.0.2", 80, 41000, seq=7000, ack=int(syn_flow["snd_nxt"]), flags=0x12
        )
        tcpdp.ingest_tcp_rx_frame(synack)
        _drain_packets(tcpdp)

        queued = tcpdp.enqueue_tcp_send(flow_id, b"GET / HTTP/1.1\r\n\r\n")
        self.assertGreater(queued, 0)
        tx = _drain_packets(tcpdp)
        self.assertEqual(len(tx), 1)
        before = tcpdp.get_tcp_flow(flow_id)
        self.assertGreater(int(before["snd_nxt"]), int(before["snd_una"]))

        ack = _build_tcp_ipv4_frame(
            "10.1.0.1",
            "10.1.0.2",
            80,
            41000,
            seq=7001,
            ack=int(before["snd_nxt"]),
            flags=0x10,
        )
        tcpdp.ingest_tcp_rx_frame(ack)
        after = tcpdp.get_tcp_flow(flow_id)
        self.assertEqual(int(after["snd_una"]), int(after["snd_nxt"]))

    def test_poll_schedules_retransmit_after_timeout(self):
        flow_id = tcpdp.enqueue_tcp_connect(_ip_to_int("192.0.2.10"), _ip_to_int("198.51.100.20"), 42000, 443)
        _drain_packets(tcpdp)
        flow = tcpdp.get_tcp_flow(flow_id)
        actions = tcpdp.poll_tcp_dataplane(int(flow["rto_deadline_ns"]) + 1, 64)
        self.assertGreaterEqual(actions, 1)
        tx = _drain_packets(tcpdp)
        self.assertEqual(len(tx), 1)
        stats = tcpdp.snapshot_tcp_dataplane()
        self.assertGreaterEqual(int(stats["tcp_retransmit_count"]), 1)

    def test_max_retransmits_fail_close(self):
        tcpdp.configure_tcp_dataplane("required", "af_xdp", 10, 1, 25, 50)
        flow_id = tcpdp.enqueue_tcp_connect(_ip_to_int("203.0.113.10"), _ip_to_int("203.0.113.20"), 43000, 443)
        stats = tcpdp.snapshot_tcp_dataplane()
        self.assertEqual(int(stats["tcp_flows_active"]), 1)
        _drain_packets(tcpdp)
        flow = tcpdp.get_tcp_flow(flow_id)
        tcpdp.poll_tcp_dataplane(int(flow["rto_deadline_ns"]) + 1, 64)
        tx = _drain_packets(tcpdp)
        self.assertEqual(len(tx), 1)
        flow = tcpdp.get_tcp_flow(flow_id)
        tcpdp.poll_tcp_dataplane(int(flow["rto_deadline_ns"]) + 1, 64)
        flow = tcpdp.get_tcp_flow(flow_id)
        self.assertEqual(int(flow["state"]), 0)
        stats = tcpdp.snapshot_tcp_dataplane()
        self.assertEqual(int(stats["tcp_flows_active"]), 0)
        self.assertEqual(int(stats["tcp_retransmit_exhausted_count"]), 1)
        completions = tcpdp.collect_tcp_completions()
        self.assertTrue(any(item["event"] == "retransmit_exhausted" for item in completions))

    def test_wrong_ack_increments_unexpected_ack_counter(self):
        flow_id = tcpdp.enqueue_tcp_connect(_ip_to_int("10.6.0.2"), _ip_to_int("10.6.0.1"), 48000, 80)
        syn_flow = tcpdp.get_tcp_flow(flow_id)
        _drain_packets(tcpdp)
        synack = _build_tcp_ipv4_frame(
            "10.6.0.1", "10.6.0.2", 80, 48000, seq=7100, ack=int(syn_flow["snd_nxt"]), flags=0x12
        )
        tcpdp.ingest_tcp_rx_frame(synack)
        _drain_packets(tcpdp)
        queued = tcpdp.enqueue_tcp_send(flow_id, b"abc")
        self.assertEqual(queued, 3)
        tx = _drain_packets(tcpdp)
        self.assertEqual(len(tx), 1)
        before = tcpdp.get_tcp_flow(flow_id)

        wrong_ack = _build_tcp_ipv4_frame(
            "10.6.0.1",
            "10.6.0.2",
            80,
            48000,
            seq=int(before["rcv_nxt"]),
            ack=int(before["snd_nxt"]) + 5,
            flags=0x10,
        )
        self.assertEqual(tcpdp.ingest_tcp_rx_frame(wrong_ack), 1)
        stats = tcpdp.snapshot_tcp_dataplane()
        self.assertEqual(int(stats["tcp_unexpected_ack_count"]), 1)
        self.assertGreaterEqual(int(stats["tcp_unexpected_rx"]), 1)

    def test_partial_ack_keeps_outstanding_and_advances_snd_una(self):
        flow_id = tcpdp.enqueue_tcp_connect(_ip_to_int("10.9.0.2"), _ip_to_int("10.9.0.1"), 51000, 80)
        syn_flow = tcpdp.get_tcp_flow(flow_id)
        _drain_packets(tcpdp)
        synack = _build_tcp_ipv4_frame(
            "10.9.0.1", "10.9.0.2", 80, 51000, seq=9100, ack=int(syn_flow["snd_nxt"]), flags=0x12
        )
        tcpdp.ingest_tcp_rx_frame(synack)
        _drain_packets(tcpdp)

        payload = b"abcdef"
        queued = tcpdp.enqueue_tcp_send(flow_id, payload)
        self.assertEqual(queued, len(payload))
        _drain_packets(tcpdp)
        before = tcpdp.get_tcp_flow(flow_id)

        partial_ack_value = int(before["snd_una"]) + 3
        partial_ack = _build_tcp_ipv4_frame(
            "10.9.0.1",
            "10.9.0.2",
            80,
            51000,
            seq=int(before["rcv_nxt"]),
            ack=partial_ack_value,
            flags=0x10,
        )
        self.assertEqual(tcpdp.ingest_tcp_rx_frame(partial_ack), 1)
        mid = tcpdp.get_tcp_flow(flow_id)
        self.assertEqual(int(mid["snd_una"]), partial_ack_value)
        self.assertGreater(int(mid["snd_nxt"]), int(mid["snd_una"]))
        self.assertGreater(int(mid["rto_deadline_ns"]), 0)

        full_ack = _build_tcp_ipv4_frame(
            "10.9.0.1",
            "10.9.0.2",
            80,
            51000,
            seq=int(mid["rcv_nxt"]),
            ack=int(mid["snd_nxt"]),
            flags=0x10,
        )
        self.assertEqual(tcpdp.ingest_tcp_rx_frame(full_ack), 1)
        after = tcpdp.get_tcp_flow(flow_id)
        self.assertEqual(int(after["snd_una"]), int(after["snd_nxt"]))
        stats = tcpdp.snapshot_tcp_dataplane()
        self.assertGreaterEqual(int(stats["tcp_partial_ack_count"]), 1)

    def test_three_dup_ack_triggers_fast_retransmit(self):
        flow_id = tcpdp.enqueue_tcp_connect(_ip_to_int("10.10.0.2"), _ip_to_int("10.10.0.1"), 52000, 80)
        syn_flow = tcpdp.get_tcp_flow(flow_id)
        _drain_packets(tcpdp)
        synack = _build_tcp_ipv4_frame(
            "10.10.0.1", "10.10.0.2", 80, 52000, seq=10100, ack=int(syn_flow["snd_nxt"]), flags=0x12
        )
        tcpdp.ingest_tcp_rx_frame(synack)
        _drain_packets(tcpdp)

        queued = tcpdp.enqueue_tcp_send(flow_id, b"hello-world")
        self.assertEqual(queued, len(b"hello-world"))
        _drain_packets(tcpdp)
        before = tcpdp.get_tcp_flow(flow_id)

        dup_ack = _build_tcp_ipv4_frame(
            "10.10.0.1",
            "10.10.0.2",
            80,
            52000,
            seq=int(before["rcv_nxt"]),
            ack=int(before["snd_una"]),
            flags=0x10,
        )
        self.assertEqual(tcpdp.ingest_tcp_rx_frame(dup_ack), 1)
        self.assertEqual(len(_drain_packets(tcpdp)), 0)
        self.assertEqual(tcpdp.ingest_tcp_rx_frame(dup_ack), 1)
        self.assertEqual(len(_drain_packets(tcpdp)), 0)
        self.assertEqual(tcpdp.ingest_tcp_rx_frame(dup_ack), 1)
        self.assertEqual(len(_drain_packets(tcpdp)), 1)
        stats = tcpdp.snapshot_tcp_dataplane()
        self.assertGreaterEqual(int(stats["tcp_fast_retransmit_count"]), 1)
        self.assertGreaterEqual(int(stats["tcp_retransmit_count"]), 1)

    def test_connect_timeout_increments_specific_counter(self):
        tcpdp.configure_tcp_dataplane("required", "af_xdp", 50, 3, 25, 500)
        flow_id = tcpdp.enqueue_tcp_connect(_ip_to_int("10.7.0.2"), _ip_to_int("10.7.0.1"), 49000, 443)
        flow = tcpdp.get_tcp_flow(flow_id)
        actions = tcpdp.poll_tcp_dataplane(int(flow["last_activity_ns"]) + 26_000_000, 64)
        self.assertGreaterEqual(actions, 1)
        stats = tcpdp.snapshot_tcp_dataplane()
        self.assertEqual(int(stats["tcp_connect_timeout_count"]), 1)
        self.assertEqual(int(stats["tcp_timeout_close_count"]), 1)
        completions = tcpdp.collect_tcp_completions()
        self.assertTrue(any(item["event"] == "connect_timeout" for item in completions))

    def test_idle_timeout_increments_specific_counter(self):
        tcpdp.configure_tcp_dataplane("required", "af_xdp", 50, 3, 250, 25)
        flow_id = tcpdp.enqueue_tcp_connect(_ip_to_int("10.8.0.2"), _ip_to_int("10.8.0.1"), 50000, 80)
        syn_flow = tcpdp.get_tcp_flow(flow_id)
        _drain_packets(tcpdp)
        synack = _build_tcp_ipv4_frame(
            "10.8.0.1", "10.8.0.2", 80, 50000, seq=8100, ack=int(syn_flow["snd_nxt"]), flags=0x12
        )
        tcpdp.ingest_tcp_rx_frame(synack)
        _drain_packets(tcpdp)
        flow = tcpdp.get_tcp_flow(flow_id)
        actions = tcpdp.poll_tcp_dataplane(int(flow["last_activity_ns"]) + 26_000_000, 64)
        self.assertGreaterEqual(actions, 1)
        flow = tcpdp.get_tcp_flow(flow_id)
        self.assertEqual(int(flow["state"]), 5)
        stats = tcpdp.snapshot_tcp_dataplane()
        self.assertEqual(int(stats["tcp_idle_timeout_count"]), 1)
        self.assertEqual(int(stats["tcp_timeout_close_count"]), 1)
        completions = tcpdp.collect_tcp_completions()
        self.assertTrue(any(item["event"] == "idle_timeout" for item in completions))

    def test_rx_payloads_are_collectable_for_l7_bridge(self):
        flow_id = tcpdp.enqueue_tcp_connect(_ip_to_int("10.2.0.2"), _ip_to_int("10.2.0.1"), 44000, 80)
        syn_flow = tcpdp.get_tcp_flow(flow_id)
        _drain_packets(tcpdp)
        synack = _build_tcp_ipv4_frame(
            "10.2.0.1", "10.2.0.2", 80, 44000, seq=8100, ack=int(syn_flow["snd_nxt"]), flags=0x12
        )
        tcpdp.ingest_tcp_rx_frame(synack)
        _drain_packets(tcpdp)
        before = tcpdp.get_tcp_flow(flow_id)

        payload = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        frame = _build_tcp_ipv4_frame(
            "10.2.0.1",
            "10.2.0.2",
            80,
            44000,
            seq=int(before["rcv_nxt"]),
            ack=int(before["snd_nxt"]),
            flags=0x18,
            payload=payload,
        )
        self.assertEqual(tcpdp.ingest_tcp_rx_frame(frame), 1)

        rx_payloads = tcpdp.collect_tcp_rx_payloads()
        self.assertTrue(rx_payloads)
        self.assertEqual(int(rx_payloads[0]["flow_id"]), flow_id)
        self.assertEqual(rx_payloads[0]["payload"], payload)

    def test_out_of_order_rx_increments_counter_and_emits_dup_ack(self):
        flow_id = tcpdp.enqueue_tcp_connect(_ip_to_int("10.11.0.2"), _ip_to_int("10.11.0.1"), 53000, 80)
        syn_flow = tcpdp.get_tcp_flow(flow_id)
        _drain_packets(tcpdp)
        synack = _build_tcp_ipv4_frame(
            "10.11.0.1", "10.11.0.2", 80, 53000, seq=11100, ack=int(syn_flow["snd_nxt"]), flags=0x12
        )
        tcpdp.ingest_tcp_rx_frame(synack)
        _drain_packets(tcpdp)
        before = tcpdp.get_tcp_flow(flow_id)

        out_of_order = _build_tcp_ipv4_frame(
            "10.11.0.1",
            "10.11.0.2",
            80,
            53000,
            seq=int(before["rcv_nxt"]) + 10,
            ack=int(before["snd_nxt"]),
            flags=0x18,
            payload=b"late",
        )
        self.assertEqual(tcpdp.ingest_tcp_rx_frame(out_of_order), 1)
        tx = _drain_packets(tcpdp)
        self.assertEqual(len(tx), 1)
        after = tcpdp.get_tcp_flow(flow_id)
        self.assertEqual(int(after["rcv_nxt"]), int(before["rcv_nxt"]))
        stats = tcpdp.snapshot_tcp_dataplane()
        self.assertGreaterEqual(int(stats["tcp_out_of_order_rx_count"]), 1)
        self.assertGreaterEqual(int(stats["tcp_unexpected_rx"]), 1)

    def test_peer_rst_marks_flow_inactive_and_emits_completion(self):
        flow_id = tcpdp.enqueue_tcp_connect(_ip_to_int("10.3.0.2"), _ip_to_int("10.3.0.1"), 45000, 443)
        _drain_packets(tcpdp)
        flow = tcpdp.get_tcp_flow(flow_id)
        rst = _build_tcp_ipv4_frame(
            "10.3.0.1",
            "10.3.0.2",
            443,
            45000,
            seq=9000,
            ack=int(flow["snd_nxt"]),
            flags=0x14,
        )
        self.assertEqual(tcpdp.ingest_tcp_rx_frame(rst), 1)
        flow = tcpdp.get_tcp_flow(flow_id)
        self.assertEqual(int(flow["state"]), 6)
        stats = tcpdp.snapshot_tcp_dataplane()
        self.assertEqual(int(stats["tcp_flows_active"]), 0)
        self.assertEqual(int(stats["tcp_peer_rst_count"]), 1)
        completions = tcpdp.collect_tcp_completions()
        self.assertTrue(any(item["event"] == "peer_rst" for item in completions))

    def test_peer_fin_moves_flow_to_timewait_and_drops_active_count(self):
        flow_id = tcpdp.enqueue_tcp_connect(_ip_to_int("10.4.0.2"), _ip_to_int("10.4.0.1"), 46000, 80)
        syn_flow = tcpdp.get_tcp_flow(flow_id)
        _drain_packets(tcpdp)
        synack = _build_tcp_ipv4_frame(
            "10.4.0.1", "10.4.0.2", 80, 46000, seq=6100, ack=int(syn_flow["snd_nxt"]), flags=0x12
        )
        tcpdp.ingest_tcp_rx_frame(synack)
        _drain_packets(tcpdp)
        before = tcpdp.get_tcp_flow(flow_id)

        fin = _build_tcp_ipv4_frame(
            "10.4.0.1",
            "10.4.0.2",
            80,
            46000,
            seq=int(before["rcv_nxt"]),
            ack=int(before["snd_nxt"]),
            flags=0x11,
        )
        self.assertEqual(tcpdp.ingest_tcp_rx_frame(fin), 1)
        tx = _drain_packets(tcpdp)
        self.assertEqual(len(tx), 1)
        flow = tcpdp.get_tcp_flow(flow_id)
        self.assertEqual(int(flow["state"]), 5)
        stats = tcpdp.snapshot_tcp_dataplane()
        self.assertEqual(int(stats["tcp_flows_active"]), 0)
        self.assertEqual(int(stats["tcp_peer_fin_count"]), 1)
        completions = tcpdp.collect_tcp_completions()
        self.assertTrue(any(item["event"] == "peer_fin" for item in completions))

    def test_phase1_stats_schema_is_populated(self):
        tcpdp.enqueue_tcp_connect(_ip_to_int("10.5.0.2"), _ip_to_int("10.5.0.1"), 47000, 443)
        stats = tcpdp.snapshot_tcp_dataplane()
        expected_keys = {
            "tcp_flows_active",
            "tcp_connect_attempts",
            "tcp_connect_established",
            "tcp_retransmit_count",
            "tcp_timeout_close_count",
            "tcp_connect_timeout_count",
            "tcp_idle_timeout_count",
            "tcp_retransmit_exhausted_count",
            "tcp_rx_ack_count",
            "tcp_dup_ack_count",
            "tcp_partial_ack_count",
            "tcp_fast_retransmit_count",
            "tcp_unexpected_ack_count",
            "tcp_tx_data_bytes",
            "tcp_rx_data_bytes",
            "tcp_out_of_order_rx_count",
            "tcp_peer_rst_count",
            "tcp_peer_fin_count",
        }
        self.assertTrue(expected_keys.issubset(stats.keys()))


if __name__ == "__main__":
    unittest.main()
