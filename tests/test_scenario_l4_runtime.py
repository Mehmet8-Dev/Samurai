from __future__ import annotations

from ddos_samurai.scenario_engine.l4_runtime import L4SessionDriver


class _FakeTcpDataplane:
    def __init__(self) -> None:
        self._next_flow_id = 100
        self.sent: list[tuple[int, bytes]] = []
        self.completions: list[dict] = []
        self.poll_calls = 0

    def enqueue_tcp_connect(self, src_ip: int, dst_ip: int, src_port: int, dst_port: int) -> int:
        _ = (src_ip, dst_ip, src_port, dst_port)
        self._next_flow_id += 1
        return self._next_flow_id

    def enqueue_tcp_send(self, flow_id: int, payload: bytes) -> int:
        self.sent.append((int(flow_id), bytes(payload or b"")))
        return len(payload or b"")

    def poll_tcp_dataplane(self, now_ns: int = 0, budget: int = 0) -> int:
        _ = (now_ns, budget)
        self.poll_calls += 1
        return 0

    def collect_tcp_completions(self):
        out = list(self.completions)
        self.completions.clear()
        return out

    def collect_tcp_rx_payloads(self):
        return []

    def snapshot_tcp_dataplane(self):
        return {"tcp_connect_attempts": 1, "tcp_connect_established": 1}


def test_l4_driver_happy_path_expect_then_send():
    dp = _FakeTcpDataplane()
    drv = L4SessionDriver(
        state_engine=None,
        tcp_dataplane=dp,
        target_ip="127.0.0.1",
        source_ip="127.0.0.1",
    )
    flow_id = drv.spawn_flow(
        1,
        [
            {"type": "tcp_connect", "dst_port": 80},
            {"type": "tcp_expect", "condition": "state == established", "timeout_ms": 500},
            {"type": "tcp_send", "payload_template": "GET / HTTP/1.1\r\n\r\n"},
            {"type": "tcp_close"},
        ],
        flow_name="syn_flood",
    )
    assert flow_id > 0
    assert dp.sent == []
    dp.completions.append({"flow_id": flow_id, "state": 3, "success": 1, "event": "connect_established"})
    rows = drv.tick(0.1)
    assert len(rows) >= 3
    assert rows[0]["success"] is True
    assert any(r["success"] is True for r in rows)
    assert dp.sent and dp.sent[0][0] == flow_id


def test_l4_driver_expect_timeout():
    dp = _FakeTcpDataplane()
    drv = L4SessionDriver(
        state_engine=None,
        tcp_dataplane=dp,
        target_ip="127.0.0.1",
        source_ip="127.0.0.1",
    )
    _ = drv.spawn_flow(
        2,
        [
            {"type": "tcp_connect", "dst_port": 443},
            {"type": "tcp_expect", "condition": "state == established", "timeout_ms": 100},
        ],
        flow_name="slowloris",
    )
    rows = drv.tick(0.2)
    assert any((r.get("timeout", False) and (not r.get("success", True))) for r in rows)

