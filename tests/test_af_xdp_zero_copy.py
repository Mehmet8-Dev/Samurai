import pytest

from ddos_samurai.af_xdp_sender import AFXDPBridgeRemoved, XDP_MODE_OFFLOAD, XDPStats, XDPSender
from ddos_samurai.zmq.wire import WorkerKind


class _FakeDispatcher:
    def __init__(self):
        self.calls = []

    def dispatch_start_job(self, **kwargs):
        self.calls.append(kwargs)
        return {"sent": True}


def test_xdp_stats_parses_extended_telemetry():
    stats = XDPStats.from_dict(
        {
            "tx_packets": 10,
            "tx_desc_reserve_failures": 3,
            "tx_frame_alloc_failures": 4,
            "tx_partial_batches": 5,
            "tx_retry_loops": 6,
            "tx_completion_events": 7,
            "tx_completed_desc": 8,
            "tx_invalid_packets": 9,
            "tx_backpressure_events": 11,
            "tx_send_calls": 12,
            "tx_send_ns_total": 13000,
            "tx_send_ns_max": 2500,
            "tx_send_avg_us": 1.08,
            "tx_send_max_us": 2.50,
            "queue_id": 4,
        }
    )
    assert stats.tx_packets == 10
    assert stats.tx_desc_reserve_failures == 3
    assert stats.tx_frame_alloc_failures == 4
    assert stats.tx_partial_batches == 5
    assert stats.tx_retry_loops == 6
    assert stats.tx_completion_events == 7
    assert stats.tx_completed_desc == 8
    assert stats.tx_invalid_packets == 9
    assert stats.tx_backpressure_events == 11
    assert stats.tx_send_calls == 12
    assert stats.tx_send_ns_total == 13000
    assert stats.tx_send_ns_max == 2500
    assert stats.tx_send_avg_us == pytest.approx(1.08)
    assert stats.tx_send_max_us == pytest.approx(2.50)
    assert stats.queue_id == 4


def test_xdp_sender_start_dispatches_zmq_afxdp_job():
    dispatcher = _FakeDispatcher()
    sender = XDPSender(
        interface="lo",
        mode=XDP_MODE_OFFLOAD,
        queue_id=3,
        dispatcher=dispatcher,
        endpoint="ipc:///tmp/samurai_jobs_afxdp_test",
        attach_bpf=False,
    )

    assert sender.start() is True
    assert len(dispatcher.calls) == 1
    call = dispatcher.calls[0]
    assert call["worker_kind"] == WorkerKind.AF_XDP
    assert call["endpoint"] == "ipc:///tmp/samurai_jobs_afxdp_test"
    assert call["args"]["xdp_interface"] == "lo"
    assert call["args"]["xdp_queue_id"] == 3
    assert call["args"]["xdp_mode"] == XDP_MODE_OFFLOAD


def test_xdp_direct_send_bridge_removed():
    sender = XDPSender(interface="lo")
    with pytest.raises(AFXDPBridgeRemoved, match="Python xdp_sender bridge"):
        sender.send([b"x"])
