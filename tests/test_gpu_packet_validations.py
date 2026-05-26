import unittest

from ddos_samurai import gpu_packet
from ddos_samurai.zmq.wire import FlowUpdateEventV1


class _FakeDispatcher:
    def __init__(self):
        self.events = []

    def dispatch_flow_update(self, **kwargs):
        self.events.append(kwargs)
        return {"ok": True}


class TestGpuPacketZmqFacade(unittest.TestCase):
    def test_parse_subnet_normalizes_network_base(self):
        base_ip, mask = gpu_packet.parse_subnet("192.168.1.123/24")
        self.assertEqual(mask, 24)
        self.assertEqual(base_ip, gpu_packet.ip_to_int("192.168.1.0"))

    def test_parse_subnet_rejects_invalid_mask(self):
        with self.assertRaises(ValueError):
            gpu_packet.parse_subnet("10.0.0.0/33")

    def test_sync_generation_raises_bridge_removed_error(self):
        with self.assertRaisesRegex(gpu_packet.GPUPacketError, "Python CUDA bridge is disabled"):
            gpu_packet.generate_packets(count=1, target_ip="127.0.0.1", target_port=80)

    def test_contract_publish_uses_zmq_dispatcher(self):
        dispatcher = _FakeDispatcher()
        event = FlowUpdateEventV1(
            version=2,
            epoch=1,
            flow_id=10,
            tcp_seq=100,
            tcp_ack=200,
            src_port=1234,
            dst_port=80,
            tcp_state=1,
            proto=6,
            flags=2,
            rtt_us=500,
            dpu_ts_ns=1000,
        )

        out = gpu_packet.contract_publish_flow_update_v1(
            event,
            dispatcher=dispatcher,
            endpoint="ipc:///tmp/samurai_jobs_gpu_test",
            correlation_id=42,
            job_id="flow-10",
        )

        self.assertEqual(out, {"ok": True})
        self.assertEqual(len(dispatcher.events), 1)
        sent = dispatcher.events[0]
        self.assertEqual(sent["correlation_id"], 42)
        self.assertEqual(sent["job_id"], "flow-10")
        self.assertEqual(sent["event"], event)
        self.assertEqual(sent["endpoint"], "ipc:///tmp/samurai_jobs_gpu_test")

    def test_zero_copy_contract_math_stays_available_without_bridge(self):
        self.assertEqual(gpu_packet.publication_budget_us(300), 50)
        self.assertEqual(gpu_packet.publication_budget_us(9000), 900)
        self.assertEqual(gpu_packet.publication_budget_us(50000), 1000)
        self.assertEqual(gpu_packet.seqlock_next_versions(8), (9, 10))
        self.assertEqual(gpu_packet.seqlock_next_versions(9), (11, 12))
        self.assertTrue(
            gpu_packet.descriptor_transition_valid(
                gpu_packet.DESCRIPTOR_STATE_FREE,
                gpu_packet.DESCRIPTOR_STATE_GPU_WRITING,
            )
        )
        self.assertFalse(
            gpu_packet.descriptor_transition_valid(
                gpu_packet.DESCRIPTOR_STATE_FREE,
                gpu_packet.DESCRIPTOR_STATE_READY_FOR_NIC,
            )
        )


if __name__ == "__main__":
    unittest.main()
