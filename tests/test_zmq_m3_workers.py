from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from ddos_samurai.zmq.dispatcher import ZmqDispatcher
from ddos_samurai.zmq.event_collector import ZmqEventCollector
from ddos_samurai.zmq.runtime_manager import ZmqRuntimeManager
from ddos_samurai.zmq.wire import (
    FlowStreamUpsertV1,
    FlowUpdateEventV1,
    MessageType,
    WorkerKind,
    default_event_endpoint,
    default_job_endpoint,
    unpack_message,
)
from ddos_samurai.zmq.worker_prototype import ZmqWorkerPrototype


class _FakeSocket:
    def __init__(self, ctx: "_FakeContext", sock_type: int):
        self._ctx = ctx
        self._type = sock_type
        self._endpoint = ""

    @property
    def endpoint(self) -> str:
        return self._endpoint

    def setsockopt(self, _key, _value):
        return None

    def connect(self, endpoint: str):
        self._endpoint = str(endpoint)
        self._ctx.ensure(self._endpoint)

    def bind(self, endpoint: str):
        self._endpoint = str(endpoint)
        self._ctx.ensure(self._endpoint)

    def send(self, payload: bytes):
        self._ctx.ensure(self._endpoint).append(bytes(payload))

    def recv(self) -> bytes:
        q = self._ctx.ensure(self._endpoint)
        if not q:
            raise RuntimeError("empty queue")
        return q.pop(0)

    def close(self, linger=0):
        _ = linger
        return None


class _FakePoller:
    def __init__(self, ctx: "_FakeContext"):
        self._ctx = ctx
        self._regs: list[tuple[_FakeSocket, int]] = []

    def register(self, sock: _FakeSocket, event_mask: int):
        self._regs.append((sock, int(event_mask)))

    def poll(self, timeout: int = 0):
        _ = timeout
        out = []
        for sock, mask in self._regs:
            q = self._ctx.ensure(sock.endpoint)
            if q:
                out.append((sock, mask))
        return out


class _FakeContext:
    def __init__(self):
        self._queues: dict[str, list[bytes]] = {}

    def ensure(self, endpoint: str) -> list[bytes]:
        if endpoint not in self._queues:
            self._queues[endpoint] = []
        return self._queues[endpoint]

    def socket(self, sock_type: int):
        return _FakeSocket(self, sock_type)


class _FakeZmq:
    PUSH = 1
    PULL = 2
    POLLIN = 1
    LINGER = 17

    class Context:
        _instance = _FakeContext()

        @classmethod
        def instance(cls):
            return cls._instance

    @staticmethod
    def Poller():
        return _FakePoller(_FakeZmq.Context._instance)


def test_m3_worker_sources_exist() -> None:
    root = Path(__file__).resolve().parents[1]
    expected = [
        root / "ddos_samurai" / "zmq" / "daemon" / "cpu_worker.cpp",
        root / "ddos_samurai" / "zmq" / "daemon" / "gpu_worker.cpp",
        root / "ddos_samurai" / "zmq" / "daemon" / "dpdk_worker.cpp",
        root / "ddos_samurai" / "zmq" / "daemon" / "afxdp_worker.cpp",
        root / "ddos_samurai" / "zmq" / "daemon" / "doca_gpunetio_worker.cpp",
        root / "ddos_samurai" / "zmq" / "daemon" / "l7_worker.cpp",
        root / "ddos_samurai" / "zmq" / "daemon" / "defense_worker.cpp",
        root / "ddos_samurai" / "zmq" / "daemon" / "scenario_worker.cpp",
        root / "ddos_samurai" / "zmq" / "daemon" / "dpu_state_runtime.hpp",
    ]
    for p in expected:
        assert p.exists(), str(p)


def test_m3_cmake_has_all_worker_targets() -> None:
    root = Path(__file__).resolve().parents[1]
    cmake = (root / "ddos_samurai" / "zmq" / "CMakeLists.txt").read_text(encoding="utf-8")
    for target in [
        "samurai_cpu_worker",
        "samurai_gpu_worker",
        "samurai_dpdk_worker",
        "samurai_afxdp_worker",
        "samurai_doca_worker",
        "samurai_l7_worker",
        "samurai_defense_worker",
        "samurai_scenario_worker",
    ]:
        assert target in cmake
    assert "add_library(" in cmake
    assert "pacing_engine_static" in cmake
    assert "cpu_native_static" in cmake
    assert "target_link_libraries(samurai_cpu_worker PRIVATE pacing_engine_static cpu_native_static pthread)" in cmake
    assert "target_link_libraries(samurai_gpu_worker PRIVATE pacing_engine_static pthread dl)" in cmake
    assert "target_link_libraries(samurai_afxdp_worker PRIVATE pacing_engine_static cpu_native_static pthread dl)" in cmake
    assert "target_link_libraries(samurai_doca_worker PRIVATE pacing_engine_static cpu_native_static pthread dl)" in cmake
    assert "target_link_libraries(samurai_l7_worker PRIVATE pacing_engine_static pthread)" in cmake
    assert "target_link_libraries(samurai_defense_worker PRIVATE pacing_engine_static cpu_native_static pthread dl)" in cmake
    assert "target_link_libraries(samurai_scenario_worker PRIVATE pacing_engine_static cpu_native_static pthread)" in cmake
    assert "pkg_check_modules(DPDK QUIET libdpdk)" in cmake
    assert "target_link_libraries(samurai_dpdk_worker PRIVATE pacing_engine_static cpu_native_static pthread)" in cmake
    assert "target_compile_definitions(samurai_dpdk_worker PRIVATE SAMURAI_WITH_DPDK=1)" in cmake


def test_m3_gpu_worker_has_native_cuda_bridge_and_failfast_fallback() -> None:
    root = Path(__file__).resolve().parents[1]
    src = (root / "ddos_samurai" / "zmq" / "daemon" / "gpu_worker.cpp").read_text(encoding="utf-8")
    assert "dlopen" in src
    assert "samurai_gpu_packet_generate_packets" in src
    assert "samurai_gpu_packet_generate_icmp_packets" in src
    assert "samurai_gpu_packet_contract_publish_flow_update_v1" in src
    assert "samurai_gpu_packet_contract_export_region_v1" in src
    assert "TryReadContractExportRegionSpec" in src
    assert "contract_export_region_spec" in src
    assert "SAMURAI_GPU_CONTRACT_EXPORT_ON_JOB_DONE" in src
    assert "samurai_gpu_packet_set_kernel_mode" in src
    assert "samurai_gpu_packet_start_stream" in src
    assert "samurai_gpu_packet_update_stream" in src
    assert "samurai_gpu_packet_stop_stream" in src
    assert "MessageType::FLOW_UPDATE" in src
    assert "MessageType::FLOW_STREAM_UPSERT" in src
    assert "FlowStreamUpsertJson" in src
    assert "UpsertFlowStreamFromStreamUpsert" in src
    assert "FlowUpdateFromStreamUpsert" in src
    assert "flow_stream_upsert_size_mismatch" in src
    assert "gpu_flow_stream_upsert_target_ip_required" in src
    assert "FlowEventStreamJson" in src
    assert "UpsertFlowStreamFromEvent" in src
    assert "flow_streams" in src
    assert "SAMURAI_GPU_FLOW_UPDATE_STREAM_LIFECYCLE" in src
    assert "SAMURAI_GPU_FLOW_UPDATE_TARGET_IP" in src
    assert "SAMURAI_GPU_FLOW_UPDATE_STREAM_QUOTA" in src
    assert "gpu_native_stream_lifecycle_symbol_missing" in src
    assert "gpu_flow_update_start_stream_failed" in src
    assert "gpu_flow_update_update_stream_failed" in src
    assert "gpu_flow_update_stop_stream_failed" in src
    assert "samurai_gpu_packet_free" in src
    assert "MessageType::HEARTBEAT" in src
    assert "MessageType::METRIC_SNAPSHOT" in src
    assert "gpu_native_lib_unavailable" in src
    assert "gpu_native_symbol_missing" in src


def test_m3_dispatch_flow_update_targets_gpu_contract_channel() -> None:
    ctx = _FakeContext()
    zmq = _FakeZmq()
    _FakeZmq.Context._instance = ctx
    endpoint = "ipc:///tmp/samurai_jobs_gpu_contract_test"
    event = FlowUpdateEventV1(
        version=12,
        epoch=5,
        flow_id=9,
        tcp_seq=101,
        tcp_ack=88,
        src_port=40000,
        dst_port=443,
        tcp_state=4,
        proto=6,
        flags=0x18,
        rtt_us=750,
        dpu_ts_ns=987654321,
    )

    dispatcher = ZmqDispatcher(context=ctx, zmq_module=zmq)
    try:
        result = dispatcher.dispatch_flow_update(
            correlation_id=77,
            job_id="contract-flow-9",
            event=event,
            endpoint=endpoint,
        )
        assert result.endpoint == endpoint
        assert result.bytes_sent == dispatcher.expected_flow_update_frame_size()

        queue = ctx.ensure(endpoint)
        assert len(queue) == 1
        header, payload = unpack_message(queue[0])
        assert header.worker_kind == WorkerKind.GPU
        assert header.msg_type == MessageType.FLOW_UPDATE
        assert header.correlation_id == 77
        assert header.job_id == "contract-flow-9"
        assert FlowUpdateEventV1.unpack(payload) == event
    finally:
        dispatcher.close()


def test_m3_dispatch_flow_stream_upsert_targets_gpu_lifecycle_channel() -> None:
    ctx = _FakeContext()
    zmq = _FakeZmq()
    _FakeZmq.Context._instance = ctx
    endpoint = "ipc:///tmp/samurai_jobs_gpu_stream_upsert_test"
    upsert = FlowStreamUpsertV1(
        version=14,
        epoch=6,
        flow_id=12,
        tcp_seq=123,
        tcp_ack=99,
        src_port=40100,
        dst_port=443,
        tcp_state=4,
        proto=6,
        flags=0x18,
        rtt_us=800,
        quota=4096,
        tx_ipg_ns=250,
        dpu_ts_ns=987654322,
        target_ip="10.0.0.9",
        payload_len=16,
        payload_byte=66,
        weight=2,
        template_id=3,
    )

    dispatcher = ZmqDispatcher(context=ctx, zmq_module=zmq)
    try:
        result = dispatcher.dispatch_flow_stream_upsert(
            correlation_id=78,
            job_id="stream-upsert-12",
            upsert=upsert,
            endpoint=endpoint,
        )
        assert result.endpoint == endpoint
        assert result.bytes_sent == dispatcher.expected_flow_stream_upsert_frame_size()

        queue = ctx.ensure(endpoint)
        assert len(queue) == 1
        header, payload = unpack_message(queue[0])
        assert header.worker_kind == WorkerKind.GPU
        assert header.msg_type == MessageType.FLOW_STREAM_UPSERT
        assert header.correlation_id == 78
        assert header.job_id == "stream-upsert-12"
        assert FlowStreamUpsertV1.unpack(payload) == upsert
    finally:
        dispatcher.close()


def test_m3_dispatch_flow_update_contract_rejects_epoch_rollback() -> None:
    ctx = _FakeContext()
    zmq = _FakeZmq()
    _FakeZmq.Context._instance = ctx
    endpoint = "ipc:///tmp/samurai_jobs_gpu_contract_epoch_guard"

    dispatcher = ZmqDispatcher(context=ctx, zmq_module=zmq)
    try:
        event_ok = FlowUpdateEventV1(
            version=2,
            epoch=7,
            flow_id=11,
            tcp_seq=100,
            tcp_ack=90,
            src_port=40001,
            dst_port=443,
            tcp_state=4,
            proto=6,
            flags=0x18,
            rtt_us=700,
            dpu_ts_ns=111,
        )
        dispatcher.dispatch_flow_update(
            correlation_id=101,
            job_id="epoch-ok",
            event=event_ok,
            endpoint=endpoint,
        )

        event_rollback = FlowUpdateEventV1(
            version=4,
            epoch=6,
            flow_id=11,
            tcp_seq=110,
            tcp_ack=95,
            src_port=40001,
            dst_port=443,
            tcp_state=4,
            proto=6,
            flags=0x18,
            rtt_us=650,
            dpu_ts_ns=222,
        )
        with pytest.raises(ValueError, match="epoch mismatch"):
            dispatcher.dispatch_flow_update(
                correlation_id=102,
                job_id="epoch-rollback",
                event=event_rollback,
                endpoint=endpoint,
            )

        stats = dispatcher.flow_update_contract_stats()
        assert stats["published"] == 1
        assert stats["epoch_mismatch"] == 1
    finally:
        dispatcher.close()


def test_m3_dispatch_flow_update_contract_detects_version_gap() -> None:
    ctx = _FakeContext()
    zmq = _FakeZmq()
    _FakeZmq.Context._instance = ctx
    endpoint = "ipc:///tmp/samurai_jobs_gpu_contract_version_gap"

    dispatcher = ZmqDispatcher(context=ctx, zmq_module=zmq)
    try:
        first = FlowUpdateEventV1(
            version=2,
            epoch=3,
            flow_id=15,
            tcp_seq=1,
            tcp_ack=1,
            src_port=50000,
            dst_port=80,
            tcp_state=1,
            proto=6,
            flags=0x02,
            rtt_us=100,
            dpu_ts_ns=1,
        )
        dispatcher.dispatch_flow_update(
            correlation_id=201,
            job_id="v-ok",
            event=first,
            endpoint=endpoint,
        )

        gap = FlowUpdateEventV1(
            version=10,
            epoch=3,
            flow_id=15,
            tcp_seq=2,
            tcp_ack=2,
            src_port=50000,
            dst_port=80,
            tcp_state=1,
            proto=6,
            flags=0x12,
            rtt_us=110,
            dpu_ts_ns=2,
        )
        with pytest.raises(ValueError, match="version gap"):
            dispatcher.dispatch_flow_update(
                correlation_id=202,
                job_id="v-gap",
                event=gap,
                endpoint=endpoint,
            )

        dispatcher.dispatch_flow_update(
            correlation_id=203,
            job_id="v-gap-allowed",
            event=gap,
            allow_version_gap=True,
            endpoint=endpoint,
        )
        stats = dispatcher.flow_update_contract_stats()
        assert stats["version_gap_detected"] >= 1
        assert stats["published"] == 2
        assert dispatcher.next_committed_flow_version(15) == 12
    finally:
        dispatcher.close()


def test_m3_dpdk_worker_has_native_tx_path_and_failfast_fallback() -> None:
    root = Path(__file__).resolve().parents[1]
    src = (root / "ddos_samurai" / "zmq" / "daemon" / "dpdk_worker.cpp").read_text(encoding="utf-8")
    assert "EnsureEalOnce" in src
    assert "rte_eth_tx_burst" in src
    assert "MessageType::HEARTBEAT" in src
    assert "MessageType::METRIC_SNAPSHOT" in src
    assert "dpdk_not_built" in src
    assert "SAMURAI_WITH_DPDK" in src


def test_m3_afxdp_worker_has_native_bridge_and_failfast_fallback() -> None:
    root = Path(__file__).resolve().parents[1]
    src = (root / "ddos_samurai" / "zmq" / "daemon" / "afxdp_worker.cpp").read_text(encoding="utf-8")
    assert "samurai_xdp_get_native_api_v1" in src
    assert "send_buffer_strided" in src
    assert "MessageType::HEARTBEAT" in src
    assert "MessageType::METRIC_SNAPSHOT" in src
    assert "xdp_native_lib_unavailable" in src
    assert "xdp_interface_required" in src


def test_m3_doca_worker_has_native_bridge_and_failfast_fallback() -> None:
    root = Path(__file__).resolve().parents[1]
    src = (root / "ddos_samurai" / "zmq" / "daemon" / "doca_gpunetio_worker.cpp").read_text(encoding="utf-8")
    backend = (root / "ddos_samurai" / "gpu_packet_cuda" / "doca_gpunetio_backend.cpp").read_text(encoding="utf-8")
    api = (root / "ddos_samurai" / "gpu_packet_cuda" / "tx_backend_doca_gpunetio.cuh").read_text(encoding="utf-8")
    assert "LoadDocaNative" in src
    assert '#include "dpu_state_runtime.hpp"' in src
    assert "samurai_doca_gpunetio_get_api_v1" in src
    assert "samurai_doca_backend_create_txq" in src
    assert "samurai_doca_backend_send_vector" in src
    assert "kDefaultGpuJobs" in src
    assert "--gpu-job-endpoint" in src
    assert "--dpu-state-publish" in src
    assert "SAMURAI_DPU_STATE_PUBLISH" in src
    assert "InitialFlowStateFromEnvelope" in src
    assert "BuildFlowStreamUpsert" in src
    assert "PublishDpuFlowStreamUpsert" in src
    assert "PublishDpuFlowUpdate" in src
    assert "DpuContractWriterGuard" in src
    assert "OpenDpuContractRdmaWriter" in src
    assert "PublishDpuFlowUpdateOptionalRdma" in src
    assert "DefaultGpuContractExportSpec" in src
    assert "SAMURAI_GPU_CONTRACT_EXPORT_SPEC" in src
    assert "SAMURAI_GPU_CONTRACT_EXPORT_PATH" in src
    assert "--dpu-contract-rdma" in src
    assert "SAMURAI_DPU_CONTRACT_RDMA" in src
    assert "SAMURAI_DPU_CONTRACT_RDMA_SPEC" in src
    assert "dpu_contract_rdma_writer_unavailable" in src
    assert "dpu_contract_rdma_publish_failed" in src
    assert "DocaContractWriterConfigV1" in api
    assert "DocaFlowUpdateEventV1" in api
    assert "contract_writer_publish_flow_update_v1" in api
    assert "samurai_doca_backend_contract_writer_open" in backend
    assert "samurai_doca_backend_contract_writer_close" in backend
    assert "samurai_doca_backend_contract_writer_publish_flow_update_v1" in backend
    assert "BackendContractFlowUpdateSlot" in backend
    assert "contract_store_event_slot" in backend
    assert "__atomic_store_n(&heads[shard], head + 1u, __ATOMIC_RELEASE)" in backend
    assert "contract writer ring overflow" in backend
    assert "MessageType::FLOW_UPDATE" in src
    assert "MessageType::FLOW_STREAM_UPSERT" in src
    assert "ZMQ_DONTWAIT" in src
    assert "dpu_gpu_flow_stream_upsert_publish_failed" in src
    assert "dpu_gpu_flow_update_publish_failed" in src
    assert "MessageType::HEARTBEAT" in src
    assert "MessageType::METRIC_SNAPSHOT" in src
    assert "doca_native_lib_unavailable" in src
    assert "doca_interface_required" in src
    assert "doca_device_required" in src


def test_m3_dpu_state_runtime_models_authoritative_flow_updates() -> None:
    root = Path(__file__).resolve().parents[1]
    src = (root / "ddos_samurai" / "zmq" / "daemon" / "dpu_state_runtime.hpp").read_text(encoding="utf-8")
    assert "struct FlowState" in src
    assert "class FlowStateTable" in src
    assert "NextCommittedVersion" in src
    assert "BuildUpdateEvent" in src
    assert "FlowUpdateEventV1" in src
    assert "kTcpStateMigrating" in src
    assert "kTcpStatePoisoned" in src


def test_m3_cuda_contract_runtime_has_device_visible_mirror() -> None:
    root = Path(__file__).resolve().parents[1]
    src = (root / "ddos_samurai" / "gpu_packet_cuda" / "host_api.cuh").read_text(encoding="utf-8")
    assert "update_ring_dev" in src
    assert "ring_head_dev" in src
    assert "ring_tail_dev" in src
    assert "hot_flow_table_dev" in src
    assert "hot_flow_versions_dev" in src
    assert "hot_flow_epochs_dev" in src
    assert "persistent_contract_runtime_alloc_device_mirror_unlocked" in src
    assert "persistent_contract_runtime_sync_device_slot_unlocked" in src
    assert "persistent_contract_runtime_refresh_device_tail_unlocked" in src
    assert "persistent_contract_runtime_sync_device_tail_unlocked" in src
    assert "persistent_contract_default_export_path" in src
    assert "SAMURAI_GPU_CONTRACT_EXPORT_PATH" in src
    assert "cudaHostRegister(mapped, layout.total_bytes, cudaHostRegisterMapped)" in src
    assert "cudaHostGetDevicePointer(&dev_base, mapped, 0)" in src
    assert "cr.export_region_spec = std::string(\"file=\") + path" in src
    assert "samurai_gpu_packet_contract_export_region_v1" in src
    assert "failed to sync contract update into device mirror" in src
    assert "contract_device_mirror_active" in src
    assert "contract_device_sync_error_events" in src
    assert "contract_export_region_spec" in src
    assert "contract_export_region_bytes" in src


def test_m3_cuda_persistent_kernel_drains_contract_ring() -> None:
    root = Path(__file__).resolve().parents[1]
    src = (root / "ddos_samurai" / "gpu_packet_cuda" / "host_api.cuh").read_text(encoding="utf-8")
    assert "persistent_contract_poll_assigned_shard" in src
    assert "contract_update_ring" in src
    assert "contract_ring_head" in src
    assert "contract_ring_tail" in src
    assert "contract_hot_flow_table" in src
    assert "contract_hot_flow_versions" in src
    assert "contract_hot_flow_epochs" in src
    assert "kPollWarpWidth = 32u" in src
    assert "lane < drain_count" in src
    assert "loaded_mask = __ballot_sync" in src
    assert "s_contract_flow_ids" in src
    assert "s_contract_versions" in src
    assert "for (uint32_t other_lane = lane + 1u" in src
    assert "contiguous_loaded" in src
    assert "const int32_t shard = static_cast<int32_t>(blockIdx.x)" in src
    assert "contract_ring_tail[shard] = tail + static_cast<uint64_t>(contiguous_loaded)" in src
    assert "sv->source_port = ev.src_port" in src
    assert "sv->tcp_flags = ev.flags" in src
    assert "sv->seq_counter = ev.tcp_seq" in src
    assert "contract_poll_events" in src
    assert "contract_kernel_poll_events" in src


def test_m3_l7_worker_has_real_runtime_and_failfast_fallback() -> None:
    root = Path(__file__).resolve().parents[1]
    src = (root / "ddos_samurai" / "zmq" / "daemon" / "l7_worker.cpp").read_text(encoding="utf-8")
    assert "ConnectWithTimeout" in src
    assert "SendAll" in src
    assert "RecvSome" in src
    assert "MessageType::HEARTBEAT" in src
    assert "MessageType::METRIC_SNAPSHOT" in src
    assert "scenario_payload_ref_missing" in src
    assert "l7_protocol_requires_udp_or_quic_worker" in src
    assert "target_required" in src


def test_m3_defense_worker_has_native_bridge_and_failfast_fallback() -> None:
    root = Path(__file__).resolve().parents[1]
    src = (root / "ddos_samurai" / "zmq" / "daemon" / "defense_worker.cpp").read_text(encoding="utf-8")
    assert "LoadDefenseNative" in src
    assert "samurai_gpu_packet_defense_init" in src
    assert "samurai_gpu_packet_classify_batch" in src
    assert "samurai_gpu_packet_classify_from_ingress" in src
    assert "samurai_gpu_packet_read_classifier_stats" in src
    assert "MessageType::HEARTBEAT" in src
    assert "MessageType::METRIC_SNAPSHOT" in src
    assert "defense_native_lib_unavailable" in src
    assert "defense_native_symbol_missing" in src
    assert "defense_classify_failed" in src


def test_m3_scenario_worker_has_real_runtime_and_failfast_fallback() -> None:
    root = Path(__file__).resolve().parents[1]
    src = (root / "ddos_samurai" / "zmq" / "daemon" / "scenario_worker.cpp").read_text(encoding="utf-8")
    assert "scenario_payload_ref_missing" in src
    assert "scenario_payload_empty" in src
    assert "CountToken" in src
    assert "MessageType::HEARTBEAT" in src
    assert "MessageType::METRIC_SNAPSHOT" in src
    assert "scenario_engine_path" in src


def test_m3_prototype_happy_path_for_all_workers() -> None:
    for kind in WorkerKind:
        ctx = _FakeContext()
        zmq = _FakeZmq()
        _FakeZmq.Context._instance = ctx

        job_ep = default_job_endpoint(kind)
        event_ep = default_event_endpoint(kind)

        dispatcher = ZmqDispatcher(context=ctx, zmq_module=zmq)
        collector = ZmqEventCollector(context=ctx, zmq_module=zmq, bind=True)
        collector.ensure_worker_channel(kind, endpoint=event_ep)
        worker = ZmqWorkerPrototype(
            worker_kind=kind,
            context=ctx,
            zmq_module=zmq,
            job_endpoint=job_ep,
            event_endpoint=event_ep,
            bind_jobs=True,
            bind_events=False,
        )

        try:
            dispatcher.dispatch_start_job(
                worker_kind=kind,
                correlation_id=1000 + int(kind),
                job_id=f"job-{kind.name.lower()}",
                endpoint=job_ep,
                args={
                    "target": "127.0.0.1",
                    "port": 443,
                    "packets": 10,
                    "size": 64,
                },
            )
            assert worker.process_one(timeout_ms=10) is True
            event = collector.wait_for_terminal_event(
                correlation_id=1000 + int(kind),
                worker_kind=kind,
                ack_timeout_s=0.2,
                heartbeat_timeout_s=0.2,
                overall_timeout_s=1.0,
            )
            assert event.header.msg_type == MessageType.JOB_DONE
            assert event.payload_decoded.get("status") == "ok"
            assert event.payload_decoded.get("worker_kind") == kind.name.lower()
        finally:
            worker.close()
            collector.close()
            dispatcher.close()


def test_m3_runtime_manager_native_only_no_python_fallback() -> None:
    class _FakePopen:
        def __init__(self, cmd, **kwargs):
            self.cmd = list(cmd)
            self.kwargs = dict(kwargs)
            self.pid = 999
            self.returncode = None

        def poll(self):
            return self.returncode

        def send_signal(self, _sig):
            self.returncode = 0

        def wait(self, timeout=None):
            _ = timeout
            if self.returncode is None:
                self.returncode = 0
            return self.returncode

        def kill(self):
            self.returncode = -9

    mgr = ZmqRuntimeManager()

    with patch("ddos_samurai.zmq.runtime_manager.shutil_which", return_value=None), patch(
        "ddos_samurai.zmq.runtime_manager.subprocess.Popen", side_effect=_FakePopen
    ) as popen_mock:
        for kind in WorkerKind:
            try:
                mgr.launch_worker(kind)
                assert False, f"expected FileNotFoundError for {kind.name}"
            except FileNotFoundError:
                pass

    assert popen_mock.call_count == 0
