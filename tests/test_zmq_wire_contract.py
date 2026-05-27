from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from ddos_samurai.zmq.wire import (
    FLOW_STREAM_UPSERT_SIZE_V1,
    FLOW_UPDATE_EVENT_SIZE_V1,
    HEADER_SIZE_V1,
    JOB_ENVELOPE_SIZE_V1,
    METRIC_SNAPSHOT_SIZE_V1,
    FlowStreamUpsertV1,
    FlowUpdateEventV1,
    JitterModel,
    JobEnvelopeV1,
    MessageType,
    PacingMode,
    SAMURAI_WIRE_MAGIC,
    SamuraiWireHeaderV1,
    WireProtocolError,
    WorkerKind,
    build_job_envelope,
    decode_job_done_json,
    encode_job_done_json,
    pack_message,
    unpack_message,
)


def test_wire_sizes_are_stable() -> None:
    assert HEADER_SIZE_V1 == 56
    assert JOB_ENVELOPE_SIZE_V1 == 480
    assert METRIC_SNAPSHOT_SIZE_V1 == 64
    assert FLOW_UPDATE_EVENT_SIZE_V1 == 48
    assert FLOW_STREAM_UPSERT_SIZE_V1 == 84


def test_header_pack_matches_golden_vector() -> None:
    header = SamuraiWireHeaderV1(
        msg_type=MessageType.START_JOB,
        payload_len=JOB_ENVELOPE_SIZE_V1,
        correlation_id=0x1122334455667788,
        worker_kind=WorkerKind.CPU,
        job_id="job-42",
    )
    assert header.pack().hex() == "49524d530101e001000000008877665544332211016a6f622d34320000000000000000000000000000000000000000000000000000000000"


def test_job_envelope_roundtrip_and_golden_vector() -> None:
    env = JobEnvelopeV1(
        target_ip="192.168.1.1",
        target_port=443,
        packet_count=1000,
        packet_size=128,
        pacing_mode=PacingMode.RPS,
        target_rps=250000.5,
        ipg_ns=500,
        burst_size=64,
        burst_gap_ns=1000,
        jitter_model=JitterModel.GAUSSIAN,
        jitter_pct=0.05,
        pin_cpu=3,
        use_so_txtime=True,
        xdp_interface="eth0",
        xdp_queue_id=7,
        xdp_mode=2,
        scenario_payload_ref="/tmp/samurai_scenario_job-42.bin",
        protocol="tcp",
        tcp_flags="S",
        spoof_enabled=True,
        spoof_mode="subnet",
        spoof_subnet="10.0.0.0/24",
        spoof_list_file="/tmp/spoof.list",
        has_payload=True,
        payload_ref="/tmp/payload.bin",
        pad_size=160,
        ttl=64,
        tos=16,
        window=4096,
        fragment_enabled=True,
        fragment_size=800,
        attack_vector="dns_amp",
        dns_name="example.org",
        dns_qtype="A,AAAA",
        dns_edns=True,
        dns_recursive=False,
    )

    payload = env.pack()
    assert payload.hex() == "3139322e3136382e312e310000000000bb01e803000080000000010000000084840e41f40100000000000040000000e803000000000000029a9999999999a93f03000000016574683000000000000000000000000007000000020000002f746d702f73616d757261695f7363656e6172696f5f6a6f622d34322e62696e000000000000000000000000000000000000000000000000000000000000000074637000000000005300000000000000017375626e65740000000000000000000031302e302e302e302f32340000000000000000000000000000000000000000002f746d702f73706f6f662e6c69737400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012f746d702f7061796c6f61642e62696e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000040100010012003646e735f616d700000000000000000006578616d706c652e6f72670000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000412c414141410000000000000000000000000000000000000000000000000000010000000000"

    decoded = JobEnvelopeV1.unpack(payload)
    assert decoded == env


def test_pack_unpack_message_roundtrip() -> None:
    payload = b"abc123"
    header = SamuraiWireHeaderV1(
        msg_type=MessageType.ACK,
        payload_len=len(payload),
        correlation_id=99,
        worker_kind=WorkerKind.L7,
        job_id="jid",
    )
    msg = pack_message(header, payload)
    h2, p2 = unpack_message(msg)
    assert h2 == header
    assert p2 == payload


def test_flow_update_event_roundtrip_and_golden_vector() -> None:
    event = FlowUpdateEventV1(
        version=10,
        epoch=3,
        flow_id=7,
        tcp_seq=100,
        tcp_ack=55,
        src_port=12345,
        dst_port=443,
        tcp_state=4,
        proto=6,
        flags=0x12,
        rtt_us=900,
        dpu_ts_ns=123456789,
    )
    payload = event.pack()
    assert payload.hex() == "0a0000000000000003000000000000000700000064000000370000003930bb01040612008403000015cd5b0700000000"
    assert FlowUpdateEventV1.unpack(payload) == event


def test_flow_update_event_rejects_in_progress_version() -> None:
    event = FlowUpdateEventV1(
        version=11,
        epoch=3,
        flow_id=7,
        tcp_seq=100,
        tcp_ack=55,
        src_port=12345,
        dst_port=443,
        tcp_state=4,
        proto=6,
        flags=0x12,
        rtt_us=900,
        dpu_ts_ns=123456789,
    )
    with pytest.raises(WireProtocolError, match="even/committed"):
        event.pack()


def test_flow_stream_upsert_roundtrip_and_flow_update_projection() -> None:
    upsert = FlowStreamUpsertV1(
        version=12,
        epoch=4,
        flow_id=99,
        tcp_seq=1000,
        tcp_ack=900,
        src_port=40000,
        dst_port=443,
        tcp_state=4,
        proto=6,
        flags=0x18,
        rtt_us=750,
        quota=2048,
        tx_ipg_ns=500,
        dpu_ts_ns=987654321,
        target_ip="10.0.0.8",
        payload_len=32,
        payload_byte=65,
        weight=3,
        template_id=7,
    )
    payload = upsert.pack()
    assert len(payload) == FLOW_STREAM_UPSERT_SIZE_V1
    assert FlowStreamUpsertV1.unpack(payload) == upsert
    event = upsert.to_flow_update()
    assert event.version == 12
    assert event.flow_id == 99
    assert event.dst_port == 443
    assert event.dpu_ts_ns == 987654321


def test_flow_stream_upsert_preserves_gpu_pause_policy_template_bit() -> None:
    upsert = FlowStreamUpsertV1(
        version=16,
        epoch=4,
        flow_id=100,
        tcp_seq=2000,
        tcp_ack=1900,
        src_port=40000,
        dst_port=443,
        tcp_state=4,
        proto=6,
        flags=0x10,
        rtt_us=650,
        quota=0,
        tx_ipg_ns=1000,
        dpu_ts_ns=987654333,
        target_ip="10.0.0.10",
        payload_len=0,
        payload_byte=0,
        weight=1,
        template_id=0x90000000,
    )

    decoded = FlowStreamUpsertV1.unpack(upsert.pack())
    assert decoded.quota == 0
    assert decoded.template_id == 0x90000000
    assert decoded.to_flow_update().tcp_seq == 2000


def test_flow_stream_upsert_rejects_in_progress_version() -> None:
    upsert = FlowStreamUpsertV1(
        version=13,
        epoch=4,
        flow_id=99,
        tcp_seq=1000,
        tcp_ack=900,
        src_port=40000,
        dst_port=443,
        tcp_state=4,
        proto=6,
        flags=0x18,
        rtt_us=750,
        quota=2048,
        tx_ipg_ns=500,
        dpu_ts_ns=987654321,
        target_ip="10.0.0.8",
    )
    with pytest.raises(WireProtocolError, match="even/committed"):
        upsert.pack()


def test_unpack_rejects_invalid_magic() -> None:
    bad = bytearray(
        SamuraiWireHeaderV1(
            msg_type=MessageType.ACK,
            payload_len=0,
            correlation_id=1,
            worker_kind=WorkerKind.CPU,
            job_id="x",
        ).pack()
    )
    bad[0:4] = b"BAD!"
    with pytest.raises(WireProtocolError):
        SamuraiWireHeaderV1.unpack(bytes(bad))


def test_build_job_envelope_maps_cli_values() -> None:
    env = build_job_envelope(
        {
            "target": "10.0.0.8",
            "port": 8443,
            "packets": 5000,
            "size": 256,
            "pacing_mode": "ipg",
            "ipg": 750,
            "jitter_model": "uniform",
            "jitter_pct": 0.1,
            "pin_cpu": 5,
            "use_so_txtime": True,
            "iface": "ens3",
            "xdp_queue_id": 2,
            "xdp_mode": 1,
            "protocol": "udp",
            "tcp_flags": "PA",
            "spoof": True,
            "spoof_mode": "subnet",
            "spoof_subnet": "10.0.0.0/24",
            "spoof_list_file": "/tmp/spoof.txt",
            "payload_file": "/tmp/payload.dat",
            "pad_size": 512,
            "ttl": 55,
            "tos": 24,
            "window": 2048,
            "fragment_enabled": True,
            "fragment_size": 600,
            "attack_vector": "dns_amp",
            "dns_name": "example.org",
            "dns_qtype": ["A", "AAAA"],
            "dns_edns": True,
            "dns_recursive": False,
        },
        scenario_payload_ref="/tmp/s.bin",
    )
    assert env.target_ip == "10.0.0.8"
    assert env.target_port == 8443
    assert env.packet_count == 5000
    assert env.packet_size == 256
    assert env.pacing_mode == PacingMode.IPG
    assert env.ipg_ns == 750
    assert env.jitter_model == JitterModel.UNIFORM
    assert env.jitter_pct == 0.1
    assert env.pin_cpu == 5
    assert env.use_so_txtime is True
    assert env.xdp_interface == "ens3"
    assert env.xdp_queue_id == 2
    assert env.xdp_mode == 1
    assert env.scenario_payload_ref == "/tmp/s.bin"
    assert env.protocol == "udp"
    assert env.tcp_flags == "PA"
    assert env.spoof_enabled is True
    assert env.spoof_mode == "subnet"
    assert env.spoof_subnet == "10.0.0.0/24"
    assert env.spoof_list_file == "/tmp/spoof.txt"
    assert env.has_payload is True
    assert env.payload_ref == "/tmp/payload.dat"
    assert env.pad_size == 512
    assert env.ttl == 55
    assert env.tos == 24
    assert env.window == 2048
    assert env.fragment_enabled is True
    assert env.fragment_size == 600
    assert env.attack_vector == "dns_amp"
    assert env.dns_name == "example.org"
    assert env.dns_qtype == "A,AAAA"
    assert env.dns_edns is True
    assert env.dns_recursive is False


def test_job_done_json_roundtrip() -> None:
    payload = {"sent": 100, "errors": 2, "status": "ok"}
    blob = encode_job_done_json(payload)
    decoded = decode_job_done_json(blob)
    assert decoded == payload


def test_cpp_header_compiles_with_static_asserts() -> None:
    cxx = shutil.which("g++") or shutil.which("clang++")
    if not cxx:
        pytest.skip("No C++ compiler found")

    root = Path(__file__).resolve().parents[1]
    hdr = root / "ddos_samurai" / "zmq" / "daemon" / "wire_protocol.h"
    source = f"""
#include \"{hdr}\"
#include <cstdint>
int main() {{
  samurai::wire::SamuraiWireHeaderV1 h{{}};
  return samurai::wire::IsHeaderV1Compatible(h) ? 0 : 0;
}}
"""
    with tempfile.TemporaryDirectory(prefix="samurai-zmq-wire-") as td:
        out_bin = Path(td) / "wire_header_compile_test"
        proc = subprocess.run(
            [cxx, "-std=c++17", "-x", "c++", "-", "-o", str(out_bin)],
            input=source,
            text=True,
            capture_output=True,
            check=False,
        )
    assert proc.returncode == 0, proc.stderr


def test_dpu_state_runtime_header_executes_tcp_policy_smoke() -> None:
    cxx = shutil.which("g++") or shutil.which("clang++")
    if not cxx:
        pytest.skip("No C++ compiler found")

    root = Path(__file__).resolve().parents[1]
    hdr = root / "ddos_samurai" / "zmq" / "daemon" / "dpu_state_runtime.hpp"
    source = f"""
#include \"{hdr}\"
#include <cstdint>

int main() {{
  samurai::dpu::FlowStateTable table;
  samurai::dpu::FlowState st{{}};
  st.flow_id = 77;
  st.src_ip = 0x0a000001u;
  st.dst_ip = 0x0a000002u;
  st.src_port = 40000;
  st.dst_port = 443;
  st.seq_num = 1000;
  st.ack_num = 900;
  st.tcp_state = samurai::dpu::kTcpStateEstablished;
  st.flags = samurai::dpu::kTcpFlagAck;
  st.proto = samurai::dpu::kProtoTcp;
  table.Upsert(st);
  table.TrackTransmitBatch(77, 1000, 100, samurai::dpu::kTcpFlagAck, 4, 100, 1000000);
  const samurai::dpu::TcpControlBlock* tcb = table.FindTcb(77);
  if (!tcb || tcb->retransmit_queue.size() != 4u || tcb->snd_nxt != 1400u) return 1;
  const auto policy = table.BuildGpuStreamPolicy(77, 64, 1200, 500);
  if (policy.pause || policy.quota == 0u || policy.payload_len != 1200u) return 2;

  table.Listen(88, 0x0a000003u, 443);
  samurai::dpu::TcpSegmentObservation syn{{}};
  syn.src_ip = 0x0a000004u;
  syn.dst_ip = 0x0a000003u;
  syn.src_port = 50000;
  syn.dst_port = 443;
  syn.seq = 12345;
  syn.flags = samurai::dpu::kTcpFlagSyn;
  syn.window = 4096;
  syn.has_mss = true;
  syn.mss = 1200;
  syn.has_window_scale = true;
  syn.window_scale = 4;
  syn.sack_permitted = true;
  syn.has_timestamp = true;
  syn.tsval = 11;
  table.AcceptPassiveOpen(88, 89, syn, 7000, 2000000);
  const samurai::dpu::FlowState* child = table.Find(89);
  if (!child || child->tcp_state != samurai::dpu::kTcpStateSynReceived) return 3;
  const samurai::dpu::TcpControlBlock* child_tcb = table.FindTcb(89);
  if (!child_tcb || child_tcb->mss != 1200u || !child_tcb->sack_permitted ||
      !child_tcb->timestamp_enabled || child_tcb->peer_window_scale != 4u) return 4;
  return 0;
}}
"""
    with tempfile.TemporaryDirectory(prefix="samurai-dpu-state-") as td:
        out_bin = Path(td) / "dpu_state_runtime_test"
        proc = subprocess.run(
            [cxx, "-std=c++17", "-x", "c++", "-", "-o", str(out_bin)],
            input=source,
            text=True,
            capture_output=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        run = subprocess.run([str(out_bin)], capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stderr


def test_dpu_state_runtime_header_executes_tcp_edge_policy_smoke() -> None:
    cxx = shutil.which("g++") or shutil.which("clang++")
    if not cxx:
        pytest.skip("No C++ compiler found")

    root = Path(__file__).resolve().parents[1]
    hdr = root / "ddos_samurai" / "zmq" / "daemon" / "dpu_state_runtime.hpp"
    source = f"""
#include \"{hdr}\"
#include <cstdint>
#include <stdexcept>

int main() {{
  samurai::dpu::FlowStateTable table;
  samurai::dpu::FlowState st{{}};
  st.flow_id = 77;
  st.src_ip = 0x0a000001u;
  st.dst_ip = 0x0a000002u;
  st.src_port = 40000;
  st.dst_port = 443;
  st.seq_num = 1000;
  st.ack_num = 900;
  st.tcp_state = samurai::dpu::kTcpStateEstablished;
  st.flags = samurai::dpu::kTcpFlagAck;
  st.proto = samurai::dpu::kProtoTcp;
  table.Upsert(st);
  table.TrackTransmitBatch(77, 1000, 100, samurai::dpu::kTcpFlagAck, 4, 100, 1000000);

  samurai::dpu::TcpSegmentObservation dup{{}};
  dup.src_ip = 0x0a000002u;
  dup.dst_ip = 0x0a000001u;
  dup.src_port = 443;
  dup.dst_port = 40000;
  dup.seq = 900;
  dup.ack = 1000;
  dup.flags = samurai::dpu::kTcpFlagAck;
  dup.window = 4096;
  samurai::dpu::TcpSegmentObservation synack = dup;
  synack.flags = samurai::dpu::kTcpFlagSyn | samurai::dpu::kTcpFlagAck;
  synack.sack_permitted = true;
  table.ObserveTcpSegment(77, synack, 1500000);
  dup.sack_block_count = 1;
  dup.sack_blocks[0] = {{1100, 1300}};
  table.ObserveTcpSegment(77, dup, 2000000);
  table.ObserveTcpSegment(77, dup, 3000000);
  const samurai::dpu::FlowState& fast = table.ObserveTcpSegment(77, dup, 4000000);
  const samurai::dpu::TcpControlBlock* tcb = table.FindTcb(77);
  if (!tcb || !tcb->retransmit_pending || tcb->retransmit_seq != 1000u ||
      tcb->retransmit_len != 100u || fast.seq_num != 1000u) return 1;
  bool saw_sacked = false;
  for (const auto& entry : tcb->retransmit_queue) {{
    if (entry.seq == 1100u && entry.sacked && !entry.acked) saw_sacked = true;
  }}
  if (!saw_sacked) return 2;

  samurai::dpu::TcpSegmentObservation ecn = dup;
  ecn.ecn_ce = true;
  table.ObserveTcpSegment(77, ecn, 5000000);
  tcb = table.FindTcb(77);
  if (!tcb || !tcb->ecn_capable || !tcb->ecn_echo_pending || !tcb->cwr_pending) return 3;

  table.ApplyPacketTooBig(77, 1200);
  tcb = table.FindTcb(77);
  if (!tcb || tcb->mss != 1160u) return 4;

  const samurai::dpu::FlowState& closing = table.InitiateClose(77, 6000000);
  if (closing.tcp_state != samurai::dpu::kTcpStateFinWait ||
      (closing.flags & samurai::dpu::kTcpFlagFin) == 0u) return 5;

  table.Listen(200, 0x0a000010u, 443, 1, 1, false);
  samurai::dpu::TcpSegmentObservation syn{{}};
  syn.src_ip = 0x0a000011u;
  syn.dst_ip = 0x0a000010u;
  syn.src_port = 51000;
  syn.dst_port = 443;
  syn.seq = 7;
  syn.flags = samurai::dpu::kTcpFlagSyn;
  syn.window = 4096;
  table.AcceptPassiveOpen(200, 201, syn, 9000, 7000000);
  samurai::dpu::TcpSegmentObservation child_ack{{}};
  child_ack.src_ip = 0x0a000011u;
  child_ack.dst_ip = 0x0a000010u;
  child_ack.src_port = 51000;
  child_ack.dst_port = 443;
  child_ack.seq = 8;
  child_ack.ack = 9001;
  child_ack.flags = samurai::dpu::kTcpFlagAck;
  child_ack.window = 4096;
  table.ObserveTcpSegment(201, child_ack, 7500000);
  const samurai::dpu::TcpListenSocket* listener = table.FindListenSocket(200);
  if (!listener || listener->pending_children != 0u || listener->accepted_count != 1u ||
      listener->accept_queue.empty()) return 6;
  std::uint32_t accepted = 0;
  if (!table.PopAcceptedFlow(200, &accepted) || accepted != 201u) return 7;

  table.Listen(205, 0x0a000015u, 443, 1, 1, false);
  bool overflowed = false;
  syn.dst_ip = 0x0a000015u;
  syn.src_port = 51001;
  table.AcceptPassiveOpen(205, 206, syn, 9100, 8000000);
  syn.src_port = 51002;
  try {{
    table.AcceptPassiveOpen(205, 207, syn, 9200, 8100000);
  }} catch (const std::overflow_error&) {{
    overflowed = true;
  }}
  if (!overflowed) return 8;
  listener = table.FindListenSocket(205);
  if (!listener || listener->backlog_drop_count != 1u) return 9;

  table.Listen(210, 0x0a000020u, 443, 1, 1, true);
  syn.dst_ip = 0x0a000020u;
  syn.src_port = 52000;
  table.AcceptPassiveOpen(210, 211, syn, 9200, 9000000);
  syn.src_port = 52001;
  table.AcceptPassiveOpen(210, 212, syn, 9300, 10000000);
  listener = table.FindListenSocket(210);
  if (!listener || listener->syn_cookie_issued_count != 1u) return 10;

  samurai::dpu::FlowState recv{{}};
  recv.flow_id = 300;
  recv.src_ip = 0x0a000030u;
  recv.dst_ip = 0x0a000031u;
  recv.src_port = 443;
  recv.dst_port = 53000;
  recv.seq_num = 1;
  recv.ack_num = 1000;
  recv.tcp_state = samurai::dpu::kTcpStateEstablished;
  recv.flags = samurai::dpu::kTcpFlagAck;
  recv.proto = samurai::dpu::kProtoTcp;
  table.Upsert(recv);
  samurai::dpu::TcpSegmentObservation ooo{{}};
  ooo.src_ip = 0x0a000031u;
  ooo.dst_ip = 0x0a000030u;
  ooo.src_port = 53000;
  ooo.dst_port = 443;
  ooo.flags = samurai::dpu::kTcpFlagAck;
  ooo.window = 4096;
  ooo.seq = 1100;
  ooo.ack = 1;
  ooo.payload_len = 100;
  table.ObserveTcpSegment(300, ooo, 11000000);
  const samurai::dpu::TcpControlBlock* recv_tcb = table.FindTcb(300);
  if (!recv_tcb || recv_tcb->receive_ready_bytes != 0u || recv_tcb->out_of_order.size() != 1u) return 11;
  ooo.seq = 1000;
  table.ObserveTcpSegment(300, ooo, 12000000);
  recv_tcb = table.FindTcb(300);
  if (!recv_tcb || recv_tcb->rcv_nxt != 1200u || recv_tcb->receive_ready_bytes != 200u ||
      recv_tcb->receive_queue.size() != 2u || !recv_tcb->out_of_order.empty()) return 12;
  if (table.ConsumeReceiveBytes(300, 150) != 150u) return 13;
  recv_tcb = table.FindTcb(300);
  if (!recv_tcb || recv_tcb->receive_ready_bytes != 50u || recv_tcb->receive_queue.empty()) return 14;
  return 0;
}}
"""
    with tempfile.TemporaryDirectory(prefix="samurai-dpu-state-edge-") as td:
        out_bin = Path(td) / "dpu_state_runtime_edge_test"
        proc = subprocess.run(
            [cxx, "-std=c++17", "-x", "c++", "-", "-o", str(out_bin)],
            input=source,
            text=True,
            capture_output=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        run = subprocess.run([str(out_bin)], capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stderr


def test_magic_constant_stable() -> None:
    assert SAMURAI_WIRE_MAGIC == 0x534D5249
