from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from ddos_samurai.zmq.wire import (
    FLOW_UPDATE_EVENT_SIZE_V1,
    HEADER_SIZE_V1,
    JOB_ENVELOPE_SIZE_V1,
    METRIC_SNAPSHOT_SIZE_V1,
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


def test_magic_constant_stable() -> None:
    assert SAMURAI_WIRE_MAGIC == 0x534D5249
