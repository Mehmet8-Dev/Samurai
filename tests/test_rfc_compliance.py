"""ZMQ/GPU facade compliance suite for current architecture."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from ddos_samurai import gpu_packet
from ddos_samurai.zmq import wire

try:
    import pytest
    pytestmark = [pytest.mark.rfc_positive, pytest.mark.ci_safe]
except Exception:  # pragma: no cover
    pytestmark = []


class _ScoreBoard:
    _checks: list[dict] = []

    @classmethod
    def reset(cls) -> None:
        cls._checks = []

    @classmethod
    def record(cls, group: str, name: str, passed: bool, weight: float = 1.0) -> None:
        cls._checks.append({"rfc": group, "name": name, "passed": passed, "weight": float(weight)})

    @classmethod
    def report(cls) -> dict:
        total_w = sum(c["weight"] for c in cls._checks)
        scored = sum(c["weight"] for c in cls._checks if c["passed"])
        pct = (scored / total_w * 100.0) if total_w else 0.0
        if pct >= 95:
            grade = "A+"
        elif pct >= 90:
            grade = "A"
        elif pct >= 80:
            grade = "B"
        elif pct >= 70:
            grade = "C"
        elif pct >= 60:
            grade = "D"
        else:
            grade = "F"
        return {
            "score": round(pct, 2),
            "grade": grade,
            "passed": int(scored),
            "total": int(total_w),
            "checks": list(cls._checks),
        }


def _score(group: str, name: str, weight: float = 1.0):
    def deco(fn):
        def wrapper(self, *a, **kw):
            try:
                fn(self, *a, **kw)
                _ScoreBoard.record(group, name, True, weight)
            except Exception:
                _ScoreBoard.record(group, name, False, weight)
                raise

        wrapper.__name__ = fn.__name__
        return wrapper

    return deco


def _write_json_with_fallback(path: str, payload: dict, fallback_name: str) -> str:
    content = json.dumps(payload, indent=2)
    candidates = [
        os.path.abspath(path),
        os.path.abspath(os.path.join(os.getcwd(), ".pytest_artifacts", fallback_name)),
        os.path.abspath(os.path.join(tempfile.gettempdir(), ".pytest_artifacts", fallback_name)),
    ]
    seen = set()
    for cand in candidates:
        if cand in seen:
            continue
        seen.add(cand)
        try:
            os.makedirs(os.path.dirname(cand), exist_ok=True)
            with open(cand, "w", encoding="utf-8") as f:
                f.write(content)
            return cand
        except PermissionError:
            continue
    raise PermissionError(f"Unable to write report to any candidate path: {candidates}")


_ScoreBoard.reset()


class TestWireContract(unittest.TestCase):
    @_score("WIRE V1", "Header pack/unpack roundtrip")
    def test_header_roundtrip(self):
        hdr = wire.SamuraiWireHeaderV1(
            msg_type=wire.MessageType.START_JOB,
            payload_len=wire.JOB_ENVELOPE_SIZE_V1,
            correlation_id=42,
            worker_kind=wire.WorkerKind.GPU,
            job_id="gpu-job-1",
        )
        raw = hdr.pack()
        out = wire.SamuraiWireHeaderV1.unpack(raw)
        self.assertEqual(out.msg_type, wire.MessageType.START_JOB)
        self.assertEqual(out.worker_kind, wire.WorkerKind.GPU)
        self.assertEqual(out.job_id, "gpu-job-1")

    @_score("WIRE V1", "Job envelope pack/unpack roundtrip")
    def test_envelope_roundtrip(self):
        env = wire.JobEnvelopeV1(
            target_ip="198.51.100.10",
            target_port=443,
            packet_count=1024,
            packet_size=128,
            protocol="tcp",
            attack_vector="basic",
            ttl=64,
            tos=0,
            dns_name="example.com",
        )
        raw = env.pack()
        out = wire.JobEnvelopeV1.unpack(raw)
        self.assertEqual(out.target_ip, "198.51.100.10")
        self.assertEqual(out.target_port, 443)
        self.assertEqual(out.protocol, "tcp")

    @_score("WIRE V1", "Flow update committed version contract")
    def test_flow_update_requires_even_version(self):
        with self.assertRaises(wire.WireProtocolError):
            wire.FlowUpdateEventV1(
                version=3,
                epoch=1,
                flow_id=7,
                tcp_seq=1,
                tcp_ack=0,
                src_port=12345,
                dst_port=443,
                tcp_state=1,
                proto=6,
                flags=0x12,
                rtt_us=100,
                dpu_ts_ns=10,
            ).pack()

    @_score("WIRE V1", "Flow stream upsert -> update conversion")
    def test_flow_stream_upsert_conversion(self):
        upsert = wire.FlowStreamUpsertV1(
            version=2,
            epoch=5,
            flow_id=9,
            tcp_seq=111,
            tcp_ack=222,
            src_port=50000,
            dst_port=443,
            tcp_state=2,
            proto=6,
            flags=0x10,
            rtt_us=900,
            quota=10,
            tx_ipg_ns=1000,
            dpu_ts_ns=777,
            target_ip="203.0.113.7",
        )
        raw = upsert.pack()
        out = wire.FlowStreamUpsertV1.unpack(raw)
        evt = out.to_flow_update()
        self.assertEqual(evt.flow_id, 9)
        self.assertEqual(evt.version, 2)


class TestGpuFacadeContract(unittest.TestCase):
    @_score("GPU Facade", "ZMQ backend is active")
    def test_backend_is_zmq(self):
        self.assertEqual(gpu_packet.get_active_backend_name(), "zmq")
        self.assertFalse(gpu_packet.is_native_path_active())

    @_score("GPU Facade", "Kernel mode is persistent-only")
    def test_kernel_mode_persistent(self):
        self.assertEqual(gpu_packet.get_kernel_mode(), "persistent")
        self.assertEqual(gpu_packet.set_kernel_mode("persistent"), "persistent")
        with self.assertRaises(gpu_packet.GPUPacketError):
            gpu_packet.set_kernel_mode("batch")

    @_score("GPU Facade", "Removed bridge APIs fail closed")
    def test_removed_bridge_apis(self):
        with self.assertRaises(gpu_packet.GPUPacketError):
            gpu_packet.generate_packets()
        with self.assertRaises(gpu_packet.GPUPacketError):
            gpu_packet.generate_packets_from_template()
        with self.assertRaises(gpu_packet.GPUPacketError):
            gpu_packet.generate_packets_from_template_pool()

    @_score("GPU Facade", "SeqLock helper contract")
    def test_seqlock_helper(self):
        begin, commit = gpu_packet.seqlock_next_versions(0)
        self.assertEqual(begin % 2, 1)
        self.assertEqual(commit % 2, 0)
        self.assertEqual(commit, begin + 1)

    @_score("GPU Facade", "Descriptor FSM contract")
    def test_descriptor_fsm(self):
        self.assertTrue(gpu_packet.descriptor_transition_valid(0, 1))
        self.assertTrue(gpu_packet.descriptor_transition_valid(1, 2))
        self.assertFalse(gpu_packet.descriptor_transition_valid(0, 2))

    @_score("GPU Facade", "Budget + subnet helpers")
    def test_budget_and_subnet(self):
        self.assertEqual(gpu_packet.publication_budget_us(1), 50)
        self.assertEqual(gpu_packet.publication_budget_us(50_000), 1000)
        net, prefix = gpu_packet.parse_subnet("192.0.2.0/24")
        self.assertEqual(prefix, 24)
        self.assertEqual(gpu_packet.int_to_ip(net), "192.0.2.0")


class TestZZFinalReport(unittest.TestCase):
    def test_zzz_write_report(self):
        r = _ScoreBoard.report()

        base = str(os.environ.get("SAMURAI_RFC_REPORT_OUT", "") or "").strip()
        if not base:
            path = os.path.join(tempfile.gettempdir(), "rfc_positive_report.json")
        else:
            base_path = os.path.abspath(os.path.expanduser(base))
            if os.path.splitext(base_path)[1]:
                path = base_path
            else:
                path = os.path.join(base_path, "rfc_positive_report.json")
        _write_json_with_fallback(path, r, "rfc_positive_report.json")

        self.assertGreaterEqual(r["score"], 95.0)


if __name__ == "__main__":
    _ScoreBoard.reset()
    unittest.main(verbosity=2)
