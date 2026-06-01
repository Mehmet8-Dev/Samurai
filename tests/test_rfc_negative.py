"""Negative-path checks for ZMQ wire/GPU facade contracts."""

from __future__ import annotations

import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

from ddos_samurai import gpu_packet
from ddos_samurai.zmq import wire

try:
    import pytest
    pytestmark = [pytest.mark.rfc_negative, pytest.mark.ci_safe]
except Exception:  # pragma: no cover
    pytestmark = []


class _ScoreBoard:
    _checks: list = []

    @classmethod
    def reset(cls):
        cls._checks = []

    @classmethod
    def record(cls, name: str, passed: bool, weight: float = 1.0):
        cls._checks.append({"name": name, "passed": passed, "weight": float(weight)})

    @classmethod
    def report(cls):
        total_w = sum(c["weight"] for c in cls._checks)
        scored = sum(c["weight"] for c in cls._checks if c["passed"])
        pct = (scored / total_w * 100.0) if total_w else 0.0
        return {
            "suite": "rfc_negative",
            "score": round(pct, 2),
            "passed": int(scored),
            "total": int(total_w),
            "checks": list(cls._checks),
        }


def _score(name: str, weight: float = 1.0):
    def deco(fn):
        def wrapper(self, *a, **kw):
            try:
                fn(self, *a, **kw)
                _ScoreBoard.record(name, True, weight)
            except Exception:
                _ScoreBoard.record(name, False, weight)
                raise

        wrapper.__name__ = fn.__name__
        return wrapper

    return deco


def _write_json_with_fallback(preferred: Path, payload: dict, fallback_name: str) -> Path:
    content = json.dumps(payload, indent=2, sort_keys=True)
    candidates = [
        preferred,
        Path.cwd() / ".pytest_artifacts" / fallback_name,
        Path(tempfile.gettempdir()) / ".pytest_artifacts" / fallback_name,
    ]
    seen = set()
    for cand in candidates:
        key = str(cand)
        if key in seen:
            continue
        seen.add(key)
        try:
            cand.parent.mkdir(parents=True, exist_ok=True)
            cand.write_text(content, encoding="utf-8")
            return cand
        except PermissionError:
            continue
    raise PermissionError(f"Unable to write report to any candidate path: {candidates}")


_ScoreBoard.reset()


class TestRFCNegativeExpectedViolations(unittest.TestCase):
    @_score("wire_header_bad_magic_detected")
    def test_wire_header_bad_magic_detected(self):
        hdr = wire.SamuraiWireHeaderV1(
            msg_type=wire.MessageType.START_JOB,
            payload_len=0,
            correlation_id=1,
            worker_kind=wire.WorkerKind.CPU,
            job_id="x",
        )
        blob = bytearray(hdr.pack())
        struct.pack_into("<I", blob, 0, 0xDEADBEEF)
        with self.assertRaises(wire.WireProtocolError):
            wire.SamuraiWireHeaderV1.unpack(bytes(blob))

    @_score("job_envelope_invalid_port_detected")
    def test_job_envelope_invalid_port_detected(self):
        env = wire.JobEnvelopeV1(
            target_ip="203.0.113.5",
            target_port=70000,
            packet_count=1,
            packet_size=64,
        )
        with self.assertRaises(wire.WireProtocolError):
            env.pack()

    @_score("flow_update_odd_version_rejected")
    def test_flow_update_odd_version_rejected(self):
        evt = wire.FlowUpdateEventV1(
            version=1,
            epoch=1,
            flow_id=1,
            tcp_seq=1,
            tcp_ack=1,
            src_port=1234,
            dst_port=443,
            tcp_state=1,
            proto=6,
            flags=0x12,
            rtt_us=1,
            dpu_ts_ns=1,
        )
        with self.assertRaises(wire.WireProtocolError):
            evt.pack()

    @_score("gpu_kernel_mode_nonpersistent_rejected")
    def test_gpu_kernel_mode_nonpersistent_rejected(self):
        with self.assertRaises(gpu_packet.GPUPacketError):
            gpu_packet.set_kernel_mode("batch")

    @_score("gpu_legacy_bridge_call_rejected")
    def test_gpu_legacy_bridge_call_rejected(self):
        with self.assertRaises(gpu_packet.GPUPacketError):
            gpu_packet.generate_packets()


class TestZZFinalRFCNegativeReport(unittest.TestCase):
    def test_zzz_write_report(self):
        r = _ScoreBoard.report()

        base = str(os.environ.get("SAMURAI_RFC_REPORT_OUT", "") or "").strip()
        if not base:
            out = Path(tempfile.gettempdir()) / "rfc_negative_report.json"
        else:
            base_path = Path(base).expanduser().resolve()
            if base_path.suffix:
                out = base_path.with_name("rfc_negative_report.json")
            else:
                out = base_path / "rfc_negative_report.json"

        _write_json_with_fallback(out, r, "rfc_negative_report.json")
        self.assertGreaterEqual(r["score"], 100.0)


if __name__ == "__main__":
    _ScoreBoard.reset()
    unittest.main(verbosity=2)
