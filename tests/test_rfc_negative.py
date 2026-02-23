"""RFC negative suite: expected-violation checks for malformed packets."""

from __future__ import annotations

import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

from ddos_samurai.cpu_packet_engine import PacketConfig, create_packet

try:
    import pytest
    pytestmark = [pytest.mark.rfc_negative, pytest.mark.ci_safe]
except Exception:  # pragma: no cover - unittest-only environments
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
        wrapper.__doc__ = fn.__doc__
        return wrapper

    return deco

_ScoreBoard.reset()


def _ones_complement_ok(buf: bytes) -> bool:
    if len(buf) % 2:
        buf += b"\x00"
    s = 0
    for i in range(0, len(buf), 2):
        s += (buf[i] << 8) | buf[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s == 0xFFFF


def _validate_packet(pkt: bytes) -> list[str]:
    v: list[str] = []
    if len(pkt) < 20:
        return ["ip_header_too_short"]

    ver = (pkt[0] >> 4) & 0xF
    ihl = (pkt[0] & 0xF) * 4
    if ver != 4:
        v.append("ip_version_not_ipv4")
    if ihl < 20 or ihl > len(pkt):
        v.append("ip_ihl_invalid")
        return v

    total = struct.unpack("!H", pkt[2:4])[0]
    if total != len(pkt):
        v.append("ip_total_length_mismatch")

    if pkt[8] == 0:
        v.append("ip_ttl_zero")

    hdr = pkt[:ihl]
    if not _ones_complement_ok(hdr):
        v.append("ip_checksum_invalid")

    proto = pkt[9]
    if proto == 6 and len(pkt) >= ihl + 20:
        data_off_words = (pkt[ihl + 12] >> 4) & 0xF
        if data_off_words < 5:
            v.append("tcp_data_offset_invalid")
    elif proto == 17 and len(pkt) >= ihl + 8:
        udp_len = struct.unpack("!H", pkt[ihl + 4:ihl + 6])[0]
        if udp_len != max(0, total - ihl):
            v.append("udp_length_mismatch")

    return v


class TestRFCNegativeExpectedViolations(unittest.TestCase):
    @_score("total_length_mismatch_detected")
    def test_total_length_mismatch_detected(self):
        pkt = bytearray(create_packet(PacketConfig("10.0.0.1", 80, protocol="tcp", tcp_flags="S")))
        struct.pack_into("!H", pkt, 2, len(pkt) + 5)
        self.assertIn("ip_total_length_mismatch", _validate_packet(bytes(pkt)))

    @_score("ttl_zero_detected")
    def test_ttl_zero_detected(self):
        pkt = bytearray(create_packet(PacketConfig("10.0.0.1", 80, protocol="tcp", tcp_flags="S")))
        pkt[8] = 0
        self.assertIn("ip_ttl_zero", _validate_packet(bytes(pkt)))

    @_score("tcp_data_offset_invalid_detected")
    def test_tcp_data_offset_invalid_detected(self):
        pkt = bytearray(create_packet(PacketConfig("10.0.0.1", 80, protocol="tcp", tcp_flags="S")))
        ihl = (pkt[0] & 0xF) * 4
        pkt[ihl + 12] = 0x40  # data offset = 4 (invalid)
        self.assertIn("tcp_data_offset_invalid", _validate_packet(bytes(pkt)))

    @_score("udp_length_mismatch_detected")
    def test_udp_length_mismatch_detected(self):
        pkt = bytearray(create_packet(PacketConfig("8.8.8.8", 53, protocol="udp", payload=b"hello")))
        ihl = (pkt[0] & 0xF) * 4
        struct.pack_into("!H", pkt, ihl + 4, 8)  # force wrong length
        self.assertIn("udp_length_mismatch", _validate_packet(bytes(pkt)))

    @_score("checksum_invalid_detected")
    def test_checksum_invalid_detected(self):
        pkt = bytearray(create_packet(PacketConfig("10.0.0.1", 80, protocol="tcp", tcp_flags="S")))
        pkt[10] ^= 0xFF
        self.assertIn("ip_checksum_invalid", _validate_packet(bytes(pkt)))


class TestZZFinalRFCNegativeReport(unittest.TestCase):
    def test_zzz_write_report(self):
        r = _ScoreBoard.report()

        # Optional SAMURAI_RFC_REPORT_OUT handling:
        # - if it points to a directory, write rfc_negative_report.json inside it.
        # - if it points to a file, write a sibling rfc_negative_report.json.
        base = str(os.environ.get("SAMURAI_RFC_REPORT_OUT", "") or "").strip()
        if not base:
            out = Path(tempfile.gettempdir()) / "rfc_negative_report.json"
        else:
            base_path = Path(base).expanduser().resolve()
            if base_path.suffix:
                out = base_path.with_name("rfc_negative_report.json")
            else:
                out = base_path / "rfc_negative_report.json"

        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(r, indent=2, sort_keys=True), encoding="utf-8")

        self.assertGreaterEqual(r["score"], 95.0)


if __name__ == "__main__":
    _ScoreBoard.reset()
    unittest.main(verbosity=2)
