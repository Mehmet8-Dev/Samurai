from __future__ import annotations

import asyncio
import ipaddress
import os
import struct
import unittest
from unittest.mock import patch

from ddos_samurai import senders
from ddos_samurai.l7_emu.runtime import _unavailable_stats, run_l7_profile
from ddos_samurai.l7_emu.types import RuntimeConfig


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


def _parse_tcp_ipv4_frame(frame: bytes) -> dict[str, object]:
    ip_offset = 14 if len(frame) >= 14 and frame[12:14] == b"\x08\x00" else 0
    ihl = (frame[ip_offset] & 0x0F) * 4
    total_len = struct.unpack("!H", frame[ip_offset + 2:ip_offset + 4])[0]
    ttl = frame[ip_offset + 8]
    tcp_offset = ip_offset + ihl
    data_off = ((frame[tcp_offset + 12] >> 4) & 0x0F) * 4
    payload_offset = tcp_offset + data_off
    payload_len = max(0, total_len - ihl - data_off)
    return {
        "src_ip": str(ipaddress.IPv4Address(frame[ip_offset + 12:ip_offset + 16])),
        "dst_ip": str(ipaddress.IPv4Address(frame[ip_offset + 16:ip_offset + 20])),
        "src_port": struct.unpack("!H", frame[tcp_offset:tcp_offset + 2])[0],
        "dst_port": struct.unpack("!H", frame[tcp_offset + 2:tcp_offset + 4])[0],
        "seq": struct.unpack("!L", frame[tcp_offset + 4:tcp_offset + 8])[0],
        "ack": struct.unpack("!L", frame[tcp_offset + 8:tcp_offset + 12])[0],
        "flags": frame[tcp_offset + 13],
        "ttl": ttl,
        "payload": frame[payload_offset:payload_offset + payload_len],
        "frame_len": 14 + total_len if ip_offset == 14 else total_len,
    }


def _split_ipv4_frames(buffer: bytes, count: int) -> list[bytes]:
    frames: list[bytes] = []
    cursor = 0
    total = bytes(buffer or b"")
    for _ in range(max(0, int(count or 0))):
        if cursor + 18 > len(total):
            break
        if total[cursor + 12:cursor + 14] != b"\x08\x00":
            break
        total_len = struct.unpack("!H", total[cursor + 16:cursor + 18])[0]
        frame_len = 14 + int(total_len)
        frames.append(total[cursor:cursor + frame_len])
        cursor += frame_len
    return frames


class TestL7DataplaneContract(unittest.TestCase):
    def test_unavailable_stats_expose_perf_contract(self):
        profile = senders.compile_l7_profile(
            protocol="http1",
            target_ip="127.0.0.1",
            target_port=8080,
            scheme="http",
            http_method="GET",
            http_path=["/"],
            payloads=[],
            concurrency=1,
        )
        stats = _unavailable_stats(profile)
        expected_keys = {
            "l7_cps",
            "l7_rps",
            "l7_active_conn_peak",
            "l7_h1_conn_reuse_ratio",
            "l7_h2_lane_reuse_ratio",
            "l7_epoll_wakeups",
            "l7_scheduler_queue_depth_peak",
            "l7_idle_evictions",
            "l7_rx_syscalls",
            "l7_tx_syscalls",
            "l7_alloc_bytes",
            "l7_alloc_count",
            "l7_tls_handshake_p50_ms",
            "l7_tls_handshake_p95_ms",
            "l7_tls_handshake_p99_ms",
            "l7_request_latency_p50_ms",
            "l7_request_latency_p95_ms",
            "l7_request_latency_p99_ms",
            "l7_profile_enabled",
            "l7_profile_snapshot_count",
            "runtime_reactor_backend",
            "runtime_tls_backend",
            "runtime_http2_backend",
            "runtime_native_hot_path_level",
            "h2_goaway_replacements",
            "h2_drain_evictions",
            "h2_replace_now_decisions",
            "h2_replace_after_idle_decisions",
            "h2_stream_pool_reuse_hits",
        }
        self.assertTrue(expected_keys.issubset(stats))

    def test_runtime_config_forwards_profile_controls(self):
        profile = senders.compile_l7_profile(
            protocol="http1",
            target_ip="127.0.0.1",
            target_port=8080,
            scheme="http",
            http_method="GET",
            http_path=["/"],
            payloads=[],
            concurrency=1,
        )
        captured = {}

        class _FakeNative:
            @staticmethod
            def run_profile(profile_dict, cfg_dict):
                captured["profile"] = dict(profile_dict)
                captured["cfg"] = dict(cfg_dict)
                return {
                    "attempted": 1,
                    "sent": 0,
                    "errors": 1,
                    "l7_profile_enabled": cfg_dict.get("profile_l7", 0),
                    "l7_profile_snapshot_count": 0,
                }

        runtime_cfg = RuntimeConfig(concurrency=2, profile_l7=True, profile_sample_limit=64)
        with patch("ddos_samurai.l7_emu.runtime._native", _FakeNative()):
            result = asyncio.run(run_l7_profile(profile, runtime_cfg))

        self.assertEqual(captured["cfg"]["concurrency"], 2)
        self.assertEqual(captured["cfg"]["profile_l7"], 1)
        self.assertEqual(captured["cfg"]["profile_sample_limit"], 64)
        self.assertEqual(result.as_dict()["l7_profile_enabled"], 1)

    def test_runtime_profile_forwards_transport_backend(self):
        profile = senders.compile_l7_profile(
            protocol="http1",
            target_ip="127.0.0.1",
            target_port=8080,
            scheme="http",
            stateful_runtime_backend="afxdp",
            transport_backend="custom_tcp",
            http_method="GET",
            http_path=["/"],
            payloads=[],
            concurrency=1,
        )
        captured = {}

        class _FakeNative:
            @staticmethod
            def run_profile(profile_dict, cfg_dict):
                captured["profile"] = dict(profile_dict)
                return {
                    "attempted": 1,
                    "sent": 0,
                    "errors": 1,
                    "runtime_transport_custom_tcp_requested": 1,
                }

        with patch("ddos_samurai.l7_emu.runtime._native", _FakeNative()):
            asyncio.run(run_l7_profile(profile, RuntimeConfig(concurrency=1)))

        self.assertEqual(
            captured["profile"]["connection_template"]["transport_backend"],
            "custom_tcp",
        )
        self.assertEqual(
            captured["profile"]["connection_template"]["stateful_runtime_backend"],
            "afxdp",
        )

    def test_stateful_runtime_backend_autopromotes_http1_transport(self):
        profile = senders.compile_l7_profile(
            protocol="http1",
            target_ip="127.0.0.1",
            target_port=8080,
            scheme="http",
            stateful_runtime_backend="afxdp",
            http_method="GET",
            http_path=["/"],
            payloads=[],
            concurrency=1,
        )
        self.assertEqual(profile.connection_template.transport_backend, "custom_tcp")
        self.assertEqual(profile.connection_template.stateful_runtime_backend, "afxdp")

    def test_stateful_runtime_backend_autopromotes_http2_transport(self):
        profile = senders.compile_l7_profile(
            protocol="http2",
            target_ip="127.0.0.1",
            target_port=443,
            scheme="https",
            stateful_runtime_backend="afxdp",
            http_method="GET",
            http_path=["/"],
            payloads=[],
            concurrency=1,
        )
        self.assertEqual(profile.connection_template.transport_backend, "custom_tcp")
        self.assertEqual(profile.connection_template.stateful_runtime_backend, "afxdp")

    def test_strict_afxdp_runtime_fails_visible_when_interface_is_missing(self):
        profile = senders.compile_l7_profile(
            protocol="http1",
            target_ip="127.0.0.1",
            target_port=8080,
            scheme="http",
            stateful_runtime_backend="afxdp",
            http_method="GET",
            http_path=["/"],
            payloads=[],
            concurrency=1,
        )

        out = asyncio.run(
            senders.run_l7_profile_public(
                profile,
                concurrency=1,
                stateful_runtime_backend="afxdp",
                stateful_runtime_strict=True,
                legacy_mode=False,
                custom_tcp_backend="af_xdp",
                custom_tcp_xdp_interface="",
            )
        )

        self.assertEqual(out["sent"], 0)
        self.assertEqual(out["errors"], 1)
        self.assertEqual(out["runtime_backend"], "afxdp")
        self.assertEqual(out["legacy_path_used"], 0)
        self.assertEqual(out["l7_capability_status"], "missing")
        self.assertEqual(out["stateful_runtime_status"], "unavailable")
        self.assertEqual(out["stateful_runtime_reason"], "custom_tcp_xdp_interface_missing")
        self.assertEqual(out["stateful_runtime_preflight_status"], "failed")
        self.assertEqual(out["stateful_runtime_preflight_reason"], "custom_tcp_xdp_interface_missing")
        self.assertEqual(out["stateful_runtime_preflight_xdp_enabled"], 1)

    def test_strict_dpdk_runtime_fails_visible_until_backend_exists(self):
        profile = senders.compile_l7_profile(
            protocol="http1",
            target_ip="127.0.0.1",
            target_port=8080,
            scheme="http",
            stateful_runtime_backend="dpdk",
            http_method="GET",
            http_path=["/"],
            payloads=[],
            concurrency=1,
        )

        out = asyncio.run(
            senders.run_l7_profile_public(
                profile,
                concurrency=1,
                stateful_runtime_backend="dpdk",
                stateful_runtime_strict=True,
                legacy_mode=False,
            )
        )

        self.assertEqual(out["sent"], 0)
        self.assertEqual(out["errors"], 1)
        self.assertEqual(out["runtime_backend"], "afxdp")
        self.assertEqual(out["legacy_path_used"], 0)
        self.assertEqual(out["stateful_runtime_status"], "unavailable")
        self.assertEqual(out["stateful_runtime_reason"], "custom_tcp_xdp_interface_missing")
        self.assertEqual(out["stateful_runtime_preflight_status"], "failed")

    def test_custom_tcp_transport_fails_visible_until_wired(self):
        try:
            from ddos_samurai import _l7_emu_native
        except Exception:  # pragma: no cover
            self.skipTest("native L7 module unavailable")

        profile = senders.compile_l7_profile(
            protocol="http1",
            target_ip="127.0.0.1",
            target_port=8080,
            scheme="http",
            transport_backend="custom_tcp",
            http_method="GET",
            http_path=["/"],
            payloads=[],
            concurrency=1,
        )

        result = _l7_emu_native.run_profile(profile.as_dict(), RuntimeConfig(concurrency=1).as_dict())

        self.assertEqual(result["runtime_transport_backend"], "custom_tcp")
        self.assertEqual(result["runtime_transport_custom_tcp_requested"], 1)
        self.assertEqual(result["runtime_transport_custom_tcp_bridge_ready"], 1)
        self.assertEqual(result["runtime_transport_custom_tcp_rx_bridge_active"], 0)
        self.assertIn("tcp_connect_attempts", result)
        self.assertIn("tcp_connect_established", result)
        self.assertEqual(result["sender_fallback_reason"], "none")
        self.assertEqual(result["l7_fallback_reason"], "none")

    def test_native_strict_runtime_disables_kernel_socket_fallback(self):
        try:
            from ddos_samurai import _l7_emu_native
        except Exception:  # pragma: no cover
            self.skipTest("native L7 module unavailable")

        profile = senders.compile_l7_profile(
            protocol="http1",
            target_ip="127.0.0.1",
            target_port=8080,
            scheme="http",
            transport_backend="kernel_socket",
            stateful_runtime_backend="afxdp",
            stateful_runtime_strict=True,
            legacy_mode=False,
            http_method="GET",
            http_path=["/"],
            payloads=[],
            concurrency=1,
        )
        profile_payload = profile.as_dict()
        profile_payload["connection_template"]["transport_backend"] = "kernel_socket"
        result = _l7_emu_native.run_profile(profile_payload, RuntimeConfig(concurrency=1).as_dict())
        self.assertEqual(result["sent"], 0)
        self.assertEqual(result["errors"], int(profile.flow_attempted))
        self.assertEqual(result["sender_fallback_reason"], "stateful_runtime_transport_unavailable")
        self.assertEqual(result["stateful_runtime_reason"], "stateful_runtime_transport_unavailable")
        self.assertIn("kernel_socket fallback is disabled", str(result.get("stateful_runtime_detail", "")))

    def test_native_strict_runtime_allows_http2_custom_tcp_binding(self):
        try:
            from ddos_samurai import _l7_emu_native
        except Exception:  # pragma: no cover
            self.skipTest("native L7 module unavailable")

        profile = senders.compile_l7_profile(
            protocol="http2",
            target_ip="127.0.0.1",
            target_port=443,
            scheme="https",
            transport_backend="custom_tcp",
            stateful_runtime_backend="afxdp",
            stateful_runtime_strict=True,
            legacy_mode=False,
            http_method="GET",
            http_path=["/"],
            payloads=[],
            concurrency=1,
        )
        result = _l7_emu_native.run_profile(profile.as_dict(), RuntimeConfig(concurrency=1).as_dict())
        self.assertEqual(result["sender_fallback_reason"], "none")
        self.assertEqual(result["stateful_runtime_reason"], "none")
        self.assertEqual(int(result.get("runtime_transport_custom_tcp_requested", 0)), 1)
        self.assertEqual(int(result.get("runtime_h2_transport_mode_custom_tcp", 0)), 1)

    def test_public_strict_h1_contract_fails_when_runtime_reports_kernel_transport(self):
        profile = senders.compile_l7_profile(
            protocol="http1",
            target_ip="127.0.0.1",
            target_port=8080,
            scheme="http",
            stateful_runtime_backend="afxdp",
            stateful_runtime_strict=True,
            legacy_mode=False,
            http_method="GET",
            http_path=["/"],
            payloads=[],
            concurrency=1,
        )

        class _FakeResult:
            @staticmethod
            def as_dict():
                return {
                    "attempted": 1,
                    "sent": 1,
                    "errors": 0,
                    "runtime_transport_backend": "kernel_socket",
                    "sender_fallback_reason": "none",
                    "l7_fallback_reason": "none",
                }

        async def _fake_run(_profile, _runtime_cfg):
            return _FakeResult()

        with patch("ddos_samurai.senders._run_l7_profile", _fake_run), patch(
            "ddos_samurai.senders._stateful_runtime_preflight",
            return_value={
                "stateful_runtime_status": "ready",
                "stateful_runtime_reason": "none",
                "stateful_runtime_detail": "",
                "stateful_runtime_preflight_status": "passed",
                "stateful_runtime_preflight_reason": "none",
                "stateful_runtime_preflight_detail": "",
            },
        ):
            out = asyncio.run(
                senders.run_l7_profile_public(
                    profile,
                    concurrency=1,
                    stateful_runtime_backend="afxdp",
                    stateful_runtime_strict=True,
                    legacy_mode=False,
                )
            )

        self.assertEqual(out["sent"], 0)
        self.assertEqual(out["errors"], int(profile.flow_attempted))
        self.assertEqual(out["stateful_runtime_status"], "unavailable")
        self.assertEqual(out["stateful_runtime_reason"], "stateful_runtime_transport_contract_violation")

    def test_public_sender_facade_services_custom_tcp_bridge(self):
        profile = senders.compile_l7_profile(
            protocol="http1",
            target_ip="127.0.0.1",
            target_port=8080,
            scheme="http",
            transport_backend="custom_tcp",
            http_method="GET",
            http_path=["/"],
            payloads=[],
            concurrency=1,
        )
        captured = {}

        class _FakeTcpDp:
            def __init__(self):
                self.calls = 0

            def drain_tcp_tx_packets(self):
                self.calls += 1
                if self.calls == 1:
                    return [b"pkt0"]
                return []

        async def _fake_run(profile_arg, runtime_cfg):
            self.assertIs(profile_arg, profile)
            self.assertEqual(runtime_cfg.as_dict()["concurrency"], 1)
            await asyncio.sleep(0.01)

            class _Result:
                @staticmethod
                def as_dict():
                    return {"attempted": 1, "sent": 1, "errors": 0}

            return _Result()

        async def _fake_xdp_sender(**kwargs):
            captured.update(kwargs)
            return {"sent": 1, "errors": 0}

        with patch("ddos_samurai.senders._run_l7_profile", side_effect=_fake_run):
            with patch("ddos_samurai.senders.custom_tcp_dataplane", _FakeTcpDp(), create=True):
                with patch("ddos_samurai.senders.XDP_AVAILABLE", True):
                    with patch("ddos_samurai.senders.check_xdp_available", side_effect=lambda: (True, "AF_XDP is available")):
                        with patch("ddos_samurai.senders.xdp_sender", side_effect=_fake_xdp_sender):
                            out = asyncio.run(
                                senders.run_l7_profile_public(
                                    profile,
                                    concurrency=1,
                                    verbose=False,
                                    custom_tcp_backend="af_xdp",
                                    custom_tcp_xdp_interface="eth0",
                                )
                            )

        self.assertEqual(captured["target_ip"], "127.0.0.1")
        self.assertEqual(captured["interface"], "eth0")
        self.assertEqual(out["custom_tcp_tx_flush_packets"], 1)
        self.assertEqual(out["custom_tcp_tx_flush_bytes"], 4)
        self.assertEqual(out["runtime_transport_service"], "native_custom_tcp_runtime_service")
        self.assertEqual(out["runtime_transport_contract"], "custom_tcp_runtime_bridge")
        self.assertGreaterEqual(int(out["runtime_transport_service_loops"]), 1)

    def test_public_sender_facade_reports_af_xdp_bridge_fallback_when_iface_missing(self):
        profile = senders.compile_l7_profile(
            protocol="http1",
            target_ip="127.0.0.1",
            target_port=8080,
            scheme="http",
            transport_backend="custom_tcp",
            http_method="GET",
            http_path=["/"],
            payloads=[],
            concurrency=1,
        )
        captured = {}

        class _FakeTcpDp:
            def __init__(self):
                self.calls = 0

            def drain_tcp_tx_packets(self):
                self.calls += 1
                if self.calls == 1:
                    return [b"pkt0"]
                return []

        async def _fake_run(profile_arg, runtime_cfg):
            self.assertIs(profile_arg, profile)
            self.assertEqual(runtime_cfg.as_dict()["concurrency"], 1)
            await asyncio.sleep(0.01)

            class _Result:
                @staticmethod
                def as_dict():
                    return {"attempted": 1, "sent": 1, "errors": 0}

            return _Result()

        async def _fake_paced_raw_socket_sender(**kwargs):
            captured.update(kwargs)
            return {"sent": 1, "errors": 0}

        with patch("ddos_samurai.senders._run_l7_profile", side_effect=_fake_run):
            with patch("ddos_samurai.senders.custom_tcp_dataplane", _FakeTcpDp(), create=True):
                with patch(
                    "ddos_samurai.senders.paced_raw_socket_sender",
                    side_effect=_fake_paced_raw_socket_sender,
                ):
                    out = asyncio.run(
                        senders.run_l7_profile_public(
                            profile,
                            concurrency=1,
                            verbose=False,
                            custom_tcp_backend="af_xdp",
                        )
                    )

        self.assertEqual(captured, {})
        self.assertEqual(out["custom_tcp_bridge_backend_requested"], "af_xdp")
        self.assertEqual(out["custom_tcp_bridge_backend_used"], "xdp")
        self.assertEqual(out["custom_tcp_bridge_backend_match"], 0)
        self.assertEqual(out["custom_tcp_bridge_degraded"], 1)
        self.assertEqual(out["custom_tcp_bridge_fallback_reason"], "custom_tcp_xdp_interface_missing")
        self.assertEqual(out["custom_tcp_bridge_xdp_enabled"], 1)
        self.assertEqual(out["stateful_runtime_preflight_status"], "skipped")

    def test_public_sender_facade_uses_xdp_bridge_when_capability_is_available(self):
        profile = senders.compile_l7_profile(
            protocol="http1",
            target_ip="127.0.0.1",
            target_port=8080,
            scheme="http",
            transport_backend="custom_tcp",
            http_method="GET",
            http_path=["/"],
            payloads=[],
            concurrency=1,
        )
        captured = {}

        class _FakeTcpDp:
            def __init__(self):
                self.calls = 0

            def drain_tcp_tx_packets(self):
                self.calls += 1
                if self.calls == 1:
                    return [b"pkt0"]
                return []

        async def _fake_run(profile_arg, runtime_cfg):
            self.assertIs(profile_arg, profile)
            self.assertEqual(runtime_cfg.as_dict()["concurrency"], 1)
            await asyncio.sleep(0.01)

            class _Result:
                @staticmethod
                def as_dict():
                    return {"attempted": 1, "sent": 1, "errors": 0}

            return _Result()

        async def _fake_paced_raw_socket_sender(**kwargs):
            captured.update(kwargs)
            return {"sent": 1, "errors": 0}

        with patch("ddos_samurai.senders._run_l7_profile", side_effect=_fake_run):
            with patch("ddos_samurai.senders.custom_tcp_dataplane", _FakeTcpDp(), create=True):
                with patch("ddos_samurai.senders.XDP_AVAILABLE", True):
                    with patch("ddos_samurai.senders.check_xdp_available", side_effect=lambda: (True, "AF_XDP is available")):
                        with patch(
                            "ddos_samurai.senders.paced_raw_socket_sender",
                            side_effect=_fake_paced_raw_socket_sender,
                        ):
                            out = asyncio.run(
                                senders.run_l7_profile_public(
                                    profile,
                                    concurrency=1,
                                    verbose=False,
                                    custom_tcp_backend="af_xdp",
                                    custom_tcp_xdp_interface="eth0",
                                    custom_tcp_xdp_queue_id=3,
                                )
                            )

        self.assertEqual(captured["sender_backend"], "xdp")
        self.assertTrue(bool(captured["xdp_enable"]))
        self.assertEqual(captured["xdp_interface"], "eth0")
        self.assertEqual(out["custom_tcp_bridge_backend_requested"], "af_xdp")
        self.assertEqual(out["custom_tcp_bridge_backend_used"], "xdp")
        self.assertEqual(out["custom_tcp_bridge_backend_match"], 1)
        self.assertEqual(out["custom_tcp_bridge_degraded"], 0)
        self.assertEqual(out["custom_tcp_bridge_fallback_reason"], "none")
        self.assertEqual(out["custom_tcp_bridge_xdp_enabled"], 1)
        self.assertEqual(out["custom_tcp_bridge_xdp_available"], 1)
        self.assertEqual(out["custom_tcp_bridge_xdp_queue_id"], 3)
        self.assertEqual(out["stateful_runtime_preflight_status"], "skipped")

    def test_real_xdp_capability_preflight_smoke_when_environment_supports_it(self):
        if not bool(getattr(senders, "XDP_AVAILABLE", False)):
            self.skipTest("AF_XDP sender module unavailable")
        if not callable(getattr(senders, "check_xdp_available", None)):
            self.skipTest("check_xdp_available hook unavailable")
        available, _msg = senders.check_xdp_available()
        if not available:
            self.skipTest("AF_XDP runtime capability unavailable in current environment")

        iface = str(os.environ.get("SAMURAI_XDP_INTERFACE", "lo") or "lo").strip()
        plan = senders._resolve_custom_tcp_flush_transport(
            requested_backend="af_xdp",
            xdp_interface=iface,
            xdp_queue_id=0,
        )
        self.assertEqual(plan["custom_tcp_bridge_backend_requested"], "af_xdp")
        self.assertEqual(plan["custom_tcp_bridge_backend_used"], "xdp")
        self.assertEqual(int(plan["custom_tcp_bridge_backend_match"]), 1)
        self.assertEqual(int(plan["custom_tcp_bridge_degraded"]), 0)
        self.assertEqual(plan["custom_tcp_bridge_fallback_reason"], "none")
        self.assertEqual(int(plan["custom_tcp_bridge_xdp_enabled"]), 1)

    def test_custom_tcp_xdp_bridge_session_smoke_with_real_dataplane(self):
        if not bool(getattr(senders, "CUSTOM_TCP_DATAPLANE_AVAILABLE", False)):
            self.skipTest("custom tcp dataplane extension unavailable")

        profile = senders.compile_l7_profile(
            protocol="http1",
            target_ip="10.20.0.1",
            target_port=8080,
            scheme="http",
            transport_backend="custom_tcp",
            http_method="GET",
            http_path=["/"],
            payloads=[],
            concurrency=1,
        )

        tcpdp = senders.custom_tcp_dataplane
        tcpdp.configure_tcp_dataplane("required", "af_xdp", 50, 3, 250, 500)

        calls = []

        async def _fake_paced_raw_socket_sender(**kwargs):
            calls.append(dict(kwargs))
            return {
                "attempted": int(kwargs.get("count", 0) or 0),
                "sent": int(kwargs.get("count", 0) or 0),
                "errors": 0,
                "bytes_sent_est": len(kwargs.get("packets_buffer", b"") or b""),
                "sender_path": "XDP_L2",
            }

        async def _fake_xdp_sender(**kwargs):
            bridged_kwargs = {
                "packets_buffer": kwargs.get("packets_buffer", b""),
                "target_ip": kwargs.get("target_ip"),
                "target_port": kwargs.get("target_port"),
                "count": int(kwargs.get("count", 0) or 0),
                "verbose": bool(kwargs.get("verbose", False)),
                "sender_backend": "xdp",
                "xdp_enable": True,
                "xdp_interface": kwargs.get("interface"),
                "xdp_queue_id": int(kwargs.get("queue_id", 0) or 0),
                "xdp_mode": int(kwargs.get("xdp_mode", 0) or 0),
            }
            return await _fake_paced_raw_socket_sender(**bridged_kwargs)

        async def _run_smoke():
            stop_event = asyncio.Event()
            bridge_task = asyncio.create_task(
                senders._service_custom_tcp_runtime(
                    stop_event,
                    profile=profile,
                    verbose=False,
                    custom_tcp_backend="af_xdp",
                    custom_tcp_xdp_interface="eth0",
                    custom_tcp_xdp_queue_id=1,
                    custom_tcp_xdp_mode=0,
                )
            )
            try:
                flow_id = tcpdp.enqueue_tcp_connect(
                    _ip_to_int("10.20.0.2"),
                    _ip_to_int("10.20.0.1"),
                    41000,
                    8080,
                )
                await asyncio.sleep(0.01)
                flow = tcpdp.get_tcp_flow(flow_id)
                synack = _build_tcp_ipv4_frame(
                    "10.20.0.1",
                    "10.20.0.2",
                    8080,
                    41000,
                    seq=9000,
                    ack=int(flow["snd_nxt"]),
                    flags=0x12,
                )
                self.assertEqual(tcpdp.ingest_tcp_rx_frame(synack), 1)

                request_payload = b"GET / HTTP/1.1\r\nHost: smoke\r\n\r\n"
                queued = tcpdp.enqueue_tcp_send(flow_id, request_payload)
                self.assertEqual(queued, len(request_payload))
                await asyncio.sleep(0.01)

                flow = tcpdp.get_tcp_flow(flow_id)
                response_payload = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                response = _build_tcp_ipv4_frame(
                    "10.20.0.1",
                    "10.20.0.2",
                    8080,
                    41000,
                    seq=int(flow["rcv_nxt"]),
                    ack=int(flow["snd_nxt"]),
                    flags=0x18,
                    payload=response_payload,
                )
                self.assertEqual(tcpdp.ingest_tcp_rx_frame(response), 1)
                rx_payloads = tcpdp.collect_tcp_rx_payloads()
                self.assertTrue(rx_payloads)
                self.assertEqual(rx_payloads[0]["payload"], response_payload)
            finally:
                stop_event.set()
                bridge_stats = await asyncio.wait_for(bridge_task, timeout=1.0)
            return bridge_stats

        with patch("ddos_samurai.senders.XDP_AVAILABLE", True):
            with patch("ddos_samurai.senders.check_xdp_available", side_effect=lambda: (True, "AF_XDP is available")):
                with patch(
                    "ddos_samurai.senders.paced_raw_socket_sender",
                    side_effect=_fake_paced_raw_socket_sender,
                ):
                    with patch(
                        "ddos_samurai.senders.xdp_sender",
                        side_effect=_fake_xdp_sender,
                    ):
                        bridge_stats = asyncio.run(_run_smoke())

        self.assertGreaterEqual(len(calls), 2)
        self.assertTrue(all(call["sender_backend"] == "xdp" for call in calls))
        self.assertTrue(all(bool(call["xdp_enable"]) for call in calls))
        self.assertTrue(all(call["xdp_interface"] == "eth0" for call in calls))
        self.assertGreaterEqual(int(bridge_stats["custom_tcp_tx_flush_packets"]), 2)
        self.assertEqual(bridge_stats["custom_tcp_bridge_backend_requested"], "af_xdp")
        self.assertEqual(bridge_stats["custom_tcp_bridge_backend_used"], "xdp")
        self.assertEqual(int(bridge_stats["custom_tcp_bridge_backend_match"]), 1)
        self.assertEqual(int(bridge_stats["custom_tcp_bridge_degraded"]), 0)
        self.assertEqual(bridge_stats["custom_tcp_bridge_fallback_reason"], "none")
        self.assertEqual(int(bridge_stats["custom_tcp_bridge_xdp_enabled"]), 1)
        self.assertEqual(bridge_stats["runtime_transport_service"], "native_custom_tcp_runtime_service")
        self.assertEqual(int(bridge_stats["runtime_transport_rx_poll_enabled"]), 1)
        self.assertEqual(int(bridge_stats["runtime_transport_snapshot_available"]), 1)

    def test_native_http1_custom_tcp_acceptance_supports_response_parse_and_keepalive_reuse(self):
        if not bool(getattr(senders, "CUSTOM_TCP_DATAPLANE_AVAILABLE", False)):
            self.skipTest("custom tcp dataplane extension unavailable")
        native_bridge = senders._native_custom_tcp_bridge_api()
        if native_bridge is None:
            self.skipTest("native custom tcp bridge unavailable")

        profile = senders.compile_l7_profile(
            protocol="http1",
            target_ip="10.30.0.1",
            target_port=8080,
            scheme="http",
            transport_backend="custom_tcp",
            http_method="GET",
            http_path=["/one", "/two"],
            payloads=[],
            concurrency=1,
            timeout_s=0.5,
        )

        peer_state = {
            "server_seq": 9000,
            "syn_count": 0,
            "request_payloads": [],
        }

        async def _fake_paced_raw_socket_sender(**kwargs):
            frames = _split_ipv4_frames(
                bytes(kwargs.get("packets_buffer", b"") or b""),
                int(kwargs.get("count", 0) or 0),
            )
            for frame in frames:
                parsed = _parse_tcp_ipv4_frame(frame)
                payload = bytes(parsed["payload"])
                flags = int(parsed["flags"])
                if (flags & 0x02) and not (flags & 0x10):
                    peer_state["syn_count"] += 1
                    synack = _build_tcp_ipv4_frame(
                        str(parsed["dst_ip"]),
                        str(parsed["src_ip"]),
                        int(parsed["dst_port"]),
                        int(parsed["src_port"]),
                        seq=int(peer_state["server_seq"]),
                        ack=int(parsed["seq"]) + 1,
                        flags=0x12,
                    )
                    native_bridge.ingest_custom_tcp_rx_frame(synack)
                    peer_state["server_seq"] += 1
                    continue
                if payload:
                    peer_state["request_payloads"].append(payload.decode("latin1"))
                    is_first = len(peer_state["request_payloads"]) == 1
                    response_payload = (
                        b"HTTP/1.1 200 OK\r\n"
                        + (b"Connection: keep-alive\r\n" if is_first else b"Connection: close\r\n")
                        + b"Content-Length: 2\r\n"
                        + b"Location: /next\r\n"
                        + b"Set-Cookie: sid=abc\r\n\r\nok"
                    )
                    response = _build_tcp_ipv4_frame(
                        str(parsed["dst_ip"]),
                        str(parsed["src_ip"]),
                        int(parsed["dst_port"]),
                        int(parsed["src_port"]),
                        seq=int(peer_state["server_seq"]),
                        ack=int(parsed["seq"]) + len(payload),
                        flags=0x18,
                        payload=response_payload,
                    )
                    native_bridge.ingest_custom_tcp_rx_frame(response)
                    peer_state["server_seq"] += len(response_payload)
            return {
                "attempted": int(kwargs.get("count", 0) or 0),
                "sent": int(kwargs.get("count", 0) or 0),
                "errors": 0,
                "bytes_sent_est": len(bytes(kwargs.get("packets_buffer", b"") or b"")),
                "sender_path": "PACED_L2",
            }

        async def _fake_xdp_sender(**kwargs):
            return await _fake_paced_raw_socket_sender(
                packets_buffer=kwargs.get("packets_buffer", b""),
                target_ip=kwargs.get("target_ip"),
                target_port=kwargs.get("target_port"),
                count=kwargs.get("count", 0),
                verbose=kwargs.get("verbose", False),
            )

        with patch("ddos_samurai.senders.XDP_AVAILABLE", True):
            with patch("ddos_samurai.senders.check_xdp_available", side_effect=lambda: (True, "AF_XDP is available")):
                with patch("ddos_samurai.senders.xdp_sender", side_effect=_fake_xdp_sender):
                    out = asyncio.run(
                        senders.run_l7_profile_public(
                            profile,
                            concurrency=1,
                            verbose=False,
                            custom_tcp_backend="af_xdp",
                            custom_tcp_xdp_interface="eth0",
                        )
                    )

        self.assertEqual(out["runtime_transport_backend"], "custom_tcp")
        self.assertEqual(out["runtime_transport_custom_tcp_requested"], 1)
        self.assertEqual(out["runtime_transport_custom_tcp_bridge_ready"], 1)
        self.assertEqual(out["attempted"], 2)
        self.assertEqual(out["sent"], 2)
        self.assertEqual(out["errors"], 0)
        self.assertEqual(out["status_2xx"], 2)
        self.assertEqual(out["l7_conn_attempted"], 1)
        self.assertEqual(out["l7_conn_established"], 1)
        self.assertGreaterEqual(out["l7_conn_reused"], 1)
        self.assertGreater(out["l7_rx_bytes"], 0)
        self.assertGreater(out["l7_tx_bytes"], 0)
        self.assertEqual(peer_state["syn_count"], 1)
        self.assertEqual(len(peer_state["request_payloads"]), 2)
        self.assertIn("GET /one HTTP/1.1", peer_state["request_payloads"][0])
        self.assertIn("GET /two HTTP/1.1", peer_state["request_payloads"][1])

    def test_public_sender_facade_accepts_profiling_kwargs(self):
        profile = senders.compile_l7_profile(
            protocol="http1",
            target_ip="127.0.0.1",
            target_port=8080,
            scheme="http",
            http_method="GET",
            http_path=["/"],
            payloads=[],
            concurrency=1,
        )
        captured_cfg = {}

        async def _fake_run(profile_arg, runtime_cfg):
            self.assertIs(profile_arg, profile)
            captured_cfg.update(runtime_cfg.as_dict())

            class _Result:
                @staticmethod
                def as_dict():
                    return {"attempted": 1, "sent": 1, "errors": 0}

            return _Result()

        with patch("ddos_samurai.senders._run_l7_profile", side_effect=_fake_run):
            out = asyncio.run(
                senders.run_l7_profile_public(
                    profile,
                    concurrency=3,
                    profile_l7=True,
                    profile_sample_limit=128,
                )
            )

        self.assertEqual(out["sent"], 1)
        self.assertEqual(captured_cfg["concurrency"], 3)
        self.assertEqual(captured_cfg["profile_l7"], 1)
        self.assertEqual(captured_cfg["profile_sample_limit"], 128)

    def test_http_app_sender_forwards_custom_tcp_transport_backend(self):
        captured = {}

        async def _fake_run_l7_profile_public(profile_arg, **kwargs):
            captured["profile"] = profile_arg
            captured["kwargs"] = dict(kwargs)
            return {"attempted": 1, "sent": 0, "errors": 1}

        with patch("ddos_samurai.senders.run_l7_profile_public", side_effect=_fake_run_l7_profile_public):
            asyncio.run(
                senders.http_app_sender(
                    target_ip="127.0.0.1",
                    target_port=8080,
                    count=1,
                    concurrency=1,
                    http_method="GET",
                    http_path=["/"],
                    payloads=[],
                    verbose=False,
                    scheme="http",
                    verify=False,
                    transport_backend="custom_tcp",
                    custom_tcp_backend="af_xdp",
                )
            )

        self.assertEqual(
            captured["profile"].connection_template.transport_backend,
            "custom_tcp",
        )
        self.assertEqual(captured["kwargs"]["custom_tcp_backend"], "af_xdp")
