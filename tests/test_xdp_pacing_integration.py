import unittest
from types import SimpleNamespace
from unittest.mock import patch

from ddos_samurai._senders import l2l3_entry, l2l3_raw


class TestXdpPacingRawPath(unittest.IsolatedAsyncioTestCase):
    async def test_paced_raw_xdp_uses_direct_xdp_v2_route_when_enabled(self):
        calls = {"reset": 0, "xdp": 0, "paced": 0}

        def paced_fn(iface, _buffer, _packet_size, _count, **kwargs):
            self.assertEqual(iface, "eth0")
            self.assertEqual(int(kwargs.get("queue_id", -1)), 2)
            self.assertEqual(int(kwargs.get("xdp_mode", -1)), 1)
            self.assertEqual(str(kwargs.get("xdp_mode2_policy", "")), "soft")
            self.assertIsNotNone(kwargs.get("config"))
            calls["paced"] += 1
            return 1

        async def _xdp_sender_fn(**_kwargs):
            calls["xdp"] += 1
            return {"attempted": 1, "sent": 1, "errors": 0}

        def _reset_stats():
            calls["reset"] += 1

        with patch.dict("os.environ", {"SAMURAI_XDP_PACING_V2": "1"}, clear=False):
            out = await l2l3_raw.paced_raw_socket_sender(
                b"A" * 64,
                "127.0.0.1",
                80,
                1,
                False,
                pacing_config=SimpleNamespace(
                    pacing_mode=1,
                    target_rps=1000.0,
                    ipg_ns=0,
                    burst_size=1,
                    burst_gap_ns=0,
                    jitter_model=0,
                    jitter_pct=0.0,
                    pin_cpu=-1,
                ),
                sender_backend="xdp",
                resolve_sender_backend_fn=lambda _: "xdp",
                resolve_sender_fallback_policy_fn=lambda _: "allow",
                xdp_sender_fn=_xdp_sender_fn,
                raw_socket_sender_fn=None,
                normalize_packets_buffer_fn=lambda buf, **_: (
                    buf,
                    {"buffer_copy_count": 0, "buffer_copy_bytes": 0},
                ),
                resolve_loss_iface_fn=lambda _: None,
                take_loss_snapshot_fn=lambda _: {},
                attach_loss_telemetry_fn=lambda out, *_args, **_kw: out,
                update_live_fn=lambda *_args, **_kw: None,
                stats_fn=lambda **kw: kw,
                apply_pacing_stats_fn=lambda out, st: dict(out, actual_rps=st.get("actual_rps", 0.0)),
                run_paced_send_with_live_progress_fn=None,
                PacedSendRuntimeError_cls=RuntimeError,
                get_gateway_info_fn=lambda _ip: ("eth0", b"\x00" * 6),
                FAST_SENDER_AVAILABLE_flag=False,
                PACING_ENGINE_AVAILABLE_flag=True,
                reset_stats_fn=_reset_stats,
                paced_send_l2_fn=None,
                paced_send_xdp_fn=paced_fn,
                paced_send_fn=None,
                get_stats_fn=lambda: {"actual_rps": 12345.0},
                format_stats_fn=None,
                cleanup_l2_fn=None,
                log_info=lambda *_args, **_kw: None,
                log_error=lambda *_args, **_kw: None,
                log_warning=lambda *_args, **_kw: None,
                xdp_queue_id=2,
                xdp_mode=1,
            )

        self.assertEqual(calls["paced"], 1)
        self.assertEqual(calls["xdp"], 0)
        self.assertEqual(calls["reset"], 1)
        self.assertEqual(str(out.get("sender_path", "")), "PACED_XDP")
        self.assertNotIn("pacing_bypassed_for_xdp", out)
        self.assertEqual(float(out.get("actual_rps", 0.0)), 12345.0)

    async def test_paced_raw_xdp_uses_legacy_route_when_v2_disabled(self):
        calls = {"xdp": 0}
        paced_fn = lambda *_args, **_kwargs: 1

        async def _xdp_sender_fn(**kwargs):
            calls["xdp"] += 1
            self.assertIsNotNone(kwargs.get("pacing_config"))
            self.assertIs(kwargs.get("paced_send_xdp_fn"), paced_fn)
            return {
                "attempted": 1,
                "sent": 1,
                "errors": 0,
                "sender_path": "PACED_XDP",
            }

        with patch.dict("os.environ", {"SAMURAI_XDP_PACING_V2": "0"}, clear=False):
            out = await l2l3_raw.paced_raw_socket_sender(
                b"A" * 64,
                "127.0.0.1",
                80,
                1,
                False,
                pacing_config=SimpleNamespace(pacing_mode=1),
                sender_backend="xdp",
                resolve_sender_backend_fn=lambda _: "xdp",
                resolve_sender_fallback_policy_fn=lambda _: "allow",
                xdp_sender_fn=_xdp_sender_fn,
                raw_socket_sender_fn=None,
                normalize_packets_buffer_fn=lambda buf, **_: (
                    buf,
                    {"buffer_copy_count": 0, "buffer_copy_bytes": 0},
                ),
                resolve_loss_iface_fn=lambda _: None,
                take_loss_snapshot_fn=lambda _: {},
                attach_loss_telemetry_fn=lambda out, *_args, **_kw: out,
                update_live_fn=lambda *_args, **_kw: None,
                stats_fn=lambda **kw: kw,
                apply_pacing_stats_fn=lambda out, st: dict(out, actual_rps=st.get("actual_rps", 0.0)),
                run_paced_send_with_live_progress_fn=None,
                PacedSendRuntimeError_cls=RuntimeError,
                get_gateway_info_fn=None,
                FAST_SENDER_AVAILABLE_flag=False,
                PACING_ENGINE_AVAILABLE_flag=True,
                reset_stats_fn=lambda: None,
                paced_send_l2_fn=None,
                paced_send_xdp_fn=paced_fn,
                paced_send_fn=None,
                get_stats_fn=lambda: {"actual_rps": 12345.0},
                format_stats_fn=None,
                cleanup_l2_fn=None,
                log_info=lambda *_args, **_kw: None,
                log_error=lambda *_args, **_kw: None,
                log_warning=lambda *_args, **_kw: None,
            )

        self.assertEqual(calls["xdp"], 1)
        self.assertEqual(str(out.get("sender_path", "")), "PACED_XDP")

    async def test_paced_raw_xdp_sets_bypass_when_xdp_pacer_missing(self):
        seen = {}

        async def _xdp_sender_fn(**kwargs):
            seen.update(kwargs)
            return {"attempted": 1, "sent": 1, "errors": 0}

        with patch.dict("os.environ", {"SAMURAI_XDP_PACING_V2": "0"}, clear=False):
            out = await l2l3_raw.paced_raw_socket_sender(
                b"A" * 64,
                "127.0.0.1",
                80,
                1,
                False,
                pacing_config=SimpleNamespace(pacing_mode=1),
                sender_backend="xdp",
                resolve_sender_backend_fn=lambda _: "xdp",
                resolve_sender_fallback_policy_fn=lambda _: "allow",
                xdp_sender_fn=_xdp_sender_fn,
                raw_socket_sender_fn=None,
                normalize_packets_buffer_fn=lambda buf, **_: (
                    buf,
                    {"buffer_copy_count": 0, "buffer_copy_bytes": 0},
                ),
                resolve_loss_iface_fn=lambda _: None,
                take_loss_snapshot_fn=lambda _: {},
                attach_loss_telemetry_fn=lambda out, *_args, **_kw: out,
                update_live_fn=lambda *_args, **_kw: None,
                stats_fn=lambda **kw: kw,
                apply_pacing_stats_fn=lambda out, st: dict(out, _ignored=st),
                run_paced_send_with_live_progress_fn=None,
                PacedSendRuntimeError_cls=RuntimeError,
                get_gateway_info_fn=None,
                FAST_SENDER_AVAILABLE_flag=False,
                PACING_ENGINE_AVAILABLE_flag=True,
                reset_stats_fn=lambda: None,
                paced_send_l2_fn=None,
                paced_send_xdp_fn=None,
                paced_send_fn=None,
                get_stats_fn=lambda: (_ for _ in ()).throw(RuntimeError("should not call")),
                format_stats_fn=None,
                cleanup_l2_fn=None,
                log_info=lambda *_args, **_kw: None,
                log_error=lambda *_args, **_kw: None,
                log_warning=lambda *_args, **_kw: None,
            )

        self.assertIsNotNone(seen.get("pacing_config"))
        self.assertIsNone(seen.get("paced_send_xdp_fn"))
        self.assertEqual(int(out.get("pacing_bypassed_for_xdp", 0) or 0), 1)


class _FakeStats:
    tx_packets = 1
    tx_bytes = 64
    packets_per_second = 1000.0
    mbps = 1.0


class _FakeXDPSender:
    send_buffer_calls = 0
    send_buffer_paced_calls = 0

    def __init__(self, **kwargs):
        self.interface = kwargs.get("interface") or "lo"
        self.is_using_xdp = True
        self._started = False

    def start(self):
        self._started = True
        return True

    def stop(self):
        self._started = False

    def send_buffer(self, *_args, **_kwargs):
        _FakeXDPSender.send_buffer_calls += 1
        return 1

    def send_buffer_paced(self, *_args, **_kwargs):
        _FakeXDPSender.send_buffer_paced_calls += 1
        return 1

    def get_stats(self):
        return _FakeStats()


class TestXdpPacingEntry(unittest.IsolatedAsyncioTestCase):
    async def test_entry_uses_paced_xdp_path_when_available(self):
        _FakeXDPSender.send_buffer_calls = 0
        called = {"paced": 0}

        def _paced_send_xdp(_buffer, _packet_size, _count, config=None):
            self.assertIsNotNone(config)
            called["paced"] += 1
            return 1

        out = await l2l3_entry.xdp_sender(
            packets_buffer=b"B" * 64,
            target_ip="127.0.0.1",
            target_port=80,
            count=1,
            verbose=False,
            interface="lo",
            queue_id=0,
            xdp_mode=0,
            batch_size=64,
            sender_fallback_policy="allow",
            fallback_backend="c_ext_l3",
            sender_context=None,
            pacing_config=SimpleNamespace(pacing_mode=1),
            paced_send_xdp_fn=_paced_send_xdp,
            resolve_sender_fallback_policy_fn=lambda _: "allow",
            resolve_sender_backend_fn=lambda _: "c_ext_l3",
            raw_socket_sender_fn=None,
            normalize_packets_buffer_fn=lambda buf, **_: (
                buf,
                {"buffer_copy_count": 0, "buffer_copy_bytes": 0},
            ),
            stats_fn=lambda **kw: kw,
            log_info=lambda *_args, **_kw: None,
            log_warning=lambda *_args, **_kw: None,
            log_error=lambda *_args, **_kw: None,
            XDP_AVAILABLE=True,
            XDPSender=_FakeXDPSender,
            check_xdp_available=lambda: (True, "ok"),
        )

        self.assertEqual(called["paced"], 1)
        self.assertEqual(_FakeXDPSender.send_buffer_calls, 0)
        self.assertEqual(str(out.get("sender_path", "")), "PACED_XDP")

    async def test_entry_uses_native_paced_xdp_when_pacing_engine_missing(self):
        _FakeXDPSender.send_buffer_calls = 0
        _FakeXDPSender.send_buffer_paced_calls = 0

        out = await l2l3_entry.xdp_sender(
            packets_buffer=b"B" * 64,
            target_ip="127.0.0.1",
            target_port=80,
            count=1,
            verbose=False,
            interface="lo",
            queue_id=0,
            xdp_mode=0,
            batch_size=64,
            sender_fallback_policy="allow",
            fallback_backend="c_ext_l3",
            sender_context=None,
            pacing_config=SimpleNamespace(pacing_mode=1, target_rps=1000.0),
            paced_send_xdp_fn=None,
            resolve_sender_fallback_policy_fn=lambda _: "allow",
            resolve_sender_backend_fn=lambda _: "c_ext_l3",
            raw_socket_sender_fn=None,
            normalize_packets_buffer_fn=lambda buf, **_: (
                buf,
                {"buffer_copy_count": 0, "buffer_copy_bytes": 0},
            ),
            stats_fn=lambda **kw: kw,
            log_info=lambda *_args, **_kw: None,
            log_warning=lambda *_args, **_kw: None,
            log_error=lambda *_args, **_kw: None,
            XDP_AVAILABLE=True,
            XDPSender=_FakeXDPSender,
            check_xdp_available=lambda: (True, "ok"),
        )

        self.assertEqual(_FakeXDPSender.send_buffer_paced_calls, 1)
        self.assertEqual(_FakeXDPSender.send_buffer_calls, 0)
        self.assertEqual(str(out.get("sender_path", "")), "PACED_XDP_NATIVE")


if __name__ == "__main__":
    unittest.main()
