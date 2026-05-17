from __future__ import annotations

import asyncio
import unittest
from pathlib import Path
from unittest import mock

from ddos_samurai._senders import l7_quic


class _DummyRunOut:
    def __init__(self, payload):
        self._payload = dict(payload or {})

    def as_dict(self):
        return dict(self._payload)


class TestL7QuicParityPhase1(unittest.TestCase):
    def test_parity_roadmap_doc_exists_with_phase_targets(self):
        plan = Path("docs/PLAN_L7_NATIVE_CUSTOM_QUIC_H3_PARITY.md")
        self.assertTrue(plan.exists())
        text = plan.read_text(encoding="utf-8")
        self.assertIn("Faz 1", text)
        self.assertIn("Faz 2", text)
        self.assertIn("Faz 3", text)
        self.assertIn("Faz 4", text)
        self.assertIn("Faz 5", text)
        self.assertIn("tam H3 parity", text)

    def test_native_parity_state_scaffold_is_wired(self):
        hpp = Path("ddos_samurai/l7_emu_native/custom_quic_stack/h3_parity_state.hpp")
        cpp = Path("ddos_samurai/l7_emu_native/custom_quic_stack/h3_parity_state.cpp")
        cp_hpp = Path("ddos_samurai/l7_emu_native/custom_quic_stack/h3_control_plane.hpp")
        cp_cpp = Path("ddos_samurai/l7_emu_native/custom_quic_stack/h3_control_plane.cpp")
        real_h3_hpp = Path("ddos_samurai/l7_emu_native/custom_quic_stack/h3_real_client.hpp")
        real_h3_cpp = Path("ddos_samurai/l7_emu_native/custom_quic_stack/h3_real_client.cpp")
        quic_stack = Path("ddos_samurai/l7_emu_native/custom_quic_stack/quic_stack.cpp")
        setup = Path("setup.py")

        self.assertTrue(hpp.exists())
        self.assertTrue(cpp.exists())
        self.assertTrue(cp_hpp.exists())
        self.assertTrue(cp_cpp.exists())
        self.assertTrue(real_h3_hpp.exists())
        self.assertTrue(real_h3_cpp.exists())
        self.assertIn("derive_h3_parity_state", cpp.read_text(encoding="utf-8"))
        self.assertIn("apply_h3_parity_metrics", cpp.read_text(encoding="utf-8"))
        self.assertIn("derive_h3_control_plane_state", cp_cpp.read_text(encoding="utf-8"))
        self.assertIn("apply_h3_control_plane_metrics", cp_cpp.read_text(encoding="utf-8"))
        self.assertIn("run_h3_real_client", real_h3_cpp.read_text(encoding="utf-8"))
        self.assertIn("h3_control_plane.hpp", quic_stack.read_text(encoding="utf-8"))
        self.assertIn("h3_parity_state.hpp", quic_stack.read_text(encoding="utf-8"))
        self.assertIn("h3_real_client.hpp", quic_stack.read_text(encoding="utf-8"))
        self.assertIn("apply_h3_control_plane_metrics(&out, derive_h3_control_plane_state(profile, udp));", quic_stack.read_text(encoding="utf-8"))
        self.assertIn("apply_h3_parity_metrics(&out, derive_h3_parity_state(profile));", quic_stack.read_text(encoding="utf-8"))
        self.assertIn("run_h3_real_client(profile, cfg, &udp);", quic_stack.read_text(encoding="utf-8"))
        self.assertIn("custom_quic_stack/h3_control_plane.cpp", setup.read_text(encoding="utf-8"))
        self.assertIn("custom_quic_stack/h3_parity_state.cpp", setup.read_text(encoding="utf-8"))
        self.assertIn("custom_quic_stack/h3_real_client.cpp", setup.read_text(encoding="utf-8"))

    def test_sender_surfaces_parity_metrics_without_native_runtime(self):
        async def _fake_run(profile, cfg):
            _ = (profile, cfg)
            return _DummyRunOut(
                {
                    "attempted": 2,
                    "sent": 1,
                    "errors": 1,
                    "quic_capability_available": 1,
                    "quic_h3_parity_phase": 3,
                    "quic_h3_parity_target_phase": 5,
                    "quic_h3_goaway_ready": 1,
                    "quic_h3_qpack_dynamic_ready": 1,
                    "quic_h3_goaway_events": 1,
                    "quic_h3_drain_cycles": 1,
                    "quic_h3_replace_now": 0,
                    "quic_h3_replace_after_idle": 1,
                    "quic_h3_control_plane_failures": 0,
                    "quic_h3_graceful_close_ratio": 1.0,
                }
            )

        with (
            mock.patch("ddos_samurai._senders.l7_quic._sender_runtime.has_l7_native_quic", return_value=True),
            mock.patch("ddos_samurai._senders.l7_quic._compile_l7_profile", return_value=object()),
            mock.patch("ddos_samurai._senders.l7_quic._run_l7_profile", side_effect=_fake_run),
        ):
            out = asyncio.run(
                l7_quic.quic_sender(
                    target_ip="127.0.0.1",
                    target_port=443,
                    count=2,
                    concurrency=1,
                    quic_path="/",
                    quic_method="GET",
                    verbose=False,
                    timeout_s=0.2,
                    l7_quic_engine="auto",
                    stats_fn=lambda **kwargs: kwargs,
                    normalize_l7_output_fn=lambda d, **_: d,
                    update_live_fn=lambda *_: None,
                )
            )

        expected = {
            "quic_h3_parity_phase",
            "quic_h3_parity_target_phase",
            "quic_h3_parity_progress_ratio",
            "quic_h3_parity_gap",
            "quic_h3_control_stream_ready",
            "quic_h3_qpack_dynamic_ready",
            "quic_h3_goaway_ready",
            "quic_h3_priority_update_ready",
            "quic_h3_extended_connect_ready",
            "quic_h3_datagram_ready",
            "quic_h3_server_push_ready",
            "quic_h3_goaway_events",
            "quic_h3_drain_cycles",
            "quic_h3_replace_now",
            "quic_h3_replace_after_idle",
            "quic_h3_control_plane_failures",
            "quic_h3_graceful_close_ratio",
        }
        self.assertTrue(expected.issubset(set(out.keys())))
        self.assertEqual(int(out.get("quic_h3_parity_phase", 0)), 3)
        self.assertEqual(int(out.get("quic_h3_parity_target_phase", 0)), 5)
        self.assertEqual(int(out.get("quic_h3_goaway_events", 0)), 1)
        self.assertGreater(float(out.get("quic_h3_parity_progress_ratio", 0.0)), 0.0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
