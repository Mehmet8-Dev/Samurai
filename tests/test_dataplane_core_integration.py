import unittest


try:
    from ddos_samurai import dataplane_core
except Exception:  # pragma: no cover
    dataplane_core = None


@unittest.skipIf(dataplane_core is None, "dataplane_core extension unavailable")
class TestDataplaneCoreIntegration(unittest.TestCase):
    def _send_once(self, backend: str, fallback_policy: str = "fail") -> dict:
        handle = dataplane_core.open(
            {
                "backend": backend,
                "fallback_policy": fallback_policy,
                "xdp_enable": 0,
                "interface": "",
            }
        )
        try:
            out = dataplane_core.send_batch(handle, b"A", 1, 1, "127.0.0.1", 80)
            return dict(out or {})
        finally:
            dataplane_core.close(handle)

    def test_explicit_backend_c_ext_l3_is_handled(self):
        out = self._send_once("c_ext_l3", fallback_policy="fail")
        self.assertNotEqual(str(out.get("sender_path", "")), "DP_UNHANDLED_BACKEND")
        self.assertEqual(str(out.get("dp_backend", "")), "c_ext_l3")

    def test_explicit_backend_python_is_handled(self):
        out = self._send_once("python", fallback_policy="fail")
        self.assertNotEqual(str(out.get("sender_path", "")), "DP_UNHANDLED_BACKEND")
        self.assertEqual(str(out.get("dp_backend", "")), "python")

    def test_fail_policy_stops_auto_chain_after_first_backend(self):
        out = self._send_once("auto", fallback_policy="fail")
        reason = str(out.get("sender_fallback_reason", "") or "")
        self.assertNotIn("raw_socket", reason)
        self.assertNotIn(";", reason)

    def test_snapshot_exposes_afpacket_hugepage_policy(self):
        handle = dataplane_core.open(
            {
                "backend": "txring",
                "fallback_policy": "fail",
                "afpacket_hugepage_mode": "required",
                "afpacket_hugepage_size_kb": 2048,
                "afpacket_ring_target_mb": 64,
                "afpacket_mlock_ring": 0,
                "afpacket_prefault_ring": 1,
            }
        )
        try:
            snap = dict(dataplane_core.snapshot(handle) or {})
        finally:
            dataplane_core.close(handle)
        self.assertEqual(str(snap.get("afpacket_hugepage_mode", "")), "required")
        self.assertEqual(int(snap.get("afpacket_hugepage_size_kb", 0) or 0), 2048)
        self.assertEqual(int(snap.get("afpacket_ring_target_mb", 0) or 0), 64)

    def test_required_mode_does_not_resolve_to_python_backend(self):
        handle = dataplane_core.open(
            {
                "backend": "auto",
                "fallback_policy": "allow",
                "core_mode": "required",
                "allow_python_fallback": 1,
            }
        )
        try:
            snap = dict(dataplane_core.snapshot(handle) or {})
        finally:
            dataplane_core.close(handle)
        self.assertNotEqual(str(snap.get("backend", "") or ""), "python")

    def test_snapshot_exposes_xdp_mode2_policy_fields(self):
        handle = dataplane_core.open(
            {
                "backend": "xdp",
                "fallback_policy": "allow",
                "xdp_enable": 1,
                "interface": "lo",
                "xdp_mode": 2,
                "xdp_mode2_policy": "hard",
            }
        )
        try:
            snap = dict(dataplane_core.snapshot(handle) or {})
        finally:
            dataplane_core.close(handle)
        self.assertEqual(str(snap.get("xdp_mode2_policy", "")), "hard")
        self.assertEqual(int(snap.get("xdp_mode", 0) or 0), 2)
        self.assertEqual(str(snap.get("xdp_mode2_probe_status", "")), "not_run")

    def test_xdp_mode2_hard_fail_includes_detail(self):
        handle = dataplane_core.open(
            {
                "backend": "xdp",
                "fallback_policy": "fail",
                "xdp_enable": 1,
                "interface": "lo",
                "xdp_mode": 2,
                "xdp_mode2_policy": "hard",
            }
        )
        try:
            out = dict(dataplane_core.send_batch(handle, b"A", 1, 1, "127.0.0.1", 80) or {})
        finally:
            dataplane_core.close(handle)
        self.assertEqual(str(out.get("sender_fallback_reason", "")), "xdp_mode2_hard_probe_not_supported")
        self.assertIn("loopback", str(out.get("sender_fallback_reason_detail", "")).lower())
