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
