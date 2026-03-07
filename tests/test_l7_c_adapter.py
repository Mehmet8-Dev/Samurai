import unittest
from unittest.mock import patch
import os

from ddos_samurai.l7 import c_adapter


class _CoreWithProbes:
    def run_http1_stateful(self, *_args, **_kwargs):
        return {}

    def run_websocket_stateful(self, *_args, **_kwargs):
        return {}

    def run_http2_stateful(self, *_args, **_kwargs):
        return {}

    def run_quic_stateful(self, *_args, **_kwargs):
        return {}

    def h2_supported(self):
        return False

    def quic_supported(self):
        return True

    def quic_stack_mode(self):
        return "h3_stateful"

    def quic_stack_probe_reason(self):
        return "h3_stateful_not_implemented"


class _CoreProbeRaises(_CoreWithProbes):
    def h2_supported(self):
        raise RuntimeError("boom")

    def quic_stack_mode(self):
        raise RuntimeError("boom")


class TestL7CAdapter(unittest.TestCase):
    def test_capability_map_respects_support_probes(self):
        core = _CoreWithProbes()
        with patch.object(c_adapter._adapter, "_l7_core", core), patch.object(
            c_adapter.quic_h3_bridge, "stack_mode", return_value="unavailable"
        ):
            caps = c_adapter.capability_map()
        self.assertTrue(caps["core_available"])
        self.assertTrue(caps["http1"])
        self.assertTrue(caps["ws"])
        self.assertFalse(caps["http2"])
        self.assertTrue(caps["quic"])
        self.assertEqual(caps.get("quic_stack_mode"), "h3_stateful")
        self.assertTrue(bool(caps.get("quic_h3_stateful", False)))
        self.assertEqual(caps.get("quic_stack_probe_reason"), "h3_stateful_not_implemented")
        self.assertEqual(caps.get("quic_effective_path"), "c_native")
        self.assertTrue(bool(caps.get("quic_native_h3_stateful", False)))
        self.assertFalse(bool(caps.get("quic_bridge_h3_stateful", True)))

    def test_capability_map_handles_probe_exception(self):
        core = _CoreProbeRaises()
        with patch.object(c_adapter._adapter, "_l7_core", core), patch.object(
            c_adapter.quic_h3_bridge, "stack_mode", return_value="unavailable"
        ):
            caps = c_adapter.capability_map()
        self.assertFalse(caps["http2"])
        self.assertFalse(caps["quic"])
        self.assertEqual(caps.get("quic_stack_mode"), "unavailable")
        self.assertFalse(bool(caps.get("quic_h3_stateful", True)))
        self.assertEqual(caps.get("quic_effective_path"), "unavailable")

    def test_capability_map_does_not_autopromote_bridge_by_default(self):
        with patch.dict(os.environ, {"SAMURAI_L7_QUIC_BRIDGE_AUTOPROMOTE": "0"}, clear=False), patch.object(
            c_adapter._adapter, "_l7_core", None
        ), patch.object(
            c_adapter.quic_h3_bridge, "stack_mode", return_value="h3_stateful_py"
        ):
            caps = c_adapter.capability_map()
        self.assertFalse(caps["core_available"])
        self.assertFalse(caps["quic"])
        self.assertEqual(caps.get("quic_stack_mode"), "unavailable")
        self.assertFalse(bool(caps.get("quic_h3_stateful", True)))
        self.assertEqual(caps.get("quic_effective_path"), "unavailable")
        self.assertFalse(bool(caps.get("quic_native_h3_stateful", True)))
        self.assertTrue(bool(caps.get("quic_bridge_h3_stateful", False)))
        self.assertFalse(bool(caps.get("quic_bridge_autopromote", True)))

    def test_capability_map_autopromotes_bridge_when_enabled(self):
        with patch.dict(os.environ, {"SAMURAI_L7_QUIC_BRIDGE_AUTOPROMOTE": "1"}, clear=False), patch.object(
            c_adapter._adapter, "_l7_core", None
        ), patch.object(
            c_adapter.quic_h3_bridge, "stack_mode", return_value="h3_stateful_py"
        ):
            caps = c_adapter.capability_map()
        self.assertTrue(caps["quic"])
        self.assertEqual(caps.get("quic_stack_mode"), "h3_stateful_py")
        self.assertTrue(bool(caps.get("quic_h3_stateful", False)))
        self.assertEqual(caps.get("quic_effective_path"), "py_bridge")
        self.assertTrue(bool(caps.get("quic_bridge_autopromote", False)))

    def test_make_config_prefers_native_core_quic_when_available(self):
        with patch.dict(os.environ, {"SAMURAI_L7_QUIC_PREFER_NATIVE": "1"}, clear=False), patch.object(
            c_adapter,
            "capability_map",
            return_value={"quic_native_h3_stateful": True},
        ):
            cfg = c_adapter.make_config(
                target_ip="127.0.0.1",
                target_port=443,
                count=1,
                concurrency=1,
                mode="quic_stateful",
                extra={},
            )
        self.assertEqual(int(cfg.extra.get("enable_quic_py_bridge", -1)), 0)

    def test_make_config_does_not_auto_enable_bridge_when_native_unavailable(self):
        with patch.dict(os.environ, {"SAMURAI_L7_QUIC_PREFER_NATIVE": "1", "SAMURAI_L7_QUIC_AUTO_BRIDGE": "0"}, clear=False), patch.object(
            c_adapter,
            "capability_map",
            return_value={"quic_native_h3_stateful": False},
        ):
            cfg = c_adapter.make_config(
                target_ip="127.0.0.1",
                target_port=443,
                count=1,
                concurrency=1,
                mode="quic_stateful",
                extra={},
            )
        self.assertEqual(int(cfg.extra.get("enable_quic_py_bridge", 1) or 0), 0)

    def test_make_config_uses_bridge_when_auto_bridge_enabled(self):
        with patch.dict(os.environ, {"SAMURAI_L7_QUIC_PREFER_NATIVE": "1", "SAMURAI_L7_QUIC_AUTO_BRIDGE": "1"}, clear=False), patch.object(
            c_adapter,
            "capability_map",
            return_value={"quic_native_h3_stateful": False},
        ):
            cfg = c_adapter.make_config(
                target_ip="127.0.0.1",
                target_port=443,
                count=1,
                concurrency=1,
                mode="quic_stateful",
                extra={},
            )
        self.assertEqual(int(cfg.extra.get("enable_quic_py_bridge", 0) or 0), 1)

    def test_make_config_inherits_require_native_env_flag(self):
        with patch.dict(os.environ, {"SAMURAI_L7_QUIC_REQUIRE_NATIVE": "1"}, clear=False), patch.object(
            c_adapter,
            "capability_map",
            return_value={"quic_native_h3_stateful": False},
        ):
            cfg = c_adapter.make_config(
                target_ip="127.0.0.1",
                target_port=443,
                count=1,
                concurrency=1,
                mode="quic_stateful",
                extra={},
            )
        self.assertEqual(int(cfg.extra.get("require_native_quic", 0) or 0), 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
