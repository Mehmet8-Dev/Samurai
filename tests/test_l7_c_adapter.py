import unittest
from unittest.mock import patch

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
        return False


class _CoreProbeRaises(_CoreWithProbes):
    def h2_supported(self):
        raise RuntimeError("boom")


class TestL7CAdapter(unittest.TestCase):
    def test_capability_map_respects_support_probes(self):
        core = _CoreWithProbes()
        with patch.object(c_adapter._adapter, "_l7_core", core):
            caps = c_adapter.capability_map()
        self.assertTrue(caps["core_available"])
        self.assertTrue(caps["http1"])
        self.assertTrue(caps["ws"])
        self.assertFalse(caps["http2"])
        self.assertFalse(caps["quic"])

    def test_capability_map_handles_probe_exception(self):
        core = _CoreProbeRaises()
        with patch.object(c_adapter._adapter, "_l7_core", core):
            caps = c_adapter.capability_map()
        self.assertFalse(caps["http2"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
