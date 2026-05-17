from __future__ import annotations

import types
import unittest
from unittest import mock

from ddos_samurai._senders import runtime


class TestSenderRuntimeQuicCapability(unittest.TestCase):
    def test_requires_runtime_capabilities_hook(self):
        fake_mod = types.SimpleNamespace(run_profile=lambda *_args, **_kwargs: {})
        with mock.patch("importlib.import_module", return_value=fake_mod):
            self.assertFalse(runtime.has_l7_native_quic())

    def test_false_when_quic_native_flag_is_false(self):
        fake_mod = types.SimpleNamespace(
            run_profile=lambda *_args, **_kwargs: {},
            runtime_capabilities=lambda: {"quic_native": False},
        )
        with mock.patch("importlib.import_module", return_value=fake_mod):
            self.assertFalse(runtime.has_l7_native_quic())

    def test_true_when_quic_native_flag_is_true(self):
        fake_mod = types.SimpleNamespace(
            run_profile=lambda *_args, **_kwargs: {},
            runtime_capabilities=lambda: {"quic_native": True},
        )
        with mock.patch("importlib.import_module", return_value=fake_mod):
            self.assertTrue(runtime.has_l7_native_quic())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
