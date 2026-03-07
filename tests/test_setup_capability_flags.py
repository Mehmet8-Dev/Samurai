import importlib.util
import os
import pathlib
import unittest
from unittest.mock import patch


def _load_setup_module():
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    setup_path = repo_root / "setup.py"
    spec = importlib.util.spec_from_file_location("samurai_setup_module", str(setup_path))
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class TestSetupCapabilityFlags(unittest.TestCase):
    def test_detect_l7_capabilities_all_present(self):
        setup_mod = _load_setup_module()
        with patch.object(setup_mod, "_pkg_config_exists", side_effect=lambda name: name in {"nghttp2", "ngtcp2", "nghttp3"}), \
             patch.object(setup_mod.ctypes.util, "find_library", side_effect=lambda name: "libok" if name in {"ssl", "crypto"} else None), \
             patch.object(setup_mod.os.path, "exists", return_value=True), \
             patch.dict(os.environ, {}, clear=False):
            caps = setup_mod.detect_l7_capabilities()
        self.assertTrue(caps["openssl"])
        self.assertTrue(caps["nghttp2"])
        self.assertTrue(caps["quic"])

    def test_detect_l7_capabilities_respects_disable_flags(self):
        setup_mod = _load_setup_module()
        with patch.object(setup_mod, "_pkg_config_exists", return_value=True), \
             patch.object(setup_mod.ctypes.util, "find_library", return_value="libok"), \
             patch.object(setup_mod.os.path, "exists", return_value=True), \
             patch.dict(
                 os.environ,
                 {
                     "SAMURAI_DISABLE_OPENSSL": "1",
                     "SAMURAI_DISABLE_NGHTTP2": "1",
                     "SAMURAI_DISABLE_QUIC": "1",
                 },
                 clear=False,
             ):
            caps = setup_mod.detect_l7_capabilities()
        self.assertFalse(caps["openssl"])
        self.assertFalse(caps["nghttp2"])
        self.assertFalse(caps["quic"])

    def test_detect_l7_capabilities_force_flags(self):
        setup_mod = _load_setup_module()
        with patch.object(setup_mod, "_pkg_config_exists", return_value=False), \
             patch.object(setup_mod.ctypes.util, "find_library", return_value=None), \
             patch.object(setup_mod.os.path, "exists", return_value=False), \
             patch.dict(
                 os.environ,
                 {
                     "SAMURAI_FORCE_NGHTTP2": "1",
                     "SAMURAI_FORCE_QUIC": "1",
                 },
                 clear=False,
             ):
            caps = setup_mod.detect_l7_capabilities()
        self.assertFalse(caps["openssl"])
        self.assertTrue(caps["nghttp2"])
        self.assertTrue(caps["quic"])

    def test_detect_l7_capabilities_accepts_lib_prefixed_pkg_names(self):
        setup_mod = _load_setup_module()
        with patch.object(
            setup_mod,
            "_pkg_config_exists",
            side_effect=lambda name: name in {"libnghttp2", "libngtcp2", "libnghttp3"},
        ), \
             patch.object(setup_mod.ctypes.util, "find_library", side_effect=lambda name: "libok" if name in {"ssl", "crypto"} else None), \
             patch.object(setup_mod.os.path, "exists", return_value=True), \
             patch.dict(os.environ, {}, clear=False):
            caps = setup_mod.detect_l7_capabilities()
        self.assertTrue(caps["openssl"])
        self.assertTrue(caps["nghttp2"])
        self.assertTrue(caps["quic"])

    def test_detect_l7_capabilities_fallbacks_without_pkg_config(self):
        setup_mod = _load_setup_module()
        with patch.object(setup_mod, "_pkg_config_exists", return_value=False), \
             patch.object(
                 setup_mod.ctypes.util,
                 "find_library",
                 side_effect=lambda name: "libok" if name in {"ssl", "crypto", "nghttp2", "ngtcp2", "nghttp3"} else None,
             ), \
             patch.object(setup_mod.os.path, "exists", return_value=True), \
             patch.dict(os.environ, {}, clear=False):
            caps = setup_mod.detect_l7_capabilities()
        self.assertTrue(caps["openssl"])
        self.assertTrue(caps["nghttp2"])
        self.assertTrue(caps["quic"])

    def test_resolve_quic_crypto_backend_prefers_forced_gnutls(self):
        setup_mod = _load_setup_module()
        with patch.object(
            setup_mod,
            "_pkg_config_exists",
            side_effect=lambda name: name == "ngtcp2_crypto_gnutls",
        ), \
             patch.object(setup_mod.ctypes.util, "find_library", return_value=None), \
             patch.dict(os.environ, {"SAMURAI_QUIC_CRYPTO_BACKEND": "gnutls"}, clear=False):
            backend, pkg_name, link_name = setup_mod._resolve_quic_crypto_backend()
        self.assertEqual(backend, "gnutls")
        self.assertEqual(pkg_name, "ngtcp2_crypto_gnutls")
        self.assertEqual(link_name, "")

    def test_resolve_quic_crypto_backend_none_disables_lookup(self):
        setup_mod = _load_setup_module()
        with patch.object(setup_mod, "_pkg_config_exists", return_value=True) as pkg_mock, \
             patch.object(setup_mod.ctypes.util, "find_library", return_value="libok") as lib_mock, \
             patch.dict(os.environ, {"SAMURAI_QUIC_CRYPTO_BACKEND": "none"}, clear=False):
            backend, pkg_name, link_name = setup_mod._resolve_quic_crypto_backend()
        self.assertEqual(backend, "none")
        self.assertEqual(pkg_name, "")
        self.assertEqual(link_name, "")
        pkg_mock.assert_not_called()
        lib_mock.assert_not_called()
