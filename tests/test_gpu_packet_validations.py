import os
import sys
import unittest
from unittest.mock import patch

import numpy as np

try:
    import pytest
    pytestmark = [pytest.mark.gpu]
except Exception:  # pragma: no cover - unittest-only environments
    pytestmark = []

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

MODULES_IMPORTABLE = False
try:
    from ddos_samurai import gpu_packet
    MODULES_IMPORTABLE = True
except Exception:
    MODULES_IMPORTABLE = False


class _FakeKernel:
    def __getitem__(self, _cfg):
        def _launch(*_args, **_kwargs):
            return None
        return _launch


class _FakeDispatcher:
    def __init__(self, compiled=False):
        self.overloads = {"sig": object()} if compiled else {}
        self.specializations = {}


class TestGpuPacketValidations(unittest.TestCase):
    def setUp(self):
        if not MODULES_IMPORTABLE:
            self.skipTest("gpu_packet module import failed")

    def test_parse_subnet_normalizes_network_base(self):
        base_ip, mask = gpu_packet.parse_subnet("192.168.1.123/24")
        self.assertEqual(mask, 24)
        self.assertEqual(base_ip, gpu_packet.ip_to_int("192.168.1.0"))

    def test_parse_subnet_rejects_invalid_mask(self):
        with self.assertRaises(ValueError):
            gpu_packet.parse_subnet("10.0.0.0/33")

    def test_generate_amplification_rejects_empty_reflectors(self):
        with self.assertRaises(ValueError):
            gpu_packet.generate_amplification_packets(
                template_bytes=b"\x45" * 64,
                reflectors_ips=[],
                victim_ip="192.0.2.1",
                count=1,
                has_ethernet=True,
            )

    def test_generate_fragmented_packets_requires_aligned_first_fragment(self):
        with self.assertRaises(ValueError):
            gpu_packet.generate_fragmented_packets(
                payload_bytes=b"A" * 128,
                count=1,
                target_ip="198.51.100.10",
                target_port=53,
                protocol="udp",
                spoof_ip=False,
                has_ethernet=True,
                frag1_size=1501,  # Makes first fragment IP payload non-8-byte aligned
                frag2_size=1500,
            )

    def test_generate_packets_udp_stride_matches_actual_packet_len(self):
        fake_kernel = _FakeKernel()
        with patch.object(gpu_packet, "create_udp_packets_kernel_nospoof", fake_kernel), \
             patch.object(gpu_packet, "create_xoroshiro128p_states", lambda _c, seed=None: None), \
             patch.object(gpu_packet.cp, "zeros", side_effect=lambda shape, dtype: np.zeros(shape, dtype=np.uint8)):
            packets, packet_size = gpu_packet.generate_packets(
                count=2,
                target_ip="203.0.113.1",
                target_port=53,
                protocol="udp",
                spoof_ip=False,
                has_ethernet=True,
            )
        self.assertEqual(packet_size, 42)
        self.assertEqual(len(packets), 84)

    def test_update_gpu_constant_keeps_constant_path_for_same_payload_after_compile(self):
        payload = np.arange(16, dtype=np.uint8)
        orig_backing = gpu_packet.TEMPLATE_CONST_HOST.copy()
        orig_fp = gpu_packet._CONST_FINGERPRINTS.get("TEMPLATE_CONST_HOST")
        try:
            gpu_packet._CONST_FINGERPRINTS["TEMPLATE_CONST_HOST"] = None
            with patch.object(gpu_packet, "template_kernel", _FakeDispatcher(compiled=False)):
                self.assertTrue(gpu_packet._update_gpu_constant("TEMPLATE_CONST_HOST", payload))
            with patch.object(gpu_packet, "template_kernel", _FakeDispatcher(compiled=True)):
                self.assertTrue(gpu_packet._update_gpu_constant("TEMPLATE_CONST_HOST", payload))
        finally:
            gpu_packet.TEMPLATE_CONST_HOST[:] = orig_backing
            gpu_packet._CONST_FINGERPRINTS["TEMPLATE_CONST_HOST"] = orig_fp

    def test_update_gpu_constant_falls_back_when_payload_changes_after_compile(self):
        payload_a = np.arange(16, dtype=np.uint8)
        payload_b = np.arange(16, dtype=np.uint8) + 1
        orig_backing = gpu_packet.TEMPLATE_CONST_HOST.copy()
        orig_fp = gpu_packet._CONST_FINGERPRINTS.get("TEMPLATE_CONST_HOST")
        try:
            gpu_packet._CONST_FINGERPRINTS["TEMPLATE_CONST_HOST"] = None
            with patch.object(gpu_packet, "template_kernel", _FakeDispatcher(compiled=False)):
                self.assertTrue(gpu_packet._update_gpu_constant("TEMPLATE_CONST_HOST", payload_a))
            with patch.object(gpu_packet, "template_kernel", _FakeDispatcher(compiled=True)):
                self.assertFalse(gpu_packet._update_gpu_constant("TEMPLATE_CONST_HOST", payload_b))
            np.testing.assert_array_equal(gpu_packet.TEMPLATE_CONST_HOST[:16], payload_a)
        finally:
            gpu_packet.TEMPLATE_CONST_HOST[:] = orig_backing
            gpu_packet._CONST_FINGERPRINTS["TEMPLATE_CONST_HOST"] = orig_fp

    def test_template_generation_cache_reduces_h2d_copy_count(self):
        fake_kernel = _FakeKernel()
        template = bytes([0x45]) + bytes([0x00] * 63)
        with patch.dict(os.environ, {"SAMURAI_GPU_CACHE_MAX_ENTRIES": "8"}, clear=False), \
             patch.object(gpu_packet, "template_kernel", fake_kernel), \
             patch.object(gpu_packet.cp, "zeros", side_effect=lambda shape, dtype: np.zeros(shape, dtype=np.uint8)), \
             patch.object(gpu_packet.cp, "array", side_effect=lambda arr, dtype=None: np.array(arr, dtype=np.uint8)), \
             patch.object(gpu_packet, "create_xoroshiro128p_states", side_effect=lambda _c, seed=None: {"count": _c}):
            gpu_packet.clear_generation_caches()
            gpu_packet.reset_generation_telemetry()

            gpu_packet.generate_packets_from_template(
                template_bytes=template,
                count=8,
                real_src_ip="192.168.1.10",
                spoof_ip=False,
                has_ethernet=False,
            )
            first = gpu_packet.get_generation_telemetry()

            gpu_packet.generate_packets_from_template(
                template_bytes=template,
                count=8,
                real_src_ip="192.168.1.10",
                spoof_ip=False,
                has_ethernet=False,
            )
            second = gpu_packet.get_generation_telemetry()

        self.assertEqual(int(first.get("gpu_template_h2d_copy_count", 0)), 1)
        self.assertEqual(int(second.get("gpu_template_h2d_copy_count", 0)), 1)
        self.assertGreaterEqual(int(second.get("gpu_template_cache_hit_count", 0)), 1)

    def test_rng_state_pool_reuse_in_template_generation(self):
        fake_kernel = _FakeKernel()
        alloc_counter = {"n": 0}

        def _fake_states(c, seed=None):
            alloc_counter["n"] += 1
            return {"count": int(c), "alloc_id": alloc_counter["n"]}

        template = bytes([0x45]) + bytes([0x00] * 63)
        with patch.dict(os.environ, {"SAMURAI_GPU_RNG_POOL_MAX_ENTRIES": "8"}, clear=False), \
             patch.object(gpu_packet, "template_kernel", fake_kernel), \
             patch.object(gpu_packet.cp, "zeros", side_effect=lambda shape, dtype: np.zeros(shape, dtype=np.uint8)), \
             patch.object(gpu_packet.cp, "array", side_effect=lambda arr, dtype=None: np.array(arr, dtype=np.uint8)), \
             patch.object(gpu_packet, "create_xoroshiro128p_states", side_effect=_fake_states):
            gpu_packet.clear_generation_caches()
            gpu_packet.reset_generation_telemetry()

            gpu_packet.generate_packets_from_template(
                template_bytes=template,
                count=16,
                real_src_ip="192.168.1.10",
                spoof_ip=False,
                has_ethernet=False,
            )
            gpu_packet.generate_packets_from_template(
                template_bytes=template,
                count=16,
                real_src_ip="192.168.1.10",
                spoof_ip=False,
                has_ethernet=False,
            )
            tel = gpu_packet.get_generation_telemetry()

        self.assertEqual(int(tel.get("gpu_rng_state_alloc_count", 0)), 1)
        self.assertGreaterEqual(int(tel.get("gpu_rng_state_reuse_count", 0)), 1)

    def test_pinned_pool_cap_triggers_eviction(self):
        pool = gpu_packet.get_pinned_host_pool()
        original_max = int(pool.get_stats().get("max_bytes", 0) or 0)
        try:
            gpu_packet.configure_pinned_host_pool(max_bytes=128)
            _ = pool.acquire(64, dtype=np.uint8, key="slot_a")
            _ = pool.acquire(80, dtype=np.uint8, key="slot_b")
            stats = pool.get_stats()
            self.assertLessEqual(int(stats.get("total_nbytes", 0)), int(stats.get("max_bytes", 0)))
            self.assertGreaterEqual(int(stats.get("pool_evictions", 0)), 1)
        finally:
            if original_max > 0:
                gpu_packet.configure_pinned_host_pool(max_bytes=original_max)
            pool.clear()

    def test_pinned_pool_oversize_request_bypasses_cache(self):
        pool = gpu_packet.get_pinned_host_pool()
        original_max = int(pool.get_stats().get("max_bytes", 0) or 0)
        try:
            gpu_packet.configure_pinned_host_pool(max_bytes=64)
            _ = pool.acquire(1024, dtype=np.uint8, key="oversize")
            stats = pool.get_stats()
            self.assertGreaterEqual(int(stats.get("oversize_bypass", 0)), 1)
            self.assertLessEqual(int(stats.get("total_nbytes", 0)), int(stats.get("max_bytes", 0)))
        finally:
            if original_max > 0:
                gpu_packet.configure_pinned_host_pool(max_bytes=original_max)
            pool.clear()


if __name__ == "__main__":
    unittest.main()
