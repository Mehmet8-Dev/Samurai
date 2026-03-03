import importlib.util
import pathlib
import random
import sys
import types
import unittest
from unittest.mock import patch

import numpy as np


def _build_fake_cupy_module():
    cp = types.ModuleType("cupy")
    cp.ndarray = np.ndarray
    cp.uint8 = np.uint8
    cp.uint16 = np.uint16
    cp.uint32 = np.uint32
    cp.uint64 = np.uint64
    cp.asarray = lambda arr, dtype=None: np.asarray(arr, dtype=dtype)
    cp.array = lambda arr, dtype=None: np.array(arr, dtype=dtype)
    cp.zeros = lambda shape, dtype=None: np.zeros(shape, dtype=dtype)
    cp.empty = lambda shape, dtype=None: np.empty(shape, dtype=dtype)
    cp.asnumpy = lambda arr: np.asarray(arr)
    cp.cuda = types.SimpleNamespace(
        Stream=lambda non_blocking=True: types.SimpleNamespace(non_blocking=bool(non_blocking)),
        Event=lambda: types.SimpleNamespace(record=lambda _s=None: None, query=lambda: True, synchronize=lambda: None),
    )
    return cp


def _build_fake_numba_modules(seed_log):
    class _FakeCudaFunction:
        def __init__(self, fn):
            self.fn = fn
            self.launch_count = 0

        def __getitem__(self, _launch_cfg):
            def _launcher(*_args, **_kwargs):
                self.launch_count += 1
                return None

            return _launcher

        def __call__(self, *args, **kwargs):
            return self.fn(*args, **kwargs)

    def _jit(*jit_args, **_jit_kwargs):
        if jit_args and callable(jit_args[0]) and len(jit_args) == 1:
            return _FakeCudaFunction(jit_args[0])

        def _decorate(fn):
            return _FakeCudaFunction(fn)

        return _decorate

    cuda_mod = types.ModuleType("numba.cuda")
    cuda_mod.jit = _jit
    cuda_mod.grid = lambda _dim: 0

    random_mod = types.ModuleType("numba.cuda.random")

    def _create_states(count, seed=0):
        seed_log.append(int(seed))
        return {"count": int(count), "seed": int(seed)}

    random_mod.create_xoroshiro128p_states = _create_states
    random_mod.xoroshiro128p_uniform_float32 = lambda _states, _thread_id: 0.5

    numba_mod = types.ModuleType("numba")
    numba_mod.cuda = cuda_mod
    numba_mod.uint8 = np.uint8
    numba_mod.uint16 = np.uint16
    numba_mod.uint32 = np.uint32
    numba_mod.uint64 = np.uint64

    return {
        "numba": numba_mod,
        "numba.cuda": cuda_mod,
        "numba.cuda.random": random_mod,
    }


def _load_gpu_payload_module():
    seed_log = []
    fake_cp = _build_fake_cupy_module()
    fake_numba_modules = _build_fake_numba_modules(seed_log)
    path = pathlib.Path(__file__).resolve().parents[1] / "ddos_samurai" / "gpu_payload.py"
    module_name = f"_gpu_payload_test_{random.randint(1, 10**9)}"
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    module = importlib.util.module_from_spec(spec)
    fake_modules = {"cupy": fake_cp, **fake_numba_modules}
    with patch.dict(sys.modules, fake_modules, clear=False):
        spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module, seed_log


class TestGpuPayloadValidations(unittest.TestCase):
    def setUp(self):
        self.gpu_payload, self.seed_log = _load_gpu_payload_module()

    def test_empty_component_lists_fail_fast(self):
        engine = self.gpu_payload.GPUPayloadEngine(count=4)
        with self.assertRaises(ValueError):
            engine.load_custom_wordlists(methods=[])
        with self.assertRaises(ValueError):
            engine.load_custom_wordlists(paths=[])
        with self.assertRaises(ValueError):
            engine.load_custom_wordlists(uas=[])

    def test_component_limits_are_enforced(self):
        engine = self.gpu_payload.GPUPayloadEngine(count=4)
        too_long = "A" * (self.gpu_payload.MAX_STR_LEN + 1)
        with self.assertRaises(ValueError):
            engine.load_custom_wordlists(methods=[too_long])
        too_many = ["/a"] * (self.gpu_payload.MAX_COMPONENTS + 1)
        with self.assertRaises(ValueError):
            engine.load_custom_wordlists(paths=too_many)

    def test_packet_budget_preflight_fails_before_kernel(self):
        engine = self.gpu_payload.GPUPayloadEngine(count=4, max_packet_size=128)
        engine.load_custom_wordlists(
            methods=["GET"],
            paths=["/" + ("x" * 64)],
            uas=["UA-" + ("y" * 128)],
        )
        with self.assertRaises(ValueError):
            engine.generate_fused_http(
                target_ip="127.0.0.1",
                target_port=443,
                real_src_ip="192.168.1.10",
            )

    def test_invalid_spoof_subnet_rejected(self):
        engine = self.gpu_payload.GPUPayloadEngine(count=2)
        with self.assertRaises(ValueError):
            engine.generate_fused_http(
                target_ip="127.0.0.1",
                target_port=443,
                real_src_ip="192.168.1.10",
                spoof_subnet="10.0.0.0/33",
            )
        with self.assertRaises(ValueError):
            engine.generate_fused_http(
                target_ip="127.0.0.1",
                target_port=443,
                real_src_ip="192.168.1.10",
                spoof_subnet="2001:db8::/64",
            )

    def test_generate_gpu_array_contract_returns_four_tuple(self):
        cookie_arr = self.gpu_payload.CookieGenerator(count=3).generate_gpu_array()
        referer_arr = self.gpu_payload.RefererGenerator(target_host="example.com", count=3).generate_gpu_array()
        self.assertEqual(len(cookie_arr), 4)
        self.assertEqual(len(referer_arr), 4)

    def test_rng_seed_default_and_override(self):
        with patch.object(self.gpu_payload.random, "randint", return_value=424242):
            e_default = self.gpu_payload.GPUPayloadEngine(count=1)
            e_override = self.gpu_payload.GPUPayloadEngine(count=1, rng_seed=999)
            e_random = self.gpu_payload.GPUPayloadEngine(count=1, rng_seed=None)
        self.assertEqual(e_default.rng_seed, 1234)
        self.assertEqual(e_override.rng_seed, 999)
        self.assertEqual(e_random.rng_seed, 424242)
        self.assertIn(1234, self.seed_log)
        self.assertIn(999, self.seed_log)
        self.assertIn(424242, self.seed_log)

