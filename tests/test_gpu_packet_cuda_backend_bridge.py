import ctypes
import gc
import importlib.util
import types

import numpy as np
import pytest

import ddos_samurai._gpu_packet_cuda_backend as backend


_NUMBA_AVAILABLE = importlib.util.find_spec("numba") is not None
pytestmark = [
    pytest.mark.skipif(
        not _NUMBA_AVAILABLE,
        reason="numba not installed in CI-safe environment; skipping CUDA backend bridge tests",
    )
]


def _to_bytes(arr) -> bytes:
    try:
        return backend._legacy.cp.asnumpy(arr).astype(np.uint8, copy=False).tobytes()
    except Exception:
        return np.asarray(arr, dtype=np.uint8).tobytes()


def _scalar(value):
    return int(getattr(value, "value", value))


class _FakeLib:
    def __init__(
        self,
        payload: bytes = b"",
        packet_size: int = 0,
        rc: int = 0,
        err: bytes = b"",
        wait_rc: int = 0,
    ):
        self.payload = bytes(payload)
        self.packet_size = int(packet_size)
        self.rc = int(rc)
        self.err = bytes(err)
        self.wait_rc = int(wait_rc)
        self._buffers = []
        self.free_called = 0
        self.wait_called = 0
        self.wait_ptrs = []
        self.calls = []

    def _set_out(self, out_data, out_size, out_packet_size):
        if self.payload:
            buf = ctypes.create_string_buffer(self.payload)
            self._buffers.append(buf)
            ptr_value = ctypes.addressof(buf)
        else:
            ptr_value = 0
        ctypes.cast(out_data, ctypes.POINTER(ctypes.c_void_p)).contents.value = ptr_value
        ctypes.cast(out_size, ctypes.POINTER(ctypes.c_size_t)).contents.value = len(self.payload)
        ctypes.cast(out_packet_size, ctypes.POINTER(ctypes.c_int)).contents.value = self.packet_size

    def samurai_gpu_packet_generate_packets(
        self,
        _count,
        _target_ip,
        _target_port,
        _protocol,
        _spoof_ip,
        _real_src_ip,
        _tcp_flags,
        _has_ethernet,
        _window,
        _stream_handle,
        _gateway_mac,
        _spoof_subnet,
        out_data,
        out_size,
        out_packet_size,
    ):
        if self.rc == 0:
            self._set_out(out_data, out_size, out_packet_size)
        return self.rc

    def samurai_gpu_packet_generate_packets_from_template(
        self,
        template_bytes,
        template_len,
        count,
        real_src_ip,
        spoof_ip,
        has_ethernet,
        stream_handle,
        gateway_mac,
        spoof_subnet,
        force_global_fallback,
        out_data,
        out_size,
        out_packet_size,
    ):
        self.calls.append(
            {
                "name": "generate_packets_from_template",
                "template_ptr": ctypes.cast(template_bytes, ctypes.c_void_p).value if template_bytes else 0,
                "template_len": _scalar(template_len),
                "count": _scalar(count),
                "real_src_ip": real_src_ip,
                "spoof_ip": _scalar(spoof_ip),
                "has_ethernet": _scalar(has_ethernet),
                "stream_handle": _scalar(stream_handle),
                "gateway_mac": _scalar(gateway_mac),
                "spoof_subnet": spoof_subnet,
                "force_global_fallback": _scalar(force_global_fallback),
            }
        )
        if self.rc == 0:
            self._set_out(out_data, out_size, out_packet_size)
        return self.rc

    def samurai_gpu_packet_generate_packets_from_template_pool(
        self,
        templates_flat,
        templates_flat_len,
        packet_size,
        num_templates,
        count,
        target_ip,
        real_src_ip,
        spoof_ip,
        specific_src_port,
        has_ethernet,
        stream_handle,
        gateway_mac,
        spoof_subnet,
        force_global_fallback,
        out_data,
        out_size,
        out_packet_size,
    ):
        self.calls.append(
            {
                "name": "generate_packets_from_template_pool",
                "templates_ptr": ctypes.cast(templates_flat, ctypes.c_void_p).value if templates_flat else 0,
                "templates_flat_len": _scalar(templates_flat_len),
                "packet_size": _scalar(packet_size),
                "num_templates": _scalar(num_templates),
                "count": _scalar(count),
                "target_ip": target_ip,
                "real_src_ip": real_src_ip,
                "spoof_ip": _scalar(spoof_ip),
                "specific_src_port": _scalar(specific_src_port),
                "has_ethernet": _scalar(has_ethernet),
                "stream_handle": _scalar(stream_handle),
                "gateway_mac": _scalar(gateway_mac),
                "spoof_subnet": spoof_subnet,
                "force_global_fallback": _scalar(force_global_fallback),
            }
        )
        if self.rc == 0:
            self._set_out(out_data, out_size, out_packet_size)
        return self.rc

    def samurai_gpu_packet_generate_stateful_packets(
        self,
        templates_flat,
        templates_flat_len,
        packet_size,
        num_templates,
        count,
        target_ip,
        spoof_ip,
        real_src_ip,
        specific_src_port,
        has_ethernet,
        stream_handle,
        gateway_mac,
        spoof_subnet,
        seq_list,
        seq_len,
        ack_list,
        ack_len,
        state_list,
        state_len,
        actual_lengths,
        actual_lengths_len,
        window_sizes,
        window_sizes_len,
        mss_values,
        mss_values_len,
        ttls,
        ttls_len,
        force_global_fallback,
        out_data,
        out_size,
        out_packet_size,
    ):
        self.calls.append(
            {
                "name": "generate_stateful_packets",
                "templates_ptr": ctypes.cast(templates_flat, ctypes.c_void_p).value if templates_flat else 0,
                "templates_flat_len": _scalar(templates_flat_len),
                "packet_size": _scalar(packet_size),
                "num_templates": _scalar(num_templates),
                "count": _scalar(count),
                "target_ip": target_ip,
                "spoof_ip": _scalar(spoof_ip),
                "real_src_ip": real_src_ip,
                "specific_src_port": _scalar(specific_src_port),
                "has_ethernet": _scalar(has_ethernet),
                "stream_handle": _scalar(stream_handle),
                "gateway_mac": _scalar(gateway_mac),
                "spoof_subnet": spoof_subnet,
                "seq_ptr": ctypes.cast(seq_list, ctypes.c_void_p).value if seq_list else 0,
                "seq_len": _scalar(seq_len),
                "ack_ptr": ctypes.cast(ack_list, ctypes.c_void_p).value if ack_list else 0,
                "ack_len": _scalar(ack_len),
                "state_ptr": ctypes.cast(state_list, ctypes.c_void_p).value if state_list else 0,
                "state_len": _scalar(state_len),
                "actual_lengths_ptr": ctypes.cast(actual_lengths, ctypes.c_void_p).value if actual_lengths else 0,
                "actual_lengths_len": _scalar(actual_lengths_len),
                "window_sizes_ptr": ctypes.cast(window_sizes, ctypes.c_void_p).value if window_sizes else 0,
                "window_sizes_len": _scalar(window_sizes_len),
                "mss_values_ptr": ctypes.cast(mss_values, ctypes.c_void_p).value if mss_values else 0,
                "mss_values_len": _scalar(mss_values_len),
                "ttls_ptr": ctypes.cast(ttls, ctypes.c_void_p).value if ttls else 0,
                "ttls_len": _scalar(ttls_len),
                "force_global_fallback": _scalar(force_global_fallback),
            }
        )
        if self.rc == 0:
            self._set_out(out_data, out_size, out_packet_size)
        return self.rc

    def samurai_gpu_packet_generate_fragmented_packets(
        self,
        _payload_bytes,
        _payload_len,
        _count,
        _target_ip,
        _target_port,
        _protocol,
        _spoof_ip,
        _real_src_ip,
        _has_ethernet,
        _frag1_size,
        _frag2_size,
        _stream_handle,
        _gateway_mac,
        _spoof_subnet,
        out_data,
        out_size,
        out_packet_size,
    ):
        if self.rc == 0:
            self._set_out(out_data, out_size, out_packet_size)
        return self.rc

    def samurai_gpu_packet_generate_amplification_packets(
        self,
        _template_bytes,
        _template_len,
        _reflectors_ips,
        _reflectors_count,
        _victim_ip,
        _count,
        _has_ethernet,
        _stream_handle,
        _gateway_mac,
        out_data,
        out_size,
        out_packet_size,
    ):
        if self.rc == 0:
            self._set_out(out_data, out_size, out_packet_size)
        return self.rc

    def samurai_gpu_packet_generate_icmp_packets(
        self,
        _count,
        _target_ip,
        _real_src_ip,
        _spoof_ip,
        _has_ethernet,
        _icmp_type,
        _icmp_code,
        _payload_size,
        _stream_handle,
        _gateway_mac,
        _spoof_subnet,
        out_data,
        out_size,
        out_packet_size,
    ):
        if self.rc == 0:
            self._set_out(out_data, out_size, out_packet_size)
        return self.rc

    def samurai_gpu_packet_free(self, _ptr):
        self.free_called += 1

    def samurai_gpu_packet_wait(self, ptr):
        self.wait_called += 1
        self.wait_ptrs.append(int(getattr(ptr, "value", ptr) or 0))
        return self.wait_rc

    def samurai_gpu_packet_last_error(self):
        return self.err


def test_generate_packets_delegates_to_legacy_when_native_disabled(monkeypatch):
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", False, raising=True)

    seen = {}

    def _fake_call(name, *args, **kwargs):
        seen["name"] = name
        seen["args"] = args
        seen["kwargs"] = kwargs
        return b"legacy", 12

    monkeypatch.setattr(backend, "_call_legacy", _fake_call, raising=True)
    packets, packet_size = backend.generate_packets(
        count=2,
        target_ip="203.0.113.1",
        target_port=53,
        protocol="udp",
    )
    assert seen["name"] == "generate_packets"
    assert packets == b"legacy"
    assert packet_size == 12


def test_generate_packets_native_success(monkeypatch):
    fake = _FakeLib(payload=b"\x01\x02\x03\x04", packet_size=2, rc=0)
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)

    class _FakeDeviceArray:
        def __init__(self, arr):
            self._arr = np.asarray(arr, dtype=np.uint8)

        def __array__(self, dtype=None):
            return np.asarray(self._arr, dtype=(dtype if dtype is not None else self._arr.dtype))

    monkeypatch.setattr(
        backend,
        "_legacy",
        types.SimpleNamespace(
            GPUPacketError=backend._legacy.GPUPacketError,
            GPUMemoryError=backend._legacy.GPUMemoryError,
            cp=types.SimpleNamespace(
                uint8=np.uint8,
                asarray=lambda arr, dtype=None: _FakeDeviceArray(
                    np.asarray(arr, dtype=(dtype if dtype is not None else np.uint8))
                ),
            ),
        ),
        raising=True,
    )

    packets, packet_size = backend.generate_packets(
        count=2,
        target_ip="203.0.113.1",
        target_port=80,
        protocol="tcp",
        spoof_ip=False,
        has_ethernet=True,
    )
    assert packet_size == 2
    assert _to_bytes(packets) == b"\x01\x02\x03\x04"
    assert fake.wait_called == 1
    assert fake.free_called == 1


def test_copy_gpu_to_host_pinned_passthroughs_host_array_without_legacy_copy(monkeypatch):
    monkeypatch.setattr(
        backend,
        "_call_legacy",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("legacy copy path should not run")),
        raising=True,
    )
    arr = np.arange(8, dtype=np.uint8)
    out = backend.copy_gpu_to_host_pinned(arr, key="unused")
    assert out is arr
    assert out.dtype == np.uint8


def test_generate_packets_native_host_ready_skips_cp_asarray(monkeypatch):
    fake = _FakeLib(payload=b"\x01\x02\x03\x04", packet_size=2, rc=0)
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)
    monkeypatch.setattr(
        backend,
        "_legacy",
        types.SimpleNamespace(
            GPUPacketError=backend._legacy.GPUPacketError,
            GPUMemoryError=backend._legacy.GPUMemoryError,
            cp=types.SimpleNamespace(
                uint8=np.uint8,
                asarray=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("cp.asarray must not run")),
            ),
        ),
        raising=True,
    )

    packets, packet_size = backend.generate_packets(
        count=2,
        target_ip="203.0.113.1",
        target_port=80,
        protocol="tcp",
        spoof_ip=False,
        has_ethernet=True,
        return_host_ready=True,
    )
    assert packet_size == 2
    assert isinstance(packets, np.ndarray)
    assert packets.dtype == np.uint8
    assert _to_bytes(packets) == b"\x01\x02\x03\x04"
    assert fake.wait_called == 0
    assert fake.free_called == 0
    del packets
    gc.collect()
    assert fake.free_called == 1


def test_generate_packets_native_wait_error_releases_host_buffer(monkeypatch):
    fake = _FakeLib(payload=b"\x01\x02\x03\x04", packet_size=2, rc=0, wait_rc=-1, err=b"wait failed")
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)
    monkeypatch.setattr(
        backend,
        "_legacy",
        types.SimpleNamespace(
            GPUPacketError=backend._legacy.GPUPacketError,
            GPUMemoryError=backend._legacy.GPUMemoryError,
            cp=types.SimpleNamespace(uint8=np.uint8, asarray=np.asarray),
        ),
        raising=True,
    )

    with pytest.raises(backend._legacy.GPUPacketError, match="wait failed"):
        backend.generate_packets(
            count=2,
            target_ip="203.0.113.1",
            target_port=80,
            protocol="tcp",
            spoof_ip=False,
            has_ethernet=True,
        )
    assert fake.wait_called == 1
    assert fake.free_called == 1


def test_generate_template_native_error(monkeypatch):
    fake = _FakeLib(payload=b"", packet_size=0, rc=-1, err=b"native fail")
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)

    with pytest.raises(backend._legacy.GPUPacketError, match="native fail"):
        backend.generate_packets_from_template(
            template_bytes=b"\x45" + b"\x00" * 63,
            count=1,
        )


def test_generate_template_native_reuses_contiguous_numpy_input(monkeypatch):
    fake = _FakeLib(payload=b"\x50\x51", packet_size=2, rc=0)
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)

    template_arr = np.arange(64, dtype=np.uint8)
    packets, packet_size = backend.generate_packets_from_template(
        template_bytes=template_arr,
        count=1,
        spoof_ip=False,
    )

    assert packet_size == 2
    assert _to_bytes(packets) == b"\x50\x51"
    assert fake.calls[-1]["template_ptr"] == int(template_arr.ctypes.data)
    assert fake.calls[-1]["template_len"] == int(template_arr.size)


def test_generate_template_pool_native_success(monkeypatch):
    fake = _FakeLib(payload=b"\x0A\x0B\x0C\x0D", packet_size=2, rc=0)
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)

    packets, packet_size = backend.generate_packets_from_template_pool(
        templates_bytes_list=[b"\x45" + b"\x00" * 63, b"\x45" + b"\x11" * 63],
        count=2,
        target_ip="203.0.113.10",
        spoof_ip=False,
        has_ethernet=False,
    )
    assert packet_size == 2
    assert _to_bytes(packets) == b"\x0A\x0B\x0C\x0D"
    assert fake.free_called == 1


def test_generate_stateful_native_success(monkeypatch):
    fake = _FakeLib(payload=b"\x20\x21\x22\x23", packet_size=2, rc=0)
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)

    packets, packet_size = backend.generate_stateful_packets(
        templates_bytes_list=[b"\x45" + b"\xAA" * 63, b"\x45" + b"\xBB" * 63],
        count=2,
        target_ip="203.0.113.11",
        spoof_ip=False,
        has_ethernet=True,
        seq_list=[1, 2],
        ack_list=[3, 4],
        state_list=[0, 1],
        actual_lengths=[64, 64],
        window_sizes=[1024, 1024],
        mss_values=[1460, 1460],
        ttls=[64, 64],
    )
    assert packet_size == 2
    assert _to_bytes(packets) == b"\x20\x21\x22\x23"
    assert fake.free_called == 1


def test_generate_stateful_native_reuses_contiguous_numpy_state_inputs(monkeypatch):
    fake = _FakeLib(payload=b"\x24\x25", packet_size=2, rc=0)
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)

    seq = np.asarray([1, 2], dtype=np.uint32)
    ack = np.asarray([3, 4], dtype=np.uint32)
    state = np.asarray([0, 1], dtype=np.uint8)
    lengths = np.asarray([64, 64], dtype=np.uint32)
    wins = np.asarray([1024, 1024], dtype=np.uint16)
    msss = np.asarray([1460, 1460], dtype=np.uint16)
    ttls = np.asarray([64, 64], dtype=np.uint8)

    packets, packet_size = backend.generate_stateful_packets(
        templates_bytes_list=[b"\x45" + b"\xAA" * 63, b"\x45" + b"\xBB" * 63],
        count=2,
        target_ip="203.0.113.11",
        spoof_ip=False,
        has_ethernet=True,
        seq_list=seq,
        ack_list=ack,
        state_list=state,
        actual_lengths=lengths,
        window_sizes=wins,
        mss_values=msss,
        ttls=ttls,
    )

    assert packet_size == 2
    assert _to_bytes(packets) == b"\x24\x25"
    call = fake.calls[-1]
    assert call["seq_ptr"] == int(seq.ctypes.data)
    assert call["ack_ptr"] == int(ack.ctypes.data)
    assert call["state_ptr"] == int(state.ctypes.data)
    assert call["actual_lengths_ptr"] == int(lengths.ctypes.data)
    assert call["window_sizes_ptr"] == int(wins.ctypes.data)
    assert call["mss_values_ptr"] == int(msss.ctypes.data)
    assert call["ttls_ptr"] == int(ttls.ctypes.data)
    assert call["seq_len"] == int(seq.size)
    assert call["actual_lengths_len"] == int(lengths.size)


def test_generate_fragmented_native_success(monkeypatch):
    fake = _FakeLib(payload=b"\x30\x31", packet_size=2, rc=0)
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)

    packets, packet_size = backend.generate_fragmented_packets(
        payload_bytes=b"A" * 32,
        count=1,
        target_ip="203.0.113.12",
        target_port=53,
        protocol="udp",
        spoof_ip=False,
        has_ethernet=True,
        frag1_size=1514,
        frag2_size=1500,
    )
    assert packet_size == 2
    assert _to_bytes(packets) == b"\x30\x31"
    assert fake.free_called == 1


def test_generate_amplification_native_success(monkeypatch):
    fake = _FakeLib(payload=b"\x40\x41", packet_size=2, rc=0)
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)

    packets, packet_size = backend.generate_amplification_packets(
        template_bytes=b"\x45" + b"\x00" * 63,
        reflectors_ips=["198.51.100.1", "198.51.100.2"],
        victim_ip="203.0.113.100",
        count=1,
        has_ethernet=True,
    )
    assert packet_size == 2
    assert _to_bytes(packets) == b"\x40\x41"
    assert fake.free_called == 1


def test_generate_icmp_native_success(monkeypatch):
    fake = _FakeLib(payload=b"\x50\x51", packet_size=2, rc=0)
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)

    packets, packet_size = backend.generate_icmp_packets(
        count=1,
        target_ip="203.0.113.15",
        real_src_ip="192.168.1.10",
        spoof_ip=False,
        has_ethernet=True,
    )
    assert packet_size == 2
    assert _to_bytes(packets) == b"\x50\x51"
    assert fake.free_called == 1


def test_native_policy_require_accepts_stream_when_native_available(monkeypatch):
    fake = _FakeLib(payload=b"\x00\x01", packet_size=2, rc=0)
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_POLICY", "require", raising=True)

    class _S:
        ptr = 1234

    packets, packet_size = backend.generate_packets(
        count=1,
        target_ip="203.0.113.1",
        target_port=80,
        protocol="tcp",
        spoof_ip=False,
        stream=_S(),
    )
    assert packet_size == 2
    assert _to_bytes(packets) == b"\x00\x01"
    assert fake.free_called == 1


def test_native_policy_require_blocks_unresolvable_stream(monkeypatch):
    fake = _FakeLib(payload=b"\x00\x01", packet_size=2, rc=0)
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_POLICY", "require", raising=True)
    with pytest.raises(backend._legacy.GPUPacketError, match="policy=require"):
        backend.generate_packets(
            count=1,
            target_ip="203.0.113.1",
            target_port=80,
            protocol="tcp",
            spoof_ip=False,
            stream=object(),
        )


def test_native_policy_require_blocks_when_native_unavailable(monkeypatch):
    monkeypatch.setattr(backend, "_LIB", None, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_POLICY", "require", raising=True)
    with pytest.raises(backend._legacy.GPUPacketError, match="policy=require"):
        backend.generate_packets(
            count=1,
            target_ip="203.0.113.1",
            target_port=80,
            protocol="udp",
            spoof_ip=False,
        )
