import ctypes

import numpy as np
import pytest

import ddos_samurai._gpu_packet_cuda_backend as backend


def _to_bytes(arr) -> bytes:
    try:
        return backend._legacy.cp.asnumpy(arr).astype(np.uint8, copy=False).tobytes()
    except Exception:
        return np.asarray(arr, dtype=np.uint8).tobytes()


class _FakeLib:
    def __init__(self, payload: bytes = b"", packet_size: int = 0, rc: int = 0, err: bytes = b""):
        self.payload = bytes(payload)
        self.packet_size = int(packet_size)
        self.rc = int(rc)
        self.err = bytes(err)
        self._buffers = []
        self.free_called = 0

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
        _template_bytes,
        _template_len,
        _count,
        _real_src_ip,
        _spoof_ip,
        _has_ethernet,
        _gateway_mac,
        _spoof_subnet,
        _force_global_fallback,
        out_data,
        out_size,
        out_packet_size,
    ):
        if self.rc == 0:
            self._set_out(out_data, out_size, out_packet_size)
        return self.rc

    def samurai_gpu_packet_generate_packets_from_template_pool(
        self,
        _templates_flat,
        _templates_flat_len,
        _packet_size,
        _num_templates,
        _count,
        _target_ip,
        _real_src_ip,
        _spoof_ip,
        _specific_src_port,
        _has_ethernet,
        _gateway_mac,
        _spoof_subnet,
        _force_global_fallback,
        out_data,
        out_size,
        out_packet_size,
    ):
        if self.rc == 0:
            self._set_out(out_data, out_size, out_packet_size)
        return self.rc

    def samurai_gpu_packet_generate_stateful_packets(
        self,
        _templates_flat,
        _templates_flat_len,
        _packet_size,
        _num_templates,
        _count,
        _target_ip,
        _spoof_ip,
        _real_src_ip,
        _specific_src_port,
        _has_ethernet,
        _gateway_mac,
        _spoof_subnet,
        _seq_list,
        _seq_len,
        _ack_list,
        _ack_len,
        _state_list,
        _state_len,
        _actual_lengths,
        _actual_lengths_len,
        _window_sizes,
        _window_sizes_len,
        _mss_values,
        _mss_values_len,
        _ttls,
        _ttls_len,
        _force_global_fallback,
        out_data,
        out_size,
        out_packet_size,
    ):
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
