import ctypes
import gc
import importlib.util

import numpy as np
import pytest

_NUMBA_AVAILABLE = importlib.util.find_spec("numba") is not None
if not _NUMBA_AVAILABLE:
    pytest.skip(
        "numba not installed in CI-safe environment; skipping native CUDA bridge tests",
        allow_module_level=True,
    )

import ddos_samurai._gpu_packet_cuda_backend as backend


def _to_bytes(arr) -> bytes:
    return np.asarray(arr, dtype=np.uint8).tobytes()


def _scalar(value):
    return int(getattr(value, "value", value))


class _FakeLib:
    def __init__(self, payload: bytes = b"", packet_size: int = 0, rc: int = 0, err: bytes = b"", wait_rc: int = 0):
        self.payload = bytes(payload)
        self.packet_size = int(packet_size)
        self.rc = int(rc)
        self.err = bytes(err)
        self.wait_rc = int(wait_rc)
        self._buffers = []
        self.calls = []
        self.free_called = 0
        self.wait_called = 0
        self.kernel_mode = 0
        self.stream_id = 0

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

    def samurai_gpu_packet_generate_packets(self, *args):
        protocol_bytes = ctypes.cast(args[3], ctypes.c_char_p).value or b""
        self.calls.append(
            {
                "name": "generate_packets",
                "count": _scalar(args[0]),
                "target_port": _scalar(args[2]),
                "protocol": protocol_bytes.decode("utf-8", errors="ignore"),
                "has_ethernet": _scalar(args[7]),
                "gateway_mac": _scalar(args[10]),
            }
        )
        if self.rc == 0:
            self._set_out(args[-3], args[-2], args[-1])
        return self.rc

    def samurai_gpu_packet_generate_packets_from_template(self, *args):
        self.calls.append(
            {
                "name": "generate_packets_from_template",
                "template_len": _scalar(args[1]),
                "count": _scalar(args[2]),
                "force_global_fallback": _scalar(args[9]),
            }
        )
        if self.rc == 0:
            self._set_out(args[-3], args[-2], args[-1])
        return self.rc

    def samurai_gpu_packet_generate_packets_from_template_pool(self, *args):
        self.calls.append(
            {
                "name": "generate_packets_from_template_pool",
                "templates_flat_len": _scalar(args[1]),
                "packet_size": _scalar(args[2]),
                "num_templates": _scalar(args[3]),
            }
        )
        if self.rc == 0:
            self._set_out(args[-3], args[-2], args[-1])
        return self.rc

    def samurai_gpu_packet_generate_stateful_packets(self, *args):
        self.calls.append(
            {
                "name": "generate_stateful_packets",
                "packet_size": _scalar(args[2]),
                "num_templates": _scalar(args[3]),
                "seq_len": _scalar(args[14]),
                "ack_len": _scalar(args[16]),
            }
        )
        if self.rc == 0:
            self._set_out(args[-3], args[-2], args[-1])
        return self.rc

    def samurai_gpu_packet_generate_fragmented_packets(self, *args):
        self.calls.append({"name": "generate_fragmented_packets", "payload_len": _scalar(args[1])})
        if self.rc == 0:
            self._set_out(args[-3], args[-2], args[-1])
        return self.rc

    def samurai_gpu_packet_generate_amplification_packets(self, *args):
        self.calls.append({"name": "generate_amplification_packets", "reflector_count": _scalar(args[3])})
        if self.rc == 0:
            self._set_out(args[-3], args[-2], args[-1])
        return self.rc

    def samurai_gpu_packet_generate_icmp_packets(self, *args):
        self.calls.append({"name": "generate_icmp_packets", "payload_size": _scalar(args[7])})
        if self.rc == 0:
            self._set_out(args[-3], args[-2], args[-1])
        return self.rc

    def samurai_gpu_packet_free(self, _ptr):
        self.free_called += 1

    def samurai_gpu_packet_wait(self, _ptr):
        self.wait_called += 1
        return self.wait_rc

    def samurai_gpu_packet_last_error(self):
        return self.err

    def samurai_gpu_packet_set_kernel_mode(self, mode):
        self.kernel_mode = int(_scalar(mode))
        return self.rc

    def samurai_gpu_packet_get_kernel_mode(self):
        return int(self.kernel_mode)

    def samurai_gpu_packet_start_stream(self, profile_json, out_stream_id):
        del profile_json
        self.stream_id += 1
        ctypes.cast(out_stream_id, ctypes.POINTER(ctypes.c_int64)).contents.value = int(self.stream_id)
        return self.rc

    def samurai_gpu_packet_update_stream(self, stream_id, update_json):
        self.calls.append({"name": "update_stream", "stream_id": int(_scalar(stream_id)), "update_json": bytes(update_json or b"")})
        return self.rc

    def samurai_gpu_packet_stop_stream(self, stream_id):
        self.calls.append({"name": "stop_stream", "stream_id": int(_scalar(stream_id))})
        return self.rc

    def samurai_gpu_packet_read_stream_stats(self, stream_id):
        sid = int(_scalar(stream_id))
        if sid == 0:
            return (
                '{"stream_id":0,"active":1,"bridge_drain_batches":7,'
                '"bridge_drain_packets":64,"ring_drop_events":3,'
                '"scheduler_fairness_cv_pct":12.5}'
            ).encode()
        return f'{{"stream_id":{sid},"active":1}}'.encode()

    def samurai_gpu_packet_shutdown_runtime(self):
        self.calls.append({"name": "shutdown_runtime"})
        return self.rc


@pytest.fixture(autouse=True)
def _reset_native_telemetry():
    backend.reset_generation_telemetry()
    yield
    backend.reset_generation_telemetry()


def test_native_disabled_raises_without_legacy_fallback(monkeypatch):
    monkeypatch.setattr(backend, "_LIB", _FakeLib(payload=b"\x00", packet_size=1), raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", False, raising=True)

    with pytest.raises(backend.GPUPacketError, match="native path unavailable"):
        backend.generate_packets(
            count=1,
            target_ip="203.0.113.1",
            target_port=53,
            protocol="udp",
        )


def test_generate_packets_native_success(monkeypatch):
    fake = _FakeLib(payload=b"\x01\x02\x03\x04", packet_size=2)
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)
    monkeypatch.setattr(backend.cp, "asarray", lambda arr, dtype=None: np.asarray(arr, dtype=np.uint8), raising=True)

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
    assert fake.wait_called == 0
    del packets
    gc.collect()
    assert fake.free_called == 1
    telemetry = backend.get_generation_telemetry()
    assert telemetry["gpu_native_d2h_copy_count"] == 1


def test_generate_packets_host_ready_releases_on_gc(monkeypatch):
    fake = _FakeLib(payload=b"\x01\x02\x03\x04", packet_size=2)
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)

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
    assert _to_bytes(packets) == b"\x01\x02\x03\x04"
    assert fake.wait_called == 0
    del packets
    gc.collect()
    assert fake.free_called == 1


def test_generate_packets_waits_when_return_host_ready_disabled(monkeypatch):
    fake = _FakeLib(payload=b"\x01\x02\x03\x04", packet_size=2)
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)

    packets, packet_size = backend.generate_packets(
        count=2,
        target_ip="203.0.113.1",
        target_port=80,
        protocol="tcp",
        spoof_ip=False,
        has_ethernet=True,
        return_host_ready=False,
    )

    assert packet_size == 2
    assert isinstance(packets, np.ndarray)
    assert _to_bytes(packets) == b"\x01\x02\x03\x04"
    assert fake.wait_called == 1


def test_generate_packets_forwards_gateway_mac_and_l2_policy(monkeypatch):
    fake = _FakeLib(payload=b"\x01\x02", packet_size=1)
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)

    backend.generate_packets(
        count=1,
        target_ip="203.0.113.1",
        target_port=53,
        protocol="udp",
        spoof_ip=False,
        has_ethernet=True,
        gateway_mac=0x001122334455,
    )

    last = fake.calls[-1]
    assert last["name"] == "generate_packets"
    assert last["protocol"] == "udp"
    assert last["has_ethernet"] == 1
    assert last["gateway_mac"] == 0x001122334455


def test_kernel_mode_and_stream_lifecycle(monkeypatch):
    fake = _FakeLib(payload=b"\x01\x02", packet_size=1)
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)

    mode = backend.set_kernel_mode("persistent")
    assert mode == "persistent"
    assert backend.get_kernel_mode() == "persistent"

    stream_id = backend.start_stream({"op": "generate_packets"})
    assert stream_id == 1
    backend.update_stream(stream_id, {"quota": 10})
    stats = backend.read_stream_stats(stream_id)
    assert stats["stream_id"] == 1
    backend.stop_stream(stream_id)
    backend.shutdown_persistent_runtime()
    assert any(c["name"] == "shutdown_runtime" for c in fake.calls)


def test_invalid_stream_is_rejected(monkeypatch):
    monkeypatch.setattr(backend, "_LIB", _FakeLib(payload=b"\x00", packet_size=1), raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)

    with pytest.raises(backend.GPUPacketError, match="stream object cannot be converted to cudaStream_t handle"):
        backend.generate_packets(
            count=1,
            target_ip="203.0.113.1",
            target_port=53,
            stream=object(),
        )


def test_generate_packets_from_template_pool_native_success(monkeypatch):
    fake = _FakeLib(payload=b"\x0A\x0B\x0C\x0D", packet_size=2)
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)
    monkeypatch.setattr(backend.cp, "asarray", lambda arr, dtype=None: np.asarray(arr, dtype=np.uint8), raising=True)

    packets, packet_size = backend.generate_packets_from_template_pool(
        templates_bytes_list=[b"\x45" + b"\x00" * 63, b"\x45" + b"\x11" * 63],
        count=2,
        target_ip="203.0.113.10",
        spoof_ip=False,
        has_ethernet=False,
    )

    assert packet_size == 2
    assert _to_bytes(packets) == b"\x0A\x0B\x0C\x0D"
    assert fake.calls[-1]["num_templates"] == 2


def test_generate_stateful_packets_native_success(monkeypatch):
    fake = _FakeLib(payload=b"\x20\x21\x22\x23", packet_size=2)
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)
    monkeypatch.setattr(backend.cp, "asarray", lambda arr, dtype=None: np.asarray(arr, dtype=np.uint8), raising=True)

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
    assert fake.calls[-1]["seq_len"] == 2
    assert fake.calls[-1]["ack_len"] == 2


def test_benchmark_template_generation_paths_reports_both_native_paths(monkeypatch):
    fake = _FakeLib(payload=b"\xAA\xBB\xCC\xDD", packet_size=2)
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)

    result = backend.benchmark_template_generation_paths(
        template_bytes=b"\x45" + b"\x00" * 63,
        count=2,
        iterations=1,
        spoof_ip=False,
        has_ethernet=False,
    )

    paths = [run["path"] for run in result["runs"]]
    assert paths == ["constant_memory", "global_memory"]
    assert result["native_only"] is True


def test_get_generation_telemetry_includes_persistent_v3_fields(monkeypatch):
    fake = _FakeLib(payload=b"\x01\x02", packet_size=1)
    monkeypatch.setattr(backend, "_LIB", fake, raising=True)
    monkeypatch.setattr(backend, "_NATIVE_ENABLED", True, raising=True)
    out = backend.get_generation_telemetry()
    assert int(out.get("bridge_drain_batches", 0) or 0) == 7
    assert int(out.get("bridge_drain_packets", 0) or 0) == 64
    assert int(out.get("ring_drop_events", 0) or 0) == 3
    assert float(out.get("scheduler_fairness_cv_pct", 0.0) or 0.0) == 12.5
