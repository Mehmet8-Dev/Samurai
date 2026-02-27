import os
import sys
import types
import unittest
from unittest.mock import AsyncMock, patch

import ddos_samurai as ddos_pkg
from ddos_samurai import orchestrator
from ddos_samurai import senders
from ddos_samurai import utils


def _base_args():
    return {
        "target": "127.0.0.1",
        "port": 80,
        "count": 7,
        "verbose": False,
        "compute_backend": "cuda",
        "attack_vector": "basic",
        "protocol": "tcp",
        "spoof": False,
        "spoof_mode": "realistic",
        "spoof_subnet": None,
        "spoof_list_file": None,
        "payloads": [],
        "tcp_flags": "S",
        "ttl": None,
        "tos": None,
        "window": None,
        "fragment": False,
        "fragment_size": 800,
        "pad": 0,
        "source_port": 0,
        "stateful": False,
        "workers": 1,
        "rps": 0.0,
        "jitter": 0.0,
        "ramp": 0.0,
        "pacing_mode": "none",
        "ipg": 0,
        "burst_size": 64,
        "burst_gap": 0,
        "jitter_model": "none",
        "jitter_pct": 0.0,
        "pin_cpu": -1,
        "use_so_txtime": False,
        "fault_inject": [],
        "fault_after_s": 0.0,
        "fault_duration_s": 0.0,
        "gpu_template_pool_size_l4": 3,
        "gpu_template_pool_size_l7": 5,
        "gpu_ring_capacity": 2,
        "gpu_pinned_max_mb": 16,
        "state_table_size": 65536,
        "state_lock_count": 256,
        "state_timeout_sec": 60,
        "state_sweep_interval_ms": 1000,
        "tls_profile": "none",
        "h2_profile": "none",
        "ja3_profile": "none",
        "dns_name": "example.com",
        "dns_qtype": ["A"],
        "dns_edns": False,
        "dns_nord": False,
    }


class _FakeCudaStream:
    def __init__(self, non_blocking=True):
        self.non_blocking = bool(non_blocking)


class _FakeCudaEvent:
    def record(self, _stream):
        return None

    def query(self):
        return True

    def synchronize(self):
        return None


def _build_fake_cupy_module():
    cp = types.ModuleType("cupy")
    cp.cuda = types.SimpleNamespace(Stream=_FakeCudaStream, Event=_FakeCudaEvent)
    return cp


def _build_fake_numba_modules():
    numba_mod = types.ModuleType("numba")
    cuda_mod = types.ModuleType("numba.cuda")
    cuda_mod.is_available = lambda: True
    numba_mod.cuda = cuda_mod
    return numba_mod, cuda_mod


def _build_fake_gpu_payload_module():
    mod = types.ModuleType("ddos_samurai.gpu_payload")

    class _DummyPayloadEngine:
        def __init__(self, _batch):
            self.count = 0

    mod.GPUPayloadEngine = _DummyPayloadEngine
    return mod


def _build_fake_gpu_packet_module():
    mod = types.ModuleType("ddos_samurai.gpu_packet")
    state = {
        "pinned_mb": 0,
        "h2d_count": 0,
        "h2d_bytes": 0,
    }

    def configure_pinned_host_pool(max_mb=None, max_bytes=None):
        if max_mb is not None:
            state["pinned_mb"] = int(max_mb)
        elif max_bytes is not None:
            state["pinned_mb"] = int(max_bytes // (1024 * 1024))

    def generate_packets_from_template_pool(
        templates_bytes_list,
        count,
        target_ip,
        real_src_ip="192.168.1.100",
        spoof_ip=True,
        specific_src_port=-1,
        has_ethernet=True,
        stream=None,
        gateway_mac=0,
        spoof_subnet="1.0.0.0/8",
        force_global_fallback=False,
    ):
        del target_ip, real_src_ip, spoof_ip, specific_src_port, has_ethernet, stream, gateway_mac, spoof_subnet, force_global_fallback
        packet_size = len(templates_bytes_list[0]) if templates_bytes_list else 54
        buf = bytearray(packet_size * int(count))
        state["h2d_count"] += 1
        state["h2d_bytes"] += len(buf)
        return buf, packet_size

    def copy_gpu_to_host_pinned(gpu_arr, key="default", stream=None, blocking=True):
        del key, stream, blocking
        return bytes(gpu_arr)

    class _PoolStats:
        @staticmethod
        def get_stats():
            return {
                "used_bytes": 0,
                "total_bytes": 0,
                "buffers_allocated": 0,
                "buffers_in_use": 0,
            }

    class _PinnedStats:
        @staticmethod
        def get_stats():
            return {"total_nbytes": 0, "buffers_allocated": 0}

    def get_memory_pool():
        return _PoolStats()

    def get_pinned_host_pool():
        return _PinnedStats()

    def get_generation_telemetry():
        return {
            "gpu_template_h2d_copy_count": int(state["h2d_count"]),
            "gpu_template_h2d_copy_bytes": int(state["h2d_bytes"]),
            "gpu_rng_state_alloc_count": 0,
            "gpu_rng_state_reuse_count": 0,
        }

    mod.configure_pinned_host_pool = configure_pinned_host_pool
    mod.generate_packets_from_template_pool = generate_packets_from_template_pool
    mod.copy_gpu_to_host_pinned = copy_gpu_to_host_pinned
    mod.get_memory_pool = get_memory_pool
    mod.get_pinned_host_pool = get_pinned_host_pool
    mod.get_generation_telemetry = get_generation_telemetry
    mod._state = state
    return mod


class _FakeFastSender:
    def __init__(self):
        self.configured = False
        self.ingest_calls = 0
        self.ingest_packets = 0
        self.sweep_calls = 0

    def configure_state_engine(self, table_size, lock_count, timeout_sec):
        self.configured = True
        self.table_size = int(table_size)
        self.lock_count = int(lock_count)
        self.timeout_sec = int(timeout_sec)
        return {
            "table_size": self.table_size,
            "lock_count": self.lock_count,
            "timeout_sec": self.timeout_sec,
        }

    def ingest_tx_packets(self, _buf, _packet_size, count):
        self.ingest_calls += 1
        self.ingest_packets += int(count)
        return int(count)

    def sweep_state_table(self, _max_scan=0):
        self.sweep_calls += 1
        return 0

    def get_state_engine_stats(self):
        return {
            "active_entries": int(self.ingest_packets),
            "timeout_evictions": 0,
            "overwrites": 0,
        }


class TestOrchestratorCudaPipeline(unittest.IsolatedAsyncioTestCase):
    async def test_cuda_pipeline_respects_ring_capacity_and_updates_state_hooks(self):
        args = _base_args()
        events = []
        fake_gpu_packet = _build_fake_gpu_packet_module()
        fake_gpu_payload = _build_fake_gpu_payload_module()
        fake_cupy = _build_fake_cupy_module()
        fake_numba, fake_numba_cuda = _build_fake_numba_modules()
        fake_fast_sender = _FakeFastSender()

        async def _fake_paced_sender(
            *,
            packets_buffer,
            target_ip,
            target_port,
            count,
            verbose,
            pacing_config=None,
            live_sent=None,
            live_errors=None,
            live_progress=None,
        ):
            del packets_buffer, target_ip, target_port, verbose, pacing_config, live_sent, live_errors, live_progress
            return {
                "attempted": int(count),
                "sent": int(count),
                "errors": 0,
                "bytes_sent_est": int(count) * 54,
                "sender_path": "PACED_L2",
            }

        # Ethernet+IPv4+TCP skeleton (54B) so template path avoids scapy fallback.
        template_bytes = (
            b"\xaa\xaa\xaa\xaa\xaa\xaa"
            b"\xbb\xbb\xbb\xbb\xbb\xbb"
            b"\x08\x00"
            b"\x45\x00\x00\x28\x00\x00\x00\x00\x40\x06\x00\x00"
            b"\x01\x01\x01\x01\x02\x02\x02\x02"
            b"\x04\xd2\x00\x50\x00\x00\x00\x01\x00\x00\x00\x00\x50\x02\x20\x00\x00\x00\x00\x00"
        )

        with patch.dict(
            sys.modules,
            {
                "cupy": fake_cupy,
                "numba": fake_numba,
                "numba.cuda": fake_numba_cuda,
                "ddos_samurai.gpu_packet": fake_gpu_packet,
                "ddos_samurai.gpu_payload": fake_gpu_payload,
            },
            clear=False,
        ), patch.object(
            ddos_pkg, "gpu_packet", fake_gpu_packet, create=True
        ), patch.object(
            ddos_pkg, "gpu_payload", fake_gpu_payload, create=True
        ), patch.object(
            orchestrator.packet, "create_packet", lambda _cfg: template_bytes
        ), patch.object(
            utils, "get_gateway_mac", lambda _target: "aa:bb:cc:dd:ee:ff"
        ), patch.object(
            senders, "FAST_SENDER_AVAILABLE", True
        ), patch.object(
            senders, "fast_sender", fake_fast_sender, create=True
        ), patch.object(
            senders, "paced_raw_socket_sender", AsyncMock(side_effect=_fake_paced_sender)
        ), patch.dict(
            os.environ, {"SAMURAI_GPU_BATCH": "2"}, clear=False
        ):
            await orchestrator.worker_process(worker_id=0, args=args, ssl_context=None, run_events=events)

        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["status"], "ok")
        self.assertEqual(int(ev["stats"]["attempted"]), int(args["count"]))
        self.assertEqual(int(ev["stats"]["sent"]), int(args["count"]))
        self.assertLessEqual(int(ev["gpu_ring_depth_peak"]), int(args["gpu_ring_capacity"]))
        self.assertGreaterEqual(int(ev["gpu_ring_depth_peak"]), 1)
        self.assertGreaterEqual(int(ev["gpu_ring_block_wait_ns"]), 0)
        self.assertTrue(fake_fast_sender.configured)
        self.assertGreaterEqual(fake_fast_sender.ingest_calls, 1)
        self.assertEqual(int(ev["state_active_entries"]), int(args["count"]))
        self.assertEqual(int(ev["state_timeout_evictions"]), 0)
        self.assertEqual(int(ev["state_overwrites"]), 0)
        self.assertEqual(int(fake_gpu_packet._state["pinned_mb"]), int(args["gpu_pinned_max_mb"]))
