import json
import time

import pytest

from ddos_samurai.control.client import SlaveControlClient
from ddos_samurai.control.master import _run_single_job


class _FakeServicer:
    def __init__(self):
        now_ms = int(time.time() * 1000)
        self.workers = {
            "w1": {
                "worker_id": "w1",
                "capabilities": {"control_endpoint": "ep1"},
                "last_heartbeat_ms": now_ms,
                "state": "idle",
                "active_shard_id": "",
            },
            "w2": {
                "worker_id": "w2",
                "capabilities": {"control_endpoint": "ep2"},
                "last_heartbeat_ms": now_ms,
                "state": "idle",
                "active_shard_id": "",
            },
        }
        self.shard_stats = {}


class _FakeServer:
    def __init__(self):
        self.servicer = _FakeServicer()


def test_chaos_worker_loss_triggers_redispatch(monkeypatch):
    server = _FakeServer()
    start_calls = []

    class _WC:
        def __init__(self, endpoint, **kwargs):
            self.endpoint = endpoint
            _ = kwargs

        def start_shard(self, shard_id, job_id, args_json, packet_count, timeout_ms):
            _ = job_id, packet_count, timeout_ms
            start_calls.append((self.endpoint, shard_id))
            if self.endpoint == "ep1":
                # First worker "dies" after dispatch.
                server.servicer.workers["w1"]["last_heartbeat_ms"] = int(time.time() * 1000) - 10000
                return {"started": True, "error": ""}
            payload = json.loads(bytes(args_json).decode("utf-8"))
            server.servicer.shard_stats[str(shard_id)] = json.dumps(
                {
                    "worker_id": payload.get("_worker_id", "w2"),
                    "shard_id": shard_id,
                    "sent": 10,
                    "errors": 0,
                    "status": "done",
                    "leader_epoch": int(payload.get("_leader_epoch", 0) or 0),
                },
                ensure_ascii=True,
            ).encode("utf-8")
            return {"started": True, "error": ""}

        def get_worker_status(self, worker_id):
            return {"state": "running", "active_shard_id": "", "stats_json": b"{}"}

        def stop_shard(self, shard_id, graceful=True):
            _ = shard_id, graceful
            return True

    monkeypatch.setattr("ddos_samurai.control.master.WorkerControlClient", _WC)
    rc, snap = _run_single_job(
        server=server,
        job_args={
            "count": 10,
            "shard_unit_count": 10,
            "job_timeout_s": 3,
            "master_poll_interval_ms": 50,
            "heartbeat_timeout_ms": 100,
            "on_worker_loss": "continue",
            "worker_status_probe": False,
            "_leader_epoch": 7,
            "cluster_secret": "",
            "control_insecure": True,
        },
        job_id="job-chaos",
    )
    assert int(rc) in {0, 1}
    assert int(snap.get("sent", 0) or 0) == 10
    assert "w1" in set(snap.get("lost_workers") or [])
    # First dispatch to ep1, then redispatch to ep2.
    assert [x[0] for x in start_calls].count("ep1") >= 1
    assert [x[0] for x in start_calls].count("ep2") >= 1


def test_chaos_stream_sender_failure_sets_failed_event(monkeypatch):
    pytest.importorskip("grpc")
    pytest.importorskip("google.protobuf")

    class _FakeCall:
        def __call__(self, req_iter, timeout=None, metadata=None):
            _ = req_iter, timeout, metadata
            raise RuntimeError("stream failed")

    class _FakeChannel:
        def stream_unary(self, *args, **kwargs):
            _ = args, kwargs
            return _FakeCall()

    client = object.__new__(SlaveControlClient)
    client.cluster_secret = ""
    client.tenant_namespace = ""
    client._stream_channels = {"ep1": _FakeChannel()}
    client._channels = {}
    client._stubs = {}
    client._last_endpoint_idx = 0
    client.endpoints = ["ep1"]
    client._iter_endpoints_for_try = lambda: ["ep1"]

    streamer = SlaveControlClient.create_stats_streamer(client)
    deadline = time.time() + 1.0
    while time.time() < deadline and not streamer["failed"].is_set():
        time.sleep(0.01)
    assert streamer["failed"].is_set() is True
    assert streamer["send"]("w", "s", {"sent": 1}, int(time.time() * 1000)) is False
    streamer["close"]()
