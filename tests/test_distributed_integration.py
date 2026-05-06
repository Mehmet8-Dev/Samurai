import json
import threading
import time
import subprocess
from pathlib import Path

import pytest

from ddos_samurai.control.master import run_distributed_master
from ddos_samurai.control.server import MasterControlServer
from ddos_samurai.control.client import SlaveControlClient
from ddos_samurai.control.client import WorkerControlClient


def _grpc_or_skip():
    return pytest.importorskip("grpc")


def test_integration_master_slave_insecure_register_heartbeat_stats():
    _grpc_or_skip()
    server = MasterControlServer("127.0.0.1:55101", insecure=True)
    server.start()
    try:
        client = SlaveControlClient("127.0.0.1:55101", insecure=True)
        reg = client.register_worker("w-int-1", "host-int-1", {"xdp": "1"})
        assert reg["accepted"] is True

        hb = client.heartbeat("w-int-1", 100)
        assert hb["acknowledged"] is True

        ok = client.report_stats("w-int-1", "s-int-1", {"sent": 9, "errors": 0, "progress": 9}, int(time.time() * 1000))
        assert ok is True
        assert "s-int-1" in server.servicer.shard_stats
    finally:
        server.stop(0.0)


def _mk_self_signed_cert(tmp_path: Path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cmd = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        str(key),
        "-out",
        str(cert),
        "-sha256",
        "-days",
        "1",
        "-nodes",
        "-subj",
        "/CN=localhost",
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("openssl not available for TLS integration test")
    return cert, key


def test_integration_tls_secret_three_workers_and_aggregate(tmp_path):
    _grpc_or_skip()
    cert, key = _mk_self_signed_cert(Path(tmp_path))
    secret = "s3cr3t"
    server = MasterControlServer(
        "localhost:55104",
        insecure=False,
        cluster_secret=secret,
        tls_cert=str(cert),
        tls_key=str(key),
    )
    server.start()
    try:
        clients = [
            SlaveControlClient("localhost:55104", insecure=False, cluster_secret=secret, tls_ca=str(cert))
            for _ in range(3)
        ]
        total_sent = 0
        for i, c in enumerate(clients, start=1):
            wid = f"w-tls-{i}"
            reg = c.register_worker(wid, wid, {"capacity_score": str(i)})
            assert reg["accepted"] is True
            sid = f"s-tls-{i}"
            sent = 333_333 if i < 3 else 333_334
            total_sent += sent
            ok = c.report_stats(wid, sid, {"worker_id": wid, "shard_id": sid, "sent": sent, "errors": 0}, int(time.time() * 1000))
            assert ok is True
        assert len(server.servicer.workers) == 3
        assert len(server.servicer.shard_stats) == 3
        agg = 0
        for blob in server.servicer.shard_stats.values():
            payload = json.loads(bytes(blob).decode("utf-8"))
            agg += int(payload.get("sent", 0) or 0)
        assert agg == total_sent == 1_000_000
    finally:
        server.stop(0.0)


def test_integration_secret_rejects_wrong_token(tmp_path):
    _grpc_or_skip()
    cert, key = _mk_self_signed_cert(Path(tmp_path))
    server = MasterControlServer(
        "localhost:55105",
        insecure=False,
        cluster_secret="correct-token",
        tls_cert=str(cert),
        tls_key=str(key),
    )
    server.start()
    try:
        bad = SlaveControlClient(
            "localhost:55105",
            insecure=False,
            cluster_secret="wrong-token",
            tls_ca=str(cert),
        )
        with pytest.raises(Exception):
            bad.register_worker("w-bad", "w-bad", {})
    finally:
        server.stop(0.0)


def test_integration_worker_control_client_start_stop_insecure():
    _grpc_or_skip()
    server = MasterControlServer("127.0.0.1:55106", insecure=True)
    server.start()
    try:
        wc = WorkerControlClient("127.0.0.1:55106", insecure=True)
        started = wc.start_shard(
            shard_id="sid-1",
            job_id="jid-1",
            args_json=json.dumps({"_worker_id": "wid-1", "count": 1}).encode("utf-8"),
            packet_count=1,
            timeout_ms=0,
        )
        assert started["started"] is True
        assert wc.stop_shard("sid-1", graceful=True) is True
    finally:
        server.stop(0.0)


def test_integration_worker_control_get_status_insecure():
    _grpc_or_skip()
    server = MasterControlServer("127.0.0.1:55107", insecure=True)
    server.start()
    try:
        slave = SlaveControlClient("127.0.0.1:55107", insecure=True)
        reg = slave.register_worker("w-status-1", "w-status-1", {"xdp": "1"})
        assert reg["accepted"] is True

        wc = WorkerControlClient("127.0.0.1:55107", insecure=True)
        status = wc.get_worker_status("w-status-1")
        assert status["worker_id"] == "w-status-1"
        assert status["state"] in {"idle", "running", "done", "error"}
        assert isinstance(status["stats_json"], (bytes, bytearray))
        assert int(status["last_heartbeat_ms"]) > 0
    finally:
        server.stop(0.0)


def test_integration_report_stats_stream_insecure():
    _grpc_or_skip()
    server = MasterControlServer("127.0.0.1:55108", insecure=True)
    server.start()
    try:
        client = SlaveControlClient("127.0.0.1:55108", insecure=True)
        reg = client.register_worker("w-stream-1", "w-stream-1", {"xdp": "1"})
        assert reg["accepted"] is True

        streamer = client.create_stats_streamer()
        ok1 = streamer["send"](
            "w-stream-1",
            "s-stream-1",
            {"worker_id": "w-stream-1", "shard_id": "s-stream-1", "sent": 3, "errors": 0, "status": "running"},
            int(time.time() * 1000),
        )
        ok2 = streamer["send"](
            "w-stream-1",
            "s-stream-1",
            {"worker_id": "w-stream-1", "shard_id": "s-stream-1", "sent": 7, "errors": 0, "status": "done"},
            int(time.time() * 1000),
        )
        assert ok1 is True and ok2 is True
        streamer["close"]()

        deadline = time.time() + 2.0
        while time.time() < deadline and "s-stream-1" not in server.servicer.shard_stats:
            time.sleep(0.05)
        assert "s-stream-1" in server.servicer.shard_stats
        payload = json.loads(bytes(server.servicer.shard_stats["s-stream-1"]).decode("utf-8"))
        assert int(payload.get("sent", 0) or 0) == 7
        assert str(payload.get("status", "")) == "done"
    finally:
        server.stop(0.0)
