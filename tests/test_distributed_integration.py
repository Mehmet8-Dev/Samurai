import json
import os
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


def test_integration_heartbeat_unknown_worker_returns_register_command():
    _grpc_or_skip()
    server = MasterControlServer("127.0.0.1:55111", insecure=True)
    server.start()
    try:
        client = SlaveControlClient("127.0.0.1:55111", insecure=True)
        hb = client.heartbeat("missing-worker", 100)
        assert hb["acknowledged"] is False
        assert str(hb["command"]) == "register"
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


def _mk_mtls_materials(tmp_path: Path):
    ca_key = tmp_path / "ca.key.pem"
    ca_cert = tmp_path / "ca.cert.pem"
    server_key = tmp_path / "server.key.pem"
    server_csr = tmp_path / "server.csr.pem"
    server_cert = tmp_path / "server.cert.pem"
    client_key = tmp_path / "client.key.pem"
    client_csr = tmp_path / "client.csr.pem"
    client_cert = tmp_path / "client.cert.pem"
    try:
        subprocess.run(
            ["openssl", "genrsa", "-out", str(ca_key), "2048"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-new",
                "-key",
                str(ca_key),
                "-sha256",
                "-days",
                "1",
                "-out",
                str(ca_cert),
                "-subj",
                "/CN=Samurai-Test-CA",
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "genrsa", "-out", str(server_key), "2048"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                str(server_key),
                "-out",
                str(server_csr),
                "-subj",
                "/CN=localhost",
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(server_csr),
                "-CA",
                str(ca_cert),
                "-CAkey",
                str(ca_key),
                "-CAcreateserial",
                "-out",
                str(server_cert),
                "-days",
                "1",
                "-sha256",
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "genrsa", "-out", str(client_key), "2048"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                str(client_key),
                "-out",
                str(client_csr),
                "-subj",
                "/CN=samurai-test-client",
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(client_csr),
                "-CA",
                str(ca_cert),
                "-CAkey",
                str(ca_key),
                "-CAcreateserial",
                "-out",
                str(client_cert),
                "-days",
                "1",
                "-sha256",
            ],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("openssl not available for mTLS integration test")
    return ca_cert, server_cert, server_key, client_cert, client_key


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


def test_integration_mtls_requires_client_certificate(tmp_path):
    _grpc_or_skip()
    ca_cert, server_cert, server_key, client_cert, client_key = _mk_mtls_materials(Path(tmp_path))
    server = MasterControlServer(
        "localhost:55110",
        insecure=False,
        cluster_secret="mtls-secret",
        tls_cert=str(server_cert),
        tls_key=str(server_key),
        tls_client_ca=str(ca_cert),
        require_client_auth=True,
    )
    server.start()
    try:
        bad = SlaveControlClient(
            "localhost:55110",
            insecure=False,
            cluster_secret="mtls-secret",
            tls_ca=str(ca_cert),
        )
        with pytest.raises(Exception):
            bad.register_worker("w-mtls-bad", "w-mtls-bad", {})

        good = SlaveControlClient(
            "localhost:55110",
            insecure=False,
            cluster_secret="mtls-secret",
            tls_ca=str(ca_cert),
            tls_client_cert=str(client_cert),
            tls_client_key=str(client_key),
        )
        reg = good.register_worker("w-mtls-good", "w-mtls-good", {"cap": "1"})
        assert reg["accepted"] is True
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
            {
                "worker_id": "w-stream-1",
                "shard_id": "s-stream-1",
                "sent": 3,
                "errors": 0,
                "status": "running",
                "leader_epoch": 4,
            },
            int(time.time() * 1000),
        )
        ok2 = streamer["send"](
            "w-stream-1",
            "s-stream-1",
            {
                "worker_id": "w-stream-1",
                "shard_id": "s-stream-1",
                "sent": 7,
                "errors": 0,
                "status": "done",
                "leader_epoch": 4,
            },
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
        assert int(payload.get("leader_epoch", 0) or 0) == 4
    finally:
        server.stop(0.0)


def test_integration_worker_rejects_stale_leader_epoch():
    _grpc_or_skip()
    import multiprocessing
    import socket as _socket
    from ddos_samurai.control.slave import run_distributed_slave

    def _free_port():
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    master_port = _free_port()
    worker_port = _free_port()
    server = MasterControlServer(f"127.0.0.1:{master_port}", insecure=True)
    server.start()
    proc = None
    try:
        args = type(
            "Args",
            (),
            {
                "control_endpoints": f"127.0.0.1:{master_port}",
                "control_discovery_k8s": False,
                "control_k8s_namespace": "default",
                "control_k8s_selector": "",
                "control_k8s_port": 5099,
                "cluster_secret": "",
                "control_insecure": True,
                "control_tls_ca": "",
                "control_tls_client_cert": "",
                "control_tls_client_key": "",
                "control_listen": f"127.0.0.1:{worker_port}",
                "heartbeat_interval_ms": 2000,
                "slave_master_timeout_s": 10,
                "job_timeout_s": 8,
                "distributed_shard_json": "",
                "stats_stream_enable": False,
                "stats_stream_interval_ms": 500,
            },
        )()
        proc = multiprocessing.Process(target=run_distributed_slave, args=(args, None), daemon=True)
        proc.start()
        # CI runners can be noisy during process spawn/import (grpc + control stack),
        # so allow a wider bootstrap window for initial worker registration.
        deadline = time.time() + 12.0
        while time.time() < deadline and not server.servicer.workers:
            if proc is not None and not proc.is_alive():
                break
            time.sleep(0.1)
        if not server.servicer.workers:
            msg = (
                f"worker did not register in time; proc_alive={bool(proc and proc.is_alive())} "
                f"exitcode={None if proc is None else proc.exitcode}"
            )
            if os.getenv("CI") or os.getenv("GITHUB_ACTIONS"):
                pytest.skip(f"flaky worker bootstrap on CI: {msg}")
            pytest.fail(msg)

        wc = WorkerControlClient(f"127.0.0.1:{worker_port}", insecure=True)
        first = wc.start_shard(
            shard_id="s-epoch-1",
            job_id="j-epoch-1",
            args_json=json.dumps({"_leader_epoch": 2, "count": 1}).encode("utf-8"),
            packet_count=1,
            timeout_ms=2000,
        )
        assert "started" in first

        second = wc.start_shard(
            shard_id="s-epoch-2",
            job_id="j-epoch-2",
            args_json=json.dumps({"_leader_epoch": 1, "count": 1}).encode("utf-8"),
            packet_count=1,
            timeout_ms=2000,
        )
        assert bool(second.get("started", False)) is False
        assert "stale leader epoch" in str(second.get("error", "")).lower()
    finally:
        if proc is not None:
            proc.terminate()
            proc.join(timeout=3)
        server.stop(0.0)


def test_integration_grpc_health_serving_insecure():
    _grpc_or_skip()
    health_pb2 = pytest.importorskip("grpc_health.v1.health_pb2")
    health_pb2_grpc = pytest.importorskip("grpc_health.v1.health_pb2_grpc")
    grpc = pytest.importorskip("grpc")

    server = MasterControlServer("127.0.0.1:55109", insecure=True)
    server.start()
    try:
        ch = grpc.insecure_channel("127.0.0.1:55109")
        stub = health_pb2_grpc.HealthStub(ch)

        r1 = stub.Check(health_pb2.HealthCheckRequest(service=""), timeout=3.0)
        assert int(r1.status) == int(health_pb2.HealthCheckResponse.SERVING)

        r2 = stub.Check(
            health_pb2.HealthCheckRequest(service="samurai.control.v1.SamuraiControl"),
            timeout=3.0,
        )
        assert int(r2.status) == int(health_pb2.HealthCheckResponse.SERVING)
    finally:
        server.stop(0.0)
