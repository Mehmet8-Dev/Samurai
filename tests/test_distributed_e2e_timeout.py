import multiprocessing as mp
import socket
import time
from argparse import Namespace

import pytest

grpc = pytest.importorskip("grpc", reason="grpc not installed")

from ddos_samurai.control.client import SlaveControlClient
from ddos_samurai.control.master import run_distributed_master


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def _master_args(port: int, on_worker_loss: str) -> Namespace:
    return Namespace(
        control_listen=f"127.0.0.1:{port}",
        cluster_secret="",
        control_insecure=True,
        control_tls_cert="",
        control_tls_key="",
        count=100,
        heartbeat_timeout_ms=700,
        on_worker_loss=on_worker_loss,
        job_timeout_s=3,
        shard_strategy="equal",
        role="master",
    )


def _run_master_proc(args: Namespace, out_q: mp.Queue) -> None:
    rc = int(run_distributed_master(args, parser=None, report_ctx={}, runtime_ctx={}))
    out_q.put(rc)


def _register_and_exit(port: int) -> None:
    cli = SlaveControlClient(f"127.0.0.1:{port}", insecure=True)
    wid = f"w-e2e-{int(time.time() * 1000)}"
    cli.register_worker(wid, wid, {"xdp": "1"})


def test_e2e_timeout_abort_policy_returns_nonzero():
    port = _free_port()
    q: mp.Queue = mp.Queue()

    m = mp.Process(target=_run_master_proc, args=(_master_args(port, "abort"), q), daemon=True)
    m.start()
    time.sleep(0.8)

    s = mp.Process(target=_register_and_exit, args=(port,), daemon=True)
    s.start()
    s.join(timeout=5)

    m.join(timeout=12)
    assert not m.is_alive(), "master process did not finish"
    rc = q.get(timeout=2)
    assert int(rc) != 0


def test_e2e_timeout_continue_policy_without_reachable_worker_endpoint_returns_nonzero():
    port = _free_port()
    q: mp.Queue = mp.Queue()

    m = mp.Process(target=_run_master_proc, args=(_master_args(port, "continue"), q), daemon=True)
    m.start()
    time.sleep(0.8)

    s = mp.Process(target=_register_and_exit, args=(port,), daemon=True)
    s.start()
    s.join(timeout=5)

    m.join(timeout=12)
    assert not m.is_alive(), "master process did not finish"
    rc = q.get(timeout=2)
    assert int(rc) != 0
