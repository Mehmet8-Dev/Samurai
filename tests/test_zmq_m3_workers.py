from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

from ddos_samurai.zmq_dispatcher import ZmqDispatcher
from ddos_samurai.zmq_event_collector import ZmqEventCollector
from ddos_samurai.zmq_runtime_manager import WORKER_PY_MODULES, ZmqRuntimeManager
from ddos_samurai.zmq_wire import MessageType, WorkerKind, default_event_endpoint, default_job_endpoint
from ddos_samurai.zmq_worker_prototype import ZmqWorkerPrototype


class _FakeSocket:
    def __init__(self, ctx: "_FakeContext", sock_type: int):
        self._ctx = ctx
        self._type = sock_type
        self._endpoint = ""

    @property
    def endpoint(self) -> str:
        return self._endpoint

    def setsockopt(self, _key, _value):
        return None

    def connect(self, endpoint: str):
        self._endpoint = str(endpoint)
        self._ctx.ensure(self._endpoint)

    def bind(self, endpoint: str):
        self._endpoint = str(endpoint)
        self._ctx.ensure(self._endpoint)

    def send(self, payload: bytes):
        self._ctx.ensure(self._endpoint).append(bytes(payload))

    def recv(self) -> bytes:
        q = self._ctx.ensure(self._endpoint)
        if not q:
            raise RuntimeError("empty queue")
        return q.pop(0)

    def close(self, linger=0):
        _ = linger
        return None


class _FakePoller:
    def __init__(self, ctx: "_FakeContext"):
        self._ctx = ctx
        self._regs: list[tuple[_FakeSocket, int]] = []

    def register(self, sock: _FakeSocket, event_mask: int):
        self._regs.append((sock, int(event_mask)))

    def poll(self, timeout: int = 0):
        _ = timeout
        out = []
        for sock, mask in self._regs:
            q = self._ctx.ensure(sock.endpoint)
            if q:
                out.append((sock, mask))
        return out


class _FakeContext:
    def __init__(self):
        self._queues: dict[str, list[bytes]] = {}

    def ensure(self, endpoint: str) -> list[bytes]:
        if endpoint not in self._queues:
            self._queues[endpoint] = []
        return self._queues[endpoint]

    def socket(self, sock_type: int):
        return _FakeSocket(self, sock_type)


class _FakeZmq:
    PUSH = 1
    PULL = 2
    POLLIN = 1
    LINGER = 17

    class Context:
        _instance = _FakeContext()

        @classmethod
        def instance(cls):
            return cls._instance

    @staticmethod
    def Poller():
        return _FakePoller(_FakeZmq.Context._instance)


def test_m3_worker_sources_exist() -> None:
    root = Path(__file__).resolve().parents[1]
    expected = [
        root / "src" / "daemon" / "cpu_worker.cpp",
        root / "src" / "daemon" / "gpu_worker.cpp",
        root / "src" / "daemon" / "dpdk_worker.cpp",
        root / "src" / "daemon" / "afxdp_worker.cpp",
        root / "src" / "daemon" / "doca_gpunetio_worker.cpp",
        root / "src" / "daemon" / "l7_worker.cpp",
        root / "src" / "daemon" / "defense_worker.cpp",
    ]
    for p in expected:
        assert p.exists(), str(p)


def test_m3_cmake_has_all_worker_targets() -> None:
    root = Path(__file__).resolve().parents[1]
    cmake = (root / "src" / "CMakeLists.txt").read_text(encoding="utf-8")
    for target in [
        "samurai_cpu_worker",
        "samurai_gpu_worker",
        "samurai_dpdk_worker",
        "samurai_afxdp_worker",
        "samurai_doca_worker",
        "samurai_l7_worker",
        "samurai_defense_worker",
    ]:
        assert target in cmake


def test_m3_prototype_happy_path_for_all_workers() -> None:
    for kind in WorkerKind:
        ctx = _FakeContext()
        zmq = _FakeZmq()
        _FakeZmq.Context._instance = ctx

        job_ep = default_job_endpoint(kind)
        event_ep = default_event_endpoint(kind)

        dispatcher = ZmqDispatcher(context=ctx, zmq_module=zmq)
        collector = ZmqEventCollector(context=ctx, zmq_module=zmq, bind=True)
        collector.ensure_worker_channel(kind, endpoint=event_ep)
        worker = ZmqWorkerPrototype(
            worker_kind=kind,
            context=ctx,
            zmq_module=zmq,
            job_endpoint=job_ep,
            event_endpoint=event_ep,
            bind_jobs=True,
            bind_events=False,
        )

        try:
            dispatcher.dispatch_start_job(
                worker_kind=kind,
                correlation_id=1000 + int(kind),
                job_id=f"job-{kind.name.lower()}",
                endpoint=job_ep,
                args={
                    "target": "127.0.0.1",
                    "port": 443,
                    "packets": 10,
                    "size": 64,
                },
            )
            assert worker.process_one(timeout_ms=10) is True
            event = collector.wait_for_terminal_event(
                correlation_id=1000 + int(kind),
                worker_kind=kind,
                ack_timeout_s=0.2,
                heartbeat_timeout_s=0.2,
                overall_timeout_s=1.0,
            )
            assert event.header.msg_type == MessageType.JOB_DONE
            assert event.payload_decoded.get("status") == "ok"
            assert event.payload_decoded.get("worker_kind") == kind.name.lower()
        finally:
            worker.close()
            collector.close()
            dispatcher.close()


def test_m3_runtime_manager_fallback_all_worker_modules() -> None:
    class _FakePopen:
        def __init__(self, cmd, **kwargs):
            self.cmd = list(cmd)
            self.kwargs = dict(kwargs)
            self.pid = 999
            self.returncode = None

        def poll(self):
            return self.returncode

        def send_signal(self, _sig):
            self.returncode = 0

        def wait(self, timeout=None):
            _ = timeout
            if self.returncode is None:
                self.returncode = 0
            return self.returncode

        def kill(self):
            self.returncode = -9

    mgr = ZmqRuntimeManager()

    with patch("ddos_samurai.zmq_runtime_manager.shutil_which", return_value=None), patch(
        "ddos_samurai.zmq_runtime_manager.subprocess.Popen", side_effect=_FakePopen
    ) as popen_mock:
        for kind in WorkerKind:
            mgr.launch_worker(kind)

    calls = [c.args[0] for c in popen_mock.call_args_list]
    assert len(calls) == len(list(WorkerKind))
    expected_modules = {WORKER_PY_MODULES[k] for k in WorkerKind}
    seen_modules = {cmd[2] for cmd in calls if len(cmd) >= 3 and cmd[:2] == [sys.executable, "-m"]}
    assert seen_modules == expected_modules
