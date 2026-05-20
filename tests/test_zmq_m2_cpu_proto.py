from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from ddos_samurai import orchestrator
from ddos_samurai.zmq_cpu_worker import CpuWorkerPrototype
from ddos_samurai.zmq_dispatcher import ZmqDispatcher
from ddos_samurai.zmq_event_collector import ZmqEventCollector
from ddos_samurai.zmq_runtime_manager import ZmqRuntimeManager
from ddos_samurai.zmq_wire import MessageType, WorkerKind


class _FakeSocket:
    def __init__(self, ctx: "_FakeContext", sock_type: int):
        self._ctx = ctx
        self._type = sock_type
        self._endpoint = ""
        self._closed = False

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
        self._closed = True


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


def test_m2_cpu_happy_path_start_ack_job_done() -> None:
    ctx = _FakeContext()
    zmq = _FakeZmq()
    _FakeZmq.Context._instance = ctx

    job_ep = "ipc:///tmp/samurai_jobs_cpu"
    event_ep = "ipc:///tmp/samurai_events_cpu"

    dispatcher = ZmqDispatcher(context=ctx, zmq_module=zmq)
    collector = ZmqEventCollector(context=ctx, zmq_module=zmq, bind=True)
    collector.ensure_worker_channel(WorkerKind.CPU, endpoint=event_ep)

    worker = CpuWorkerPrototype(
        context=ctx,
        zmq_module=zmq,
        job_endpoint=job_ep,
        event_endpoint=event_ep,
        bind_jobs=True,
        bind_events=False,
    )

    try:
        out = dispatcher.dispatch_start_job(
            worker_kind=WorkerKind.CPU,
            correlation_id=42,
            job_id="m2-test",
            endpoint=job_ep,
            args={
                "target": "127.0.0.1",
                "port": 443,
                "packets": 100,
                "size": 64,
                "pacing_mode": "none",
            },
        )
        assert out.bytes_sent > 0

        assert worker.process_one(timeout_ms=10) is True

        event = collector.wait_for_terminal_event(
            correlation_id=42,
            worker_kind=WorkerKind.CPU,
            ack_timeout_s=0.2,
            heartbeat_timeout_s=0.2,
            overall_timeout_s=1.0,
        )
        assert event.header.msg_type == MessageType.JOB_DONE
        assert isinstance(event.payload_decoded, dict)
        assert event.payload_decoded.get("status") == "ok"
    finally:
        worker.close()
        collector.close()
        dispatcher.close()


def test_m2_fail_fast_ack_timeout() -> None:
    ctx = _FakeContext()
    zmq = _FakeZmq()
    _FakeZmq.Context._instance = ctx

    collector = ZmqEventCollector(context=ctx, zmq_module=zmq, bind=True)
    collector.ensure_worker_channel(WorkerKind.CPU)

    with pytest.raises(TimeoutError):
        collector.wait_for_terminal_event(
            correlation_id=999,
            worker_kind=WorkerKind.CPU,
            ack_timeout_s=0.05,
            heartbeat_timeout_s=0.1,
            overall_timeout_s=0.1,
        )


def test_runtime_manager_cpu_fallback_to_python_module() -> None:
    class _FakePopen:
        def __init__(self, cmd, **kwargs):
            self.cmd = list(cmd)
            self.kwargs = dict(kwargs)
            self.pid = 12345
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
        wp = mgr.launch_worker(WorkerKind.CPU)
        assert wp.running is True
        assert popen_mock.called
        cmd = popen_mock.call_args.args[0]
        assert cmd[:3] == [sys.executable, "-m", "ddos_samurai.zmq_cpu_worker"]


def test_orchestrator_start_worker_zmq_appends_event() -> None:
    class _FakeRuntime:
        def launch_worker(self, worker_kind, **kwargs):
            _ = worker_kind
            _ = kwargs
            return None

        def stop_worker(self, worker_kind, timeout_s=1.0):
            _ = worker_kind
            _ = timeout_s
            return 0

    class _FakeDispatcher:
        def dispatch_start_job(self, **kwargs):
            _ = kwargs
            return None

        def dispatch_shutdown_worker(self, **kwargs):
            _ = kwargs
            return None

        def close(self):
            return None

    class _FakeEvent:
        def __init__(self):
            from ddos_samurai.zmq_wire import MessageType, SamuraiWireHeaderV1, WorkerKind

            self.header = SamuraiWireHeaderV1(
                msg_type=MessageType.JOB_DONE,
                payload_len=0,
                correlation_id=123,
                worker_kind=WorkerKind.CPU,
                job_id="jid",
            )
            self.payload = b""
            self.payload_decoded = {"attempted": 10, "sent": 9, "errors": 1, "status": "ok"}
            self.endpoint = "ipc:///tmp/samurai_events_cpu"

    class _FakeCollector:
        def ensure_worker_channel(self, *args, **kwargs):
            _ = args
            _ = kwargs
            return None

        def wait_for_terminal_event(self, **kwargs):
            _ = kwargs
            return _FakeEvent()

        def close(self):
            return None

    events = []
    with patch("ddos_samurai.orchestrator.ZmqRuntimeManager", return_value=_FakeRuntime()), patch(
        "ddos_samurai.orchestrator.ZmqDispatcher", return_value=_FakeDispatcher()
    ), patch("ddos_samurai.orchestrator.ZmqEventCollector", return_value=_FakeCollector()):
        orchestrator.start_worker_zmq(
            worker_id=1,
            args={"target": "127.0.0.1", "port": 443, "count": 10, "attack_vector": "basic", "compute_backend": "cpu"},
            run_events=events,
        )

    assert len(events) == 1
    ev = events[0]
    assert ev["status"] == "ok"
    assert int(ev["stats"]["attempted"]) == 10
    assert int(ev["stats"]["sent"]) == 9
    assert int(ev["stats"]["errors"]) == 1
