from __future__ import annotations

import importlib
import json
import os
import statistics
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from ddos_samurai.zmq.dispatcher import ZmqDispatcher
from ddos_samurai.zmq.event_collector import ZmqEventCollector
from ddos_samurai.zmq.runtime_manager import ZmqRuntimeManager
from ddos_samurai.zmq.wire import MessageType, WorkerKind
from ddos_samurai.zmq.worker_prototype import ZmqWorkerPrototype


pytestmark = [pytest.mark.ci_safe, pytest.mark.benchmark]

FORBIDDEN_CEXT_IMPORTS = [
    "ddos_samurai.fast_sender",
    "ddos_samurai.xdp_sender",
    "ddos_samurai.dataplane_core",
    "ddos_samurai.pacing_engine",
]

CONTROL_PLANE_IMPORT_CHAIN = [
    "ddos_samurai",
    "ddos_samurai.orchestrator",
    "ddos_samurai.cli.runtime",
    "ddos_samurai.control.slave",
]


class _FakeSocket:
    def __init__(self, ctx: "_FakeContext", _sock_type: int):
        self._ctx = ctx
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
        queue = self._ctx.ensure(self._endpoint)
        if not queue:
            raise RuntimeError("empty queue")
        return queue.pop(0)

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
            if self._ctx.ensure(sock.endpoint):
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


def _run_control_plane_import_cycle() -> float:
    for name in [*FORBIDDEN_CEXT_IMPORTS, *CONTROL_PLANE_IMPORT_CHAIN]:
        sys.modules.pop(name, None)

    start = time.perf_counter()
    for name in CONTROL_PLANE_IMPORT_CHAIN:
        importlib.import_module(name)
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    forbidden_seen = [name for name in FORBIDDEN_CEXT_IMPORTS if name in sys.modules]
    assert not forbidden_seen, f"forbidden legacy imports detected: {forbidden_seen}"
    return float(elapsed_ms)


def _pick_numeric(payload: dict, keys: list[str]) -> float | None:
    for key in keys:
        if key in payload and payload[key] is not None:
            try:
                return float(payload[key])
            except (TypeError, ValueError):
                continue
    return None


def test_m7_runtime_import_guard_benchmark() -> None:
    loops = int(os.environ.get("SAMURAI_M7_IMPORT_LOOPS", "20"))
    max_p95_ms = float(os.environ.get("SAMURAI_M7_IMPORT_P95_MS_MAX", "600"))

    samples_ms = [_run_control_plane_import_cycle() for _ in range(max(5, loops))]
    p95_ms = sorted(samples_ms)[int(round((len(samples_ms) - 1) * 0.95))]
    median_ms = statistics.median(samples_ms)

    assert p95_ms <= max_p95_ms, {
        "samples_ms": samples_ms,
        "median_ms": median_ms,
        "p95_ms": p95_ms,
        "limit_ms": max_p95_ms,
    }


def test_m7_zmq_soak_no_event_loss_or_backlog() -> None:
    loops = int(os.environ.get("SAMURAI_M7_SOAK_JOBS", "300"))

    ctx = _FakeContext()
    zmq = _FakeZmq()
    _FakeZmq.Context._instance = ctx

    worker_kind = WorkerKind.CPU
    job_ep = "ipc:///tmp/samurai_jobs_cpu"
    event_ep = "ipc:///tmp/samurai_events_cpu"

    dispatcher = ZmqDispatcher(context=ctx, zmq_module=zmq)
    collector = ZmqEventCollector(context=ctx, zmq_module=zmq, bind=True)
    collector.ensure_worker_channel(worker_kind, endpoint=event_ep)
    worker = ZmqWorkerPrototype(
        worker_kind=worker_kind,
        context=ctx,
        zmq_module=zmq,
        job_endpoint=job_ep,
        event_endpoint=event_ep,
        bind_jobs=True,
        bind_events=False,
    )

    done_count = 0
    try:
        for cid in range(1, max(10, loops) + 1):
            dispatcher.dispatch_start_job(
                worker_kind=worker_kind,
                correlation_id=cid,
                job_id=f"m7-soak-{cid}",
                endpoint=job_ep,
                args={"target": "127.0.0.1", "port": 443, "packets": 8, "size": 64},
            )
            assert worker.process_one(timeout_ms=10) is True
            terminal = collector.wait_for_terminal_event(
                correlation_id=cid,
                worker_kind=worker_kind,
                ack_timeout_s=0.1,
                heartbeat_timeout_s=0.2,
                overall_timeout_s=1.0,
            )
            assert terminal.header.msg_type == MessageType.JOB_DONE
            done_count += 1
    finally:
        worker.close()
        collector.close()
        dispatcher.close()

    assert done_count == max(10, loops)
    assert ctx.ensure(job_ep) == []
    assert ctx.ensure(event_ep) == []


def test_m7_worker_crash_recovery_restart_under_budget() -> None:
    budget_ms = float(os.environ.get("SAMURAI_M7_CRASH_RECOVERY_MAX_MS", "500"))

    class _FakePopen:
        _next_pid = 5000

        def __init__(self, cmd, **kwargs):
            self.cmd = list(cmd)
            self.kwargs = dict(kwargs)
            self.pid = _FakePopen._next_pid
            _FakePopen._next_pid += 1
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
    with patch("ddos_samurai.zmq.runtime_manager.shutil_which", return_value="/usr/bin/samurai_cpu_worker"), patch(
        "ddos_samurai.zmq.runtime_manager.subprocess.Popen", side_effect=_FakePopen
    ):
        wp1 = mgr.launch_worker(WorkerKind.CPU)
        wp1.process.returncode = -11  # crash simulation (segfault)

        t0 = time.perf_counter()
        wp2 = mgr.launch_worker(WorkerKind.CPU)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        assert wp2.pid != wp1.pid
        assert elapsed_ms <= budget_ms, {"elapsed_ms": elapsed_ms, "budget_ms": budget_ms}
        health = mgr.worker_health(WorkerKind.CPU)
        assert int(health.get("running", 0)) == 1


def test_m7_lab_perf_report_thresholds_if_provided() -> None:
    report_path = str(os.environ.get("SAMURAI_M7_PERF_REPORT", "") or "").strip()
    if not report_path:
        pytest.skip("SAMURAI_M7_PERF_REPORT not set; skipping dedicated-lab M7 thresholds")

    payload = json.loads(Path(report_path).read_text(encoding="utf-8"))
    flat = dict(payload if isinstance(payload, dict) else {})

    metrics = flat.get("metrics")
    if isinstance(metrics, dict):
        flat = {**flat, **metrics}

    dpdk_pps = _pick_numeric(flat, ["dpdk_pps", "effective_pps", "pps"])
    if dpdk_pps is None:
        dpdk_mpps = _pick_numeric(flat, ["dpdk_mpps"])
        if dpdk_mpps is not None:
            dpdk_pps = dpdk_mpps * 1_000_000.0

    python_cpu_pct = _pick_numeric(flat, ["python_cpu_pct", "python_cpu_percent", "control_plane_cpu_pct"])
    soak_seconds = _pick_numeric(flat, ["soak_duration_s", "soak_seconds", "duration_s"])
    crash_recovery_ms = _pick_numeric(flat, ["worker_restart_ms", "crash_recovery_ms", "restart_ms"])
    legacy_import_count = _pick_numeric(flat, ["legacy_cext_import_count", "forbidden_import_count"])
    if legacy_import_count is None and isinstance(flat.get("forbidden_imports"), list):
        legacy_import_count = float(len(flat.get("forbidden_imports")))

    assert dpdk_pps is not None and dpdk_pps >= 10_000_000.0, {"dpdk_pps": dpdk_pps}
    assert python_cpu_pct is not None and python_cpu_pct < 10.0, {"python_cpu_pct": python_cpu_pct}
    assert soak_seconds is not None and soak_seconds >= 3600.0, {"soak_seconds": soak_seconds}
    assert crash_recovery_ms is not None and crash_recovery_ms < 500.0, {"crash_recovery_ms": crash_recovery_ms}
    assert legacy_import_count is not None and legacy_import_count == 0.0, {
        "legacy_import_count": legacy_import_count
    }
