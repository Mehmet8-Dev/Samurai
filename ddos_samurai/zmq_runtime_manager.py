from __future__ import annotations

import os
import signal
import subprocess
import sys
from shutil import which as shutil_which
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .zmq_wire import WorkerKind


WORKER_BINARIES: dict[WorkerKind, str] = {
    WorkerKind.CPU: "samurai_cpu_worker",
    WorkerKind.GPU: "samurai_gpu_worker",
    WorkerKind.DPDK: "samurai_dpdk_worker",
    WorkerKind.AF_XDP: "samurai_afxdp_worker",
    WorkerKind.DOCA: "samurai_doca_worker",
    WorkerKind.L7: "samurai_l7_worker",
    WorkerKind.DEFENSE: "samurai_defense_worker",
}


@dataclass
class WorkerProcess:
    worker_kind: WorkerKind
    binary: str
    process: subprocess.Popen

    @property
    def pid(self) -> int:
        return int(self.process.pid)

    @property
    def running(self) -> bool:
        return self.process.poll() is None


class ZmqRuntimeManager:
    """Starts/stops detached worker daemons for decoupled dataplane."""

    def __init__(self) -> None:
        self._workers: dict[WorkerKind, WorkerProcess] = {}

    def _resolve_binary(self, worker_kind: WorkerKind, *, search_dir: str | None = None) -> str:
        bin_name = WORKER_BINARIES[WorkerKind(worker_kind)]
        if search_dir:
            candidate = Path(search_dir) / bin_name
            if candidate.exists() and os.access(candidate, os.X_OK):
                return str(candidate)
        return str(bin_name)

    def launch_worker(
        self,
        worker_kind: WorkerKind,
        *,
        search_dir: str | None = None,
        extra_args: Sequence[str] | None = None,
        env: dict[str, str] | None = None,
    ) -> WorkerProcess:
        kind = WorkerKind(worker_kind)
        current = self._workers.get(kind)
        if current is not None and current.running:
            return current

        binary = self._resolve_binary(kind, search_dir=search_dir)
        cmd = [binary, *(list(extra_args or []))]
        if kind == WorkerKind.CPU and shutil_which(binary) is None:
            cmd = [sys.executable, "-m", "ddos_samurai.zmq_cpu_worker", *(list(extra_args or []))]
            binary = f"{sys.executable} -m ddos_samurai.zmq_cpu_worker"
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
            env=dict(os.environ, **(env or {})),
        )
        wp = WorkerProcess(worker_kind=kind, binary=binary, process=proc)
        self._workers[kind] = wp
        return wp

    def stop_worker(self, worker_kind: WorkerKind, *, timeout_s: float = 3.0) -> int:
        kind = WorkerKind(worker_kind)
        wp = self._workers.get(kind)
        if wp is None:
            return 0
        proc = wp.process
        if proc.poll() is not None:
            self._workers.pop(kind, None)
            return int(proc.returncode or 0)

        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=float(timeout_s))
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=1.0)
        rc = int(proc.returncode or 0)
        self._workers.pop(kind, None)
        return rc

    def worker_health(self, worker_kind: WorkerKind) -> dict[str, int | str]:
        kind = WorkerKind(worker_kind)
        wp = self._workers.get(kind)
        if wp is None:
            return {"running": 0, "pid": -1, "returncode": 0}
        rc = wp.process.poll()
        return {
            "running": 1 if rc is None else 0,
            "pid": int(wp.process.pid),
            "returncode": 0 if rc is None else int(rc),
            "binary": wp.binary,
        }

    def stop_all(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for kind in list(self._workers.keys()):
            out[kind.name.lower()] = int(self.stop_worker(kind))
        return out
