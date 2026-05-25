from __future__ import annotations

import argparse
import time
from typing import Any

from .wire import (
    MessageType,
    MetricSnapshotV1,
    SamuraiWireHeaderV1,
    WireProtocolError,
    WorkerKind,
    default_event_endpoint,
    default_job_endpoint,
    encode_job_done_json,
    pack_message,
    unpack_message,
)


class ZmqWorkerPrototype:
    """Generic worker prototype used for M2/M3 smoke paths."""

    def __init__(
        self,
        *,
        worker_kind: WorkerKind,
        context: Any | None = None,
        zmq_module: Any | None = None,
        job_endpoint: str | None = None,
        event_endpoint: str | None = None,
        bind_jobs: bool = True,
        bind_events: bool = False,
        heartbeat_interval_s: float = 1.0,
    ) -> None:
        if zmq_module is None:
            try:
                import zmq as zmq_module  # type: ignore
            except ImportError as exc:
                raise RuntimeError("pyzmq is required for ZmqWorkerPrototype") from exc

        self._kind = WorkerKind(worker_kind)
        self._kind_name = self._kind.name.lower()
        self._zmq = zmq_module
        self._context = context if context is not None else self._zmq.Context.instance()
        self._job_endpoint = str(job_endpoint or default_job_endpoint(self._kind))
        self._event_endpoint = str(event_endpoint or default_event_endpoint(self._kind))
        self._bind_jobs = bool(bind_jobs)
        self._bind_events = bool(bind_events)
        self._heartbeat_interval_s = float(max(0.05, heartbeat_interval_s))

        self._job_sock = self._context.socket(self._zmq.PULL)
        self._event_sock = self._context.socket(self._zmq.PUSH)
        if self._bind_jobs:
            self._job_sock.bind(self._job_endpoint)
        else:
            self._job_sock.connect(self._job_endpoint)
        if self._bind_events:
            self._event_sock.bind(self._event_endpoint)
        else:
            self._event_sock.connect(self._event_endpoint)

        self._alive = True
        self._active_correlations: set[int] = set()

    def close(self) -> None:
        self._alive = False
        try:
            self._job_sock.close(linger=0)
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
            pass
        try:
            self._event_sock.close(linger=0)
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
            pass

    def _emit(self, *, msg_type: MessageType, correlation_id: int, job_id: str, payload: bytes = b"") -> None:
        payload_bytes = bytes(payload or b"")
        header = SamuraiWireHeaderV1(
            msg_type=msg_type,
            payload_len=len(payload_bytes),
            correlation_id=int(correlation_id),
            worker_kind=self._kind,
            job_id=str(job_id or ""),
        )
        self._event_sock.send(pack_message(header, payload_bytes))

    def _emit_error(self, *, correlation_id: int, job_id: str, reason: str) -> None:
        self._emit(
            msg_type=MessageType.ERROR,
            correlation_id=correlation_id,
            job_id=job_id,
            payload=str(reason or "error").encode("utf-8", errors="replace"),
        )

    def _handle_start_job(self, header: SamuraiWireHeaderV1, payload: bytes) -> None:
        _ = payload
        cid = int(header.correlation_id)
        job_id = str(header.job_id)
        if cid in self._active_correlations:
            self._emit_error(
                correlation_id=cid,
                job_id=job_id,
                reason="duplicate_correlation_id",
            )
            return
        self._active_correlations.add(cid)

        self._emit(msg_type=MessageType.ACK, correlation_id=cid, job_id=job_id)
        snap = MetricSnapshotV1(
            timestamp_ns=time.monotonic_ns(),
            packets_sent=0,
            packets_errors=0,
            bytes_sent=0,
            actual_rps=0.0,
            jitter_p99_ns=0.0,
            rate_accuracy_pct=100.0,
            busywait_cycles=0,
            sleep_calls=0,
        )
        self._emit(
            msg_type=MessageType.METRIC_SNAPSHOT,
            correlation_id=cid,
            job_id=job_id,
            payload=snap.pack(),
        )

        done = {
            "status": "ok",
            "worker_kind": self._kind_name,
            "correlation_id": cid,
            "job_id": job_id,
            "packets_sent": 0,
            "packets_errors": 0,
            "bytes_sent": 0,
            "note": f"{self._kind_name}_worker_prototype",
        }
        self._emit(
            msg_type=MessageType.JOB_DONE,
            correlation_id=cid,
            job_id=job_id,
            payload=encode_job_done_json(done),
        )
        self._active_correlations.discard(cid)

    def process_one(self, *, timeout_ms: int = 200) -> bool:
        if not self._alive:
            return False
        poller = self._zmq.Poller()
        poller.register(self._job_sock, self._zmq.POLLIN)
        ready = dict(poller.poll(timeout=int(timeout_ms)))
        if self._job_sock not in ready:
            return False

        frame = self._job_sock.recv()
        try:
            header, payload = unpack_message(frame)
        except WireProtocolError as exc:
            self._emit_error(correlation_id=0, job_id="invalid", reason=f"wire_error:{exc}")
            return True

        if header.msg_type == MessageType.START_JOB:
            self._handle_start_job(header, payload)
            return True
        if header.msg_type == MessageType.STOP_JOB:
            self._emit(msg_type=MessageType.ACK, correlation_id=header.correlation_id, job_id=header.job_id)
            done = {
                "status": "stopped",
                "worker_kind": self._kind_name,
                "correlation_id": int(header.correlation_id),
                "job_id": str(header.job_id),
            }
            self._emit(
                msg_type=MessageType.JOB_DONE,
                correlation_id=header.correlation_id,
                job_id=header.job_id,
                payload=encode_job_done_json(done),
            )
            self._active_correlations.discard(int(header.correlation_id))
            return True
        if header.msg_type == MessageType.SHUTDOWN:
            self._emit(msg_type=MessageType.ACK, correlation_id=header.correlation_id, job_id=header.job_id)
            self._alive = False
            return True

        self._emit_error(
            correlation_id=header.correlation_id,
            job_id=header.job_id,
            reason=f"unsupported_msg_type:{int(header.msg_type)}",
        )
        return True

    def serve_forever(self) -> int:
        last_hb = time.monotonic()
        while self._alive:
            handled = self.process_one(timeout_ms=100)
            now = time.monotonic()
            if (now - last_hb) >= self._heartbeat_interval_s:
                self._emit(
                    msg_type=MessageType.HEARTBEAT,
                    correlation_id=0,
                    job_id="heartbeat",
                )
                last_hb = now
            if not handled:
                continue
        return 0


def parse_worker_kind(raw: str) -> WorkerKind:
    name = str(raw or "cpu").strip().lower()
    aliases = {
        "cpu": WorkerKind.CPU,
        "gpu": WorkerKind.GPU,
        "dpdk": WorkerKind.DPDK,
        "af_xdp": WorkerKind.AF_XDP,
        "afxdp": WorkerKind.AF_XDP,
        "doca": WorkerKind.DOCA,
        "l7": WorkerKind.L7,
        "defense": WorkerKind.DEFENSE,
        "scenario": WorkerKind.SCENARIO,
    }
    if name in aliases:
        return aliases[name]
    try:
        return WorkerKind(int(name))
    except (ValueError, TypeError):
        raise ValueError(f"unknown worker kind: {raw}")


def main(argv: list[str] | None = None, *, default_kind: WorkerKind = WorkerKind.CPU) -> int:
    parser = argparse.ArgumentParser(description="DDoSamurai ZMQ generic worker prototype")
    parser.add_argument("--worker-kind", default=default_kind.name.lower())
    parser.add_argument("--job-endpoint", default="")
    parser.add_argument("--event-endpoint", default="")
    parser.add_argument("--jobs-mode", choices=("bind", "connect"), default="bind")
    parser.add_argument("--events-mode", choices=("bind", "connect"), default="connect")
    args = parser.parse_args(argv)

    kind = parse_worker_kind(str(args.worker_kind))
    bind_jobs = str(args.jobs_mode) == "bind"
    bind_events = str(args.events_mode) == "bind"

    worker = ZmqWorkerPrototype(
        worker_kind=kind,
        job_endpoint=(str(args.job_endpoint).strip() or default_job_endpoint(kind)),
        event_endpoint=(str(args.event_endpoint).strip() or default_event_endpoint(kind)),
        bind_jobs=bind_jobs,
        bind_events=bind_events,
    )
    try:
        return worker.serve_forever()
    finally:
        worker.close()
