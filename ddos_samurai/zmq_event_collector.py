from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from .zmq_wire import (
    HEADER_SIZE_V1,
    METRIC_SNAPSHOT_SIZE_V1,
    MessageType,
    MetricSnapshotV1,
    SamuraiWireHeaderV1,
    WireProtocolError,
    WorkerKind,
    decode_job_done_json,
    default_event_endpoint,
    unpack_message,
)


@dataclass(frozen=True)
class WorkerEvent:
    header: SamuraiWireHeaderV1
    payload: bytes
    payload_decoded: Any
    endpoint: str


class ZmqEventCollector:
    """Control-plane receiver for worker event channels (PUSH -> PULL)."""

    def __init__(
        self,
        *,
        context: Any | None = None,
        linger_ms: int = 0,
        bind: bool = True,
        zmq_module: Any | None = None,
    ) -> None:
        if zmq_module is None:
            try:
                import zmq as zmq_module  # type: ignore
            except ImportError as exc:
                raise RuntimeError("pyzmq is required for ZmqEventCollector") from exc

        self._zmq = zmq_module
        self._context = context if context is not None else self._zmq.Context.instance()
        self._linger_ms = int(linger_ms)
        self._bind = bool(bind)
        self._sockets: dict[str, Any] = {}

    def close(self) -> None:
        for socket in list(self._sockets.values()):
            try:
                socket.close(linger=self._linger_ms)
            except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
                pass
        self._sockets.clear()

    def ensure_worker_channel(self, worker_kind: WorkerKind, endpoint: str | None = None) -> str:
        out_endpoint = str(endpoint or default_event_endpoint(WorkerKind(worker_kind)))
        if out_endpoint in self._sockets:
            return out_endpoint
        sock = self._context.socket(self._zmq.PULL)
        sock.setsockopt(self._zmq.LINGER, self._linger_ms)
        if self._bind:
            sock.bind(out_endpoint)
        else:
            sock.connect(out_endpoint)
        self._sockets[out_endpoint] = sock
        return out_endpoint

    def _decode_payload(self, header: SamuraiWireHeaderV1, payload: bytes) -> Any:
        if header.msg_type == MessageType.METRIC_SNAPSHOT and len(payload) == METRIC_SNAPSHOT_SIZE_V1:
            return MetricSnapshotV1.unpack(payload)
        if header.msg_type == MessageType.JOB_DONE:
            return decode_job_done_json(payload)
        if header.msg_type == MessageType.ERROR:
            try:
                return payload.decode("utf-8", errors="replace")
            except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
                return ""
        return None

    def poll_once(self, timeout_ms: int = 100) -> WorkerEvent | None:
        if not self._sockets:
            return None
        poller = self._zmq.Poller()
        for sock in self._sockets.values():
            poller.register(sock, self._zmq.POLLIN)
        ready = dict(poller.poll(timeout=int(timeout_ms)))
        if not ready:
            return None

        for endpoint, sock in self._sockets.items():
            if sock not in ready:
                continue
            frame = sock.recv()
            header, payload = unpack_message(frame)
            decoded = self._decode_payload(header, payload)
            return WorkerEvent(
                header=header,
                payload=payload,
                payload_decoded=decoded,
                endpoint=endpoint,
            )
        return None

    def wait_for_terminal_event(
        self,
        *,
        correlation_id: int,
        worker_kind: WorkerKind,
        ack_timeout_s: float = 2.0,
        heartbeat_timeout_s: float = 5.0,
        overall_timeout_s: float = 120.0,
    ) -> WorkerEvent:
        self.ensure_worker_channel(worker_kind)
        start = time.monotonic()
        ack_received = False
        last_heartbeat = start

        while True:
            now = time.monotonic()
            if not ack_received and (now - start) > float(ack_timeout_s):
                raise TimeoutError(
                    f"ACK timeout for correlation_id={correlation_id} after {ack_timeout_s:.3f}s"
                )
            if ack_received and (now - last_heartbeat) > float(heartbeat_timeout_s):
                raise TimeoutError(
                    f"HEARTBEAT timeout for correlation_id={correlation_id} after {heartbeat_timeout_s:.3f}s"
                )
            if (now - start) > float(overall_timeout_s):
                raise TimeoutError(
                    f"overall timeout for correlation_id={correlation_id} after {overall_timeout_s:.3f}s"
                )

            event = self.poll_once(timeout_ms=100)
            if event is None:
                continue
            if event.header.worker_kind != WorkerKind(worker_kind):
                continue
            if int(event.header.correlation_id) != int(correlation_id):
                continue

            if event.header.msg_type == MessageType.ACK:
                ack_received = True
                last_heartbeat = time.monotonic()
                continue
            if event.header.msg_type == MessageType.HEARTBEAT:
                last_heartbeat = time.monotonic()
                continue
            if event.header.msg_type == MessageType.METRIC_SNAPSHOT:
                last_heartbeat = time.monotonic()
                continue
            if event.header.msg_type in {MessageType.ERROR, MessageType.JOB_DONE}:
                return event

            raise WireProtocolError(f"unexpected msg_type for job wait: {event.header.msg_type}")
