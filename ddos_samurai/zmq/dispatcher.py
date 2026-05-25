from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .wire import (
    HEADER_SIZE_V1,
    MessageType,
    SamuraiWireHeaderV1,
    WorkerKind,
    build_job_envelope,
    default_job_endpoint,
    pack_message,
)


@dataclass(frozen=True)
class DispatchResult:
    endpoint: str
    bytes_sent: int


class ZmqDispatcher:
    """Control-plane sender for worker command channels (PUSH -> PULL)."""

    def __init__(
        self,
        *,
        context: Any | None = None,
        linger_ms: int = 0,
        zmq_module: Any | None = None,
    ) -> None:
        if zmq_module is None:
            try:
                import zmq as zmq_module  # type: ignore
            except ImportError as exc:
                raise RuntimeError("pyzmq is required for ZmqDispatcher") from exc

        self._zmq = zmq_module
        self._context = context if context is not None else self._zmq.Context.instance()
        self._linger_ms = int(linger_ms)
        self._sockets: dict[str, Any] = {}

    def close(self) -> None:
        for socket in list(self._sockets.values()):
            try:
                socket.close(linger=self._linger_ms)
            except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
                pass
        self._sockets.clear()

    def _socket_for(self, endpoint: str) -> Any:
        sock = self._sockets.get(endpoint)
        if sock is not None:
            return sock
        sock = self._context.socket(self._zmq.PUSH)
        sock.setsockopt(self._zmq.LINGER, self._linger_ms)
        sock.connect(str(endpoint))
        self._sockets[str(endpoint)] = sock
        return sock

    def _send(self, endpoint: str, payload: bytes) -> DispatchResult:
        sock = self._socket_for(endpoint)
        sock.send(payload)
        return DispatchResult(endpoint=str(endpoint), bytes_sent=len(payload))

    def send_raw(
        self,
        *,
        worker_kind: WorkerKind,
        msg_type: MessageType,
        correlation_id: int,
        job_id: str,
        payload: bytes = b"",
        endpoint: str | None = None,
    ) -> DispatchResult:
        body = bytes(payload or b"")
        header = SamuraiWireHeaderV1(
            msg_type=msg_type,
            payload_len=len(body),
            correlation_id=int(correlation_id),
            worker_kind=WorkerKind(worker_kind),
            job_id=str(job_id or ""),
        )
        frame = pack_message(header, body)
        out_endpoint = str(endpoint or default_job_endpoint(WorkerKind(worker_kind)))
        return self._send(out_endpoint, frame)

    def dispatch_start_job(
        self,
        *,
        worker_kind: WorkerKind,
        correlation_id: int,
        job_id: str,
        args: Mapping[str, Any],
        scenario_payload_ref: str = "",
        endpoint: str | None = None,
    ) -> DispatchResult:
        env = build_job_envelope(args, scenario_payload_ref=scenario_payload_ref)
        payload = env.pack()
        return self.send_raw(
            worker_kind=worker_kind,
            msg_type=MessageType.START_JOB,
            correlation_id=correlation_id,
            job_id=job_id,
            payload=payload,
            endpoint=endpoint,
        )

    def dispatch_stop_job(
        self,
        *,
        worker_kind: WorkerKind,
        correlation_id: int,
        job_id: str,
        endpoint: str | None = None,
    ) -> DispatchResult:
        return self.send_raw(
            worker_kind=worker_kind,
            msg_type=MessageType.STOP_JOB,
            correlation_id=correlation_id,
            job_id=job_id,
            payload=b"",
            endpoint=endpoint,
        )

    def dispatch_shutdown_worker(
        self,
        *,
        worker_kind: WorkerKind,
        correlation_id: int,
        job_id: str = "shutdown",
        endpoint: str | None = None,
    ) -> DispatchResult:
        return self.send_raw(
            worker_kind=worker_kind,
            msg_type=MessageType.SHUTDOWN,
            correlation_id=correlation_id,
            job_id=job_id,
            payload=b"",
            endpoint=endpoint,
        )

    @staticmethod
    def expected_start_job_frame_size() -> int:
        from .wire import JOB_ENVELOPE_SIZE_V1

        return int(HEADER_SIZE_V1 + JOB_ENVELOPE_SIZE_V1)
