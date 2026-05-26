from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .wire import (
    FlowStreamUpsertV1,
    FLOW_STREAM_UPSERT_SIZE_V1,
    FlowUpdateEventV1,
    FLOW_UPDATE_EVENT_SIZE_V1,
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
        self._flow_last_version: dict[int, int] = {}
        self._flow_last_epoch: dict[int, int] = {}
        self._flow_contract_stats: dict[str, int] = {
            "published": 0,
            "version_gap_detected": 0,
            "epoch_mismatch": 0,
            "stale_version": 0,
        }

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

    def dispatch_flow_update(
        self,
        *,
        correlation_id: int,
        job_id: str,
        event: FlowUpdateEventV1,
        allow_version_gap: bool = False,
        endpoint: str | None = None,
    ) -> DispatchResult:
        self._validate_flow_update_contract(event, allow_version_gap=allow_version_gap)
        payload = event.pack()
        out = self.send_raw(
            worker_kind=WorkerKind.GPU,
            msg_type=MessageType.FLOW_UPDATE,
            correlation_id=correlation_id,
            job_id=job_id,
            payload=payload,
            endpoint=endpoint,
        )
        flow_id = int(event.flow_id)
        self._flow_last_version[flow_id] = int(event.version)
        self._flow_last_epoch[flow_id] = int(event.epoch)
        self._flow_contract_stats["published"] = int(self._flow_contract_stats.get("published", 0) or 0) + 1
        return out

    def dispatch_flow_stream_upsert(
        self,
        *,
        correlation_id: int,
        job_id: str,
        upsert: FlowStreamUpsertV1,
        allow_version_gap: bool = False,
        endpoint: str | None = None,
    ) -> DispatchResult:
        self._validate_flow_update_contract(upsert.to_flow_update(), allow_version_gap=allow_version_gap)
        payload = upsert.pack()
        out = self.send_raw(
            worker_kind=WorkerKind.GPU,
            msg_type=MessageType.FLOW_STREAM_UPSERT,
            correlation_id=correlation_id,
            job_id=job_id,
            payload=payload,
            endpoint=endpoint,
        )
        flow_id = int(upsert.flow_id)
        self._flow_last_version[flow_id] = int(upsert.version)
        self._flow_last_epoch[flow_id] = int(upsert.epoch)
        self._flow_contract_stats["published"] = int(self._flow_contract_stats.get("published", 0) or 0) + 1
        return out

    def _validate_flow_update_contract(self, event: FlowUpdateEventV1, *, allow_version_gap: bool) -> None:
        flow_id = int(event.flow_id)
        version = int(event.version)
        epoch = int(event.epoch)
        if version & 1:
            raise ValueError("flow update version must be even/committed")
        prev_epoch = self._flow_last_epoch.get(flow_id)
        prev_version = self._flow_last_version.get(flow_id)
        if prev_epoch is None or prev_version is None:
            return
        if epoch < int(prev_epoch):
            self._flow_contract_stats["epoch_mismatch"] = int(self._flow_contract_stats.get("epoch_mismatch", 0) or 0) + 1
            raise ValueError(f"epoch mismatch detected for flow_id={flow_id}: got={epoch} prev={prev_epoch}")
        if epoch > int(prev_epoch):
            return
        if version <= int(prev_version):
            self._flow_contract_stats["stale_version"] = int(self._flow_contract_stats.get("stale_version", 0) or 0) + 1
            raise ValueError(f"stale or duplicate version for flow_id={flow_id}: got={version} prev={prev_version}")
        if version > int(prev_version) + 2:
            self._flow_contract_stats["version_gap_detected"] = int(
                self._flow_contract_stats.get("version_gap_detected", 0) or 0
            ) + 1
            if not bool(allow_version_gap):
                raise ValueError(
                    f"version gap detected for flow_id={flow_id}: got={version} expected={int(prev_version) + 2}"
                )

    def next_committed_flow_version(self, flow_id: int, *, initial_version: int = 0) -> int:
        flow_key = int(flow_id)
        current = int(self._flow_last_version.get(flow_key, int(initial_version)))
        if current & 1:
            current += 1
        return int(current + 2)

    def flow_update_contract_stats(self) -> dict[str, int]:
        return {
            "published": int(self._flow_contract_stats.get("published", 0) or 0),
            "version_gap_detected": int(self._flow_contract_stats.get("version_gap_detected", 0) or 0),
            "epoch_mismatch": int(self._flow_contract_stats.get("epoch_mismatch", 0) or 0),
            "stale_version": int(self._flow_contract_stats.get("stale_version", 0) or 0),
            "tracked_flows": int(len(self._flow_last_version)),
        }

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

    @staticmethod
    def expected_flow_update_frame_size() -> int:
        return int(HEADER_SIZE_V1 + FLOW_UPDATE_EVENT_SIZE_V1)

    @staticmethod
    def expected_flow_stream_upsert_frame_size() -> int:
        return int(HEADER_SIZE_V1 + FLOW_STREAM_UPSERT_SIZE_V1)
