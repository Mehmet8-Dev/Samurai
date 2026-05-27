"""DPU authoritative flow-state model for ZMQ back-signaling.

This module is control-plane glue, not a Python dataplane bridge.  It owns the
same state transitions the BlueField/DPU runtime is expected to own and emits
committed ``FLOW_UPDATE`` events through the ZMQ GPU worker contract.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from typing import Callable

from .dispatcher import DispatchResult, ZmqDispatcher
from .wire import FlowUpdateEventV1

TCP_STATE_CLOSED = 0
TCP_STATE_SYN_SENT = 1
TCP_STATE_ESTABLISHED = 4
TCP_STATE_MIGRATING = 250
TCP_STATE_POISONED = 255

PROTO_TCP = 6
PROTO_UDP = 17


@dataclass(frozen=True)
class DpuFlowState:
    """Authoritative per-flow state mirrored to GPU hot-flow state."""

    flow_id: int
    seq_num: int = 0
    ack_num: int = 0
    src_port: int = 0
    dst_port: int = 0
    tcp_state: int = TCP_STATE_CLOSED
    flags: int = 0
    rtt_us: int = 0
    last_tx_ts: int = 0
    last_ack_ts: int = 0
    epoch: int = 1
    proto: int = PROTO_TCP
    version: int = 0
    poisoned: bool = False
    migrating: bool = False


@dataclass(frozen=True)
class DpuStatePublishResult:
    state: DpuFlowState
    event: FlowUpdateEventV1
    dispatch: DispatchResult


def publication_budget_us(rtt_us: int) -> int:
    target = int(rtt_us) // 10
    return max(50, min(1000, target))


def next_committed_version(current_version: int) -> int:
    base = int(current_version)
    if base & 1:
        base += 1
    return base + 2


class DpuStateAuthority:
    """Owns flow state and publishes DPU->GPU committed update events."""

    def __init__(
        self,
        *,
        dispatcher: ZmqDispatcher | None = None,
        time_ns: Callable[[], int] | None = None,
    ) -> None:
        self._dispatcher = dispatcher
        self._time_ns = time_ns or time.time_ns
        self._flows: dict[int, DpuFlowState] = {}

    def get(self, flow_id: int) -> DpuFlowState | None:
        return self._flows.get(int(flow_id))

    def snapshot(self) -> dict[int, DpuFlowState]:
        return dict(self._flows)

    def upsert_flow(
        self,
        flow_id: int,
        *,
        seq_num: int = 0,
        ack_num: int = 0,
        src_port: int = 0,
        dst_port: int = 0,
        tcp_state: int = TCP_STATE_CLOSED,
        flags: int = 0,
        rtt_us: int = 0,
        epoch: int = 1,
        proto: int = PROTO_TCP,
    ) -> DpuFlowState:
        flow_key = _u32(flow_id, "flow_id")
        prev = self._flows.get(flow_key)
        version = next_committed_version(prev.version if prev is not None else 0)
        state = DpuFlowState(
            flow_id=flow_key,
            seq_num=_u32(seq_num, "seq_num"),
            ack_num=_u32(ack_num, "ack_num"),
            src_port=_u16(src_port, "src_port"),
            dst_port=_u16(dst_port, "dst_port"),
            tcp_state=_u8(tcp_state, "tcp_state"),
            flags=_u16(flags, "flags"),
            rtt_us=_u32(rtt_us, "rtt_us"),
            last_tx_ts=prev.last_tx_ts if prev is not None else 0,
            last_ack_ts=prev.last_ack_ts if prev is not None else 0,
            epoch=_u64(epoch, "epoch"),
            proto=_u8(proto, "proto"),
            version=version,
        )
        self._flows[flow_key] = state
        return state

    def transition_flow(self, flow_id: int, **updates: int) -> DpuFlowState:
        flow_key = _u32(flow_id, "flow_id")
        prev = self._require(flow_key)
        allowed = {
            "seq_num",
            "ack_num",
            "src_port",
            "dst_port",
            "tcp_state",
            "flags",
            "rtt_us",
            "last_tx_ts",
            "last_ack_ts",
            "epoch",
            "proto",
        }
        unknown = sorted(set(updates) - allowed)
        if unknown:
            raise ValueError(f"unknown flow state fields: {', '.join(unknown)}")
        checked: dict[str, int] = {}
        for key, value in updates.items():
            checked[key] = _check_field(key, value)
        if "epoch" in checked and int(checked["epoch"]) < int(prev.epoch):
            raise ValueError(
                f"epoch rollback detected for flow_id={flow_key}: got={checked['epoch']} prev={prev.epoch}"
            )
        next_tcp_state = int(checked.get("tcp_state", prev.tcp_state))
        state = replace(
            prev,
            **checked,
            version=next_committed_version(prev.version),
            poisoned=next_tcp_state == TCP_STATE_POISONED,
            migrating=next_tcp_state == TCP_STATE_MIGRATING,
        )
        self._flows[flow_key] = state
        return state

    def migrate_flow(self, flow_id: int, *, new_epoch: int | None = None) -> DpuFlowState:
        prev = self._require(_u32(flow_id, "flow_id"))
        target_epoch = int(new_epoch) if new_epoch is not None else int(prev.epoch) + 1
        if target_epoch <= int(prev.epoch):
            raise ValueError(f"migration epoch must increase for flow_id={prev.flow_id}")
        state = replace(
            prev,
            epoch=_u64(target_epoch, "epoch"),
            tcp_state=TCP_STATE_MIGRATING,
            version=next_committed_version(prev.version),
            migrating=True,
        )
        self._flows[state.flow_id] = state
        return state

    def complete_migration(self, flow_id: int, *, owner_epoch: int | None = None) -> DpuFlowState:
        prev = self._require(_u32(flow_id, "flow_id"))
        if not prev.migrating and int(prev.tcp_state) != TCP_STATE_MIGRATING:
            raise ValueError(f"flow_id={prev.flow_id} is not migrating")
        target_epoch = int(owner_epoch) if owner_epoch is not None else int(prev.epoch)
        if target_epoch < int(prev.epoch):
            raise ValueError(f"migration completion epoch rollback for flow_id={prev.flow_id}")
        state = replace(
            prev,
            epoch=_u64(target_epoch, "owner_epoch"),
            tcp_state=TCP_STATE_ESTABLISHED,
            version=next_committed_version(prev.version),
            poisoned=False,
            migrating=False,
        )
        self._flows[state.flow_id] = state
        return state

    def resync_flow(self, snapshot: DpuFlowState) -> DpuFlowState:
        flow_key = _u32(snapshot.flow_id, "flow_id")
        prev = self._flows.get(flow_key)
        if prev is not None and int(snapshot.epoch) < int(prev.epoch):
            raise ValueError(f"resync epoch rollback for flow_id={flow_key}")
        state = replace(
            snapshot,
            flow_id=flow_key,
            seq_num=_u32(snapshot.seq_num, "seq_num"),
            ack_num=_u32(snapshot.ack_num, "ack_num"),
            src_port=_u16(snapshot.src_port, "src_port"),
            dst_port=_u16(snapshot.dst_port, "dst_port"),
            tcp_state=_u8(snapshot.tcp_state, "tcp_state"),
            flags=_u16(snapshot.flags, "flags"),
            rtt_us=_u32(snapshot.rtt_us, "rtt_us"),
            last_tx_ts=_u64(snapshot.last_tx_ts, "last_tx_ts"),
            last_ack_ts=_u64(snapshot.last_ack_ts, "last_ack_ts"),
            epoch=_u64(snapshot.epoch, "epoch"),
            proto=_u8(snapshot.proto, "proto"),
            version=next_committed_version(prev.version if prev is not None else 0),
            poisoned=int(snapshot.tcp_state) == TCP_STATE_POISONED,
            migrating=int(snapshot.tcp_state) == TCP_STATE_MIGRATING,
        )
        self._flows[flow_key] = state
        return state

    def poison_flow(self, flow_id: int) -> DpuFlowState:
        prev = self._require(_u32(flow_id, "flow_id"))
        state = replace(
            prev,
            tcp_state=TCP_STATE_POISONED,
            version=next_committed_version(prev.version),
            poisoned=True,
            migrating=False,
        )
        self._flows[state.flow_id] = state
        return state

    def build_update_event(
        self,
        state: DpuFlowState | int,
        *,
        dpu_ts_ns: int | None = None,
    ) -> FlowUpdateEventV1:
        st = self._require(_u32(state, "flow_id")) if isinstance(state, int) else state
        return FlowUpdateEventV1(
            version=int(st.version),
            epoch=int(st.epoch),
            flow_id=int(st.flow_id),
            tcp_seq=int(st.seq_num),
            tcp_ack=int(st.ack_num),
            src_port=int(st.src_port),
            dst_port=int(st.dst_port),
            tcp_state=int(st.tcp_state),
            proto=int(st.proto),
            flags=int(st.flags),
            rtt_us=int(st.rtt_us),
            dpu_ts_ns=int(self._time_ns() if dpu_ts_ns is None else dpu_ts_ns),
        )

    def publish_flow(
        self,
        flow_id: int,
        *,
        correlation_id: int,
        job_id: str | None = None,
        dispatcher: ZmqDispatcher | None = None,
        endpoint: str | None = None,
        allow_version_gap: bool = False,
    ) -> DpuStatePublishResult:
        st = self._require(_u32(flow_id, "flow_id"))
        ev = self.build_update_event(st)
        disp = dispatcher or self._dispatcher
        if disp is None:
            disp = ZmqDispatcher()
        out = disp.dispatch_flow_update(
            correlation_id=int(correlation_id),
            job_id=str(job_id or f"dpu-flow-{st.flow_id}"),
            event=ev,
            endpoint=endpoint,
            allow_version_gap=bool(allow_version_gap),
        )
        return DpuStatePublishResult(state=st, event=ev, dispatch=out)

    def _require(self, flow_id: int) -> DpuFlowState:
        flow_key = int(flow_id)
        try:
            return self._flows[flow_key]
        except KeyError as exc:
            raise KeyError(f"unknown DPU flow_id={flow_key}") from exc


def _check_field(name: str, value: int) -> int:
    if name in {"seq_num", "ack_num", "rtt_us"}:
        return _u32(value, name)
    if name in {"src_port", "dst_port", "flags"}:
        return _u16(value, name)
    if name in {"tcp_state", "proto"}:
        return _u8(value, name)
    if name in {"last_tx_ts", "last_ack_ts", "epoch"}:
        return _u64(value, name)
    raise ValueError(f"unknown flow state field: {name}")


def _u8(value: int, name: str) -> int:
    out = int(value)
    if not 0 <= out <= 0xFF:
        raise ValueError(f"{name} must fit uint8")
    return out


def _u16(value: int, name: str) -> int:
    out = int(value)
    if not 0 <= out <= 0xFFFF:
        raise ValueError(f"{name} must fit uint16")
    return out


def _u32(value: int | DpuFlowState, name: str) -> int:
    if isinstance(value, DpuFlowState):
        value = value.flow_id
    out = int(value)
    if not 0 <= out <= 0xFFFFFFFF:
        raise ValueError(f"{name} must fit uint32")
    return out


def _u64(value: int, name: str) -> int:
    out = int(value)
    if not 0 <= out <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"{name} must fit uint64")
    return out
