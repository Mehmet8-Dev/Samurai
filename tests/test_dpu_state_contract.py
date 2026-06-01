from __future__ import annotations

from ddos_samurai.zmq.dpu_state import (
    DpuStateAuthority,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_MIGRATING,
    TCP_STATE_POISONED,
    publication_budget_us,
)
from ddos_samurai.zmq.wire import MessageType, WorkerKind, unpack_message


class _FakeSocket:
    def __init__(self, ctx: "_FakeContext", sock_type: int):
        self._ctx = ctx
        self._endpoint = ""
        self._type = sock_type

    def setsockopt(self, _key, _value):
        return None

    def connect(self, endpoint: str):
        self._endpoint = str(endpoint)
        self._ctx.ensure(self._endpoint)

    def send(self, payload: bytes):
        self._ctx.ensure(self._endpoint).append(bytes(payload))

    def close(self, linger=0):
        _ = linger
        return None


class _FakeContext:
    def __init__(self):
        self._queues: dict[str, list[bytes]] = {}

    def ensure(self, endpoint: str) -> list[bytes]:
        self._queues.setdefault(endpoint, [])
        return self._queues[endpoint]

    def socket(self, sock_type: int):
        return _FakeSocket(self, sock_type)


class _FakeZmq:
    PUSH = 1
    LINGER = 17

    class Context:
        _instance = _FakeContext()

        @classmethod
        def instance(cls):
            return cls._instance


def test_dpu_state_upsert_publish_emits_committed_gpu_flow_update() -> None:
    from ddos_samurai.zmq import DpuStateAuthority as ExportedAuthority
    from ddos_samurai.zmq.dispatcher import ZmqDispatcher

    ctx = _FakeContext()
    zmq = _FakeZmq()
    endpoint = "ipc:///tmp/samurai_dpu_state_to_gpu"
    dispatcher = ZmqDispatcher(context=ctx, zmq_module=zmq)
    authority = ExportedAuthority(dispatcher=dispatcher, time_ns=lambda: 123456)

    try:
        state = authority.upsert_flow(
            42,
            seq_num=1000,
            ack_num=900,
            src_port=40000,
            dst_port=443,
            tcp_state=TCP_STATE_ESTABLISHED,
            flags=0x18,
            rtt_us=750,
            epoch=3,
        )
        assert state.version == 2

        result = authority.publish_flow(42, correlation_id=99, endpoint=endpoint)

        header, payload = unpack_message(ctx.ensure(endpoint)[0])
        assert result.event.version == 2
        assert result.event.epoch == 3
        assert result.event.flow_id == 42
        assert result.event.tcp_seq == 1000
        assert result.event.tcp_ack == 900
        assert result.event.dpu_ts_ns == 123456
        assert header.worker_kind == WorkerKind.GPU
        assert header.msg_type == MessageType.FLOW_UPDATE
        assert header.correlation_id == 99
        assert result.dispatch.bytes_sent == len(ctx.ensure(endpoint)[0])
        assert payload == result.event.pack()
    finally:
        dispatcher.close()


def test_dpu_state_versions_advance_by_committed_seqlock_steps() -> None:
    authority = DpuStateAuthority(time_ns=lambda: 1)

    first = authority.upsert_flow(7, seq_num=10, epoch=1)
    second = authority.transition_flow(7, seq_num=11, ack_num=5)
    third = authority.transition_flow(7, flags=0x12)

    assert first.version == 2
    assert second.version == 4
    assert third.version == 6
    assert third.seq_num == 11
    assert third.ack_num == 5
    assert third.flags == 0x12
    assert authority.build_update_event(7).version == 6


def test_dpu_state_rejects_epoch_rollback_and_marks_migration() -> None:
    authority = DpuStateAuthority()
    authority.upsert_flow(8, epoch=5)

    try:
        authority.transition_flow(8, epoch=4)
    except ValueError as exc:
        assert "epoch rollback" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("epoch rollback accepted")

    migrated = authority.migrate_flow(8)
    assert migrated.epoch == 6
    assert migrated.version == 4
    assert migrated.tcp_state == TCP_STATE_MIGRATING
    assert migrated.migrating is True


def test_dpu_state_poison_and_publication_budget_contract() -> None:
    authority = DpuStateAuthority()
    authority.upsert_flow(9, epoch=1, rtt_us=900)
    poisoned = authority.poison_flow(9)

    assert poisoned.tcp_state == TCP_STATE_POISONED
    assert poisoned.poisoned is True
    assert poisoned.version == 4
    assert publication_budget_us(10) == 50
    assert publication_budget_us(900) == 90
    assert publication_budget_us(50000) == 1000
