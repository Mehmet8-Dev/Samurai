from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Mapping

SAMURAI_WIRE_MAGIC = 0x534D5249  # "SMRI"
WIRE_VERSION_V1 = 1


class WireProtocolError(ValueError):
    """Raised when wire payload/header validation fails."""


class MessageType(IntEnum):
    START_JOB = 1
    STOP_JOB = 2
    SHUTDOWN = 3

    ACK = 10
    HEARTBEAT = 11

    METRIC_SNAPSHOT = 20

    ERROR = 30

    JOB_DONE = 40


class WorkerKind(IntEnum):
    CPU = 1
    GPU = 2
    DPDK = 3
    AF_XDP = 4
    DOCA = 5
    L7 = 6
    DEFENSE = 7


DEFAULT_JOB_ENDPOINTS: dict[WorkerKind, str] = {
    WorkerKind.CPU: "ipc:///tmp/samurai_jobs_cpu",
    WorkerKind.GPU: "ipc:///tmp/samurai_jobs_gpu",
    WorkerKind.DPDK: "ipc:///tmp/samurai_jobs_dpdk",
    WorkerKind.AF_XDP: "ipc:///tmp/samurai_jobs_afxdp",
    WorkerKind.DOCA: "ipc:///tmp/samurai_jobs_doca",
    WorkerKind.L7: "ipc:///tmp/samurai_jobs_l7",
    WorkerKind.DEFENSE: "ipc:///tmp/samurai_jobs_defense",
}

DEFAULT_EVENT_ENDPOINTS: dict[WorkerKind, str] = {
    WorkerKind.CPU: "ipc:///tmp/samurai_events_cpu",
    WorkerKind.GPU: "ipc:///tmp/samurai_events_gpu",
    WorkerKind.DPDK: "ipc:///tmp/samurai_events_dpdk",
    WorkerKind.AF_XDP: "ipc:///tmp/samurai_events_afxdp",
    WorkerKind.DOCA: "ipc:///tmp/samurai_events_doca",
    WorkerKind.L7: "ipc:///tmp/samurai_events_l7",
    WorkerKind.DEFENSE: "ipc:///tmp/samurai_events_defense",
}


def default_job_endpoint(worker_kind: WorkerKind) -> str:
    return str(DEFAULT_JOB_ENDPOINTS[WorkerKind(worker_kind)])


def default_event_endpoint(worker_kind: WorkerKind) -> str:
    return str(DEFAULT_EVENT_ENDPOINTS[WorkerKind(worker_kind)])


class PacingMode(IntEnum):
    NONE = 0
    RPS = 1
    IPG = 2
    BURST = 3


class JitterModel(IntEnum):
    NONE = 0
    UNIFORM = 1
    GAUSSIAN = 2
    EXPONENTIAL = 3


_HEADER_STRUCT = struct.Struct("<IBBIHQB32s3s")
_JOB_ENVELOPE_STRUCT = struct.Struct("<16sHIIBdQIQBdiB16sII64s3s")
# NOTE: Field definitions naturally total 64 bytes.
_METRIC_SNAPSHOT_STRUCT = struct.Struct("<QQQQdddII")

HEADER_SIZE_V1 = _HEADER_STRUCT.size
JOB_ENVELOPE_SIZE_V1 = _JOB_ENVELOPE_STRUCT.size
METRIC_SNAPSHOT_SIZE_V1 = _METRIC_SNAPSHOT_STRUCT.size


def _pack_fixed_string(value: str, size: int, field_name: str) -> bytes:
    raw = str(value or "").encode("utf-8")
    if len(raw) >= size:
        raise WireProtocolError(f"{field_name} too long: {len(raw)} >= {size}")
    return raw + (b"\x00" * (size - len(raw)))


def _unpack_fixed_string(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


@dataclass(frozen=True)
class SamuraiWireHeaderV1:
    msg_type: MessageType
    payload_len: int
    correlation_id: int
    worker_kind: WorkerKind
    job_id: str
    flags: int = 0
    magic: int = SAMURAI_WIRE_MAGIC
    version: int = WIRE_VERSION_V1

    def pack(self) -> bytes:
        if self.version != WIRE_VERSION_V1:
            raise WireProtocolError(f"unsupported version: {self.version}")
        if self.magic != SAMURAI_WIRE_MAGIC:
            raise WireProtocolError(f"invalid magic: 0x{self.magic:08X}")
        if self.payload_len < 0:
            raise WireProtocolError("payload_len must be >= 0")
        if self.flags < 0 or self.flags > 0xFFFF:
            raise WireProtocolError("flags must fit uint16")
        if self.correlation_id < 0 or self.correlation_id > 0xFFFFFFFFFFFFFFFF:
            raise WireProtocolError("correlation_id must fit uint64")
        job_id_raw = _pack_fixed_string(self.job_id, 32, "job_id")
        return _HEADER_STRUCT.pack(
            int(self.magic),
            int(self.version),
            int(self.msg_type),
            int(self.payload_len),
            int(self.flags),
            int(self.correlation_id),
            int(self.worker_kind),
            job_id_raw,
            b"\x00\x00\x00",
        )

    @classmethod
    def unpack(cls, blob: bytes) -> "SamuraiWireHeaderV1":
        if len(blob) != HEADER_SIZE_V1:
            raise WireProtocolError(f"header size mismatch: {len(blob)} != {HEADER_SIZE_V1}")
        magic, version, msg_type, payload_len, flags, correlation_id, worker_kind, job_id_raw, _ = _HEADER_STRUCT.unpack(blob)
        if magic != SAMURAI_WIRE_MAGIC:
            raise WireProtocolError(f"invalid magic: 0x{magic:08X}")
        if version != WIRE_VERSION_V1:
            raise WireProtocolError(f"unsupported version: {version}")
        try:
            msg_type_enum = MessageType(msg_type)
        except ValueError as exc:
            raise WireProtocolError(f"unknown msg_type: {msg_type}") from exc
        try:
            worker_kind_enum = WorkerKind(worker_kind)
        except ValueError as exc:
            raise WireProtocolError(f"unknown worker_kind: {worker_kind}") from exc
        return cls(
            magic=int(magic),
            version=int(version),
            msg_type=msg_type_enum,
            payload_len=int(payload_len),
            flags=int(flags),
            correlation_id=int(correlation_id),
            worker_kind=worker_kind_enum,
            job_id=_unpack_fixed_string(job_id_raw),
        )


@dataclass(frozen=True)
class JobEnvelopeV1:
    target_ip: str
    target_port: int
    packet_count: int
    packet_size: int
    pacing_mode: PacingMode = PacingMode.NONE
    target_rps: float = 0.0
    ipg_ns: int = 0
    burst_size: int = 1
    burst_gap_ns: int = 0
    jitter_model: JitterModel = JitterModel.NONE
    jitter_pct: float = 0.0
    pin_cpu: int = -1
    use_so_txtime: bool = False
    xdp_interface: str = ""
    xdp_queue_id: int = 0
    xdp_mode: int = 0
    scenario_payload_ref: str = ""

    def pack(self) -> bytes:
        if not (0 <= int(self.target_port) <= 0xFFFF):
            raise WireProtocolError("target_port must fit uint16")
        if not (0 <= int(self.packet_count) <= 0xFFFFFFFF):
            raise WireProtocolError("packet_count must fit uint32")
        if not (0 <= int(self.packet_size) <= 0xFFFFFFFF):
            raise WireProtocolError("packet_size must fit uint32")
        if not (0 <= int(self.ipg_ns) <= 0xFFFFFFFFFFFFFFFF):
            raise WireProtocolError("ipg_ns must fit uint64")
        if not (0 <= int(self.burst_size) <= 0xFFFFFFFF):
            raise WireProtocolError("burst_size must fit uint32")
        if not (0 <= int(self.burst_gap_ns) <= 0xFFFFFFFFFFFFFFFF):
            raise WireProtocolError("burst_gap_ns must fit uint64")
        if not (-0x80000000 <= int(self.pin_cpu) <= 0x7FFFFFFF):
            raise WireProtocolError("pin_cpu must fit int32")
        if not (0 <= int(self.xdp_queue_id) <= 0xFFFFFFFF):
            raise WireProtocolError("xdp_queue_id must fit uint32")
        if not (0 <= int(self.xdp_mode) <= 0xFFFFFFFF):
            raise WireProtocolError("xdp_mode must fit uint32")
        if float(self.jitter_pct) < 0.0 or float(self.jitter_pct) > 1.0:
            raise WireProtocolError("jitter_pct must be in [0.0, 1.0]")

        return _JOB_ENVELOPE_STRUCT.pack(
            _pack_fixed_string(self.target_ip, 16, "target_ip"),
            int(self.target_port),
            int(self.packet_count),
            int(self.packet_size),
            int(self.pacing_mode),
            float(self.target_rps),
            int(self.ipg_ns),
            int(self.burst_size),
            int(self.burst_gap_ns),
            int(self.jitter_model),
            float(self.jitter_pct),
            int(self.pin_cpu),
            1 if bool(self.use_so_txtime) else 0,
            _pack_fixed_string(self.xdp_interface, 16, "xdp_interface"),
            int(self.xdp_queue_id),
            int(self.xdp_mode),
            _pack_fixed_string(self.scenario_payload_ref, 64, "scenario_payload_ref"),
            b"\x00\x00\x00",
        )

    @classmethod
    def unpack(cls, blob: bytes) -> "JobEnvelopeV1":
        if len(blob) != JOB_ENVELOPE_SIZE_V1:
            raise WireProtocolError(
                f"job envelope size mismatch: {len(blob)} != {JOB_ENVELOPE_SIZE_V1}"
            )
        (
            target_ip_raw,
            target_port,
            packet_count,
            packet_size,
            pacing_mode,
            target_rps,
            ipg_ns,
            burst_size,
            burst_gap_ns,
            jitter_model,
            jitter_pct,
            pin_cpu,
            use_so_txtime,
            xdp_interface_raw,
            xdp_queue_id,
            xdp_mode,
            scenario_payload_ref_raw,
            _,
        ) = _JOB_ENVELOPE_STRUCT.unpack(blob)
        try:
            pacing_mode_enum = PacingMode(pacing_mode)
        except ValueError as exc:
            raise WireProtocolError(f"unknown pacing_mode: {pacing_mode}") from exc
        try:
            jitter_model_enum = JitterModel(jitter_model)
        except ValueError as exc:
            raise WireProtocolError(f"unknown jitter_model: {jitter_model}") from exc
        return cls(
            target_ip=_unpack_fixed_string(target_ip_raw),
            target_port=int(target_port),
            packet_count=int(packet_count),
            packet_size=int(packet_size),
            pacing_mode=pacing_mode_enum,
            target_rps=float(target_rps),
            ipg_ns=int(ipg_ns),
            burst_size=int(burst_size),
            burst_gap_ns=int(burst_gap_ns),
            jitter_model=jitter_model_enum,
            jitter_pct=float(jitter_pct),
            pin_cpu=int(pin_cpu),
            use_so_txtime=bool(use_so_txtime),
            xdp_interface=_unpack_fixed_string(xdp_interface_raw),
            xdp_queue_id=int(xdp_queue_id),
            xdp_mode=int(xdp_mode),
            scenario_payload_ref=_unpack_fixed_string(scenario_payload_ref_raw),
        )


@dataclass(frozen=True)
class MetricSnapshotV1:
    timestamp_ns: int
    packets_sent: int
    packets_errors: int
    bytes_sent: int
    actual_rps: float
    jitter_p99_ns: float
    rate_accuracy_pct: float
    busywait_cycles: int
    sleep_calls: int

    def pack(self) -> bytes:
        return _METRIC_SNAPSHOT_STRUCT.pack(
            int(self.timestamp_ns),
            int(self.packets_sent),
            int(self.packets_errors),
            int(self.bytes_sent),
            float(self.actual_rps),
            float(self.jitter_p99_ns),
            float(self.rate_accuracy_pct),
            int(self.busywait_cycles),
            int(self.sleep_calls),
        )

    @classmethod
    def unpack(cls, blob: bytes) -> "MetricSnapshotV1":
        if len(blob) != METRIC_SNAPSHOT_SIZE_V1:
            raise WireProtocolError(
                f"metric snapshot size mismatch: {len(blob)} != {METRIC_SNAPSHOT_SIZE_V1}"
            )
        fields = _METRIC_SNAPSHOT_STRUCT.unpack(blob)
        return cls(*fields)


_PACING_MODE_MAP: dict[str, PacingMode] = {
    "none": PacingMode.NONE,
    "rps": PacingMode.RPS,
    "ipg": PacingMode.IPG,
    "burst": PacingMode.BURST,
}

_JITTER_MODEL_MAP: dict[str, JitterModel] = {
    "none": JitterModel.NONE,
    "uniform": JitterModel.UNIFORM,
    "gaussian": JitterModel.GAUSSIAN,
    "exponential": JitterModel.EXPONENTIAL,
}


@dataclass(frozen=True)
class PacingConfig:
    pacing_mode: PacingMode = PacingMode.NONE
    target_rps: float = 0.0
    ipg_ns: int = 0
    burst_size: int = 64
    burst_gap_ns: int = 0
    jitter_model: JitterModel = JitterModel.NONE
    jitter_pct: float = 0.0
    pin_cpu: int = -1
    use_so_txtime: bool = False


def build_pacing_config(args: Mapping[str, Any]) -> PacingConfig:
    mode = _PACING_MODE_MAP.get(str(args.get("pacing_mode", "none") or "none").strip().lower(), PacingMode.NONE)
    if mode == PacingMode.NONE and float(args.get("rps", 0) or 0) > 0:
        mode = PacingMode.RPS
    return PacingConfig(
        pacing_mode=mode,
        target_rps=float(args.get("rps", 0) or 0),
        ipg_ns=int(args.get("ipg", 0) or 0),
        burst_size=int(args.get("burst_size", 64) or 64),
        burst_gap_ns=int(args.get("burst_gap", 0) or 0),
        jitter_model=_JITTER_MODEL_MAP.get(
            str(args.get("jitter_model", "none") or "none").strip().lower(),
            JitterModel.NONE,
        ),
        jitter_pct=float(args.get("jitter_pct", 0.0) or 0.0),
        pin_cpu=int(args.get("pin_cpu", -1) or -1),
        use_so_txtime=bool(args.get("use_so_txtime", False)),
    )


def build_job_envelope(args: Mapping[str, Any], *, scenario_payload_ref: str = "") -> JobEnvelopeV1:
    pacing = build_pacing_config(args)
    return JobEnvelopeV1(
        target_ip=str(args.get("target", "") or ""),
        target_port=int(args.get("port", 0) or 0),
        packet_count=int(args.get("packets", 0) or 0),
        packet_size=int(args.get("size", 64) or 64),
        pacing_mode=pacing.pacing_mode,
        target_rps=pacing.target_rps,
        ipg_ns=pacing.ipg_ns,
        burst_size=pacing.burst_size,
        burst_gap_ns=pacing.burst_gap_ns,
        jitter_model=pacing.jitter_model,
        jitter_pct=pacing.jitter_pct,
        pin_cpu=pacing.pin_cpu,
        use_so_txtime=pacing.use_so_txtime,
        xdp_interface=str(args.get("iface", "") or ""),
        xdp_queue_id=int(args.get("dpdk_queue", args.get("xdp_queue_id", 0)) or 0),
        xdp_mode=int(args.get("xdp_mode", 0) or 0),
        scenario_payload_ref=str(scenario_payload_ref or ""),
    )


def pack_message(header: SamuraiWireHeaderV1, payload: bytes = b"") -> bytes:
    payload_bytes = bytes(payload or b"")
    if int(header.payload_len) != len(payload_bytes):
        raise WireProtocolError(
            f"payload_len mismatch: header={header.payload_len} actual={len(payload_bytes)}"
        )
    return header.pack() + payload_bytes


def unpack_message(message: bytes) -> tuple[SamuraiWireHeaderV1, bytes]:
    if len(message) < HEADER_SIZE_V1:
        raise WireProtocolError(
            f"message too short: {len(message)} < header size {HEADER_SIZE_V1}"
        )
    header = SamuraiWireHeaderV1.unpack(message[:HEADER_SIZE_V1])
    payload = bytes(message[HEADER_SIZE_V1:])
    if len(payload) != int(header.payload_len):
        raise WireProtocolError(
            f"payload length mismatch: expected={header.payload_len} got={len(payload)}"
        )
    return header, payload


def encode_job_done_json(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(dict(payload), separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def decode_job_done_json(payload: bytes) -> dict[str, Any]:
    try:
        obj = json.loads(bytes(payload).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WireProtocolError(f"invalid JOB_DONE JSON payload: {exc}") from exc
    if not isinstance(obj, dict):
        raise WireProtocolError("JOB_DONE JSON must decode to object")
    return obj
