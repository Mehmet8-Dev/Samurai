"""ZMQ-only AF_XDP control facade.

The old Python ``xdp_sender`` extension wrapper has been removed from the
public runtime.  AF_XDP jobs are submitted to the native ZMQ AF_XDP worker.
"""

from __future__ import annotations

import os
import socket
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Optional, Tuple

from .zmq.dispatcher import DispatchResult, ZmqDispatcher
from .zmq.wire import WorkerKind

XDP_MODE_SKB = 0
XDP_MODE_NATIVE = 1
XDP_MODE_OFFLOAD = 2
DEFAULT_BATCH_SIZE = 64
DEFAULT_QUEUE_ID = 0


class AFXDPBridgeRemoved(RuntimeError):
    pass


@dataclass
class XDPStats:
    tx_packets: int = 0
    tx_bytes: int = 0
    tx_errors: int = 0
    tx_wakeups: int = 0
    tx_desc_reserve_failures: int = 0
    tx_frame_alloc_failures: int = 0
    tx_partial_batches: int = 0
    tx_retry_loops: int = 0
    tx_completion_events: int = 0
    tx_completed_desc: int = 0
    tx_invalid_packets: int = 0
    tx_backpressure_events: int = 0
    tx_send_calls: int = 0
    tx_send_ns_total: int = 0
    tx_send_ns_max: int = 0
    tx_send_avg_us: float = 0.0
    tx_send_max_us: float = 0.0
    queue_id: int = 0
    elapsed_seconds: float = 0.0
    packets_per_second: float = 0.0
    mbps: float = 0.0
    mode: int = 0
    mode_name: str = "Unknown"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "XDPStats":
        values = {}
        for field in cls.__dataclass_fields__:  # type: ignore[attr-defined]
            if field in data:
                values[field] = data[field]
        return cls(**values)

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


def _mode_name(mode: int) -> str:
    if int(mode) == XDP_MODE_SKB:
        return "SKB/Copy"
    if int(mode) == XDP_MODE_NATIVE:
        return "Native/Zero-Copy"
    if int(mode) == XDP_MODE_OFFLOAD:
        return "Offload(Requested)"
    return "Unknown"


def _normalize_mode2_policy(value: Optional[str]) -> str:
    policy = str(value or "soft").strip().lower()
    if policy not in {"soft", "hard"}:
        raise ValueError("mode2_policy must be 'soft' or 'hard'")
    return policy


def probe_xdp_mode2_capability(interface: str) -> Tuple[str, str]:
    iface = str(interface or "").strip()
    if not iface:
        return "unknown", "interface is empty"
    if iface == "lo":
        return "unsupported", "loopback interface does not support XDP HW offload"
    return "unknown", "offload capability must be proven by the native ZMQ AF_XDP worker"


def get_default_interface() -> Optional[str]:
    try:
        return socket.gethostbyname(socket.gethostname()) and ""
    except OSError:
        return None


def get_interface_queue_count(interface: str) -> int:
    _ = interface
    raw = str(os.environ.get("SAMURAI_XDP_QUEUE_COUNT", "1") or "1").strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return 1


def check_xdp_available(*, quiet: bool = False) -> tuple[bool, str]:
    _ = quiet
    return False, "Python xdp_sender bridge removed; use the native ZMQ AF_XDP worker"


def _bridge_removed(name: str) -> None:
    raise AFXDPBridgeRemoved(f"{name} removed: use ZMQ WorkerKind.AF_XDP instead of Python xdp_sender bridge")


def dispatch_afxdp_job(
    args: Dict[str, Any],
    *,
    dispatcher: ZmqDispatcher | None = None,
    endpoint: str | None = None,
    correlation_id: int | None = None,
    job_id: str = "afxdp-zmq-job",
) -> DispatchResult:
    disp = dispatcher or ZmqDispatcher()
    cid = int(correlation_id if correlation_id is not None else (time.time_ns() & 0xFFFFFFFFFFFFFFFF))
    return disp.dispatch_start_job(
        worker_kind=WorkerKind.AF_XDP,
        correlation_id=cid,
        job_id=str(job_id or "afxdp-zmq-job"),
        args=dict(args or {}),
        endpoint=endpoint,
    )


class XDPSender:
    """ZMQ-only AF_XDP sender facade.

    ``start`` submits a job to the native AF_XDP worker.  Per-packet send calls
    intentionally fail fast because the Python ``xdp_sender`` bridge is gone.
    """

    def __init__(
        self,
        interface: str | None = None,
        *,
        mode: int = XDP_MODE_NATIVE,
        queue_id: int = DEFAULT_QUEUE_ID,
        batch_size: int = DEFAULT_BATCH_SIZE,
        dispatcher: ZmqDispatcher | None = None,
        endpoint: str | None = None,
        attach_bpf: bool = True,
        **kwargs: Any,
    ) -> None:
        self.interface = str(interface or "")
        self.mode = int(mode)
        self.queue_id = int(queue_id)
        self.batch_size = int(batch_size)
        self.dispatcher = dispatcher
        self.endpoint = endpoint
        self.attach_bpf = bool(attach_bpf)
        self.extra_args = dict(kwargs)
        self.started = False
        self.last_dispatch: Any = None

    def start(self) -> bool:
        args = {
            "xdp_interface": self.interface,
            "xdp_queue_id": self.queue_id,
            "xdp_mode": self.mode,
            "batch_size": self.batch_size,
            "attach_bpf": self.attach_bpf,
        }
        args.update(self.extra_args)
        self.last_dispatch = dispatch_afxdp_job(
            args,
            dispatcher=self.dispatcher,
            endpoint=self.endpoint,
            job_id=str(args.get("job_id") or "afxdp-zmq-sender"),
        )
        self.started = True
        return True

    def stop(self) -> bool:
        self.started = False
        return True

    def get_stats(self) -> XDPStats:
        return XDPStats(queue_id=self.queue_id, mode=self.mode, mode_name=_mode_name(self.mode))

    def send(self, packets: Iterable[bytes]) -> int:
        _ = packets
        _bridge_removed("XDPSender.send")

    def send_udp(self, *args: Any, **kwargs: Any) -> int:
        _ = args, kwargs
        _bridge_removed("XDPSender.send_udp")

    def send_frame(self, *args: Any, **kwargs: Any) -> int:
        _ = args, kwargs
        _bridge_removed("XDPSender.send_frame")

    def reserve_tx_frames(self, *args: Any, **kwargs: Any) -> Any:
        _ = args, kwargs
        _bridge_removed("XDPSender.reserve_tx_frames")

    def submit_tx_frames(self, *args: Any, **kwargs: Any) -> int:
        _ = args, kwargs
        _bridge_removed("XDPSender.submit_tx_frames")


class XDPBulkSender:
    """Compatibility facade for callers migrating to the ZMQ AF_XDP worker."""

    def __init__(
        self,
        interface: str | None = None,
        *,
        threads: int = 1,
        batch_size: int = DEFAULT_BATCH_SIZE,
        queue_count: int | None = None,
        dispatcher: ZmqDispatcher | None = None,
        endpoint: str | None = None,
        **kwargs: Any,
    ) -> None:
        self.interface = str(interface or "")
        self.threads = max(1, int(threads))
        self.batch_size = max(1, int(batch_size))
        self.queue_count = max(1, int(queue_count if queue_count is not None else get_interface_queue_count(self.interface)))
        self.dispatcher = dispatcher
        self.endpoint = endpoint
        self.extra_args = dict(kwargs)
        self.started = False
        self.last_dispatches: list[Any] = []

    def start(self) -> bool:
        self.started = True
        return True

    def stop(self) -> bool:
        self.started = False
        return True

    def send_continuous(self, *args: Any, **kwargs: Any) -> int:
        _ = args, kwargs
        _bridge_removed("XDPBulkSender.send_continuous")

    def get_stats(self) -> list[XDPStats]:
        return [
            XDPStats(queue_id=queue_id, mode=XDP_MODE_NATIVE, mode_name=_mode_name(XDP_MODE_NATIVE))
            for queue_id in range(self.queue_count)
        ]


def run_gpu_rx_pipeline(*args: Any, **kwargs: Any) -> None:
    _ = args, kwargs
    raise RuntimeError("GPU RX Python bridge was removed; use the native defense/GPU ZMQ worker path")

