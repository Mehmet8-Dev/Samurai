from __future__ import annotations

import asyncio
import logging
import ssl
from typing import Any, Optional, Sequence

log = logging.getLogger(__name__)

try:
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import DataReceived, ResponseReceived, StreamEnded, StreamReset

    HYPER_H2_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    HYPER_H2_AVAILABLE = False


def _make_ssl_context(verify: bool, ssl_context: Optional[ssl.SSLContext]) -> ssl.SSLContext:
    if isinstance(ssl_context, ssl.SSLContext):
        return ssl_context
    ctx = ssl.create_default_context()
    if not bool(verify):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def send_h2_requests(
    *,
    host: str,
    port: int,
    requests: Sequence[dict[str, Any]],
    verify: bool = True,
    ssl_context: Optional[ssl.SSLContext] = None,
    timeout_s: float = 10.0,
    settings: Optional[dict[int, int]] = None,
    window_update: int = 0,
) -> dict[str, int]:
    """
    Minimal HTTP/2 client transport using hyper-h2.
    Sends requests sequentially over one connection and aggregates status counters.
    """
    if not HYPER_H2_AVAILABLE:
        raise RuntimeError("hyper-h2 unavailable")

    total = int(len(requests))
    if total <= 0:
        return {
            "attempted": 0,
            "sent": 0,
            "errors": 0,
            "responses_total": 0,
            "status_2xx": 0,
            "status_4xx": 0,
            "status_5xx": 0,
        }

    tls_ctx = _make_ssl_context(verify=bool(verify), ssl_context=ssl_context)
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host=host, port=int(port), ssl=tls_ctx, server_hostname=str(host)),
        timeout=float(timeout_s),
    )
    conn = H2Connection(config=H2Configuration(client_side=True, header_encoding="utf-8"))

    # Apply profile-local settings before initiating the connection preface.
    for key, value in dict(settings or {}).items():
        try:
            conn.local_settings[int(key)] = int(value)
        except Exception:
            continue

    conn.initiate_connection()
    writer.write(conn.data_to_send())
    await writer.drain()

    sent = 0
    errors = 0
    responses_total = 0
    status_2xx = 0
    status_4xx = 0
    status_5xx = 0

    try:
        for item in requests:
            method = str(item.get("method", "GET") or "GET").upper()
            path = str(item.get("path", "/") or "/")
            headers_in = dict(item.get("headers", {}) or {})
            headers = [
                (":method", method),
                (":path", path),
                (":scheme", "https"),
                (":authority", str(host)),
                ("user-agent", str(headers_in.pop("user-agent", headers_in.pop("User-Agent", "DDoSamurai-H2/3.0")))),
            ]
            for hk, hv in headers_in.items():
                if hk and hv is not None:
                    headers.append((str(hk), str(hv)))

            stream_id = conn.get_next_available_stream_id()
            conn.send_headers(stream_id=stream_id, headers=headers, end_stream=True)
            if window_update > 0:
                try:
                    conn.increment_flow_control_window(int(window_update), stream_id=stream_id)
                except Exception:
                    pass
            writer.write(conn.data_to_send())
            await writer.drain()

            stream_done = False
            stream_status = 0
            while not stream_done:
                data = await asyncio.wait_for(reader.read(65535), timeout=float(timeout_s))
                if not data:
                    raise RuntimeError("HTTP/2 connection closed before stream completion")
                events = conn.receive_data(data)
                for ev in events:
                    if isinstance(ev, ResponseReceived) and int(ev.stream_id) == int(stream_id):
                        try:
                            ev_headers = dict(ev.headers or [])
                        except Exception:
                            ev_headers = {}
                        stream_status = int(ev_headers.get(":status", 0) or 0)
                    elif isinstance(ev, DataReceived):
                        conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                    elif isinstance(ev, StreamEnded) and int(ev.stream_id) == int(stream_id):
                        stream_done = True
                    elif isinstance(ev, StreamReset) and int(ev.stream_id) == int(stream_id):
                        stream_done = True

                pending = conn.data_to_send()
                if pending:
                    writer.write(pending)
                    await writer.drain()

            sent += 1
            responses_total += 1
            if 200 <= stream_status < 300:
                status_2xx += 1
            elif 400 <= stream_status < 500:
                status_4xx += 1
            elif stream_status >= 500:
                status_5xx += 1
    except Exception:
        errors = max(0, total - sent)
        raise
    finally:
        try:
            conn.close_connection()
            pending = conn.data_to_send()
            if pending:
                writer.write(pending)
                await writer.drain()
        except Exception:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    return {
        "attempted": total,
        "sent": sent,
        "errors": errors,
        "responses_total": responses_total,
        "status_2xx": status_2xx,
        "status_4xx": status_4xx,
        "status_5xx": status_5xx,
    }
