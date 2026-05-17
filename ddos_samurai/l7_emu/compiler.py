from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .types import ConnectionTemplate, Expectation, FlowOp, FlowOpcode, FlowProgram, L7EmuProfile


def _coerce_paths(http_path: Any) -> List[str]:
    if isinstance(http_path, str):
        return [http_path or "/"]
    out = [str(p or "/") for p in list(http_path or ["/"])]
    return out or ["/"]


def _normalize_headers(headers: Dict[str, Any] | None) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key, value in dict(headers or {}).items():
        k = str(key or "").strip()
        if not k:
            continue
        out[k] = str(value if value is not None else "")
    return out


def _plan_items(request_plan: Any) -> List[Any]:
    return list(getattr(request_plan, "items", []) or [])


def _encode_body(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    return str(value).encode("utf-8")


def _flow_attempted(flow_program: FlowProgram) -> int:
    return max(1, sum(1 for op in flow_program.ops if op.opcode == FlowOpcode.SEND_HEADERS))


def _parse_expectation(raw: Dict[str, Any] | None) -> Expectation | None:
    if not raw:
        return None
    return Expectation(
        kind=str(raw.get("kind", "") or ""),
        name=str(raw.get("name", "") or ""),
        value=str(raw.get("value", "") or ""),
        status_min=int(raw.get("status_min", 0) or 0),
        status_max=int(raw.get("status_max", 0) or 0),
    )


def _parse_profile_op(raw: Dict[str, Any]) -> List[FlowOp]:
    opcode = FlowOpcode(str(raw.get("opcode", "") or "").strip().upper())
    if opcode == FlowOpcode.LOOP:
        repeat = max(0, int(raw.get("loop_count", 0) or 0))
        nested = list(raw.get("ops", []) or [])
        expanded: List[FlowOp] = []
        for _ in range(repeat):
            for item in nested:
                expanded.extend(_parse_profile_op(dict(item or {})))
        return expanded
    return [
        FlowOp(
            opcode=opcode,
            method=str(raw.get("method", "") or ""),
            path=str(raw.get("path", "") or ""),
            headers=_normalize_headers(raw.get("headers")),
            body=_encode_body(raw.get("body")),
            expect=_parse_expectation(raw.get("expect")),
            capture_name=str(raw.get("capture_name", "") or ""),
            capture_source=str(raw.get("capture_source", "") or ""),
            think_time_ms=int(raw.get("think_time_ms", 0) or 0),
            loop_count=int(raw.get("loop_count", 0) or 0),
        )
    ]


def _build_profile_program(profile_data: Dict[str, Any]) -> FlowProgram:
    ops: List[FlowOp] = []
    for item in list(profile_data.get("ops", []) or []):
        ops.extend(_parse_profile_op(dict(item or {})))
    if not ops:
        raise ValueError("profile mode requires at least one flow op")
    return FlowProgram(ops=ops)


def _build_http1_compat_program(
    *,
    http_method: str,
    http_paths: Sequence[str],
    payloads: Sequence[Any] | None,
    request_plan: Any,
) -> FlowProgram:
    ops: List[FlowOp] = [FlowOp(opcode=FlowOpcode.CONNECT)]
    plan_items = _plan_items(request_plan)
    if plan_items:
        for item in plan_items:
            headers = _normalize_headers(getattr(item, "headers", None))
            user_agent = getattr(item, "user_agent", None)
            if user_agent:
                headers.setdefault("User-Agent", str(user_agent))
            content_type = getattr(item, "content_type", None)
            if content_type:
                headers.setdefault("Content-Type", str(content_type))
            body = getattr(item, "body", None) or b""
            method = str(getattr(item, "method", http_method) or http_method).upper()
            path = str(getattr(item, "path", "/") or "/")
            ops.append(FlowOp(opcode=FlowOpcode.SEND_HEADERS, method=method, path=path, headers=headers))
            if body:
                ops.append(FlowOp(opcode=FlowOpcode.SEND_BODY, body=bytes(body)))
            ops.append(FlowOp(opcode=FlowOpcode.EXPECT_STATUS, expect=Expectation(kind="status", status_min=100, status_max=599)))
            ops.append(
                FlowOp(
                    opcode=FlowOpcode.CAPTURE_HEADER,
                    capture_name="location",
                    capture_source="location",
                )
            )
            ops.append(FlowOp(opcode=FlowOpcode.CAPTURE_COOKIE, capture_name="set-cookie", capture_source="set-cookie"))
    else:
        all_paths = list(http_paths or ["/"])
        payload = b""
        if payloads:
            first_payload = list(payloads)[0]
            if isinstance(first_payload, bytes):
                payload = first_payload
            else:
                payload = str(first_payload).encode("utf-8")
        for path in all_paths:
            ops.append(FlowOp(opcode=FlowOpcode.SEND_HEADERS, method=str(http_method).upper(), path=str(path or "/")))
            if payload:
                ops.append(FlowOp(opcode=FlowOpcode.SEND_BODY, body=payload))
            ops.append(FlowOp(opcode=FlowOpcode.EXPECT_STATUS, expect=Expectation(kind="status", status_min=100, status_max=599)))
            ops.append(
                FlowOp(
                    opcode=FlowOpcode.CAPTURE_HEADER,
                    capture_name="location",
                    capture_source="location",
                )
            )
            ops.append(FlowOp(opcode=FlowOpcode.CAPTURE_COOKIE, capture_name="set-cookie", capture_source="set-cookie"))
    ops.append(FlowOp(opcode=FlowOpcode.CLOSE))
    return FlowProgram(ops=ops)


def _build_http2_compat_program(
    *,
    http_method: str,
    http_paths: Sequence[str],
    request_plan: Any,
) -> FlowProgram:
    ops: List[FlowOp] = [FlowOp(opcode=FlowOpcode.CONNECT)]
    plan_items = _plan_items(request_plan)
    if plan_items:
        for item in plan_items:
            headers = _normalize_headers(getattr(item, "headers", None))
            user_agent = getattr(item, "user_agent", None)
            if user_agent:
                headers.setdefault("user-agent", str(user_agent))
            content_type = getattr(item, "content_type", None)
            if content_type:
                headers.setdefault("content-type", str(content_type))
            body = getattr(item, "body", None) or b""
            method = str(getattr(item, "method", http_method) or http_method).upper()
            path = str(getattr(item, "path", "/") or "/")
            ops.append(FlowOp(opcode=FlowOpcode.SEND_HEADERS, method=method, path=path, headers=headers))
            if body:
                ops.append(FlowOp(opcode=FlowOpcode.SEND_BODY, body=bytes(body)))
            ops.append(FlowOp(opcode=FlowOpcode.EXPECT_STATUS, expect=Expectation(kind="status", status_min=100, status_max=599)))
            if headers:
                for key, value in headers.items():
                    ops.append(
                        FlowOp(
                            opcode=FlowOpcode.EXPECT_HEADER,
                            expect=Expectation(kind="header", name=str(key), value=str(value)),
                        )
                    )
    else:
        for path in list(http_paths or ["/"]):
            ops.append(FlowOp(opcode=FlowOpcode.SEND_HEADERS, method=str(http_method).upper(), path=str(path or "/")))
            ops.append(FlowOp(opcode=FlowOpcode.EXPECT_STATUS, expect=Expectation(kind="status", status_min=100, status_max=599)))
    ops.append(FlowOp(opcode=FlowOpcode.CLOSE))
    return FlowProgram(ops=ops)

def _with_quic_expectations(
    flow_program: FlowProgram,
    *,
    quic_expect_status_min: int,
    quic_expect_status_max: int,
    quic_expect_header_name: str,
    quic_expect_header_value_contains: str,
    quic_expect_body_substring: str,
    quic_require_response_body: bool,
    quic_min_response_body_bytes: int,
) -> FlowProgram:
    ops = list(flow_program.ops)
    tail: List[FlowOp] = []
    if ops and ops[-1].opcode == FlowOpcode.CLOSE:
        tail.append(ops.pop())

    status_min = max(100, min(599, int(quic_expect_status_min or 100)))
    status_max = max(100, min(599, int(quic_expect_status_max or 599)))
    if status_max < status_min:
        status_max = status_min

    ops.append(
        FlowOp(
            opcode=FlowOpcode.EXPECT_STATUS,
            expect=Expectation(kind="status", status_min=status_min, status_max=status_max),
        )
    )

    header_name = str(quic_expect_header_name or "").strip()
    if header_name:
        ops.append(
            FlowOp(
                opcode=FlowOpcode.EXPECT_HEADER,
                expect=Expectation(
                    kind="header",
                    name=header_name,
                    value=str(quic_expect_header_value_contains or ""),
                ),
            )
        )

    body_substring = str(quic_expect_body_substring or "")
    if body_substring:
        ops.append(
            FlowOp(
                opcode=FlowOpcode.EXPECT_BODY_SUBSTRING,
                expect=Expectation(kind="body_substring", value=body_substring),
            )
        )

    if bool(quic_require_response_body):
        ops.append(
            FlowOp(
                opcode=FlowOpcode.EXPECT_BODY_SUBSTRING,
                expect=Expectation(kind="body_required", value="1"),
            )
        )

    min_body = max(0, int(quic_min_response_body_bytes or 0))
    if min_body > 0:
        ops.append(
            FlowOp(
                opcode=FlowOpcode.EXPECT_BODY_SUBSTRING,
                expect=Expectation(kind="body_min_bytes", value=str(min_body)),
            )
        )

    ops.extend(tail)
    return FlowProgram(ops=ops)


def compile_l7_profile(
    *,
    protocol: str,
    target_ip: str,
    target_port: int,
    scheme: str,
    transport_backend: str = "custom_tcp",
    stateful_runtime_backend: Optional[str] = None,
    stateful_runtime_strict: bool = False,
    legacy_mode: bool = True,
    source_ip: str = "",
    template_mode: str = "compat",
    compat_mode: str = "http1",
    verify: bool = True,
    timeout_s: float = 5.0,
    concurrency: int = 1,
    http_method: str = "GET",
    http_path: Any = "/",
    payloads: Sequence[Any] | None = None,
    request_plan: Any = None,
    profile_data: Dict[str, Any] | None = None,
    tls_profile_name: str = "none",
    session_repeats: int = 1,
    max_streams_per_connection: int = 1,
    quic_expect_status_min: int = 100,
    quic_expect_status_max: int = 599,
    quic_expect_header_name: str = "",
    quic_expect_header_value_contains: str = "",
    quic_expect_body_substring: str = "",
    quic_require_response_body: bool = False,
    quic_min_response_body_bytes: int = 0,
) -> L7EmuProfile:
    proto = str(protocol or "").strip().lower()
    if proto not in {"http1", "http2", "quic"}:
        raise ValueError(f"unsupported L7 emulation protocol: {protocol!r}")
    runtime_backend_explicit = stateful_runtime_backend is not None and str(stateful_runtime_backend).strip() != ""
    runtime_backend = str(stateful_runtime_backend or "afxdp").strip().lower()
    if runtime_backend not in {"afxdp", "dpdk"}:
        raise ValueError(f"unsupported stateful runtime backend: {stateful_runtime_backend!r}")
    backend = str(transport_backend or "custom_tcp").strip().lower()
    if backend == "kernel_socket":
        backend = "custom_tcp"
    if backend not in {"custom_tcp"}:
        raise ValueError(f"unsupported L7 transport backend: {transport_backend!r}")
    alpn_values: List[str] = []
    if profile_data and "alpn" in profile_data:
        raw_alpn = profile_data.get("alpn")
        if isinstance(raw_alpn, str):
            alpn_values = [str(raw_alpn).strip().lower()]
        else:
            alpn_values = [str(x or "").strip().lower() for x in list(raw_alpn or [])]
        alpn_values = [x for x in alpn_values if x]
    paths = _coerce_paths(http_path)
    method = str(http_method or "GET").upper()
    scheme_norm = str((profile_data or {}).get("scheme", scheme) or scheme).strip().lower()
    source_ip_norm = str(
        source_ip
        or (profile_data or {}).get("source_ip", "")
        or (profile_data or {}).get("client_ip", "")
        or ""
    ).strip()
    if str(template_mode or "compat").strip().lower() == "profile":
        if not profile_data:
            raise ValueError("profile mode requires profile_data")
        flow_program = _build_profile_program(profile_data)
        if proto == "http1":
            sender_path = "L7_EMU_HTTP1"
        elif proto == "http2":
            sender_path = "L7_EMU_H2"
        else:
            if scheme_norm not in {"https", "quic"}:
                raise ValueError("quic protocol requires scheme 'https' or 'quic'")
            effective_alpn = tuple(dict.fromkeys(alpn_values or ["h3"]))
            if "h3" not in effective_alpn:
                raise ValueError("quic protocol requires ALPN to include 'h3' for minimal HTTP/3")
            sender_path = "L7_QUIC_CUSTOM"
        flow_attempted = _flow_attempted(flow_program)
        max_streams = 1 if proto == "http1" else max(1, int(max_streams_per_connection or concurrency or 1))
    elif proto == "http1":
        flow_program = _build_http1_compat_program(
            http_method=method,
            http_paths=paths,
            payloads=payloads,
            request_plan=request_plan,
        )
        sender_path = "L7_EMU_HTTP1"
        flow_attempted = _flow_attempted(flow_program)
        max_streams = 1
    elif proto == "http2":
        flow_program = _build_http2_compat_program(
            http_method=method,
            http_paths=paths,
            request_plan=request_plan,
        )
        sender_path = "L7_EMU_H2"
        flow_attempted = _flow_attempted(flow_program)
        max_streams = max(1, int(max_streams_per_connection or concurrency or 1))
    else:
        if scheme_norm not in {"https", "quic"}:
            raise ValueError("quic protocol requires scheme 'https' or 'quic'")
        effective_alpn = tuple(dict.fromkeys(alpn_values or ["h3"]))
        if "h3" not in effective_alpn:
            raise ValueError("quic protocol requires ALPN to include 'h3' for minimal HTTP/3")
        flow_program = _build_http2_compat_program(
            http_method=method,
            http_paths=paths,
            request_plan=request_plan,
        )
        sender_path = "L7_QUIC_CUSTOM"
        flow_attempted = _flow_attempted(flow_program)
        max_streams = max(1, int(max_streams_per_connection or concurrency or 1))
    if proto == "quic":
        flow_program = _with_quic_expectations(
            flow_program,
            quic_expect_status_min=quic_expect_status_min,
            quic_expect_status_max=quic_expect_status_max,
            quic_expect_header_name=quic_expect_header_name,
            quic_expect_header_value_contains=quic_expect_header_value_contains,
            quic_expect_body_substring=quic_expect_body_substring,
            quic_require_response_body=quic_require_response_body,
            quic_min_response_body_bytes=quic_min_response_body_bytes,
        )
    conn_template = ConnectionTemplate(
        protocol=proto,
        target_ip=str(target_ip),
        target_port=int(target_port),
        scheme=str((profile_data or {}).get("scheme", scheme) or scheme),
        host_header=str((profile_data or {}).get("host_header", target_ip) or target_ip),
        transport_backend=backend,
        stateful_runtime_backend=runtime_backend,
        stateful_runtime_strict=bool(stateful_runtime_strict),
        legacy_mode=bool(legacy_mode),
        source_ip=source_ip_norm,
        verify=bool(verify),
        tls_profile_name=str(tls_profile_name or "none"),
        max_connections=max(1, int(concurrency or 1)),
        max_streams_per_connection=max_streams,
        session_repeats=max(1, int(session_repeats or 1)),
        keepalive=True,
        timeout_ms=max(1, int(float(timeout_s or 5.0) * 1000.0)),
        alpn=tuple(dict.fromkeys(alpn_values or (["h3"] if proto == "quic" else []))),
        quic_minimal_http3=bool(proto == "quic"),
    )
    return L7EmuProfile(
        protocol=proto,
        sender_path=sender_path,
        template_mode=str(template_mode or "compat"),
        compat_mode=str(compat_mode or proto),
        flow_attempted=int(flow_attempted),
        flow_program=flow_program,
        connection_template=conn_template,
    )


def load_l7_profile_file(path: str | Path) -> Dict[str, Any]:
    profile_path = Path(path)
    return json.loads(profile_path.read_text(encoding="utf-8"))
