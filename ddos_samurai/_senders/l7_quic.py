import asyncio
import ssl


async def quic_sender(
    target_ip,
    target_port,
    count,
    concurrency,
    quic_path,
    quic_method,
    verbose,
    ssl_context=None,
    retries=0,
    timeout_s=3.0,
    quic_verify=True,
    l7_quic_engine="python",
    l7_quic_require_native=False,
    l7_fallback_policy="allow",
    l7_capability_strict=False,
    lab_profile="off",
    quic_streams_per_conn=0,
    quic_requests_per_conn=0,
    quic_conn_pool_size=1,
    quic_expect_status_min=200,
    quic_expect_status_max=399,
    quic_require_response_headers=True,
    quic_require_response_body=False,
    quic_min_response_body_bytes=0,
    quic_expect_header_name="",
    quic_expect_header_value_contains="",
    quic_expect_body_substring="",
    request_plan=None,
    live_sent=None,
    live_errors=None,
    live_progress=None,
    *,
    stats_fn,
    normalize_l7_output_fn,
    update_live_fn,
    log_info,
    log_error,
    log_warning,
    l7_dispatch_mod,
    L7RouteRequest_cls,
    l7_c_adapter_mod,
    l7_legacy_mod,
    AIOQUIC_AVAILABLE: bool,
    connect_fn,
    QuicConfiguration_cls,
    H3_ALPN_val,
    H3Connection_cls,
):
    """
    Send HTTP/3 requests over QUIC using aioquic.
    """
    route = l7_dispatch_mod.build_route_decision(
        L7RouteRequest_cls(
            protocol="quic",
            l7_engine="python",
            protocol_engine=str(l7_quic_engine or "auto"),
            fallback_policy=str(l7_fallback_policy or "allow"),
            capability_strict=bool(l7_capability_strict),
            legacy_path_enable=True,
            lab_profile=str(lab_profile or "off"),
        )
    )
    planned_items = list(getattr(request_plan, "items", []) or []) if request_plan is not None else []
    planned_methods = [str(getattr(item, "method", "") or "").strip().upper() for item in planned_items]
    planned_methods = [m for m in planned_methods if m]
    planned_paths = [str(getattr(item, "path", "") or "").strip() for item in planned_items]
    planned_paths = [p for p in planned_paths if p]
    planned_headers = [dict(getattr(item, "headers", {}) or {}) for item in planned_items]
    planned_bodies = [getattr(item, "body", None) for item in planned_items]
    planned_content_types = [str(getattr(item, "content_type", "") or "").strip() for item in planned_items]
    lab_profile_norm = str(lab_profile or "off").strip().lower()
    require_native_effective = bool(l7_quic_require_native) or (
        lab_profile_norm == "dedicated" and bool(l7_capability_strict)
    )
    c_fallback_reason = "none"
    verify_tls = bool(quic_verify and ssl_context is None)
    if require_native_effective and route.engine != "c_state":
        return stats_fn(
            **normalize_l7_output_fn(
                {
                    "attempted": count,
                    "sent": 0,
                    "errors": count,
                    "sender_path": "C_STATE_QUIC_NATIVE_REQUIRED",
                    "sender_fallback_reason": "quic_native_required_route_mismatch",
                },
                attempted_default=count,
                sender_path="C_STATE_QUIC_NATIVE_REQUIRED",
                engine_path_used=route.l7_engine_path_used,
                fallback_reason="quic_native_required_route_mismatch",
                route=route,
            )
        )

    if route.engine == "c_state":
        c_extra = {
            "quic_path": str(planned_paths[0] if planned_paths else (quic_path or "/")),
            "quic_method": str(planned_methods[0] if planned_methods else (quic_method or "GET")),
            "scheme": "https",
            "verify": bool(verify_tls),
            "require_native_quic": 1 if bool(require_native_effective) else 0,
            "retries": int(retries or 0),
            "timeout_s": float(timeout_s or 3.0),
            "quic_streams_per_conn": int(quic_streams_per_conn or 0),
            "quic_requests_per_conn": int(quic_requests_per_conn or 0),
            "quic_conn_pool_size": int(quic_conn_pool_size or 1),
            "quic_expect_status_min": int(quic_expect_status_min or 200),
            "quic_expect_status_max": int(quic_expect_status_max or 399),
            "quic_require_response_headers": 1 if bool(quic_require_response_headers) else 0,
            "quic_require_response_body": 1 if bool(quic_require_response_body) else 0,
            "quic_min_response_body_bytes": int(quic_min_response_body_bytes or 0),
            "quic_expect_header_name": str(quic_expect_header_name or ""),
            "quic_expect_header_value_contains": str(quic_expect_header_value_contains or ""),
            "quic_expect_body_substring": str(quic_expect_body_substring or ""),
            "l7_request_plan_count": int(len(planned_items)),
        }
        if require_native_effective:
            c_extra["enable_quic_py_bridge"] = 0
        c_cfg = l7_c_adapter_mod.make_config(
            target_ip=str(target_ip),
            target_port=int(target_port or 0),
            count=int(count or 0),
            concurrency=int(concurrency or 1),
            mode="quic_stateful",
            extra=c_extra,
        )
        c_res = await l7_c_adapter_mod.run("quic", c_cfg)
        if l7_legacy_mod.should_return_c_result(
            c_res,
            allow_python_fallback=(route.allow_python_fallback and not bool(require_native_effective)),
        ):
            c_stats = normalize_l7_output_fn(
                c_res.as_stats(),
                attempted_default=count,
                sender_path="C_STATE_QUIC",
                engine_path_used=route.l7_engine_path_used,
                fallback_reason=str(getattr(c_res, "sender_fallback_reason", "none") or "none"),
                route=route,
            )
            update_live_fn(live_progress, int(c_stats.get("attempted", count) or 0))
            update_live_fn(live_sent, int(c_stats.get("sent", 0) or 0))
            update_live_fn(live_errors, int(c_stats.get("errors", 0) or 0))
            return stats_fn(**c_stats)
        c_fallback_reason = str(getattr(c_res, "sender_fallback_reason", "none") or "none")
        if require_native_effective:
            return stats_fn(
                **normalize_l7_output_fn(
                    c_res.as_stats(),
                    attempted_default=count,
                    sender_path="C_STATE_QUIC_NATIVE_REQUIRED",
                    engine_path_used=route.l7_engine_path_used,
                    fallback_reason=c_fallback_reason,
                    route=route,
                )
            )
        log_warning(
            "L7 c_state QUIC engine unavailable/failed; "
            f"Python QUIC path fallback enabled (reason={c_fallback_reason})."
        )

    if not AIOQUIC_AVAILABLE:
        log_error("QUIC/HTTP3 desteği için 'aioquic' kütüphanesi yüklü değil.")
        return stats_fn(
            **normalize_l7_output_fn(
                {"attempted": count, "sent": 0, "errors": count, "sender_path": "PY_QUIC"},
                attempted_default=count,
                sender_path="PY_QUIC",
                engine_path_used="PY_QUIC",
                fallback_reason=c_fallback_reason,
                route=route,
            )
        )

    log_info(
        f"QUIC sender initialized. Target: {target_ip}:{target_port}, Count: {count}, "
        f"Method: {quic_method}, Path: {quic_path}, gpu_plan_items={len(planned_items)}"
    )

    configuration = QuicConfiguration_cls(is_client=True, alpn_protocols=H3_ALPN_val)
    if ssl_context or not verify_tls:
        configuration.verify_mode = ssl.CERT_NONE

    ok_requests = 0
    err_requests = 0
    effective_concurrency = min(max(1, concurrency), count) if count > 0 else 1
    per_worker_base = count // effective_concurrency
    remainder = count % effective_concurrency

    def _worker_count(worker_id):
        return per_worker_base + (1 if worker_id < remainder else 0)

    def _normalize_quic_path(path_value: str) -> str:
        path_norm = str(path_value or "").strip()
        if not path_norm:
            return str(quic_path or "/")
        if not path_norm.startswith("/"):
            path_norm = "/" + path_norm
        return path_norm

    request_items = []
    for i in range(max(0, int(count or 0))):
        if planned_items:
            item = planned_items[i % len(planned_items)]
            method_i = str(getattr(item, "method", quic_method) or quic_method)
            path_i = str(getattr(item, "path", quic_path) or quic_path)
            headers_i = dict(planned_headers[i % len(planned_headers)] if planned_headers else {})
            plan_ua = str(getattr(item, "user_agent", "") or "").strip()
            if plan_ua and "user-agent" not in {str(k).lower() for k in headers_i.keys()}:
                headers_i["user-agent"] = plan_ua
            body_i = planned_bodies[i % len(planned_bodies)] if planned_bodies else None
            content_type_i = (
                planned_content_types[i % len(planned_content_types)] if planned_content_types else ""
            )
            if body_i is not None and content_type_i and "content-type" not in {
                str(k).lower() for k in headers_i.keys()
            }:
                headers_i["content-type"] = content_type_i
        else:
            method_i = str(quic_method or "GET")
            path_i = str(quic_path or "/")
            headers_i = {}
            body_i = None
        if body_i is None:
            body_bytes_i = b""
        elif isinstance(body_i, bytes):
            body_bytes_i = body_i
        else:
            body_bytes_i = str(body_i).encode("utf-8")
        request_items.append((method_i.upper(), _normalize_quic_path(path_i), headers_i, body_bytes_i))

    worker_offsets = []
    _cursor = 0
    for i in range(effective_concurrency):
        worker_offsets.append(_cursor)
        _cursor += _worker_count(i)

    async def _quic_worker(worker_id):
        nonlocal ok_requests, err_requests
        my_count = _worker_count(worker_id)
        if my_count <= 0:
            return
        start_idx = int(worker_offsets[worker_id]) if worker_id < len(worker_offsets) else 0
        try:
            async with connect_fn(
                target_ip, target_port, configuration=configuration, create_protocol=H3Connection_cls
            ) as protocol:
                h3_conn = protocol._quic
                for req_local in range(my_count):
                    update_live_fn(live_progress, 1)
                    try:
                        req_idx = start_idx + req_local
                        req_method, req_path, req_headers, req_body = (
                            request_items[req_idx]
                            if req_idx < len(request_items)
                            else (str(quic_method or "GET").upper(), _normalize_quic_path(str(quic_path or "/")), {}, b"")
                        )
                        stream_id = h3_conn.get_next_available_stream_id()
                        h3_headers = [
                            (b":method", req_method.encode()),
                            (b":path", req_path.encode()),
                            (b":scheme", b"https"),
                            (b":authority", target_ip.encode() if isinstance(target_ip, str) else target_ip),
                            (b"user-agent", b"Samurai/2.0"),
                        ]
                        for hk, hv in dict(req_headers or {}).items():
                            if hk is None or hv is None:
                                continue
                            hname = str(hk).strip().lower()
                            if not hname:
                                continue
                            if hname.startswith(":") or hname == "authority":
                                continue
                            if hname == "user-agent":
                                h3_headers = [x for x in h3_headers if x[0] != b"user-agent"]
                            h3_headers.append((hname.encode(), str(hv).encode()))
                        h3_conn.send_headers(
                            stream_id=stream_id,
                            headers=h3_headers,
                            end_stream=(len(req_body) == 0),
                        )
                        if req_body:
                            h3_conn.send_data(stream_id=stream_id, data=req_body, end_stream=True)
                        ok_requests += 1
                        update_live_fn(live_sent, 1)
                        if verbose:
                            log_info(f"H3 request sent: {req_method} {req_path} stream={stream_id}")
                        await asyncio.sleep(0)
                    except Exception as req_e:
                        err_requests += 1
                        update_live_fn(live_errors, 1)
                        if verbose:
                            log_error(f"H3 request failed: {req_e}")
        except Exception as e:
            conn_remaining = my_count
            err_requests += conn_remaining
            update_live_fn(live_errors, conn_remaining)
            if verbose:
                log_error(f"QUIC connection failed: {e}")

    tasks = [asyncio.create_task(_quic_worker(i)) for i in range(effective_concurrency)]
    await asyncio.gather(*tasks)
    log_info(f"QUIC sender finished. ok={ok_requests} err={err_requests}")
    return stats_fn(
        **normalize_l7_output_fn(
            {
                "attempted": count,
                "sent": ok_requests,
                "errors": max(err_requests, count - ok_requests),
                "quic_stream_fail_ratio": float(max(err_requests, 0)) / float(max(1, int(count or 0))),
                "quic_handshake_fail_ratio": 0.0,
                "sender_path": "PY_QUIC",
                "l7_request_plan_used": int(bool(planned_items)),
                "l7_request_plan_items": int(len(planned_items)),
            },
            attempted_default=count,
            sender_path="PY_QUIC",
            engine_path_used="PY_QUIC",
            fallback_reason=c_fallback_reason,
            route=route,
        )
    )

