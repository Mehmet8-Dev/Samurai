import asyncio
import random
import traceback

from .. import h2_mimic


async def http2_sender(
    target_ip,
    target_port,
    count,
    concurrency,
    http_path,
    http_method,
    verbose,
    scheme="https",
    cookies=None,
    user_agent=None,
    ssl_context=None,
    h2_profile_name=None,
    h2_transport_name="auto",
    request_plan=None,
    verify=True,
    http2_connections=1,
    http2_streams_per_conn=100,
    l7_http2_engine="python",
    l7_fallback_policy="allow",
    l7_capability_strict=False,
    lab_profile="off",
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
    HTTPX_AVAILABLE: bool,
    httpx_module,
    HYPER_H2_AVAILABLE: bool,
    h2_transport_module,
):
    """
    Sends HTTP/2 requests using httpx, leveraging multiplexing.
    If request_plan is provided, method/path/user-agent are consumed per item.
    """
    base_url = f"{scheme}://{target_ip}:{target_port}"

    def _resolve_default_h2_path(path_value):
        if isinstance(path_value, (list, tuple)):
            for entry in path_value:
                candidate = str(entry or "").strip()
                if candidate:
                    return candidate
            return "/"
        candidate = str(path_value or "").strip()
        return candidate if candidate else "/"

    default_http_method = str(http_method or "GET").strip() or "GET"
    default_http_path = _resolve_default_h2_path(http_path)
    default_user_agent = str(user_agent or "").strip()
    planned_items = []
    if request_plan is not None:
        planned_items = list(getattr(request_plan, "items", []) or [])
    planned_methods = []
    planned_paths = []
    planned_user_agents = []
    if planned_items:
        for item in planned_items:
            planned_methods.append(str(getattr(item, "method", default_http_method) or default_http_method))
            planned_paths.append(str(getattr(item, "path", default_http_path) or default_http_path))
            planned_user_agents.append(str(getattr(item, "user_agent", "") or "").strip())
    dispatch_count = int(len(planned_items) if planned_items else count)
    if dispatch_count <= 0:
        return stats_fn(attempted=0, sent=0, errors=0)
    route = l7_dispatch_mod.build_route_decision(
        L7RouteRequest_cls(
            protocol="http2",
            l7_engine="python",
            protocol_engine=str(l7_http2_engine or "auto"),
            fallback_policy=str(l7_fallback_policy or "allow"),
            capability_strict=bool(l7_capability_strict),
            legacy_path_enable=True,
            lab_profile=str(lab_profile or "off"),
        )
    )
    c_fallback_reason = "none"
    if route.engine == "c_state":
        c_cfg = l7_c_adapter_mod.make_config(
            target_ip=str(target_ip),
            target_port=int(target_port or 0),
            count=dispatch_count,
            concurrency=max(1, int(concurrency or 1)),
            mode="http2_stateful",
            extra={
                "scheme": str(scheme or "https"),
                "verify": bool(verify),
                "http_method": str(default_http_method),
                "http_path": str(default_http_path),
                "user_agent": str(default_user_agent),
                "h2_profile": str(h2_profile_name or "none"),
                "h2_transport": str(h2_transport_name or "auto"),
                "h2_connections": int(http2_connections or 1),
                "h2_streams_per_conn": int(http2_streams_per_conn or 100),
                "h2_request_plan_count": int(dispatch_count if planned_items else 0),
                "h2_request_plan_methods": planned_methods,
                "h2_request_plan_paths": planned_paths,
                "h2_request_plan_user_agents": [] if default_user_agent else planned_user_agents,
            },
        )
        c_res = await l7_c_adapter_mod.run("http2", c_cfg)
        if l7_legacy_mod.should_return_c_result(c_res, allow_python_fallback=route.allow_python_fallback):
            c_stats = normalize_l7_output_fn(
                c_res.as_stats(),
                attempted_default=dispatch_count,
                sender_path="C_STATE_H2",
                engine_path_used=route.l7_engine_path_used,
                fallback_reason=str(getattr(c_res, "sender_fallback_reason", "none") or "none"),
                route=route,
            )
            update_live_fn(live_progress, int(c_stats.get("attempted", dispatch_count) or 0))
            update_live_fn(live_sent, int(c_stats.get("sent", 0) or 0))
            update_live_fn(live_errors, int(c_stats.get("errors", 0) or 0))
            return stats_fn(**c_stats)
        c_fallback_reason = str(getattr(c_res, "sender_fallback_reason", "none") or "none")
        log_warning(
            "L7 c_state HTTP/2 engine unavailable/failed; "
            f"Python HTTP/2 path fallback enabled (reason={c_fallback_reason})."
        )

    if not HTTPX_AVAILABLE:
        log_error("HTTP/2 desteği için 'httpx[http2]' kütüphanesi yüklü değil.")
        return stats_fn(
            **normalize_l7_output_fn(
                {"attempted": dispatch_count, "sent": 0, "errors": dispatch_count, "sender_path": "PY_HTTP2"},
                attempted_default=dispatch_count,
                sender_path="PY_HTTP2",
                engine_path_used="PY_HTTP2",
                fallback_reason=c_fallback_reason,
                route=route,
            )
        )

    h2_conn_count = max(1, int(http2_connections or 1))
    h2_stream_cap = max(1, int(http2_streams_per_conn or 1))
    max_dispatch_concurrency = max(1, min(int(concurrency or 1), h2_conn_count * h2_stream_cap))
    log_info(
        f"HTTP/2 sender initialized. Target: {base_url}, Count: {dispatch_count}, "
        f"Concurrency: {max_dispatch_concurrency}, Conn: {h2_conn_count}, "
        f"Streams/Conn: {h2_stream_cap}"
    )

    transport_name = str(h2_transport_name or "auto").strip().lower()
    if transport_name not in {"auto", "httpx", "hyper-h2"}:
        transport_name = "auto"
    profile_requested = bool(str(h2_profile_name or "").strip() and str(h2_profile_name).strip().lower() != "none")
    profile_disabled = int(not profile_requested)
    scheme_name = str(scheme or "https").strip().lower()
    ssl_ctx_obj = ssl_context if hasattr(ssl_context, "wrap_socket") else None
    verify_tls = bool(verify)

    resolved_profile = None
    try:
        resolved_profile = h2_mimic.resolve_h2_profile(h2_profile_name)
    except Exception as exc:
        log_error(f"HTTP/2 profile resolve failed: {exc}")
        update_live_fn(live_progress, dispatch_count)
        update_live_fn(live_errors, dispatch_count)
        return stats_fn(
            **normalize_l7_output_fn(
                {
                    "attempted": dispatch_count,
                    "sent": 0,
                    "errors": dispatch_count,
                    "h2_profile_requested": int(profile_requested),
                    "h2_profile_applied": 0,
                    "h2_profile_disabled": profile_disabled,
                    "h2_profile_apply_failed": int(profile_requested),
                    "h2_transport": transport_name,
                    "h2_connections": h2_conn_count,
                    "h2_streams_per_conn": h2_stream_cap,
                    "sender_path": "PY_HTTP2",
                },
                attempted_default=dispatch_count,
                sender_path="PY_HTTP2",
                engine_path_used="PY_HTTP2",
                fallback_reason=c_fallback_reason,
                route=route,
            )
        )

    if transport_name == "hyper-h2":
        if scheme_name != "https":
            log_error("HTTP/2 hyper-h2 transport only supports scheme=https.")
            update_live_fn(live_progress, dispatch_count)
            update_live_fn(live_errors, dispatch_count)
            return stats_fn(
                **normalize_l7_output_fn(
                    {
                        "attempted": dispatch_count,
                        "sent": 0,
                        "errors": dispatch_count,
                        "h2_profile_requested": int(profile_requested),
                        "h2_profile_applied": 0,
                        "h2_profile_disabled": profile_disabled,
                        "h2_profile_apply_failed": 0,
                        "h2_transport": "hyper-h2",
                        "h2_connections": h2_conn_count,
                        "h2_streams_per_conn": h2_stream_cap,
                        "sender_path": "PY_HTTP2",
                    },
                    attempted_default=dispatch_count,
                    sender_path="PY_HTTP2",
                    engine_path_used="PY_HTTP2",
                    fallback_reason=c_fallback_reason,
                    route=route,
                )
            )
        if (not bool(HYPER_H2_AVAILABLE)) or h2_transport_module is None:
            log_error("HTTP/2 hyper-h2 transport requested but dependency is unavailable.")
            update_live_fn(live_progress, dispatch_count)
            update_live_fn(live_errors, dispatch_count)
            return stats_fn(
                **normalize_l7_output_fn(
                    {
                        "attempted": dispatch_count,
                        "sent": 0,
                        "errors": dispatch_count,
                        "h2_profile_requested": int(profile_requested),
                        "h2_profile_applied": 0,
                        "h2_profile_disabled": profile_disabled,
                        "h2_profile_apply_failed": 0,
                        "h2_transport": "hyper-h2",
                        "h2_connections": h2_conn_count,
                        "h2_streams_per_conn": h2_stream_cap,
                        "sender_path": "PY_HTTP2",
                    },
                    attempted_default=dispatch_count,
                    sender_path="PY_HTTP2",
                    engine_path_used="PY_HTTP2",
                    fallback_reason=c_fallback_reason,
                    route=route,
                )
            )

    can_try_hyper_h2 = (
        transport_name in {"auto", "hyper-h2"}
        and (resolved_profile is not None or transport_name == "hyper-h2")
        and scheme_name == "https"
        and bool(HYPER_H2_AVAILABLE)
        and h2_transport_module is not None
    )
    if can_try_hyper_h2:
        reqs = []
        for i in range(dispatch_count):
            if planned_items:
                item = planned_items[i]
                req_method = str(getattr(item, "method", http_method) or http_method)
                req_path = str(getattr(item, "path", "/") or "/")
                req_headers = dict(getattr(item, "headers", {}) or {})
                plan_ua = str(getattr(item, "user_agent", "") or "").strip()
                if user_agent:
                    req_headers["user-agent"] = str(user_agent)
                elif plan_ua:
                    req_headers["user-agent"] = plan_ua
                req_body = getattr(item, "body", None)
                req_content_type = str(getattr(item, "content_type", "") or "").strip()
                if req_body is not None and req_content_type and "content-type" not in {
                    str(k).lower() for k in req_headers
                }:
                    req_headers["content-type"] = req_content_type
            else:
                req_method = str(http_method or "GET")
                req_path = str(random.choice(http_path) if isinstance(http_path, list) else http_path)
                req_headers = {}
                if user_agent:
                    req_headers["user-agent"] = str(user_agent)
                req_body = None
            reqs.append({"method": req_method, "path": req_path, "headers": req_headers, "body": req_body})

        try:
            h2_settings = dict(getattr(resolved_profile, "settings", {}) or {}) if resolved_profile is not None else {}
            h2_window_update = int(getattr(resolved_profile, "window_update", 0) or 0) if resolved_profile is not None else 0
            if h2_conn_count <= 1:
                h2_out = await h2_transport_module.send_h2_requests(
                    host=str(target_ip),
                    port=int(target_port),
                    requests=reqs,
                    verify=verify_tls,
                    ssl_context=ssl_ctx_obj,
                    timeout_s=10.0,
                    settings=h2_settings,
                    window_update=h2_window_update,
                    max_inflight_streams=h2_stream_cap,
                )
                merged = dict(h2_out or {})
            else:
                groups = [[] for _ in range(h2_conn_count)]
                for idx, req in enumerate(reqs):
                    groups[idx % h2_conn_count].append(req)
                tasks = []
                for grp in groups:
                    if not grp:
                        continue
                    tasks.append(
                        asyncio.create_task(
                            h2_transport_module.send_h2_requests(
                                host=str(target_ip),
                                port=int(target_port),
                                requests=grp,
                                verify=verify_tls,
                                ssl_context=ssl_ctx_obj,
                                timeout_s=10.0,
                                settings=h2_settings,
                                window_update=h2_window_update,
                                max_inflight_streams=h2_stream_cap,
                            )
                        )
                    )
                merged = {
                    "attempted": dispatch_count,
                    "sent": 0,
                    "errors": 0,
                    "responses_total": 0,
                    "status_2xx": 0,
                    "status_4xx": 0,
                    "status_5xx": 0,
                }
                if tasks:
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    for item in results:
                        if isinstance(item, Exception):
                            continue
                        merged["sent"] += int(item.get("sent", 0) or 0)
                        merged["responses_total"] += int(item.get("responses_total", 0) or 0)
                        merged["status_2xx"] += int(item.get("status_2xx", 0) or 0)
                        merged["status_4xx"] += int(item.get("status_4xx", 0) or 0)
                        merged["status_5xx"] += int(item.get("status_5xx", 0) or 0)
                merged["errors"] = max(0, dispatch_count - int(merged.get("sent", 0) or 0))

            sent_count = int(merged.get("sent", 0) or 0)
            err_count = int(merged.get("errors", max(0, dispatch_count - sent_count)) or 0)
            update_live_fn(live_progress, dispatch_count)
            update_live_fn(live_sent, sent_count)
            update_live_fn(live_errors, err_count)
            log_info(f"HTTP/2 (hyper-h2) finished sending {dispatch_count} requests.")
            return stats_fn(
                **normalize_l7_output_fn(
                    {
                        "attempted": dispatch_count,
                        "sent": sent_count,
                        "errors": max(err_count, dispatch_count - sent_count),
                        "responses_total": int(merged.get("responses_total", sent_count) or sent_count),
                        "status_2xx": int(merged.get("status_2xx", 0) or 0),
                        "status_4xx": int(merged.get("status_4xx", 0) or 0),
                        "status_5xx": int(merged.get("status_5xx", 0) or 0),
                        "h2_profile_requested": int(profile_requested),
                        "h2_profile_applied": int(bool(profile_requested and resolved_profile is not None)),
                        "h2_profile_disabled": profile_disabled,
                        "h2_profile_apply_failed": 0,
                        "h2_transport": "hyper-h2",
                        "h2_connections": h2_conn_count,
                        "h2_streams_per_conn": h2_stream_cap,
                        "sender_path": "PY_HTTP2",
                    },
                    attempted_default=dispatch_count,
                    sender_path="PY_HTTP2",
                    engine_path_used="PY_HTTP2",
                    fallback_reason=c_fallback_reason,
                    route=route,
                )
            )
        except Exception as exc:
            log_warning(f"HTTP/2 hyper-h2 transport failed: {exc}")
            if transport_name == "hyper-h2":
                update_live_fn(live_progress, dispatch_count)
                update_live_fn(live_errors, dispatch_count)
                return stats_fn(
                    **normalize_l7_output_fn(
                        {
                            "attempted": dispatch_count,
                            "sent": 0,
                            "errors": dispatch_count,
                            "h2_profile_requested": int(profile_requested),
                            "h2_profile_applied": 0,
                            "h2_profile_disabled": profile_disabled,
                            "h2_profile_apply_failed": int(
                                bool(profile_requested and resolved_profile is not None)
                            ),
                            "h2_transport": "hyper-h2",
                            "h2_connections": h2_conn_count,
                            "h2_streams_per_conn": h2_stream_cap,
                            "sender_path": "PY_HTTP2",
                        },
                        attempted_default=dispatch_count,
                        sender_path="PY_HTTP2",
                        engine_path_used="PY_HTTP2",
                        fallback_reason=c_fallback_reason,
                        route=route,
                    )
                )

    ok = 0
    err = 0
    responses = 0
    status_2xx = 0
    status_4xx = 0
    status_5xx = 0
    h2_cfg = None

    async def _flush(tasks):
        nonlocal ok, err, responses, status_2xx, status_4xx, status_5xx
        if not tasks:
            return
        res = await asyncio.gather(*tasks, return_exceptions=True)
        tasks.clear()

        batch_sent = 0
        batch_err = 0
        for r in res:
            if isinstance(r, Exception):
                err += 1
                batch_err += 1
            else:
                ok += 1
                batch_sent += 1
                responses += 1
                code = int(getattr(r, "status_code", 0) or 0)
                if 200 <= code < 300:
                    status_2xx += 1
                elif 400 <= code < 500:
                    status_4xx += 1
                elif code >= 500:
                    status_5xx += 1

        update_live_fn(live_sent, batch_sent)
        update_live_fn(live_errors, batch_err)

    headers = {}
    if user_agent:
        headers["User-Agent"] = user_agent

    try:
        limits = httpx_module.Limits(max_keepalive_connections=h2_conn_count, max_connections=h2_conn_count)
        async with httpx_module.AsyncClient(
            http2=True,
            base_url=base_url,
            limits=limits,
            cookies=cookies,
            headers=headers,
            verify=ssl_ctx_obj if ssl_ctx_obj is not None else verify_tls,
        ) as client:
            h2_cfg = h2_mimic.apply_h2_profile(client, h2_profile_name)
            if h2_cfg.applied:
                log_info(f"HTTP/2 profile applied: {h2_cfg.resolved}")
            else:
                log_warning(
                    f"HTTP/2 profile not applied: requested={h2_cfg.requested} "
                    f"resolved={h2_cfg.resolved} reason={h2_cfg.reason}"
                )

            tasks = []
            for i in range(dispatch_count):
                update_live_fn(live_progress, 1)
                if planned_items:
                    item = planned_items[i]
                    req_method = str(getattr(item, "method", http_method) or http_method)
                    req_path = str(getattr(item, "path", "/") or "/")
                    per_req_headers = dict(getattr(item, "headers", {}) or {})
                    if user_agent:
                        per_req_headers["User-Agent"] = str(user_agent)
                    else:
                        plan_ua = str(getattr(item, "user_agent", "") or "").strip()
                        if plan_ua:
                            per_req_headers["User-Agent"] = plan_ua
                    req_body = getattr(item, "body", None)
                    req_content_type = str(getattr(item, "content_type", "") or "").strip()
                    if req_body is not None and req_content_type:
                        existing_keys = {str(k).lower() for k in per_req_headers.keys()}
                        if "content-type" not in existing_keys:
                            per_req_headers["Content-Type"] = req_content_type
                    tasks.append(
                        asyncio.create_task(
                            client.request(
                                req_method,
                                req_path,
                                headers=per_req_headers or None,
                                content=req_body,
                            )
                        )
                    )
                else:
                    path = random.choice(http_path) if isinstance(http_path, list) else http_path
                    tasks.append(asyncio.create_task(client.request(http_method, path)))

                if len(tasks) >= max_dispatch_concurrency:
                    await _flush(tasks)

            if tasks:
                await _flush(tasks)

    except (httpx_module.ReadError, httpx_module.RemoteProtocolError, httpx_module.ConnectError) as e:
        log_error(f"HTTP/2 bağlantı hatası: Hedef sunucu HTTP/2'yi desteklemiyor veya bağlantıyı kesti. ({e})")
        err += max(1, dispatch_count - ok)
    except Exception as e:
        log_error(f"HTTP/2 sender failed: {e}\n{traceback.format_exc()}")
        err += max(1, dispatch_count - ok)
    finally:
        log_info(f"HTTP/2 sender finished sending {dispatch_count} requests.")
    return stats_fn(
        **normalize_l7_output_fn(
            {
                "attempted": dispatch_count,
                "sent": ok,
                "errors": max(err, dispatch_count - ok),
                "responses_total": responses,
                "status_2xx": status_2xx,
                "status_4xx": status_4xx,
                "status_5xx": status_5xx,
                "h2_profile_requested": bool(h2_cfg and h2_cfg.requested and h2_cfg.requested != "none"),
                "h2_profile_applied": bool(h2_cfg and h2_cfg.applied),
                "h2_profile_disabled": bool(h2_cfg and h2_cfg.reason == "profile_disabled"),
                "h2_profile_apply_failed": bool(
                    h2_cfg and (not h2_cfg.applied) and h2_cfg.reason != "profile_disabled"
                ),
                "h2_transport": "httpx",
                "h2_connections": h2_conn_count,
                "h2_streams_per_conn": h2_stream_cap,
                "sender_path": "PY_HTTP2",
            },
            attempted_default=dispatch_count,
            sender_path="PY_HTTP2",
            engine_path_used="PY_HTTP2",
            fallback_reason=c_fallback_reason,
            route=route,
        )
    )

