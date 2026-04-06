import asyncio


async def websocket_scenario_sender(
    target_ip,
    target_port,
    count,
    concurrency,
    ws_path,
    verbose,
    auth_message="",
    subscribe_messages=None,
    ping_message="ping",
    ping_count=1,
    await_response=False,
    l7_engine="python",
    lab_profile="off",
    l7_fallback_policy="allow",
    l7_capability_strict=False,
    request_plan=None,
    ssl_context=None,
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
    l7_telemetry_mod,
    WEBSOCKETS_AVAILABLE: bool,
    websockets_module,
):
    """
    Stateful WebSocket scenario runner:
      connect -> auth -> subscribe -> ping/pong (optional recv on each step)
    `count` denotes number of WS sessions/scenario runs.
    """
    route = l7_dispatch_mod.build_route_decision(
        L7RouteRequest_cls(
            protocol="ws",
            l7_engine=str(l7_engine or "python"),
            protocol_engine="auto",
            fallback_policy=str(l7_fallback_policy or "allow"),
            capability_strict=bool(l7_capability_strict),
            lab_profile=str(lab_profile or "off"),
        )
    )
    planned_items = list(getattr(request_plan, "items", []) or []) if request_plan is not None else []
    planned_paths = [str(getattr(item, "path", "") or "").strip() for item in planned_items]
    planned_paths = [p for p in planned_paths if p]
    planned_auth_msgs = [str(getattr(item, "ws_auth_message", "") or "").strip() for item in planned_items]
    planned_sub_msgs = [str(getattr(item, "ws_subscribe_message", "") or "").strip() for item in planned_items]
    planned_ping_msgs = [str(getattr(item, "ws_ping_message", "") or "").strip() for item in planned_items]

    def _normalize_ws_path(path_val: str) -> str:
        p = str(path_val or "").strip()
        if not p:
            return str(ws_path or "/")
        if p.startswith("ws://") or p.startswith("wss://"):
            try:
                from urllib.parse import urlsplit

                parsed = urlsplit(p)
                if parsed.path:
                    p = parsed.path
            except Exception:
                pass
        if not p.startswith("/"):
            p = "/" + p
        return p

    c_fallback_reason = "none"
    if route.engine == "c_state":
        cfg = l7_c_adapter_mod.make_config(
            target_ip=str(target_ip),
            target_port=int(target_port or 0),
            count=int(count or 0),
            concurrency=int(concurrency or 1),
            mode="websocket_stateful",
            extra={
                "scheme": "wss" if int(target_port or 0) == 443 else "ws",
                "ws_path": _normalize_ws_path(planned_paths[0] if planned_paths else ws_path),
                "ws_auth_message": str(auth_message or ""),
                "ws_subscribe_count": int(len(subscribe_messages or [])),
                "ws_subscribe_messages": "\x1f".join(str(m) for m in list(subscribe_messages or [])),
                "ws_ping_message": str(ping_message or "ping"),
                "ws_ping_count": int(ping_count or 0),
                "ws_await_response": bool(await_response),
                "ws_scenario_enabled": 1,
                "lab_profile": str(lab_profile or "off"),
                "l7_request_plan_count": int(len(planned_items)),
            },
        )
        c_res = await l7_c_adapter_mod.run("ws", cfg)
        if l7_legacy_mod.should_return_c_result(c_res, allow_python_fallback=route.allow_python_fallback):
            c_stats = l7_telemetry_mod.normalize_l7_stats(
                c_res.as_stats(),
                attempted_default=count,
                sender_path="C_STATE_WS",
                engine_path_used=route.l7_engine_path_used,
                fallback_reason=str(getattr(c_res, "sender_fallback_reason", "none") or "none"),
            )
            c_stats.update(route.as_stats())
            update_live_fn(live_progress, int(c_stats.get("attempted", count) or 0))
            update_live_fn(live_sent, int(c_stats.get("sent", 0) or 0))
            update_live_fn(live_errors, int(c_stats.get("errors", 0) or 0))
            return stats_fn(**c_stats)
        c_fallback_reason = str(getattr(c_res, "sender_fallback_reason", "none") or "none")
        log_warning(
            "L7 c_state websocket engine unavailable/failed; "
            f"Python websocket path fallback enabled (reason={c_fallback_reason})."
        )

    if not WEBSOCKETS_AVAILABLE:
        log_error("WebSocket desteği için 'websockets' kütüphanesi yüklü değil.")
        return stats_fn(
            **normalize_l7_output_fn(
                {"attempted": count, "sent": 0, "errors": count, "sender_path": "PY_WS"},
                attempted_default=count,
                sender_path="PY_WS",
                engine_path_used="PY_WS",
                fallback_reason=c_fallback_reason,
                route=route,
            )
        )

    scheme = "wss" if target_port == 443 else "ws"
    base_ws_path = _normalize_ws_path(ws_path)
    session_paths = []
    session_auth_messages = []
    session_subscribe_messages = []
    session_ping_messages = []
    for idx in range(max(0, int(count or 0))):
        if planned_paths:
            session_paths.append(_normalize_ws_path(planned_paths[idx % len(planned_paths)]))
        else:
            session_paths.append(base_ws_path)
        plan_auth = planned_auth_msgs[idx % len(planned_auth_msgs)] if planned_auth_msgs else ""
        plan_sub = planned_sub_msgs[idx % len(planned_sub_msgs)] if planned_sub_msgs else ""
        plan_ping = planned_ping_msgs[idx % len(planned_ping_msgs)] if planned_ping_msgs else ""
        session_auth_messages.append(plan_auth if plan_auth else str(auth_message or ""))
        if plan_sub:
            session_subscribe_messages.append([plan_sub])
        else:
            session_subscribe_messages.append([str(m) for m in list(subscribe_messages or [])])
        session_ping_messages.append(plan_ping if plan_ping else str(ping_message or "ping"))
    uri = f"{scheme}://{target_ip}:{target_port}{base_ws_path}"
    log_info(
        f"WebSocket scenario sender initialized. URI: {uri}, Sessions: {count}, "
        f"gpu_plan_items={len(planned_items)}"
    )

    subscribe_messages = list(subscribe_messages or [])
    ping_count = max(0, int(ping_count or 0))

    sessions_ok = 0
    session_errors = 0
    auth_sent = 0
    subscribe_sent = 0
    ping_sent = 0
    pong_received = 0

    effective_concurrency = min(max(1, int(concurrency or 1)), count) if count > 0 else 1
    per_worker_base = count // effective_concurrency
    remainder = count % effective_concurrency

    def _worker_count(worker_id: int) -> int:
        return per_worker_base + (1 if worker_id < remainder else 0)

    worker_offsets = []
    _cursor = 0
    for i in range(effective_concurrency):
        worker_offsets.append(_cursor)
        _cursor += _worker_count(i)

    async def _maybe_recv(ws):
        nonlocal pong_received
        if not await_response:
            return
        _ = await asyncio.wait_for(ws.recv(), timeout=3.0)
        pong_received += 1

    async def _scenario_worker(worker_id: int):
        nonlocal sessions_ok, session_errors, auth_sent, subscribe_sent, ping_sent
        my_sessions = _worker_count(worker_id)
        base_index = int(worker_offsets[worker_id]) if worker_id < len(worker_offsets) else 0
        for session_local in range(my_sessions):
            session_idx = base_index + session_local
            session_path = session_paths[session_idx] if session_idx < len(session_paths) else base_ws_path
            session_uri = f"{scheme}://{target_ip}:{target_port}{session_path}"
            session_auth = (
                session_auth_messages[session_idx]
                if session_idx < len(session_auth_messages)
                else str(auth_message or "")
            )
            session_subs = (
                session_subscribe_messages[session_idx]
                if session_idx < len(session_subscribe_messages)
                else list(subscribe_messages or [])
            )
            session_ping = (
                session_ping_messages[session_idx]
                if session_idx < len(session_ping_messages)
                else str(ping_message or "ping")
            )
            update_live_fn(live_progress, 1)
            try:
                async with websockets_module.connect(session_uri, ssl=ssl_context) as websocket:
                    if session_auth:
                        await websocket.send(str(session_auth))
                        auth_sent += 1
                        await _maybe_recv(websocket)

                    for sub_msg in session_subs:
                        await websocket.send(str(sub_msg))
                        subscribe_sent += 1
                        await _maybe_recv(websocket)

                    for _ in range(ping_count):
                        await websocket.send(str(session_ping))
                        ping_sent += 1
                        await _maybe_recv(websocket)

                    sessions_ok += 1
                    update_live_fn(live_sent, 1)
            except Exception as exc:
                session_errors += 1
                update_live_fn(live_errors, 1)
                if verbose:
                    log_error(f"WS scenario failed: {exc}")

    tasks = [asyncio.create_task(_scenario_worker(i)) for i in range(effective_concurrency)]
    await asyncio.gather(*tasks)
    log_info(
        "WebSocket scenario finished. "
        f"sessions_ok={sessions_ok} errors={session_errors} auth={auth_sent} "
        f"sub={subscribe_sent} ping={ping_sent} pong={pong_received}"
    )
    py_stats = l7_telemetry_mod.normalize_l7_stats(
        {
            "attempted": count,
            "sent": sessions_ok,
            "errors": max(session_errors, count - sessions_ok),
            "ws_sessions_ok": sessions_ok,
            "ws_auth_sent": auth_sent,
            "ws_subscribe_sent": subscribe_sent,
            "ws_ping_sent": ping_sent,
            "ws_pong_received": pong_received,
            "ws_scenario_enabled": 1,
            "sender_path": "PY_WS_SCENARIO",
            "l7_engine_path_used": "PY_WS",
            "l7_fallback_reason": c_fallback_reason,
            "l7_request_plan_used": int(bool(planned_items)),
            "l7_request_plan_items": int(len(planned_items)),
        },
        attempted_default=count,
        sender_path="PY_WS_SCENARIO",
        engine_path_used="PY_WS",
        fallback_reason=c_fallback_reason,
    )
    py_stats.update(route.as_stats())
    py_stats["l7_engine_path_used"] = "PY_WS"
    return stats_fn(**py_stats)
