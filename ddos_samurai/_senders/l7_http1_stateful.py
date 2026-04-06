import os
import random
import time

import numpy as np

from .. import virtual_user as virtual_user_module


async def http_stateful_sender(
    target_ip,
    target_port,
    vu_count,
    concurrency,
    workflow_steps,
    verbose,
    scheme="http",
    verify=False,
    timeout_s=10.0,
    user_agent=None,
    ssl_context=None,
    retries=0,
    http_method="GET",
    http_path="/",
    payloads=None,
    session_repeats=1,
    max_active_sessions=None,
    session_keepalive=True,
    l7_engine="python",
    lab_profile="off",
    l7_fallback_policy="allow",
    l7_capability_strict=False,
    request_plan=None,
    live_sent=None,
    live_errors=None,
    live_progress=None,
    *,
    stats_fn,
    update_live_fn,
    log_info,
    log_warning,
    l7_dispatch_mod,
    L7RouteRequest_cls,
    l7_c_adapter_mod,
    l7_legacy_mod,
    l7_telemetry_mod,
):
    """
    Stateful HTTP sender using VirtualUser engine.
    Each VU has its own cookie jar, token cache, and redirect history.
    """
    del verbose
    base_url = f"{scheme}://{target_ip}:{target_port}"
    vu_count = max(0, int(vu_count or 0))
    if vu_count <= 0:
        return stats_fn(attempted=0, sent=0, errors=0)
    planned_items = list(getattr(request_plan, "items", []) or []) if request_plan is not None else []
    planned_paths = [str(getattr(item, "path", "") or "").strip() for item in planned_items]
    planned_paths = [p for p in planned_paths if p]
    planned_methods = [str(getattr(item, "method", "") or "").strip().upper() for item in planned_items]
    planned_methods = [m for m in planned_methods if m]
    planned_uas = [str(getattr(item, "user_agent", "") or "").strip() for item in planned_items]
    planned_uas = [ua for ua in planned_uas if ua]
    planned_headers = [dict(getattr(item, "headers", {}) or {}) for item in planned_items]
    planned_bodies = [getattr(item, "body", None) for item in planned_items]
    planned_content_types = [str(getattr(item, "content_type", "") or "").strip() for item in planned_items]

    if not user_agent and planned_uas:
        user_agent = planned_uas[0]

    route = l7_dispatch_mod.build_route_decision(
        L7RouteRequest_cls(
            protocol="http1",
            l7_engine=str(l7_engine or "python"),
            protocol_engine="auto",
            fallback_policy=str(l7_fallback_policy or "allow"),
            capability_strict=bool(l7_capability_strict),
            lab_profile=str(lab_profile or "off"),
        )
    )
    c_fallback_reason = "none"
    if route.engine == "c_state":
        _http_path_first = str(planned_paths[0]) if planned_paths else (
            str(http_path[0]) if isinstance(http_path, list) and len(http_path) > 0 else str(http_path or "/")
        )
        _http_method_first = str(planned_methods[0]) if planned_methods else str(http_method or "GET")
        cfg = l7_c_adapter_mod.make_config(
            target_ip=str(target_ip),
            target_port=int(target_port or 0),
            count=int(vu_count),
            concurrency=int(concurrency or 1),
            session_repeats=int(session_repeats or 1),
            max_active_sessions=int(max_active_sessions or 0),
            mode="http1_stateful",
            extra={
                "scheme": str(scheme or "http"),
                "verify": bool(verify),
                "timeout_s": float(timeout_s or 10.0),
                "lab_profile": str(lab_profile or "off"),
                "retries": int(retries or 0),
                "http_method": _http_method_first,
                "http_path": _http_path_first,
                "l7_request_plan_count": int(len(planned_items)),
            },
        )
        c_res = await l7_c_adapter_mod.run("http1", cfg)
        if l7_legacy_mod.should_return_c_result(c_res, allow_python_fallback=route.allow_python_fallback):
            c_stats = l7_telemetry_mod.normalize_l7_stats(
                c_res.as_stats(),
                attempted_default=vu_count,
                sender_path="C_STATE_HTTP1",
                engine_path_used=route.l7_engine_path_used,
                fallback_reason=str(getattr(c_res, "sender_fallback_reason", "none") or "none"),
            )
            c_stats.update(route.as_stats())
            update_live_fn(live_progress, int(c_stats.get("attempted", vu_count) or 0))
            update_live_fn(live_sent, int(c_stats.get("sent", 0) or 0))
            update_live_fn(live_errors, int(c_stats.get("errors", 0) or 0))
            return stats_fn(**c_stats)
        c_fallback_reason = str(getattr(c_res, "sender_fallback_reason", "none") or "none")
        log_warning(
            "L7 c_state HTTP engine unavailable/failed; "
            f"Python VirtualUser path fallback enabled (reason={c_fallback_reason})."
        )

    max_vus = max(1, int(os.environ.get("SAMURAI_L7_MAX_VUS", "20000") or 20000))
    if vu_count > max_vus:
        log_warning(f"Stateful HTTP VU count capped: {vu_count} -> {max_vus}")
        vu_count = max_vus

    max_retries = max(0, int(retries or 0))
    session_repeats = max(1, int(session_repeats or 1))
    if max_active_sessions is None:
        max_active_sessions = int(os.environ.get("SAMURAI_L7_MAX_ACTIVE_SESSIONS", "0") or 0)
    max_active_sessions = int(max_active_sessions or 0)
    if max_active_sessions > 0:
        concurrency = min(int(concurrency or 1), max_active_sessions)
    concurrency = max(1, int(concurrency or 1))
    steps_provider = None

    def _build_default_workflow(
        *,
        path_list: list[str],
        method_name: str,
        body_payload,
        action_headers: dict[str, str] | None = None,
    ):
        step0 = str(path_list[0])
        step1 = str(path_list[1] if len(path_list) > 1 else path_list[0])
        step2 = str(path_list[2] if len(path_list) > 2 else path_list[-1])
        action_headers = dict(action_headers or {})
        common_headers = {}
        if "accept" in action_headers:
            common_headers["Accept"] = str(action_headers["accept"])
        if "accept-language" in action_headers:
            common_headers["Accept-Language"] = str(action_headers["accept-language"])
        return [
            virtual_user_module.WorkflowStep(
                name="bootstrap",
                method="GET",
                path=step0,
                expected_status=(200, 399),
                follow_redirects=True,
                extract=[
                    virtual_user_module.ExtractRule(
                        field_name="X-CSRF-Token", source="header", header_name="X-CSRF-Token"
                    ),
                    virtual_user_module.ExtractRule(
                        field_name="csrf_token",
                        source="body_regex",
                        regex_pattern=r'name=["\']csrf(?:_token)?["\']\s+value=["\']([^"\']+)["\']',
                    ),
                    virtual_user_module.ExtractRule(
                        field_name="sessionid", source="cookie", cookie_name="sessionid"
                    ),
                ],
                timeout_s=float(timeout_s),
                max_retries=max_retries,
                headers=common_headers,
            ),
            virtual_user_module.WorkflowStep(
                name="prefetch",
                method="GET",
                path=step1,
                expected_status=(200, 399),
                follow_redirects=True,
                timeout_s=float(timeout_s),
                max_retries=max_retries,
                headers=common_headers,
            ),
            virtual_user_module.WorkflowStep(
                name="action",
                method=method_name,
                path=step2,
                body=body_payload,
                expected_status=(200, 499),
                follow_redirects=True,
                inject_tokens=["X-CSRF-Token", "X-CSRF-Token:csrf_token"],
                timeout_s=float(timeout_s),
                max_retries=max_retries,
                headers=action_headers,
            ),
        ]

    if not workflow_steps:
        default_paths = list(planned_paths) if planned_paths else (
            list(http_path) if isinstance(http_path, list) else [http_path]
        )
        default_paths = [str(p) for p in default_paths if str(p).strip()] or ["/"]
        default_method = str(planned_methods[0] if planned_methods else (http_method or "GET")).upper()
        default_body = None
        if planned_bodies and planned_bodies[0] is not None:
            default_body = planned_bodies[0]
        elif isinstance(payloads, list) and payloads:
            default_body = random.choice(payloads)
        default_headers = dict(planned_headers[0] if planned_headers else {})
        if default_body is not None and planned_content_types and planned_content_types[0]:
            default_headers.setdefault("Content-Type", planned_content_types[0])
        workflow_steps = _build_default_workflow(
            path_list=default_paths,
            method_name=default_method,
            body_payload=default_body,
            action_headers=default_headers,
        )
        if planned_items:

            def _item_for_session(uid: int, rep_idx: int):
                idx = (int(uid) * int(session_repeats) + int(rep_idx)) % max(1, len(planned_items))
                return planned_items[idx]

            def _steps_provider(uid: int, rep_idx: int):
                plan_item = _item_for_session(uid, rep_idx)
                item_method = str(getattr(plan_item, "method", default_method) or default_method).upper()
                item_path = str(getattr(plan_item, "path", default_paths[0]) or default_paths[0])
                item_headers = dict(getattr(plan_item, "headers", {}) or {})
                item_body = getattr(plan_item, "body", None)
                item_content_type = str(getattr(plan_item, "content_type", "") or "").strip()
                if item_body is not None and item_content_type:
                    item_headers.setdefault("Content-Type", item_content_type)
                if not user_agent:
                    plan_ua = str(getattr(plan_item, "user_agent", "") or "").strip()
                    if plan_ua:
                        item_headers.setdefault("User-Agent", plan_ua)
                return _build_default_workflow(
                    path_list=[item_path, item_path, item_path],
                    method_name=item_method,
                    body_payload=item_body,
                    action_headers=item_headers,
                )

            steps_provider = _steps_provider

    step_count = len(workflow_steps)
    log_info(f"Stateful HTTP sender: {vu_count} VUs × {step_count} steps → {base_url}")

    run_started = time.monotonic()
    results, metrics = await virtual_user_module.run_vu_pool(
        vu_count=vu_count,
        base_url=base_url,
        steps=workflow_steps,
        steps_provider=steps_provider,
        concurrency=concurrency,
        verify=ssl_context if ssl_context else verify,
        timeout_s=timeout_s,
        user_agent=user_agent,
        session_repeats=session_repeats,
        max_active_sessions=max_active_sessions if max_active_sessions > 0 else None,
        session_keepalive=bool(session_keepalive),
    )
    run_duration_s = max(0.0, time.monotonic() - run_started)

    total_steps = sum(r.steps_ok + r.steps_failed for r in results)
    total_ok = sum(r.steps_ok for r in results)
    total_err = sum(r.steps_failed for r in results)
    retries_used = sum(int(getattr(r, "retries_used", 0) or 0) for r in results)
    handshake_samples_ms = [
        float(getattr(r, "first_step_latency_ms", 0.0) or 0.0)
        for r in results
        if float(getattr(r, "first_step_latency_ms", 0.0) or 0.0) > 0.0
    ]
    if handshake_samples_ms:
        l7_handshake_p99_ms = float(np.percentile(np.asarray(handshake_samples_ms, dtype=np.float64), 99))
    else:
        l7_handshake_p99_ms = 0.0
    l7_conn_total = int(metrics.workflows_completed) + int(metrics.workflows_failed)
    l7_conn_rate = float(l7_conn_total) / float(max(1e-9, run_duration_s))
    l7_step_fail_ratio = float(total_err) / float(max(1, total_steps))

    update_live_fn(live_sent, total_ok)
    update_live_fn(live_errors, total_err)
    update_live_fn(live_progress, total_steps)

    log_info(
        f"Stateful HTTP finished. VUs={vu_count} ok={metrics.workflows_completed} "
        f"fail={metrics.workflows_failed} session_success={metrics.session_success_rate:.2%}"
    )

    py_stats = l7_telemetry_mod.normalize_l7_stats(
        {
            "attempted": total_steps,
            "sent": total_ok,
            "errors": total_err,
            "retries_used": retries_used,
            "l7_active_sessions_peak": int(getattr(metrics, "active_sessions_peak", 0) or 0),
            "l7_conn_rate": float(l7_conn_rate),
            "l7_handshake_p99_ms": float(l7_handshake_p99_ms),
            "l7_step_fail_ratio": float(l7_step_fail_ratio),
            "sender_path": "PY_HTTP1_STATEFUL",
            "l7_engine_path_used": "PY_HTTP1",
            "l7_fallback_reason": c_fallback_reason,
            "l7_request_plan_used": int(bool(planned_items)),
            "l7_request_plan_items": int(len(planned_items)),
            **metrics.as_dict(),
        },
        attempted_default=total_steps,
        sender_path="PY_HTTP1_STATEFUL",
        engine_path_used="PY_HTTP1",
        fallback_reason=c_fallback_reason,
    )
    py_stats.update(route.as_stats())
    py_stats["l7_engine_path_used"] = "PY_HTTP1"
    return stats_fn(**py_stats)
