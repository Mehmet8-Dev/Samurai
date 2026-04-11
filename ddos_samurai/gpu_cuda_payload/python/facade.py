from __future__ import annotations

import asyncio
import random
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .adapters import normalize_vector_spec

try:
    from ddos_samurai import _gpu_cuda_payload_native as _native
except Exception:  # pragma: no cover - optional native module
    _native = None


def _python_compile_vector_spec(spec: Dict[str, Any], seed: int, batch_size: int) -> Dict[str, Any]:
    n = int(batch_size)
    if n <= 0:
        raise ValueError("batch_size must be > 0")
    rng = random.Random(int(seed) & 0xFFFFFFFFFFFFFFFF)
    methods = list(spec["methods"])
    paths = list(spec["paths"])
    header_profiles = list(spec["header_profiles"])
    body_profiles = list(spec["body_profiles"])
    max_steps = int(spec["max_steps"])
    method_idx: List[int] = []
    path_idx: List[int] = []
    header_profile_idx: List[int] = []
    body_kind: List[int] = []
    step_id: List[int] = []
    think_time_ms: List[int] = []
    flags: List[int] = []
    for i in range(n):
        method_idx.append(rng.randrange(len(methods)))
        path_idx.append(rng.randrange(len(paths)))
        header_profile_idx.append(rng.randrange(len(header_profiles)))
        body_kind.append(rng.randrange(len(body_profiles)))
        step = i % max_steps
        step_id.append(step)
        think_time_ms.append(2000 + rng.randrange(5000) if step == 0 else 50 + rng.randrange(200))
        flags.append(rng.getrandbits(31))
    return {
        "schema_version": 1,
        "seed": int(seed),
        "count": n,
        "method_idx": method_idx,
        "path_idx": path_idx,
        "header_profile_idx": header_profile_idx,
        "body_kind": body_kind,
        "step_id": step_id,
        "think_time_ms": think_time_ms,
        "flags": flags,
        "metadata": {
            "mode": spec["mode"],
            "methods": methods,
            "paths": paths,
            "header_profiles": header_profiles,
            "body_profiles": body_profiles,
            "max_steps": max_steps,
        },
    }


def compile_vector_spec(spec: Dict[str, Any], seed: int, batch_size: int) -> Dict[str, Any]:
    normalized = normalize_vector_spec(spec)
    if _native is not None:
        return dict(_native.compile_vector_spec(normalized, int(seed), int(batch_size)))
    return _python_compile_vector_spec(normalized, int(seed), int(batch_size))


@dataclass(frozen=True)
class _CompatPlanItem:
    method: str
    path: str
    user_agent: Optional[str] = None
    headers: Dict[str, str] | None = None
    body: bytes | None = None
    content_type: Optional[str] = None


@dataclass(frozen=True)
class _CompatPlan:
    items: List[_CompatPlanItem]


def plan_batch_to_h2_request_plan(plan_batch: Dict[str, Any]) -> Any:
    try:
        from ddos_samurai.gpu_payload import H2RequestPlan as _Plan
        from ddos_samurai.gpu_payload import H2RequestPlanItem as _PlanItem
    except Exception:  # pragma: no cover - fallback when GPU deps are unavailable
        _Plan = _CompatPlan
        _PlanItem = _CompatPlanItem

    metadata = dict(plan_batch.get("metadata") or {})
    methods = list(metadata.get("methods") or ["GET"])
    paths = list(metadata.get("paths") or ["/"])
    method_idx = list(plan_batch.get("method_idx") or [])
    path_idx = list(plan_batch.get("path_idx") or [])
    step_id = list(plan_batch.get("step_id") or [])
    count = int(plan_batch.get("count", 0) or 0)

    items: List[Any] = []
    for i in range(count):
        m = methods[int(method_idx[i]) % len(methods)] if methods else "GET"
        p = paths[int(path_idx[i]) % len(paths)] if paths else "/"
        step = int(step_id[i]) if i < len(step_id) else 0
        headers = {
            "x-gpu-vector-step": str(step),
            "x-gpu-vector-source": "gpu_cuda_payload_v1",
        }
        items.append(_PlanItem(method=str(m).upper(), path=str(p), headers=headers))
    return _Plan(items=items)


def build_request_plan_from_session_plan(session_plan: Any) -> Any:
    events = []
    if isinstance(session_plan, dict):
        events = list(session_plan.get("events", []) or [])
    else:
        events = list(getattr(session_plan, "events", []) or [])

    items: List[Any] = []
    try:
        from ddos_samurai.gpu_payload import H2RequestPlan as _Plan
        from ddos_samurai.gpu_payload import H2RequestPlanItem as _PlanItem
    except Exception:  # pragma: no cover - fallback when optional deps are unavailable
        _Plan = _CompatPlan
        _PlanItem = _CompatPlanItem

    for ev in events:
        if isinstance(ev, dict):
            event_type = str(ev.get("event_type", "") or "")
            method = str(ev.get("method", "GET") or "GET")
            path = str(ev.get("path", "/") or "/")
            header_profile = str(ev.get("header_profile", "") or "")
            payload_class = str(ev.get("payload_class", "") or "")
        else:
            event_type = str(getattr(ev, "event_type", "") or "")
            method = str(getattr(ev, "method", "GET") or "GET")
            path = str(getattr(ev, "path", "/") or "/")
            header_profile = str(getattr(ev, "header_profile", "") or "")
            payload_class = str(getattr(ev, "payload_class", "") or "")
        if event_type not in {"http_request", "http2_headers", "quic_request", "ws_open", "ws_frame"}:
            continue
        headers: Dict[str, str] = {}
        if header_profile:
            headers["x-header-profile"] = header_profile
        if payload_class:
            headers["x-payload-class"] = payload_class
        items.append(
            _PlanItem(
                method=method if method else "GET",
                path=path if path else "/",
                headers=headers,
            )
        )
    return _Plan(items=items)


def _run_coro_sync(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    out: Dict[str, Any] = {}
    err: Dict[str, BaseException] = {}

    def _runner():
        try:
            out["value"] = asyncio.run(coro)
        except BaseException as exc:  # pragma: no cover - defensive
            err["value"] = exc

    t = threading.Thread(target=_runner, daemon=True)
    t.start()
    t.join()
    if "value" in err:
        raise err["value"]
    return out.get("value")


def _strict_runtime_precheck(runtime_cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    strict = bool(runtime_cfg.get("stateful_runtime_strict", True))
    legacy_mode = bool(runtime_cfg.get("legacy_mode", False))
    transport_backend = str(runtime_cfg.get("transport_backend", "custom_tcp") or "custom_tcp").strip().lower()
    stateful_runtime_backend = str(runtime_cfg.get("stateful_runtime_backend", "afxdp") or "afxdp").strip().lower()
    if not strict or legacy_mode or transport_backend != "custom_tcp" or stateful_runtime_backend not in {"afxdp", "dpdk"}:
        return {
            "attempted": int(runtime_cfg.get("count", 0) or 0),
            "sent": 0,
            "errors": int(runtime_cfg.get("count", 0) or 0),
            "sender_fallback_reason": "stateful_runtime_transport_unavailable",
            "stateful_runtime_reason": "stateful_runtime_transport_unavailable",
            "stateful_runtime_detail": "gpu_cuda_payload requires strict stateful custom_tcp (afxdp|dpdk) runtime",
            "stateful_runtime_strict": 1 if strict else 0,
        }
    return None


def execute_plan_batch(plan_batch: Dict[str, Any], runtime_cfg: Dict[str, Any]) -> Dict[str, Any]:
    precheck = _strict_runtime_precheck(runtime_cfg)
    if precheck is not None:
        return precheck

    from ddos_samurai.l7_emu.compiler import compile_l7_profile
    from ddos_samurai.l7_emu.runtime import run_l7_profile
    from ddos_samurai.l7_emu.types import RuntimeConfig

    target_ip = str(runtime_cfg.get("target_ip", "127.0.0.1") or "127.0.0.1")
    target_port = int(runtime_cfg.get("target_port", 443) or 443)
    protocol = str(runtime_cfg.get("protocol", "http2") or "http2").strip().lower()
    if protocol not in {"http1", "http2"}:
        protocol = "http2"
    concurrency = max(1, int(runtime_cfg.get("concurrency", 1) or 1))
    count = max(1, int(plan_batch.get("count", runtime_cfg.get("count", 1)) or 1))
    request_plan = plan_batch_to_h2_request_plan(plan_batch)
    profile = compile_l7_profile(
        protocol=protocol,
        target_ip=target_ip,
        target_port=target_port,
        scheme=str(runtime_cfg.get("scheme", "https" if protocol == "http2" else "http") or "http"),
        transport_backend="custom_tcp",
        stateful_runtime_backend=str(runtime_cfg.get("stateful_runtime_backend", "afxdp") or "afxdp"),
        stateful_runtime_strict=True,
        legacy_mode=False,
        http_method=str(runtime_cfg.get("http_method", "GET") or "GET"),
        http_path=runtime_cfg.get("http_path", ["/"]),
        request_plan=request_plan,
        concurrency=concurrency,
        max_streams_per_connection=max(1, int(runtime_cfg.get("max_streams_per_connection", concurrency) or concurrency)),
    )
    run_cfg = RuntimeConfig(
        concurrency=concurrency,
        stateful_runtime_backend=str(runtime_cfg.get("stateful_runtime_backend", "afxdp") or "afxdp"),
        stateful_runtime_strict=True,
        legacy_mode=False,
        profile_l7=bool(runtime_cfg.get("profile_l7", False)),
        profile_sample_limit=int(runtime_cfg.get("profile_sample_limit", 0) or 0),
    )

    run_out = _run_coro_sync(run_l7_profile(profile, run_cfg))
    result = run_out.as_dict()
    result.setdefault("attempted", count)
    result.setdefault("stateful_runtime_strict", 1)
    result.setdefault("gpu_vector_engine", "gpu_cuda_payload_v1")
    return result


def evaluate_oracle(plan_batch: Dict[str, Any], run_result: Dict[str, Any], checks: Dict[str, Any] | None = None) -> Dict[str, Any]:
    payload = dict(checks or {})
    payload.setdefault("require_strict", True)
    if _native is not None:
        return dict(_native.evaluate_oracle(plan_batch, run_result, payload))
    sent = int(run_result.get("sent", 0) or 0)
    errors = int(run_result.get("errors", 0) or 0)
    reasons: List[str] = []
    if sent <= 0:
        reasons.append("no_sent_traffic")
    if errors > sent + 1:
        reasons.append("error_ratio_high")
    if bool(payload.get("require_strict", True)) and int(run_result.get("stateful_runtime_strict", 0) or 0) == 0:
        reasons.append("strict_runtime_not_enforced")
    return {
        "pass": len(reasons) == 0,
        "reasons": reasons,
        "sent": sent,
        "errors": errors,
    }
