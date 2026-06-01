from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from .metrics_schema import build_empty_stats, recompute_loss_metrics
from .zmq.dispatcher import ZmqDispatcher
from .zmq.event_collector import ZmqEventCollector
from .zmq.runtime_manager import ZmqRuntimeManager
from .zmq.wire import (
    JitterModel,
    MessageType,
    PacingConfig,
    PacingMode,
    WorkerKind,
    default_event_endpoint,
    default_job_endpoint,
)


def _empty_stats() -> dict:
    return build_empty_stats(status="ok")


def _add_stats(acc: dict, item: dict) -> dict:
    out = dict(acc or _empty_stats())
    d = dict(item or {})
    out["attempted"] = int(out.get("attempted", 0) or 0) + int(d.get("attempted", 0) or 0)
    out["sent"] = int(out.get("sent", 0) or 0) + int(d.get("sent", 0) or 0)
    out["errors"] = int(out.get("errors", 0) or 0) + int(d.get("errors", 0) or 0)
    out["bytes_sent_est"] = int(out.get("bytes_sent_est", 0) or 0) + int(d.get("bytes_sent_est", 0) or 0)
    return out


_PACING_MODE_MAP = {
    "none": PacingMode.NONE,
    "rps": PacingMode.RPS,
    "ipg": PacingMode.IPG,
    "burst": PacingMode.BURST,
}
_JITTER_MODEL_MAP = {
    "none": JitterModel.NONE,
    "uniform": JitterModel.UNIFORM,
    "gaussian": JitterModel.GAUSSIAN,
    "exponential": JitterModel.EXPONENTIAL,
}


def _build_pacing_config(args: dict) -> PacingConfig:
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


def _resolve_worker_kind_for_zmq(args: dict) -> WorkerKind:
    backend = str(args.get("compute_backend", "cpu") or "cpu").strip().lower()
    sender_backend = str(args.get("sender_backend", "") or "").strip().lower()
    attack_vector = str(args.get("attack_vector", "basic") or "basic").strip().lower()
    scenario_mode = str(args.get("scenario_mode", "off") or "off").strip().lower()
    scenario_payload_ref = str(args.get("scenario_payload_ref", "") or "").strip()
    xdp_enable = _coerce_bool(args.get("xdp_enable", False), default=False)

    if scenario_mode in {"shadow", "enforce"} or bool(scenario_payload_ref):
        return WorkerKind.SCENARIO

    if backend == "cuda":
        if attack_vector in {"defense", "gpu-defense"}:
            return WorkerKind.DEFENSE
        return WorkerKind.GPU
    if backend == "dpdk":
        return WorkerKind.DPDK
    if xdp_enable or sender_backend == "xdp":
        return WorkerKind.AF_XDP
    if backend in {"af_xdp", "xdp"}:
        return WorkerKind.AF_XDP
    if attack_vector in {"http", "http2", "websocket", "slowloris", "l4_tcp", "quic"}:
        return WorkerKind.L7
    return WorkerKind.CPU


def _update_shared_counters(progress, progress_lock, sent_total, errors_total, *, attempted: int, sent: int, errors: int) -> None:
    if progress is None:
        return
    if progress_lock is not None:
        with progress_lock:
            progress.value += int(attempted)
            if sent_total is not None:
                sent_total.value += int(sent)
            if errors_total is not None:
                errors_total.value += int(errors)
        return
    progress.value += int(attempted)
    if sent_total is not None:
        sent_total.value += int(sent)
    if errors_total is not None:
        errors_total.value += int(errors)


def _coerce_bool(raw: Any, default: bool = False) -> bool:
    if isinstance(raw, bool):
        return bool(raw)
    if raw is None:
        return bool(default)
    txt = str(raw).strip().lower()
    if txt in {"1", "true", "yes", "on"}:
        return True
    if txt in {"0", "false", "no", "off"}:
        return False
    return bool(default)


def _resolve_worker_search_dir(args: dict) -> str | None:
    explicit = str(args.get("zmq_worker_search_dir", "") or "").strip()
    if explicit:
        return explicit
    env_dir = str(os.environ.get("SAMURAI_ZMQ_WORKER_DIR", "") or "").strip()
    if env_dir:
        return env_dir
    repo_root = Path(__file__).resolve().parents[1]
    auto = repo_root / "build-workers"
    if auto.exists():
        return str(auto)
    return None


def _resolve_xdp_native_lib_path() -> str | None:
    env_path = str(os.environ.get("SAMURAI_XDP_NATIVE_LIB", "") or "").strip()
    if env_path:
        return env_path

    repo_root = Path(__file__).resolve().parents[1]
    candidates = [
        repo_root / "ddos_samurai" / "xdp_sender.so",
        repo_root / "ddos_samurai" / "xdp_sender.cpython-312-x86_64-linux-gnu.so",
        repo_root / "ddos_samurai" / "xdp_sender.cpython-311-x86_64-linux-gnu.so",
        repo_root / "ddos_samurai" / "xdp_sender.cpython-310-x86_64-linux-gnu.so",
        repo_root / "build" / "lib.linux-x86_64-cpython-312" / "ddos_samurai" / "xdp_sender.cpython-312-x86_64-linux-gnu.so",
        repo_root / "build" / "lib.linux-x86_64-cpython-311" / "ddos_samurai" / "xdp_sender.cpython-311-x86_64-linux-gnu.so",
        repo_root / "build" / "lib.linux-x86_64-cpython-310" / "ddos_samurai" / "xdp_sender.cpython-310-x86_64-linux-gnu.so",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return None


def _snapshot_loss_telemetry(args: dict) -> dict[str, Any] | None:
    try:
        from . import loss_telemetry

        iface = str(args.get("loss_iface", args.get("iface", "")) or "").strip() or None
        return dict(loss_telemetry.snapshot(iface=iface))
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        return None


def _attach_loss_telemetry_delta(args: dict, worker_stats: dict, before: dict[str, Any] | None, after: dict[str, Any] | None) -> None:
    if not isinstance(before, dict) or not isinstance(after, dict):
        return
    try:
        from . import loss_telemetry

        d = dict(loss_telemetry.delta(before, after) or {})
        worker_stats.update(d)
        iface = str(args.get("loss_iface", args.get("iface", "")) or "").strip()
        if iface:
            worker_stats.setdefault("iface", iface)
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        return


def _prepare_scenario_payload_ref(args: dict, *, worker_id: int, job_id: str) -> tuple[str, list[str]]:
    existing = str(args.get("scenario_payload_ref", "") or "").strip()
    if existing:
        return existing, []

    scenario_mode = str(args.get("scenario_mode", "off") or "off").strip().lower()
    if scenario_mode not in {"shadow", "enforce"}:
        return "", []

    sessions = list(args.get("scenario_sessions") or [])
    if not sessions:
        return "", []

    out_dir = str(args.get("scenario_payload_dir", os.environ.get("SAMURAI_SCENARIO_PAYLOAD_DIR", "/tmp")) or "/tmp").strip()
    os.makedirs(out_dir, exist_ok=True)
    safe_job = "".join(c if (str(c).isalnum() or str(c) in {"-", "_"}) else "_" for c in str(job_id))[:64] or "job"
    out_path = os.path.join(out_dir, f"samurai_scenario_{safe_job}_{int(worker_id)}.json")
    payload = {
        "schema_version": 1,
        "job_id": str(job_id),
        "worker_id": int(worker_id),
        "scenario_mode": scenario_mode,
        "created_ts_ns": int(time.time_ns()),
        "sessions": sessions,
        "runtime_metrics": dict(args.get("scenario_runtime_metrics") or {}),
        "runtime_batches": list(args.get("scenario_runtime_batches") or []),
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False)
    return str(out_path), [str(out_path)]


def start_worker_zmq(
    worker_id,
    args,
    progress=None,
    progress_lock=None,
    tls_profile="none",
    run_events=None,
    sent_total=None,
    errors_total=None,
    resource_stats=None,
    stop_event=None,
):
    _ = tls_profile
    _ = resource_stats

    worker_started = time.time()
    worker_status = "ok"
    worker_error = ""
    worker_stats = _empty_stats()
    backend_used = "zmq"

    correlation_id = int(args.get("correlation_id", 0) or 0)
    if correlation_id <= 0:
        correlation_id = int((time.time_ns() ^ int(worker_id)) & 0xFFFFFFFFFFFFFFFF)
    job_id = str(args.get("job_id", "") or "").strip() or f"w{int(worker_id)}-{correlation_id:016x}"
    last_correlation_id = int(correlation_id)

    dispatcher: ZmqDispatcher | None = None
    collector: ZmqEventCollector | None = None
    runtime: ZmqRuntimeManager | None = None
    worker_kind: WorkerKind | None = None
    telemetry_before: dict[str, Any] | None = None
    telemetry_after: dict[str, Any] | None = None
    scenario_payload_ref, scenario_payload_temp_paths = _prepare_scenario_payload_ref(
        dict(args or {}),
        worker_id=int(worker_id),
        job_id=job_id,
    )

    def _stop_requested() -> bool:
        if stop_event is None:
            return False
        try:
            return bool(stop_event.is_set())
        except (AttributeError, TypeError, ValueError, OSError):
            return False

    try:
        worker_kind = _resolve_worker_kind_for_zmq(args)
        job_endpoint = str(args.get("zmq_job_endpoint", "") or default_job_endpoint(worker_kind))
        event_endpoint = str(args.get("zmq_event_endpoint", "") or default_event_endpoint(worker_kind))
        worker_search_dir = _resolve_worker_search_dir(args)

        runtime = ZmqRuntimeManager()
        worker_env: dict[str, str] | None = None
        if worker_kind == WorkerKind.AF_XDP:
            xdp_native_lib = _resolve_xdp_native_lib_path()
            if xdp_native_lib:
                worker_env = {"SAMURAI_XDP_NATIVE_LIB": xdp_native_lib}
            else:
                import logging as _logging
                _logging.getLogger(__name__).warning(
                    "AF_XDP worker selected but _resolve_xdp_native_lib_path() returned None; "
                    "worker will attempt exe-relative discovery"
                )
        runtime.launch_worker(
            worker_kind,
            search_dir=worker_search_dir,
            extra_args=[
                "--job-endpoint",
                job_endpoint,
                "--event-endpoint",
                event_endpoint,
                "--jobs-mode",
                "bind",
                "--events-mode",
                "connect",
            ],
            env=worker_env,
        )

        collector = ZmqEventCollector(bind=True)
        collector.ensure_worker_channel(worker_kind, endpoint=event_endpoint)

        telemetry_before = _snapshot_loss_telemetry(args)

        dispatcher = ZmqDispatcher()
        ack_timeout_s = float(args.get("zmq_ack_timeout_s", 2.0) or 2.0)
        heartbeat_timeout_s = float(args.get("zmq_heartbeat_timeout_s", 5.0) or 5.0)
        overall_timeout_s = float(args.get("zmq_overall_timeout_s", 120.0) or 120.0)
        soak_deadline_ts = float(args.get("soak_deadline_ts", 0.0) or 0.0)
        soak_continuous = bool(soak_deadline_ts > 0.0)
        iteration = 0

        while True:
            if _stop_requested():
                if worker_status == "ok":
                    worker_status = "interrupted"
                    worker_error = "worker_stop_requested"
                break
            if soak_continuous and time.time() >= soak_deadline_ts:
                break

            iteration += 1
            job_correlation_id = int((correlation_id + iteration - 1) & 0xFFFFFFFFFFFFFFFF)
            last_correlation_id = int(job_correlation_id)
            job_id_iter = str(job_id if not soak_continuous else f"{job_id}:iter-{iteration}")

            dispatcher.dispatch_start_job(
                worker_kind=worker_kind,
                correlation_id=job_correlation_id,
                job_id=job_id_iter,
                args=args,
                scenario_payload_ref=scenario_payload_ref,
                endpoint=job_endpoint,
            )

            wait_overall_timeout_s = float(overall_timeout_s)
            if soak_continuous:
                remaining_s = max(0.0, float(soak_deadline_ts) - float(time.time()))
                grace_s = max(2.0, float(heartbeat_timeout_s) * 2.0)
                wait_overall_timeout_s = max(1.0, min(float(overall_timeout_s), remaining_s + grace_s))

            terminal = collector.wait_for_terminal_event(
                correlation_id=job_correlation_id,
                worker_kind=worker_kind,
                ack_timeout_s=ack_timeout_s,
                heartbeat_timeout_s=heartbeat_timeout_s,
                overall_timeout_s=wait_overall_timeout_s,
            )

            if terminal.header.msg_type == MessageType.ERROR:
                worker_status = "failed"
                worker_error = str(terminal.payload_decoded or "worker_error")
                break

            if terminal.header.msg_type != MessageType.JOB_DONE:
                worker_status = "failed"
                worker_error = f"unexpected_terminal_msg_type:{int(terminal.header.msg_type)}"
                break

            payload_map = dict(terminal.payload_decoded or {}) if isinstance(terminal.payload_decoded, dict) else {}
            attempted_i = int(payload_map.get("attempted", 0) or 0)
            sent_i = int(payload_map.get("sent", payload_map.get("packets_sent", 0)) or 0)
            errors_i = int(payload_map.get("errors", payload_map.get("packets_errors", 0)) or 0)
            if attempted_i <= 0:
                attempted_i = max(0, sent_i + errors_i)
            if errors_i <= 0 and attempted_i > sent_i:
                errors_i = max(0, attempted_i - sent_i)
            bytes_i = int(payload_map.get("bytes_sent_est", payload_map.get("bytes_sent", 0)) or 0)
            worker_stats = _add_stats(
                worker_stats,
                {
                    "attempted": int(attempted_i),
                    "sent": int(sent_i),
                    "errors": int(errors_i),
                    "bytes_sent_est": int(bytes_i),
                },
            )

            last_metric = getattr(terminal, "last_metric", None)
            if last_metric is not None:
                worker_stats["packets_sent"] = int(last_metric.packets_sent)
                worker_stats["packets_errors"] = int(last_metric.packets_errors)
                worker_stats["bytes_sent"] = int(last_metric.bytes_sent)
                worker_stats["actual_rps"] = float(last_metric.actual_rps)
                worker_stats["jitter_p99_ns"] = float(last_metric.jitter_p99_ns)
                worker_stats["rate_accuracy_pct"] = float(last_metric.rate_accuracy_pct)
                worker_stats["busywait_cycles"] = int(last_metric.busywait_cycles)
                worker_stats["sleep_calls"] = int(last_metric.sleep_calls)

            for key in (
                "status",
                "worker_kind",
                "note",
                "actual_rps",
                "rate_accuracy_pct",
                "jitter_p99_ns",
                "busywait_cycles",
                "sleep_calls",
                "xdp_mode",
                "xdp_queue_id",
            ):
                if key in payload_map:
                    worker_stats[key] = payload_map[key]

            if not soak_continuous:
                break
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError) as exc:
        worker_status = "failed"
        worker_error = str(exc)
    finally:
        telemetry_after = _snapshot_loss_telemetry(args)
        try:
            if dispatcher is not None and worker_kind is not None:
                try:
                    dispatcher.dispatch_shutdown_worker(
                        worker_kind=worker_kind,
                        correlation_id=(last_correlation_id + 1) & 0xFFFFFFFFFFFFFFFF,
                        job_id=f"{job_id}:shutdown",
                    )
                except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
                    pass
                dispatcher.close()
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
            pass
        try:
            if collector is not None:
                collector.close()
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
            pass
        try:
            if runtime is not None and worker_kind is not None:
                runtime.stop_worker(worker_kind, timeout_s=1.0)
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
            pass
        for path in list(scenario_payload_temp_paths or []):
            try:
                os.remove(path)
            except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
                pass

    _attach_loss_telemetry_delta(args, worker_stats, telemetry_before, telemetry_after)

    attempted = int(worker_stats.get("attempted", args.get("count", 0)) or 0)
    sent = int(worker_stats.get("sent", worker_stats.get("packets_sent", 0)) or 0)
    errors = int(worker_stats.get("errors", worker_stats.get("packets_errors", 0)) or 0)
    if attempted <= 0:
        attempted = max(0, sent + errors)
    if errors <= 0 and attempted > sent:
        errors = max(0, attempted - sent)

    worker_stats["attempted"] = int(attempted)
    worker_stats["sent"] = int(sent)
    worker_stats["errors"] = int(errors)
    worker_stats["bytes_sent_est"] = int(worker_stats.get("bytes_sent_est", worker_stats.get("bytes_sent", 0)) or 0)
    worker_stats["status"] = str(worker_status)
    worker_stats["error"] = str(worker_error)
    recompute_loss_metrics(worker_stats, inplace=True)

    _update_shared_counters(
        progress,
        progress_lock,
        sent_total,
        errors_total,
        attempted=attempted,
        sent=sent,
        errors=errors,
    )

    if run_events is not None:
        run_events.append(
            {
                "worker_id": int(worker_id),
                "attack_vector": str(args.get("attack_vector", "unknown")),
                "compute_backend": str(backend_used),
                "protocol": str(args.get("protocol", "")),
                "target": str(args.get("target", "")),
                "count_cfg": int(args.get("count", 0) or 0),
                "status": str(worker_status),
                "error": str(worker_error),
                "duration_s": float(max(0.0, time.time() - worker_started)),
                "scenario_payload_ref": str(scenario_payload_ref),
                "stats": dict(worker_stats),
            }
        )


def start_worker(
    worker_id,
    args,
    progress=None,
    progress_lock=None,
    tls_profile="none",
    run_events=None,
    sent_total=None,
    errors_total=None,
    resource_stats=None,
    stop_event=None,
):
    return start_worker_zmq(
        worker_id,
        args,
        progress=progress,
        progress_lock=progress_lock,
        tls_profile=tls_profile,
        run_events=run_events,
        sent_total=sent_total,
        errors_total=errors_total,
        resource_stats=resource_stats,
        stop_event=stop_event,
    )


async def worker_process(*args: Any, **kwargs: Any):
    raise RuntimeError("worker_process kaldırıldı: ZMQ daemons + start_worker_zmq kullanın")
