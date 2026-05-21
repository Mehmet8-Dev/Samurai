"""Distributed slave entry point."""

from __future__ import annotations

import json
import socket
import threading
import time
from concurrent import futures

from .. import utils
from .. import orchestrator
from .client import SlaveControlClient
from .discovery import EndpointDiscovery
from .proto import load_generated


class _SharedValue:
    def __init__(self, value: int = 0):
        self.value = int(value)


class _ThreadWorker:
    def __init__(self, *, target, args: tuple, name: str):
        self._target = target
        self._args = tuple(args)
        self._thread = threading.Thread(target=self._run, name=str(name), daemon=True)
        self.exitcode = None
        self._terminate_requested = False

    def _run(self):
        try:
            self._target(*self._args)
            if self.exitcode is None:
                self.exitcode = 0
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
            self.exitcode = 1

    def start(self):
        self._thread.start()

    def join(self, timeout: float | None = None):
        self._thread.join(timeout=timeout)

    def is_alive(self) -> bool:
        if self._terminate_requested:
            return False
        return bool(self._thread.is_alive())

    def terminate(self):
        # Cooperative stop marker; direct STOP_JOB orchestration can be added later.
        self._terminate_requested = True
        if self.exitcode is None:
            self.exitcode = -15


def _execute_shard_locally(shard_args_dict: dict, shard_id: str) -> dict:
    progress = _SharedValue(0)
    sent_total = _SharedValue(0)
    errors_total = _SharedValue(0)
    lock = threading.Lock()
    events = []
    resources = {}
    tls_profile = str(shard_args_dict.get("tls_profile", "none") or "none")

    proc = _ThreadWorker(
        target=orchestrator.start_worker_zmq,
        args=(1, dict(shard_args_dict), progress, lock, tls_profile, events, sent_total, errors_total, resources),
        name=f"ShardWorker-{shard_id}",
    )
    started = time.time()
    proc.start()
    proc.join()
    duration_s = max(0.0, float(time.time() - started))
    return {
        "worker_id": socket.gethostname(),
        "shard_id": str(shard_id),
        "status": "ok" if int(proc.exitcode or 0) == 0 else "error",
        "exitcode": int(proc.exitcode or 0),
        "duration_s": duration_s,
        "progress": int(progress.value),
        "sent": int(sent_total.value),
        "errors": int(errors_total.value),
        "events": list(events),
    }


def _start_shard_runtime(shard_args_dict: dict, shard_id: str) -> dict:
    progress = _SharedValue(0)
    sent_total = _SharedValue(0)
    errors_total = _SharedValue(0)
    lock = threading.Lock()
    events = []
    resources = {}
    tls_profile = str(shard_args_dict.get("tls_profile", "none") or "none")
    started = time.time()
    proc = _ThreadWorker(
        target=orchestrator.start_worker_zmq,
        args=(1, dict(shard_args_dict), progress, lock, tls_profile, events, sent_total, errors_total, resources),
        name=f"ShardWorker-{shard_id}",
    )
    proc.start()
    return {
        "proc": proc,
        "progress": progress,
        "sent_total": sent_total,
        "errors_total": errors_total,
        "events": events,
        "started_ts": float(started),
    }


def _finalize_shard_runtime(runtime: dict, worker_id: str, shard_id: str) -> dict:
    proc = runtime.get("proc")
    started = float(runtime.get("started_ts", time.time()) or time.time())
    raw_exit = getattr(proc, "exitcode", None)
    exitcode = int(raw_exit) if raw_exit is not None else 1
    stats = {
        "worker_id": str(worker_id),
        "shard_id": str(shard_id),
        "status": "ok" if exitcode == 0 else "error",
        "exitcode": exitcode,
        "duration_s": max(0.0, float(time.time() - started)),
        "progress": int(getattr(runtime.get("progress"), "value", 0) or 0),
        "sent": int(getattr(runtime.get("sent_total"), "value", 0) or 0),
        "errors": int(getattr(runtime.get("errors_total"), "value", 0) or 0),
        "events": list(runtime.get("events") or []),
    }
    return stats


def run_distributed_slave(args, parser) -> int:
    _ = parser
    discovery = EndpointDiscovery(
        manual_endpoints=str(getattr(args, "control_endpoints", "")),
        prefer_k8s=bool(getattr(args, "control_discovery_k8s", False)),
        k8s_namespace=str(getattr(args, "control_k8s_namespace", "default")),
        k8s_selector=str(getattr(args, "control_k8s_selector", "")),
        k8s_port=int(getattr(args, "control_k8s_port", 5099) or 5099),
    )
    endpoints = ",".join(discovery.resolve_with_fallback())
    client = SlaveControlClient(
        endpoints=endpoints,
        cluster_secret=str(getattr(args, "cluster_secret", "")),
        tenant_namespace=str(getattr(args, "tenant_namespace", "") or "").strip(),
        insecure=bool(getattr(args, "control_insecure", False)),
        tls_ca=str(getattr(args, "control_tls_ca", "")),
        tls_client_cert=str(getattr(args, "control_tls_client_cert", "")),
        tls_client_key=str(getattr(args, "control_tls_client_key", "")),
    )
    capabilities = {
        "gpu_available": "unknown",
        "xdp_available": "unknown",
    }
    tenant_namespace = str(getattr(args, "tenant_namespace", "") or "").strip()
    worker_region = str(getattr(args, "worker_region", "") or "").strip()
    if tenant_namespace:
        capabilities["tenant_namespace"] = tenant_namespace
    if worker_region:
        capabilities["region"] = worker_region
    listen = str(getattr(args, "control_listen", "0.0.0.0:5099") or "0.0.0.0:5099").strip()
    try:
        host, port = listen.rsplit(":", 1)
        if host in {"0.0.0.0", ""}:
            host = socket.gethostbyname(socket.gethostname())
        capabilities["control_endpoint"] = f"{host}:{int(port)}"
    except Exception:
        pass
    worker_id = socket.gethostname()
    register_timeout_s = max(5, int(getattr(args, "slave_master_timeout_s", 10) or 10))
    register_deadline = time.time() + float(register_timeout_s)
    reg = {}
    last_register_exc = None
    while time.time() < register_deadline:
        try:
            reg = client.register_worker(
                worker_id=worker_id,
                hostname=worker_id,
                capabilities=capabilities,
            )
            if bool(reg.get("accepted", False)):
                last_register_exc = None
                break
            utils.log_critical(f"Master worker kaydını reddetti: {reg.get('rejection_reason', 'unknown')}")
            return 1
        except Exception as exc:
            last_register_exc = exc
            time.sleep(0.25)
    if not bool(reg.get("accepted", False)):
        reason = "timeout"
        if last_register_exc is not None:
            reason = f"{type(last_register_exc).__name__}: {last_register_exc}"
        utils.log_critical(
            f"Master worker kaydı başarısız: endpoint={','.join(client.endpoints)} reason={reason}"
        )
        return 1
    utils.log_info(f"Distributed slave connected: endpoints={','.join(client.endpoints)}")
    stats_stream_enabled = bool(getattr(args, "stats_stream_enable", True))
    stats_stream_interval_s = max(0.05, float(int(getattr(args, "stats_stream_interval_ms", 500) or 500)) / 1000.0)
    if stats_stream_enabled:
        stats_stream = client.create_stats_streamer()
    else:
        stats_stream = {"send": lambda *a, **k: False, "close": lambda: None, "failed": threading.Event()}
    epoch_ctx = {"current": 0}
    tenant_namespace = str(getattr(args, "tenant_namespace", "") or "").strip()

    def _emit_stats(worker_id_arg: str, shard_id_arg: str, stats_arg: dict) -> None:
        ts = int(time.time() * 1000)
        payload = dict(stats_arg or {})
        if "leader_epoch" not in payload:
            payload["leader_epoch"] = int(epoch_ctx.get("current", 0) or 0)
        if tenant_namespace and "tenant_namespace" not in payload:
            payload["tenant_namespace"] = tenant_namespace
        if worker_region and "worker_region" not in payload:
            payload["worker_region"] = worker_region
        if worker_region and "region" not in payload:
            payload["region"] = worker_region
        sent = False
        try:
            sent = bool(stats_stream["send"](worker_id_arg, shard_id_arg, payload, ts))
        except Exception:
            sent = False
        if not sent:
            try:
                client.report_stats(
                    worker_id=worker_id_arg,
                    shard_id=shard_id_arg,
                    stats=payload,
                    timestamp_ms=ts,
                )
            except Exception:
                pass

    # Optional worker-side RPC server: enables master -> worker StartShard/StopShard direct RPC.
    grpc_server = None
    try:
        import grpc

        pb2, pb2_grpc = load_generated()
        shard_lock = threading.Lock()
        shard_runs: dict[str, dict] = {}
        shard_status: dict[str, dict] = {}
        worker_state = {"state": "idle", "active_shard_id": ""}
        leader_epoch_state = {"max_seen": 0}

        def _active_count_locked() -> int:
            return sum(1 for rec in shard_runs.values() if bool(rec.get("running", False)))

        def _refresh_worker_state_locked() -> None:
            active = [sid for sid, rec in shard_runs.items() if bool(rec.get("running", False))]
            if active:
                worker_state["state"] = "running"
                worker_state["active_shard_id"] = str(active[0])
                return
            latest = None
            latest_ts = 0.0
            for sid, rec in shard_status.items():
                ts = float(rec.get("updated_ts", 0.0) or 0.0)
                if ts >= latest_ts:
                    latest_ts = ts
                    latest = (sid, rec)
            if latest is None:
                worker_state["state"] = "idle"
                worker_state["active_shard_id"] = ""
                return
            _, rec = latest
            worker_state["state"] = str(rec.get("state", "idle") or "idle")
            worker_state["active_shard_id"] = str(rec.get("active_shard_id", "") or "")

        def _monitor_runtime(shard_id: str) -> None:
            with shard_lock:
                rec = dict(shard_runs.get(shard_id) or {})
            runtime = dict(rec.get("runtime") or {})
            runtime_id = int(rec.get("runtime_id", 0) or 0)
            proc = runtime.get("proc")
            if proc is None:
                with shard_lock:
                    shard_status[shard_id] = {
                        "state": "error",
                        "active_shard_id": "",
                        "updated_ts": time.time(),
                        "stats_json": b"{}",
                    }
                    _refresh_worker_state_locked()
                return
            started_ts = float(runtime.get("started_ts", time.time()) or time.time())
            while proc.is_alive():
                live = {
                    "worker_id": str(worker_id),
                    "shard_id": str(shard_id),
                    "status": "running",
                    "duration_s": max(0.0, float(time.time() - started_ts)),
                    "progress": int(getattr(runtime.get("progress"), "value", 0) or 0),
                    "sent": int(getattr(runtime.get("sent_total"), "value", 0) or 0),
                    "errors": int(getattr(runtime.get("errors_total"), "value", 0) or 0),
                    "leader_epoch": int(rec.get("leader_epoch", epoch_ctx.get("current", 0)) or 0),
                }
                _emit_stats(worker_id_arg=worker_id, shard_id_arg=str(shard_id), stats_arg=live)
                proc.join(timeout=stats_stream_interval_s)
            with shard_lock:
                latest = dict(shard_runs.get(shard_id) or {})
                if not latest:
                    return
                if int(latest.get("runtime_id", 0) or 0) != runtime_id:
                    return
            stats = _finalize_shard_runtime(runtime, worker_id=worker_id, shard_id=shard_id)
            stats["leader_epoch"] = int(rec.get("leader_epoch", epoch_ctx.get("current", 0)) or 0)
            _emit_stats(worker_id_arg=worker_id, shard_id_arg=str(shard_id), stats_arg=stats)
            payload = json.dumps(stats, ensure_ascii=True).encode("utf-8")
            with shard_lock:
                shard_runs.pop(shard_id, None)
                shard_status[shard_id] = {
                    "state": "done" if int(stats.get("exitcode", 1) or 1) == 0 else "error",
                    "active_shard_id": "",
                    "updated_ts": time.time(),
                    "stats_json": payload,
                }
                _refresh_worker_state_locked()

        class _WorkerServicer(pb2_grpc.SamuraiControlServicer):
            def StartShard(self, request, context):
                _ = context
                try:
                    shard_args = json.loads(bytes(request.args_json or b"{}").decode("utf-8"))
                except (ValueError, TypeError, UnicodeDecodeError):
                    return pb2.StartShardResponse(started=False, error="invalid args_json")
                req_epoch = int(shard_args.get("_leader_epoch", 0) or 0)
                sid = str(request.shard_id)
                with shard_lock:
                    max_seen = int(leader_epoch_state.get("max_seen", 0) or 0)
                    if req_epoch < max_seen:
                        return pb2.StartShardResponse(
                            started=False,
                            error=f"stale leader epoch: got={req_epoch} min={max_seen}",
                        )
                    if req_epoch > max_seen:
                        leader_epoch_state["max_seen"] = req_epoch
                    epoch_ctx["current"] = int(leader_epoch_state.get("max_seen", 0) or 0)
                    existing = dict(shard_runs.get(sid) or {})
                    if bool(existing.get("running", False)):
                        return pb2.StartShardResponse(started=False, error="shard already running")
                    try:
                        runtime = _start_shard_runtime(shard_args, sid)
                    except Exception as exc:
                        shard_status[sid] = {
                            "state": "error",
                            "active_shard_id": "",
                            "updated_ts": time.time(),
                            "stats_json": b"{}",
                        }
                        _refresh_worker_state_locked()
                        return pb2.StartShardResponse(started=False, error=f"start failed: {exc}")
                    shard_runs[sid] = {
                        "runtime": runtime,
                        "runtime_id": int(time.time_ns()),
                        "running": True,
                        "job_id": str(request.job_id or ""),
                        "leader_epoch": int(req_epoch),
                    }
                    shard_status[sid] = {
                        "state": "queued" if _active_count_locked() > 1 else "running",
                        "active_shard_id": sid,
                        "updated_ts": time.time(),
                        "stats_json": b"{}",
                    }
                    _refresh_worker_state_locked()
                t = threading.Thread(target=_monitor_runtime, args=(sid,), daemon=True, name=f"ShardMonitor-{sid}")
                t.start()
                with shard_lock:
                    cur = dict(shard_status.get(sid) or {})
                    if cur.get("state") == "queued":
                        cur["state"] = "running"
                        cur["updated_ts"] = time.time()
                        shard_status[sid] = cur
                        _refresh_worker_state_locked()
                return pb2.StartShardResponse(started=True, error="")

            def StopShard(self, request, context):
                _ = context
                sid = str(request.shard_id)
                with shard_lock:
                    rec = dict(shard_runs.pop(sid, {}) or {})
                runtime = dict(rec.get("runtime") or {})
                proc = runtime.get("proc")
                if proc is None or not bool(rec.get("running", False)):
                    return pb2.StopShardResponse(stopped=False)
                try:
                    if proc.is_alive():
                        proc.terminate()
                    proc.join(timeout=3.0)
                except Exception:
                    return pb2.StopShardResponse(stopped=False)
                stats = _finalize_shard_runtime(runtime, worker_id=worker_id, shard_id=sid)
                stats["status"] = "stopped"
                stats["leader_epoch"] = int(rec.get("leader_epoch", epoch_ctx.get("current", 0)) or 0)
                _emit_stats(worker_id_arg=worker_id, shard_id_arg=sid, stats_arg=stats)
                with shard_lock:
                    shard_status[sid] = {
                        "state": "error",
                        "active_shard_id": "",
                        "updated_ts": time.time(),
                        "stats_json": json.dumps(stats, ensure_ascii=True).encode("utf-8"),
                    }
                    _refresh_worker_state_locked()
                return pb2.StopShardResponse(stopped=True)

            def GetWorkerStatus(self, request, context):
                _ = context
                wid = str(request.worker_id or "")
                if wid and wid != worker_id:
                    return pb2.GetWorkerStatusResponse(
                        worker_id=wid,
                        state="disconnected",
                        active_shard_id="",
                        stats_json=b"{}",
                        last_heartbeat_ms=0,
                    )
                with shard_lock:
                    state = str(worker_state.get("state", "idle") or "idle")
                    active_sid = str(worker_state.get("active_shard_id", "") or "")
                    stats_json = b"{}"
                    if active_sid:
                        stats_json = bytes((shard_status.get(active_sid) or {}).get("stats_json", b"{}"))
                    elif shard_status:
                        latest_sid = max(
                            shard_status.keys(),
                            key=lambda sid: float((shard_status.get(sid) or {}).get("updated_ts", 0.0) or 0.0),
                        )
                        stats_json = bytes((shard_status.get(latest_sid) or {}).get("stats_json", b"{}"))
                return pb2.GetWorkerStatusResponse(
                    worker_id=worker_id,
                    state=state,
                    active_shard_id=active_sid,
                    stats_json=stats_json,
                    last_heartbeat_ms=int(time.time() * 1000),
                )

        grpc_server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
        pb2_grpc.add_SamuraiControlServicer_to_server(_WorkerServicer(), grpc_server)
        if bool(getattr(args, "control_insecure", False)):
            grpc_server.add_insecure_port(listen)
        else:
            # Keep deterministic direct-mode: if worker-side TLS server is not configured here,
            # direct RPC orchestration will fail-fast at master.
            grpc_server = None
        if grpc_server is not None:
            grpc_server.start()
            host, port = listen.rsplit(":", 1)
            if host in {"0.0.0.0", ""}:
                host = socket.gethostbyname(socket.gethostname())
            capabilities["control_endpoint"] = f"{host}:{int(port)}"
    except Exception:
        grpc_server = None

    # v1 live adapter: shard argumanlari local worker dict olarak verildiginde calistirir.
    shard_json = str(getattr(args, "distributed_shard_json", "") or "").strip()
    if shard_json:
        try:
            shard_payload = json.loads(shard_json)
        except (ValueError, TypeError) as exc:
            utils.log_critical(f"Shard payload parse hatası: {exc}")
            return 1
        shard_id = str(shard_payload.get("shard_id", "shard-1") or "shard-1")
        shard_args = dict(shard_payload.get("args_dict") or {})
        stats = _execute_shard_locally(shard_args, shard_id)
        _emit_stats(worker_id_arg=worker_id, shard_id_arg=shard_id, stats_arg=stats)
        utils.log_info(
            f"Shard completed: shard_id={shard_id} sent={int(stats.get('sent', 0))} "
            f"errors={int(stats.get('errors', 0))} exitcode={int(stats.get('exitcode', 0))}"
        )
        try:
            stats_stream["close"]()
        except Exception:
            pass
        return 0 if int(stats.get("exitcode", 1) or 1) == 0 else 1

    # Heartbeat health loop (no orchestration commands are consumed here).
    hb_ms = int(getattr(args, "heartbeat_interval_ms", 2000) or 2000)
    master_timeout_s = int(getattr(args, "slave_master_timeout_s", 30) or 0)
    boot = int(time.time() * 1000)
    run_forever = int(getattr(args, "job_timeout_s", 0) or 0) <= 0
    loops = 0
    last_master_ok_ts = time.time()
    while True:
        now = int(time.time() * 1000)
        try:
            hb = client.heartbeat(worker_id=worker_id, uptime_ms=max(0, now - boot))
            last_master_ok_ts = time.time()
            if str(hb.get("command", "") or "").strip().lower() == "register":
                try:
                    _ = client.register_worker(
                        worker_id=worker_id,
                        hostname=worker_id,
                        capabilities=capabilities,
                    )
                except Exception:
                    pass
        except Exception as exc:
            if master_timeout_s > 0 and (time.time() - last_master_ok_ts) >= float(master_timeout_s):
                utils.log_warning(
                    "Master heartbeat RPC unavailable for too long; slave exits "
                    f"(timeout={master_timeout_s}s): {exc}"
                )
                break
        loops += 1
        if not run_forever and loops >= max(3, int(getattr(args, "job_timeout_s", 0) or 0)):
            break
        time.sleep(max(0.5, hb_ms / 1000.0))
    if grpc_server is not None:
        grpc_server.stop(0.0)
    try:
        stats_stream["close"]()
    except Exception:
        pass
    return 0
