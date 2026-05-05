"""Distributed slave entry point."""

from __future__ import annotations

import json
import multiprocessing
import socket
import time
from concurrent import futures

from .. import utils
from .. import orchestrator
from .client import SlaveControlClient
from .discovery import EndpointDiscovery
from .proto import load_generated


def _execute_shard_locally(shard_args_dict: dict, shard_id: str) -> dict:
    progress = multiprocessing.Value("L", 0)
    sent_total = multiprocessing.Value("L", 0)
    errors_total = multiprocessing.Value("L", 0)
    lock = multiprocessing.Lock()
    manager = multiprocessing.Manager()
    events = manager.list()
    resources = manager.dict()
    tls_profile = str(shard_args_dict.get("tls_profile", "none") or "none")

    proc = multiprocessing.Process(
        target=orchestrator.start_worker,
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
        insecure=bool(getattr(args, "control_insecure", False)),
        tls_ca=str(getattr(args, "control_tls_ca", "")),
    )
    capabilities = {
        "gpu_available": "unknown",
        "xdp_available": "unknown",
    }
    listen = str(getattr(args, "control_listen", "0.0.0.0:5099") or "0.0.0.0:5099").strip()
    try:
        host, port = listen.rsplit(":", 1)
        if host in {"0.0.0.0", ""}:
            host = socket.gethostbyname(socket.gethostname())
        capabilities["control_endpoint"] = f"{host}:{int(port)}"
    except Exception:
        pass
    worker_id = socket.gethostname()
    reg = client.register_worker(
        worker_id=worker_id,
        hostname=worker_id,
        capabilities=capabilities,
    )
    if not bool(reg.get("accepted", False)):
        utils.log_critical(f"Master worker kaydını reddetti: {reg.get('rejection_reason', 'unknown')}")
        return 1
    utils.log_info(f"Distributed slave connected: endpoints={','.join(client.endpoints)}")

    # Optional worker-side RPC server: enables master -> worker StartShard/StopShard direct RPC.
    grpc_server = None
    try:
        import grpc

        pb2, pb2_grpc = load_generated()

        class _WorkerServicer(pb2_grpc.SamuraiControlServicer):
            def StartShard(self, request, context):
                _ = context
                try:
                    shard_args = json.loads(bytes(request.args_json or b"{}").decode("utf-8"))
                except (ValueError, TypeError, UnicodeDecodeError):
                    return pb2.StartShardResponse(started=False, error="invalid args_json")
                stats = _execute_shard_locally(shard_args, str(request.shard_id))
                try:
                    client.report_stats(
                        worker_id=worker_id,
                        shard_id=str(request.shard_id),
                        stats=stats,
                        timestamp_ms=int(time.time() * 1000),
                    )
                except Exception:
                    pass
                return pb2.StartShardResponse(started=(int(stats.get("exitcode", 1) or 1) == 0), error="")

            def StopShard(self, request, context):
                _ = request
                _ = context
                return pb2.StopShardResponse(stopped=True)

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
        client.report_stats(worker_id=worker_id, shard_id=shard_id, stats=stats, timestamp_ms=int(time.time() * 1000))
        utils.log_info(
            f"Shard completed: shard_id={shard_id} sent={int(stats.get('sent', 0))} "
            f"errors={int(stats.get('errors', 0))} exitcode={int(stats.get('exitcode', 0))}"
        )
        return 0 if int(stats.get("exitcode", 1) or 1) == 0 else 1

    # Heartbeat health loop (no orchestration commands are consumed here).
    hb_ms = int(getattr(args, "heartbeat_interval_ms", 2000) or 2000)
    boot = int(time.time() * 1000)
    run_forever = int(getattr(args, "job_timeout_s", 0) or 0) <= 0
    loops = 0
    while True:
        now = int(time.time() * 1000)
        _ = client.heartbeat(worker_id=worker_id, uptime_ms=max(0, now - boot))
        loops += 1
        if not run_forever and loops >= max(3, int(getattr(args, "job_timeout_s", 0) or 0)):
            break
        time.sleep(max(0.5, hb_ms / 1000.0))
    if grpc_server is not None:
        grpc_server.stop(0.0)
    return 0
