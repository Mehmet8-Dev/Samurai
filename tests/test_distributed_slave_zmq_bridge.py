from __future__ import annotations

import time

from ddos_samurai.control import slave


def test_execute_shard_locally_uses_zmq_path(monkeypatch):
    def _fake_start_worker_zmq(
        worker_id,
        args,
        progress=None,
        progress_lock=None,
        tls_profile="none",
        run_events=None,
        sent_total=None,
        errors_total=None,
        resource_stats=None,
    ):
        _ = worker_id, args, tls_profile, resource_stats
        if progress_lock is not None:
            with progress_lock:
                progress.value += 10
                sent_total.value += 9
                errors_total.value += 1
        if run_events is not None:
            run_events.append({"status": "ok", "stats": {"attempted": 10, "sent": 9, "errors": 1}})

    monkeypatch.setattr(slave.orchestrator, "start_worker_zmq", _fake_start_worker_zmq)

    out = slave._execute_shard_locally({"count": 10}, "s-1")
    assert out["status"] == "ok"
    assert int(out["progress"]) == 10
    assert int(out["sent"]) == 9
    assert int(out["errors"]) == 1
    assert isinstance(out["events"], list)
    assert len(out["events"]) == 1


def test_start_and_finalize_shard_runtime_zmq(monkeypatch):
    def _fake_start_worker_zmq(
        worker_id,
        args,
        progress=None,
        progress_lock=None,
        tls_profile="none",
        run_events=None,
        sent_total=None,
        errors_total=None,
        resource_stats=None,
    ):
        _ = worker_id, args, tls_profile, resource_stats
        time.sleep(0.05)
        if progress_lock is not None:
            with progress_lock:
                progress.value += 4
                sent_total.value += 4
                errors_total.value += 0
        if run_events is not None:
            run_events.append({"status": "ok", "stats": {"attempted": 4, "sent": 4, "errors": 0}})

    monkeypatch.setattr(slave.orchestrator, "start_worker_zmq", _fake_start_worker_zmq)

    rt = slave._start_shard_runtime({"count": 4}, "s-2")
    proc = rt["proc"]
    proc.join(timeout=1.0)
    out = slave._finalize_shard_runtime(rt, worker_id="w-1", shard_id="s-2")
    assert out["status"] == "ok"
    assert int(out["progress"]) == 4
    assert int(out["sent"]) == 4
    assert int(out["errors"]) == 0
    assert len(out["events"]) == 1
