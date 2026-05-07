from ddos_samurai.control.management_api import create_management_app


def test_management_api_summary_and_abort_with_auth():
    fastapi_testclient = __import__("fastapi.testclient", fromlist=["TestClient"])
    TestClient = fastapi_testclient.TestClient

    state = {
        "workers": [{"worker_id": "w1", "state": "running", "active_shard_id": "s1", "last_heartbeat_ms": 1}],
        "workers_count": 1,
        "shards": [{"shard_id": "s1", "stats_size_bytes": 64}],
        "shards_reported_count": 1,
        "latest_snapshot": {"sent": 10, "errors": 0},
        "current_job": {"state": "running", "job_id": "job-1"},
        "ha": {"mode": "off", "is_leader": 1},
        "events": [{"ts_ms": 1, "kind": "master_started"}],
    }
    called = {"abort": 0}

    def _state():
        return dict(state)

    def _abort():
        called["abort"] += 1
        return {"aborted": True, "workers_notified": 1}

    app = create_management_app(
        state_provider=_state,
        abort_callback=_abort,
        metrics_provider=lambda: "samurai_distributed_workers 1\n",
        auth_token="sekret",
    )
    cli = TestClient(app)

    r0 = cli.get("/healthz")
    assert r0.status_code == 200
    assert r0.json().get("status") == "ok"

    r1 = cli.get("/v1/cluster/summary")
    assert r1.status_code == 401

    hdr = {"Authorization": "Bearer sekret"}
    r2 = cli.get("/v1/cluster/summary", headers=hdr)
    assert r2.status_code == 200
    body = r2.json()
    assert int(body.get("workers_count", 0)) == 1
    assert int(body.get("shards_reported_count", 0)) == 1
    assert str((body.get("current_job") or {}).get("job_id", "")) == "job-1"
    assert int((body.get("ha") or {}).get("is_leader", 0)) == 1

    r3 = cli.get("/v1/cluster/workers", headers=hdr)
    assert r3.status_code == 200
    assert len(r3.json().get("workers") or []) == 1

    r4 = cli.post("/v1/jobs/abort", headers=hdr)
    assert r4.status_code == 200
    assert bool((r4.json() or {}).get("aborted", False)) is True
    assert int(called.get("abort", 0) or 0) == 1

    r5 = cli.get("/metrics", headers=hdr)
    assert r5.status_code == 200
    assert "samurai_distributed_workers 1" in str(r5.text)

    r6 = cli.get("/v1/cluster/events", headers=hdr)
    assert r6.status_code == 200
    events = list((r6.json() or {}).get("events") or [])
    assert events and str(events[0].get("kind", "")) == "master_started"


def test_management_api_role_based_authorization():
    fastapi_testclient = __import__("fastapi.testclient", fromlist=["TestClient"])
    TestClient = fastapi_testclient.TestClient

    state = {
        "workers": [],
        "workers_count": 0,
        "shards": [],
        "shards_reported_count": 0,
        "latest_snapshot": {},
        "current_job": {"state": "idle", "job_id": ""},
        "ha": {"mode": "off", "is_leader": 1},
        "events": [],
    }
    called = {"abort": 0}

    def _state():
        return dict(state)

    def _abort():
        called["abort"] += 1
        return {"aborted": True, "workers_notified": 0}

    app = create_management_app(
        state_provider=_state,
        abort_callback=_abort,
        auth_role_tokens={"admin": "adm", "operator": "op", "viewer": "view"},
    )
    cli = TestClient(app)

    viewer_hdr = {"Authorization": "Bearer view"}
    operator_hdr = {"Authorization": "Bearer op"}
    admin_hdr = {"Authorization": "Bearer adm"}
    bad_hdr = {"Authorization": "Bearer nope"}

    assert cli.get("/v1/cluster/summary", headers=viewer_hdr).status_code == 200
    assert cli.get("/v1/cluster/summary", headers=operator_hdr).status_code == 200
    assert cli.get("/v1/cluster/summary", headers=admin_hdr).status_code == 200
    assert cli.get("/v1/cluster/summary", headers=bad_hdr).status_code == 401

    assert cli.post("/v1/jobs/abort", headers=viewer_hdr).status_code == 403
    assert cli.post("/v1/jobs/abort", headers=operator_hdr).status_code == 200
    assert cli.post("/v1/jobs/abort", headers=admin_hdr).status_code == 200
    assert int(called["abort"]) == 2
