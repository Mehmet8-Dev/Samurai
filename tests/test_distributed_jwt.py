import time

from ddos_samurai.control.jwt_claims import decode_jwt_hs256, encode_jwt_hs256
from ddos_samurai.control.management_api import create_management_app
from ddos_samurai.control.server import _SamuraiServicer, _SecretServerInterceptor


def test_jwt_hs256_roundtrip():
    token = encode_jwt_hs256({"role": "viewer", "tenant_namespace": "tenant-a", "exp": int(time.time()) + 30}, "sekret")
    out = decode_jwt_hs256(token, "sekret")
    assert str(out.get("role", "")) == "viewer"
    assert str(out.get("tenant_namespace", "")) == "tenant-a"


def test_server_interceptor_accepts_jwt_role_and_blocks_forbidden_rpc():
    token = encode_jwt_hs256({"role": "viewer", "tenant_namespace": "tenant-a", "exp": int(time.time()) + 30}, "sekret")
    itc = _SecretServerInterceptor(
        expected_secret="legacy-secret",
        rbac_enabled=True,
        role_secrets={},
        default_role="viewer",
        jwt_secret="sekret",
        jwt_role_claim="role",
    )
    ok, err = itc._authorized({"x-cluster-secret": token}, "GetWorkerStatus")
    assert ok is True
    assert str(err) == ""
    ok2, err2 = itc._authorized({"x-cluster-secret": token}, "AbortJob")
    assert ok2 is False
    assert "forbidden" in str(err2)


def test_servicer_tenant_guard_can_use_jwt_claim_without_tenant_header():
    token = encode_jwt_hs256({"role": "worker", "tenant_namespace": "tenant-a", "exp": int(time.time()) + 30}, "sekret")
    s = _SamuraiServicer(tenant_namespace="tenant-a", jwt_secret="sekret", jwt_tenant_claim="tenant_namespace")

    class _Ctx:
        @staticmethod
        def invocation_metadata():
            return [("x-cluster-secret", token)]

    assert s._tenant_guard(_Ctx(), worker_id="") is True


def test_management_api_live_sse_and_ws():
    fastapi_testclient = __import__("fastapi.testclient", fromlist=["TestClient"])
    TestClient = fastapi_testclient.TestClient

    state = {
        "workers": [{"worker_id": "w1", "tenant_namespace": "tenant-a", "region": "eu-central", "state": "running"}],
        "shards": [{"shard_id": "s1", "tenant_namespace": "tenant-a", "region": "eu-central", "stats_size_bytes": 10}],
        "latest_snapshot": {"sent": 1, "errors": 0},
        "current_job": {"state": "running", "job_id": "j1", "tenant_namespace": "tenant-a"},
        "ha": {"mode": "off", "is_leader": 1},
        "events": [{"ts_ms": 1, "kind": "job_started", "tenant_namespace": "tenant-a"}],
    }
    app = create_management_app(
        state_provider=lambda: dict(state),
        abort_callback=lambda: {"aborted": True},
        jwt_secret="sekret",
        live_interval_ms=50,
    )
    cli = TestClient(app)
    tok = encode_jwt_hs256({"role": "viewer", "tenant_namespace": "tenant-a", "exp": int(time.time()) + 30}, "sekret")
    hdr = {"Authorization": f"Bearer {tok}"}

    assert any(getattr(r, "path", "") == "/v1/cluster/live/sse" for r in list(app.routes))

    with cli.websocket_connect(f"/v1/cluster/live/ws?token={tok}") as ws:
        msg = ws.receive_text()
        assert '"type": "snapshot"' in msg
        assert '"tenant_namespace": "tenant-a"' in msg
