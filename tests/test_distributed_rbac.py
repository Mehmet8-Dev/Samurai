from ddos_samurai.control.server import _SecretServerInterceptor


def test_rbac_allows_read_but_blocks_control_for_viewer():
    ic = _SecretServerInterceptor(
        expected_secret="cluster",
        rbac_enabled=True,
        role_secrets={"viewer": "cluster"},
        default_role="viewer",
    )
    ok_read, _ = ic._authorized({"x-cluster-secret": "cluster"}, "GetWorkerStatus")
    ok_ctl, err_ctl = ic._authorized({"x-cluster-secret": "cluster"}, "StartShard")
    assert ok_read is True
    assert ok_ctl is False
    assert "forbidden" in str(err_ctl)


def test_rbac_unknown_secret_rejected():
    ic = _SecretServerInterceptor(
        expected_secret="cluster",
        rbac_enabled=True,
        role_secrets={"admin": "a-token"},
        default_role="viewer",
    )
    ok, err = ic._authorized({"x-cluster-secret": "wrong"}, "GetWorkerStatus")
    assert ok is False
    assert "invalid cluster secret" in str(err)


def test_rbac_without_cluster_secret_still_enforced():
    ic = _SecretServerInterceptor(
        expected_secret="",
        rbac_enabled=True,
        role_secrets={"worker": "w-token", "operator": "o-token"},
        default_role="viewer",
    )
    ok_stats, _ = ic._authorized({"x-cluster-secret": "w-token"}, "ReportStats")
    ok_stop, err_stop = ic._authorized({"x-cluster-secret": "w-token"}, "StopShard")
    ok_unknown, err_unknown = ic._authorized({"x-cluster-secret": "x-token"}, "GetWorkerStatus")
    assert ok_stats is True
    assert ok_stop is False
    assert "forbidden" in str(err_stop)
    assert ok_unknown is False
    assert "unknown role secret" in str(err_unknown)
