from ddos_samurai.control.proto import load_generated
from ddos_samurai.control.server import _SamuraiServicer


class _Ctx:
    def __init__(self, md):
        self._md = list(md or [])

    def invocation_metadata(self):
        return list(self._md)

    def abort(self, status, details):
        raise RuntimeError(f"{status}:{details}")


def test_register_worker_rejected_on_tenant_mismatch():
    pb2, _ = load_generated()
    svc = _SamuraiServicer(tenant_namespace="tenant-a")
    req = pb2.RegisterWorkerRequest(worker_id="w1", hostname="h1", capabilities={})

    bad = _Ctx([("x-tenant-namespace", "tenant-b")])
    res_bad = svc.RegisterWorker(req, bad)
    assert bool(res_bad.accepted) is False
    assert "tenant namespace mismatch" in str(res_bad.rejection_reason or "")

    good = _Ctx([("x-tenant-namespace", "tenant-a")])
    res_ok = svc.RegisterWorker(req, good)
    assert bool(res_ok.accepted) is True


def test_report_stats_rejected_without_matching_tenant():
    pb2, _ = load_generated()
    svc = _SamuraiServicer(tenant_namespace="tenant-a")

    reg_ctx = _Ctx([("x-tenant-namespace", "tenant-a")])
    _ = svc.RegisterWorker(pb2.RegisterWorkerRequest(worker_id="w1", hostname="h1", capabilities={}), reg_ctx)

    bad_ctx = _Ctx([("x-tenant-namespace", "tenant-b")])
    req = pb2.ReportStatsRequest(worker_id="w1", shard_id="s1", stats_json=b"{}", timestamp_ms=1)
    try:
        _ = svc.ReportStats(req, bad_ctx)
        assert False, "expected tenant mismatch abort"
    except RuntimeError as exc:
        assert "tenant namespace mismatch" in str(exc)
