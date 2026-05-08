import json
from pathlib import Path

from ddos_samurai.control.server import MasterControlServer, _SecretServerInterceptor


def test_rbac_audit_append_only_jsonl(tmp_path):
    out = Path(tmp_path) / "rbac" / "audit.jsonl"
    srv = MasterControlServer(
        listen_addr="127.0.0.1:5099",
        insecure=True,
        rbac_audit_log_path=str(out),
    )
    srv._append_rbac_audit({"rpc": "GetWorkerStatus", "allowed": 1})
    srv._append_rbac_audit({"rpc": "AbortJob", "allowed": 0})
    rows = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(rows) == 2
    first = json.loads(rows[0])
    second = json.loads(rows[1])
    assert str(first.get("rpc", "")) == "GetWorkerStatus"
    assert str(second.get("rpc", "")) == "AbortJob"
    assert str(first.get("schema", "")) == "samurai.rbac.audit.v1"
    assert str(second.get("schema", "")) == "samurai.rbac.audit.v1"


def test_rbac_audit_logger_respects_success_flag():
    items = []

    class _Ctx:
        @staticmethod
        def peer():
            return "ipv4:127.0.0.1:12345"

    i1 = _SecretServerInterceptor(
        expected_secret="cluster",
        audit_logger=lambda x: items.append(dict(x)),
        audit_success=False,
    )
    i1._audit(ctx=_Ctx(), rpc_name="GetWorkerStatus", provided_secret="cluster", role="viewer", allowed=True, error="")
    assert items == []
    i1._audit(
        ctx=_Ctx(),
        rpc_name="GetWorkerStatus",
        provided_secret="bad",
        role="",
        allowed=False,
        error="invalid cluster secret",
    )
    assert len(items) == 1
    assert int(items[0].get("allowed", 1)) == 0
    assert str(items[0].get("rpc", "")) == "GetWorkerStatus"
