import json

import pytest

from ddos_samurai.control.server import _SamuraiServicer
from ddos_samurai.control.proto import load_generated


pytest.importorskip("grpc")
pytest.importorskip("google.protobuf")


def test_report_stats_rejects_stale_leader_epoch():
    pb2, _ = load_generated()
    s = _SamuraiServicer(cluster_id="t")
    s.set_leader_epoch_min(5)
    req = pb2.ReportStatsRequest(
        worker_id="w1",
        shard_id="s1",
        stats_json=json.dumps({"sent": 10, "leader_epoch": 4}, ensure_ascii=True).encode("utf-8"),
        timestamp_ms=1,
    )
    resp = s.ReportStats(req, context=None)
    assert bool(resp.received) is False
    assert "s1" not in s.shard_stats


def test_report_stats_accepts_current_leader_epoch():
    pb2, _ = load_generated()
    s = _SamuraiServicer(cluster_id="t")
    s.set_leader_epoch_min(5)
    req = pb2.ReportStatsRequest(
        worker_id="w1",
        shard_id="s1",
        stats_json=json.dumps({"sent": 10, "leader_epoch": 5}, ensure_ascii=True).encode("utf-8"),
        timestamp_ms=1,
    )
    resp = s.ReportStats(req, context=None)
    assert bool(resp.received) is True
    assert "s1" in s.shard_stats
