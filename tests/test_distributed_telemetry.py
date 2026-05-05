from ddos_samurai.control.telemetry import DistributedAggregator


def test_telemetry_aggregate_kpis_and_ids():
    agg = DistributedAggregator()
    agg.add({"worker_id": "w1", "shard_id": "s1", "sent": 5, "errors": 1, "progress": 3})
    agg.add({"worker_id": "w2", "shard_id": "s2", "sent": 7, "errors": 2, "progress": 4})
    snap = agg.snapshot()
    assert snap["sent"] == 12
    assert snap["errors"] == 3
    assert snap["progress"] == 7
    assert snap["workers"] == 2
    assert snap["shards"] == 2
    assert snap["worker_ids"] == ["w1", "w2"]
    assert snap["shard_ids"] == ["s1", "s2"]
