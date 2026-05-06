from ddos_samurai.control.telemetry import DistributedAggregator


def test_telemetry_aggregate_kpis_and_ids():
    agg = DistributedAggregator()
    agg.add(
        {
            "worker_id": "w1",
            "shard_id": "s1",
            "sent": 5,
            "errors": 1,
            "progress": 3,
            "wire_tx_packets_delta": 11,
            "status": "running",
        }
    )
    agg.add(
        {
            "worker_id": "w2",
            "shard_id": "s2",
            "sent": 7,
            "errors": 2,
            "progress": 4,
            "wire_tx_packets_delta": 13,
            "status": "error",
            "exitcode": 1,
        }
    )
    snap = agg.snapshot()
    assert snap["sent"] == 12
    assert snap["errors"] == 3
    assert snap["progress"] == 7
    assert snap["workers"] == 2
    assert snap["shards"] == 2
    assert snap["worker_ids"] == ["w1", "w2"]
    assert snap["shard_ids"] == ["s1", "s2"]
    assert int(snap["numeric_totals"]["wire_tx_packets_delta"]) == 24
    assert len(snap["per_shard"]) == 2
    assert snap["top_error_shards"][0]["shard_id"] == "s2"
    assert snap["worker_rollup"][0]["worker_id"] == "w2"
