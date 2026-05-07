from ddos_samurai.control.shard import split_job_to_shards


def test_equal_split_and_remainder():
    shards = split_job_to_shards(10, ["w1", "w2", "w3"])
    assert [s["packet_count"] for s in shards] == [4, 3, 3]


def test_zero_worker_edge_case():
    assert split_job_to_shards(10, []) == []


def test_zero_count_still_returns_shards_per_worker():
    shards = split_job_to_shards(0, ["w1", "w2"])
    assert len(shards) == 2
    assert [s["packet_count"] for s in shards] == [0, 0]


def test_capability_split_prefers_higher_weight_worker():
    shards = split_job_to_shards(
        12,
        ["w1", "w2"],
        strategy="capability",
        worker_capabilities={
            "w1": {"capacity_score": "1"},
            "w2": {"capacity_score": "3"},
        },
    )
    by_worker = {s["worker_id"]: int(s["packet_count"]) for s in shards}
    assert by_worker["w2"] > by_worker["w1"]
    assert by_worker["w1"] + by_worker["w2"] == 12


def test_region_split_prefers_target_region_worker():
    shards = split_job_to_shards(
        30,
        ["w-eu", "w-us"],
        strategy="region",
        target_region="eu-central",
        worker_capabilities={
            "w-eu": {"region": "eu-central", "capacity_score": "1"},
            "w-us": {"region": "us-east", "capacity_score": "1"},
        },
    )
    by_worker = {s["worker_id"]: int(s["packet_count"]) for s in shards}
    assert by_worker["w-eu"] > by_worker["w-us"]
    assert by_worker["w-eu"] + by_worker["w-us"] == 30
