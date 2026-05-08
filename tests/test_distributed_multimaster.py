from ddos_samurai.control.master import (
    _distributed_state_to_prometheus,
    _job_target_region,
    _should_delegate_job,
)
from ddos_samurai.control.multimaster import RedisMultiMasterCoordinator


def test_multimaster_job_region_helpers():
    job = {"target_region": "eu-central"}
    assert _job_target_region(job) == "eu-central"
    assert _should_delegate_job(job, multi_master_enabled=True, region_id="us-east") is True
    assert _should_delegate_job(job, multi_master_enabled=True, region_id="eu-central") is False
    assert _should_delegate_job(job, multi_master_enabled=False, region_id="us-east") is False


def test_multimaster_coordinator_disabled_is_safe_noop():
    mm = RedisMultiMasterCoordinator(enabled=False, region_id="eu-central")
    assert mm.heartbeat({"workers_count": 1}) is False
    assert mm.publish_event({"kind": "x"}) is False
    assert mm.publish_snapshot({"sent": 10}) is False
    assert mm.enqueue_job("us-east", {"count": 1}) is False
    assert mm.dequeue_jobs(max_count=2) == []
    assert mm.regions_state() == []
    assert mm.latest_region_snapshots() == []
    snap = mm.snapshot()
    assert bool(snap.get("enabled", True)) is False
    assert str(snap.get("region_id", "")) == "eu-central"


def test_distributed_prometheus_includes_multimaster_metrics():
    state = {
        "latest_snapshot": {"workers": 1, "shards_reported": 2, "sent": 10, "errors": 1},
        "workers": [{"worker_id": "w-1", "state": "idle", "region": "eu-central", "last_heartbeat_ms": 10}],
        "shards": [{"shard_id": "s-1", "region": "eu-central", "stats_size_bytes": 16}],
        "ha": {"mode": "redis", "is_leader": 1, "leader_epoch": 7},
        "multi_master": {"enabled": True, "region_id": "eu-central"},
        "multi_master_regions": [
            {"region_id": "eu-central", "node_id": "m1", "ts_ms": 123},
            {"region_id": "us-east", "node_id": "m2", "ts_ms": 456},
        ],
    }
    out = _distributed_state_to_prometheus(state)
    assert "samurai_distributed_multi_master_enabled 1.0" in out
    assert "samurai_distributed_multi_master_regions_live 2.0" in out
    assert 'samurai_distributed_multi_master_region_heartbeat_ms{region="eu-central",node_id="m1"} 123.0' in out
    assert 'samurai_distributed_multi_master_region_heartbeat_ms{region="us-east",node_id="m2"} 456.0' in out


def test_multimaster_coordinator_enqueue_dequeue_with_fake_redis(monkeypatch):
    class _Pipe:
        def __init__(self, redis):
            self._redis = redis
            self._ops = []

        def lpush(self, key, value):
            self._ops.append(("lpush", key, value))
            return self

        def ltrim(self, key, start, end):
            self._ops.append(("ltrim", key, start, end))
            return self

        def rpush(self, key, value):
            self._ops.append(("rpush", key, value))
            return self

        def execute(self):
            for op in self._ops:
                kind = op[0]
                if kind == "lpush":
                    _, key, value = op
                    self._redis._lists.setdefault(key, []).insert(0, value)
                elif kind == "rpush":
                    _, key, value = op
                    self._redis._lists.setdefault(key, []).append(value)
                elif kind == "ltrim":
                    _, key, start, end = op
                    arr = self._redis._lists.setdefault(key, [])
                    n = len(arr)
                    s = int(start)
                    e = int(end)
                    if s < 0:
                        s = n + s
                    if e < 0:
                        e = n + e
                    s = max(0, s)
                    e = min(n - 1, e)
                    if n == 0 or s > e:
                        self._redis._lists[key] = []
                    else:
                        self._redis._lists[key] = arr[s : e + 1]
            self._ops = []
            return True

    class _FakeRedis:
        def __init__(self):
            self._kv = {}
            self._lists = {}

        def ping(self):
            return True

        def setex(self, key, ttl, value):
            _ = ttl
            self._kv[key] = value
            return True

        def set(self, key, value, ex=None):
            _ = ex
            self._kv[key] = value
            return True

        def get(self, key):
            return self._kv.get(key)

        def pipeline(self):
            return _Pipe(self)

        def lpop(self, key):
            arr = self._lists.setdefault(key, [])
            if not arr:
                return None
            return arr.pop(0)

        def scan_iter(self, match=None, count=None):
            _ = count
            if str(match or "").endswith(":latest"):
                for k in list(self._kv.keys()):
                    if k.endswith(":latest"):
                        yield k
            elif str(match or "").endswith(":hb"):
                for k in list(self._kv.keys()):
                    if k.endswith(":hb"):
                        yield k

    class _FakeRedisMod:
        @staticmethod
        def from_url(url, decode_responses=True):
            _ = url, decode_responses
            return _FakeRedis()

    monkeypatch.setitem(__import__("sys").modules, "redis", _FakeRedisMod())
    mm = RedisMultiMasterCoordinator(
        enabled=True,
        redis_url="redis://fake:6379/0",
        namespace="ns",
        region_id="eu-central",
        node_id="m1",
        heartbeat_ttl_s=10,
    )
    assert mm.enabled is True
    assert mm.heartbeat({"workers_count": 2}) is True
    assert mm.publish_snapshot({"sent": 10}) is True
    assert mm.enqueue_job("us-east", {"count": 100, "target_region": "us-east"}) is True
    out = mm.dequeue_jobs(max_count=3)
    assert out == []
    mm2 = RedisMultiMasterCoordinator(
        enabled=True,
        redis_url="redis://fake:6379/0",
        namespace="ns",
        region_id="us-east",
        node_id="m2",
        heartbeat_ttl_s=10,
    )
    # Inject shared fake backend manually for deterministic test.
    mm2._redis = mm._redis
    got = mm2.dequeue_jobs(max_count=3)
    assert len(got) == 1
    assert int(got[0].get("count", 0) or 0) == 100
