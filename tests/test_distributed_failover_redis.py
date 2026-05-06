import shutil
import subprocess
import time
from types import SimpleNamespace

import pytest

from ddos_samurai.control.ha import RedisLeaseLeaderElector
from ddos_samurai.control.master import _run_single_job


def _start_redis_or_skip():
    try:
        import redis  # noqa: F401
    except Exception:
        pytest.skip("redis package is not available")
    redis_server = shutil.which("redis-server")
    if not redis_server:
        pytest.skip("redis-server is not available")
    port = 6401
    proc = subprocess.Popen(
        [redis_server, "--save", "", "--appendonly", "no", "--port", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.2)
    return proc, f"redis://127.0.0.1:{port}/0"


def test_failover_takeover_and_controlled_abort_path():
    proc, url = _start_redis_or_skip()
    try:
        e1 = RedisLeaseLeaderElector("master-a", redis_url=url, lease_key="samurai:test:failover", lease_seconds=3.0)
        e2 = RedisLeaseLeaderElector("master-b", redis_url=url, lease_key="samurai:test:failover", lease_seconds=3.0)
        assert e1.try_acquire() is True
        e1.start_renew_loop(interval_seconds=0.5)
        assert e2.try_acquire() is False

        # Leader dies -> follower takeover
        e1.stop()
        acquired = False
        for _ in range(20):
            if e2.try_acquire():
                acquired = True
                break
            time.sleep(0.2)
        assert acquired is True
        assert e2.is_leader() is True

        # Controlled abort path on leadership loss (fencing guard)
        server = SimpleNamespace(servicer=SimpleNamespace(workers={}, shard_stats={}))
        rc, snap = _run_single_job(
            server=server,
            job_args={"count": 100, "job_timeout_s": 3},
            job_id="job-test-fence",
            leadership_guard=lambda: False,
        )
        assert int(rc) == 1
        assert str(snap.get("error", "")) == "leadership_lost_abort"
        e2.stop()
    finally:
        proc.terminate()
        proc.wait(timeout=3)
