from pathlib import Path

import shutil
import subprocess
import time

import pytest

from ddos_samurai.control.ha import FileLeaseLeaderElector, StaticLeaderElector


def test_static_leader_elector_selects_lexicographic_min():
    e = StaticLeaderElector(node_id="node-b", peers_csv="node-c,node-a")
    snap = e.snapshot()
    assert str(snap.get("leader_id", "")) == "node-a"
    assert e.is_leader() is False


def test_static_leader_elector_self_is_leader_when_min():
    e = StaticLeaderElector(node_id="node-a", peers_csv="node-c,node-b")
    snap = e.snapshot()
    assert str(snap.get("leader_id", "")) == "node-a"
    assert e.is_leader() is True


def test_file_lease_leader_elector_blocks_second_owner_until_release(tmp_path):
    lease = Path(tmp_path) / "ha-lease.json"
    e1 = FileLeaseLeaderElector(node_id="node-a", lease_path=str(lease), lease_seconds=5.0)
    e2 = FileLeaseLeaderElector(node_id="node-b", lease_path=str(lease), lease_seconds=5.0)
    assert e1.try_acquire() is True
    assert e1.is_leader() is True
    assert e2.try_acquire() is False
    assert e2.is_leader() is False
    e1.release()
    assert e2.try_acquire() is True
    assert e2.is_leader() is True
    e2.release()


def test_file_lease_renew_extends_ownership(tmp_path):
    lease = Path(tmp_path) / "ha-lease-renew.json"
    e = FileLeaseLeaderElector(node_id="node-a", lease_path=str(lease), lease_seconds=2.0)
    assert e.try_acquire() is True
    s1 = e.snapshot()
    assert str(s1.get("leader_id", "")) == "node-a"
    assert e.renew_once() is True
    s2 = e.snapshot()
    assert float(s2.get("lease_expires_at", 0.0) or 0.0) >= float(s1.get("lease_expires_at", 0.0) or 0.0)
    e.release()


def test_redis_lease_elector_acquire_and_epoch():
    try:
        import redis  # noqa: F401
    except Exception:
        pytest.skip("redis package is not available")
    redis_server = shutil.which("redis-server")
    if not redis_server:
        pytest.skip("redis-server is not available")

    port = 6399
    proc = subprocess.Popen(
        [redis_server, "--save", "", "--appendonly", "no", "--port", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(0.2)
        from ddos_samurai.control.ha import RedisLeaseLeaderElector

        url = f"redis://127.0.0.1:{port}/0"
        e1 = RedisLeaseLeaderElector("node-a", redis_url=url, lease_key="samurai:test:ha", lease_seconds=3.0)
        e2 = RedisLeaseLeaderElector("node-b", redis_url=url, lease_key="samurai:test:ha", lease_seconds=3.0)
        assert e1.try_acquire() is True
        assert e1.leader_epoch >= 1
        assert e2.try_acquire() is False
        assert e1.renew_once() is True
        e1.release()
        assert e2.try_acquire() is True
        assert e2.leader_epoch >= 2
        e2.release()
    finally:
        proc.terminate()
        proc.wait(timeout=3)
