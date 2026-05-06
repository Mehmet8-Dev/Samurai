from pathlib import Path

import shutil
import subprocess
import sys
import time
import types

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


def test_etcd_lease_elector_with_fake_client():
    class _FakeLease:
        def __init__(self, lease_id):
            self.id = lease_id

        def refresh(self):
            return True

        def revoke(self):
            return True

    class _FakeTx:
        @staticmethod
        def version(_k):
            class _Cmp:
                def __eq__(self, _v):
                    return ("cmp",)

            return _Cmp()

        @staticmethod
        def put(k, v, lease=None):
            return ("put", k, v, lease)

    class _FakeClient:
        def __init__(self):
            self.kv = {}
            self.transactions = _FakeTx()
            self._lease_id = 100

        def status(self):
            return {"version": "fake"}

        def lease(self, _ttl):
            self._lease_id += 1
            return _FakeLease(self._lease_id)

        def transaction(self, compare, success, failure):
            _ = compare
            _ = failure
            if "k" not in self.kv:
                _, k, v, _lease = success[0]
                self.kv[k] = v
                return True, []
            return False, []

        def get(self, key):
            val = self.kv.get(key)
            if val is None:
                return None, None
            if isinstance(val, bytes):
                return val, None
            return str(val).encode("utf-8"), None

        def put(self, key, value):
            self.kv[key] = str(value)
            return True

        def delete(self, key):
            self.kv.pop(key, None)
            return True

    fake_mod = types.SimpleNamespace(client=lambda **kwargs: _FakeClient())
    old = sys.modules.get("etcd3")
    sys.modules["etcd3"] = fake_mod
    try:
        from ddos_samurai.control.ha import EtcdLeaseLeaderElector

        e = EtcdLeaseLeaderElector(
            node_id="node-a",
            endpoints_csv="127.0.0.1:2379",
            lease_key="k",
            lease_seconds=3.0,
            timeout_seconds=1.0,
        )
        assert e.try_acquire() is True
        assert e.is_leader() is True
        assert int(e.leader_epoch) >= 1
        assert e.renew_once() is True
        snap = e.snapshot()
        assert snap["mode"] == "etcd"
        assert int(snap["is_leader"]) == 1
        e.stop()
    finally:
        if old is None:
            sys.modules.pop("etcd3", None)
        else:
            sys.modules["etcd3"] = old
