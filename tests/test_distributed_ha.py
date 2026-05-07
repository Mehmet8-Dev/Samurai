from pathlib import Path
import socket

import shutil
import subprocess
import sys
import time
import types

import pytest

from ddos_samurai.control.ha import FileLeaseLeaderElector, NativeRaftLeaderElector, StaticLeaderElector


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = int(s.getsockname()[1])
    s.close()
    return p


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


def test_native_raft_elects_single_leader():
    p1, p2, p3 = _free_port(), _free_port(), _free_port()
    n1 = NativeRaftLeaderElector(
        node_id="n1",
        listen_addr=f"127.0.0.1:{p1}",
        peers_csv=f"n2@127.0.0.1:{p2},n3@127.0.0.1:{p3}",
        election_timeout_min_ms=220,
        election_timeout_max_ms=380,
        heartbeat_interval_ms=80,
    )
    n2 = NativeRaftLeaderElector(
        node_id="n2",
        listen_addr=f"127.0.0.1:{p2}",
        peers_csv=f"n1@127.0.0.1:{p1},n3@127.0.0.1:{p3}",
        election_timeout_min_ms=220,
        election_timeout_max_ms=380,
        heartbeat_interval_ms=80,
    )
    n3 = NativeRaftLeaderElector(
        node_id="n3",
        listen_addr=f"127.0.0.1:{p3}",
        peers_csv=f"n1@127.0.0.1:{p1},n2@127.0.0.1:{p2}",
        election_timeout_min_ms=220,
        election_timeout_max_ms=380,
        heartbeat_interval_ms=80,
    )
    nodes = [n1, n2, n3]
    try:
        for n in nodes:
            n.start_renew_loop(interval_seconds=0.05)
        leader_count = 0
        deadline = time.time() + 5.0
        while time.time() < deadline:
            leaders = [n for n in nodes if n.is_leader()]
            leader_count = len(leaders)
            if leader_count == 1:
                break
            time.sleep(0.05)
        assert leader_count == 1
    finally:
        for n in nodes:
            n.stop()


def test_native_raft_failover_takeover_and_epoch_advance():
    p1, p2, p3 = _free_port(), _free_port(), _free_port()
    n1 = NativeRaftLeaderElector(
        node_id="n1",
        listen_addr=f"127.0.0.1:{p1}",
        peers_csv=f"n2@127.0.0.1:{p2},n3@127.0.0.1:{p3}",
        election_timeout_min_ms=220,
        election_timeout_max_ms=380,
        heartbeat_interval_ms=80,
    )
    n2 = NativeRaftLeaderElector(
        node_id="n2",
        listen_addr=f"127.0.0.1:{p2}",
        peers_csv=f"n1@127.0.0.1:{p1},n3@127.0.0.1:{p3}",
        election_timeout_min_ms=220,
        election_timeout_max_ms=380,
        heartbeat_interval_ms=80,
    )
    n3 = NativeRaftLeaderElector(
        node_id="n3",
        listen_addr=f"127.0.0.1:{p3}",
        peers_csv=f"n1@127.0.0.1:{p1},n2@127.0.0.1:{p2}",
        election_timeout_min_ms=220,
        election_timeout_max_ms=380,
        heartbeat_interval_ms=80,
    )
    nodes = [n1, n2, n3]
    try:
        for n in nodes:
            n.start_renew_loop(interval_seconds=0.05)
        leader = None
        deadline = time.time() + 5.0
        while time.time() < deadline:
            leaders = [n for n in nodes if n.is_leader()]
            if len(leaders) == 1:
                leader = leaders[0]
                break
            time.sleep(0.05)
        assert leader is not None
        old_id = str(leader.snapshot().get("node_id", ""))
        old_epoch = int(leader.leader_epoch)
        leader.stop()
        survivors = [n for n in nodes if n is not leader]
        new_leader = None
        deadline = time.time() + 6.0
        while time.time() < deadline:
            leaders = [n for n in survivors if n.is_leader()]
            if len(leaders) == 1:
                new_leader = leaders[0]
                break
            time.sleep(0.05)
        assert new_leader is not None
        assert str(new_leader.snapshot().get("node_id", "")) != old_id
        assert int(new_leader.leader_epoch) > int(old_epoch)
    finally:
        for n in nodes:
            try:
                n.stop()
            except Exception:
                pass


def test_native_raft_replicated_command_commits_and_applies():
    p1, p2, p3 = _free_port(), _free_port(), _free_port()
    n1 = NativeRaftLeaderElector(
        node_id="n1",
        listen_addr=f"127.0.0.1:{p1}",
        peers_csv=f"n2@127.0.0.1:{p2},n3@127.0.0.1:{p3}",
        election_timeout_min_ms=220,
        election_timeout_max_ms=380,
        heartbeat_interval_ms=80,
    )
    n2 = NativeRaftLeaderElector(
        node_id="n2",
        listen_addr=f"127.0.0.1:{p2}",
        peers_csv=f"n1@127.0.0.1:{p1},n3@127.0.0.1:{p3}",
        election_timeout_min_ms=220,
        election_timeout_max_ms=380,
        heartbeat_interval_ms=80,
    )
    n3 = NativeRaftLeaderElector(
        node_id="n3",
        listen_addr=f"127.0.0.1:{p3}",
        peers_csv=f"n1@127.0.0.1:{p1},n2@127.0.0.1:{p2}",
        election_timeout_min_ms=220,
        election_timeout_max_ms=380,
        heartbeat_interval_ms=80,
    )
    nodes = [n1, n2, n3]
    try:
        for n in nodes:
            n.start_renew_loop(interval_seconds=0.05)
        leader = None
        deadline = time.time() + 5.0
        while time.time() < deadline:
            leaders = [n for n in nodes if n.is_leader()]
            if len(leaders) == 1:
                leader = leaders[0]
                break
            time.sleep(0.05)
        assert leader is not None
        ok = leader.replicate_command({"op": "set", "key": "x", "value": 42}, wait_commit_s=3.0)
        assert ok is True

        deadline = time.time() + 5.0
        while time.time() < deadline:
            applied_counts = [len(n.get_applied_commands()) for n in nodes]
            if min(applied_counts) >= 1:
                break
            time.sleep(0.05)
        for n in nodes:
            entries = n.get_applied_commands()
            assert len(entries) >= 1
            assert dict(entries[0].get("command", {}) or {}).get("op") == "set"
            assert dict(entries[0].get("command", {}) or {}).get("key") == "x"
    finally:
        for n in nodes:
            try:
                n.stop()
            except Exception:
                pass


def test_native_raft_replicated_log_survives_leader_failover():
    p1, p2, p3 = _free_port(), _free_port(), _free_port()
    n1 = NativeRaftLeaderElector(
        node_id="n1",
        listen_addr=f"127.0.0.1:{p1}",
        peers_csv=f"n2@127.0.0.1:{p2},n3@127.0.0.1:{p3}",
        election_timeout_min_ms=220,
        election_timeout_max_ms=380,
        heartbeat_interval_ms=80,
    )
    n2 = NativeRaftLeaderElector(
        node_id="n2",
        listen_addr=f"127.0.0.1:{p2}",
        peers_csv=f"n1@127.0.0.1:{p1},n3@127.0.0.1:{p3}",
        election_timeout_min_ms=220,
        election_timeout_max_ms=380,
        heartbeat_interval_ms=80,
    )
    n3 = NativeRaftLeaderElector(
        node_id="n3",
        listen_addr=f"127.0.0.1:{p3}",
        peers_csv=f"n1@127.0.0.1:{p1},n2@127.0.0.1:{p2}",
        election_timeout_min_ms=220,
        election_timeout_max_ms=380,
        heartbeat_interval_ms=80,
    )
    nodes = [n1, n2, n3]
    try:
        for n in nodes:
            n.start_renew_loop(interval_seconds=0.05)
        leader = None
        deadline = time.time() + 5.0
        while time.time() < deadline:
            leaders = [n for n in nodes if n.is_leader()]
            if len(leaders) == 1:
                leader = leaders[0]
                break
            time.sleep(0.05)
        assert leader is not None
        assert leader.replicate_command({"seq": 1}, wait_commit_s=3.0) is True

        leader.stop()
        survivors = [n for n in nodes if n is not leader]
        new_leader = None
        deadline = time.time() + 6.0
        while time.time() < deadline:
            leaders = [n for n in survivors if n.is_leader()]
            if len(leaders) == 1:
                new_leader = leaders[0]
                break
            time.sleep(0.05)
        assert new_leader is not None
        assert new_leader.replicate_command({"seq": 2}, wait_commit_s=3.0) is True

        deadline = time.time() + 6.0
        while time.time() < deadline:
            ok = True
            for n in survivors:
                seqs = [dict(x.get("command", {}) or {}).get("seq") for x in n.get_applied_commands()]
                if 1 not in seqs or 2 not in seqs:
                    ok = False
                    break
            if ok:
                break
            time.sleep(0.05)
        for n in survivors:
            seqs = [dict(x.get("command", {}) or {}).get("seq") for x in n.get_applied_commands()]
            assert 1 in seqs and 2 in seqs
    finally:
        for n in nodes:
            try:
                n.stop()
            except Exception:
                pass


def test_native_raft_snapshot_compaction_progresses():
    p1, p2, p3 = _free_port(), _free_port(), _free_port()
    n1 = NativeRaftLeaderElector(
        node_id="n1",
        listen_addr=f"127.0.0.1:{p1}",
        peers_csv=f"n2@127.0.0.1:{p2},n3@127.0.0.1:{p3}",
        election_timeout_min_ms=220,
        election_timeout_max_ms=380,
        heartbeat_interval_ms=80,
        snapshot_threshold=32,
        snapshot_keep_entries=8,
    )
    n2 = NativeRaftLeaderElector(
        node_id="n2",
        listen_addr=f"127.0.0.1:{p2}",
        peers_csv=f"n1@127.0.0.1:{p1},n3@127.0.0.1:{p3}",
        election_timeout_min_ms=220,
        election_timeout_max_ms=380,
        heartbeat_interval_ms=80,
        snapshot_threshold=32,
        snapshot_keep_entries=8,
    )
    n3 = NativeRaftLeaderElector(
        node_id="n3",
        listen_addr=f"127.0.0.1:{p3}",
        peers_csv=f"n1@127.0.0.1:{p1},n2@127.0.0.1:{p2}",
        election_timeout_min_ms=220,
        election_timeout_max_ms=380,
        heartbeat_interval_ms=80,
        snapshot_threshold=32,
        snapshot_keep_entries=8,
    )
    nodes = [n1, n2, n3]
    try:
        for n in nodes:
            n.start_renew_loop(interval_seconds=0.05)
        leader = None
        deadline = time.time() + 5.0
        while time.time() < deadline:
            leaders = [n for n in nodes if n.is_leader()]
            if len(leaders) == 1:
                leader = leaders[0]
                break
            time.sleep(0.05)
        assert leader is not None
        for i in range(1, 80):
            assert leader.replicate_command({"seq": i}, wait_commit_s=2.0) is True
        snap = leader.snapshot()
        assert int(snap.get("snapshot_last_index", 0) or 0) > 0
        assert int(snap.get("last_log_index", 0) or 0) >= 79
        assert int(snap.get("commit_index", 0) or 0) >= 79
    finally:
        for n in nodes:
            try:
                n.stop()
            except Exception:
                pass


def test_native_raft_dynamic_membership_add_remove_peer():
    p1, p2, p3 = _free_port(), _free_port(), _free_port()
    n1 = NativeRaftLeaderElector(
        node_id="n1",
        listen_addr=f"127.0.0.1:{p1}",
        peers_csv=f"n2@127.0.0.1:{p2}",
        election_timeout_min_ms=220,
        election_timeout_max_ms=380,
        heartbeat_interval_ms=80,
    )
    n2 = NativeRaftLeaderElector(
        node_id="n2",
        listen_addr=f"127.0.0.1:{p2}",
        peers_csv=f"n1@127.0.0.1:{p1}",
        election_timeout_min_ms=220,
        election_timeout_max_ms=380,
        heartbeat_interval_ms=80,
    )
    n3 = NativeRaftLeaderElector(
        node_id="n3",
        listen_addr=f"127.0.0.1:{p3}",
        peers_csv=f"n1@127.0.0.1:{p1},n2@127.0.0.1:{p2}",
        election_timeout_min_ms=2000,
        election_timeout_max_ms=3000,
        heartbeat_interval_ms=80,
    )
    nodes = [n1, n2, n3]
    try:
        for n in nodes:
            n.start_renew_loop(interval_seconds=0.05)
        leader = None
        deadline = time.time() + 5.0
        while time.time() < deadline:
            leaders = [n for n in [n1, n2] if n.is_leader()]
            if len(leaders) == 1:
                leader = leaders[0]
                break
            time.sleep(0.05)
        assert leader is not None
        assert leader.add_peer("n3", f"127.0.0.1:{p3}", wait_commit_s=3.0) is True
        deadline = time.time() + 4.0
        while time.time() < deadline:
            if int(n1.snapshot().get("peer_count", 0) or 0) == 2 and int(n2.snapshot().get("peer_count", 0) or 0) == 2:
                break
            time.sleep(0.05)
        assert int(n1.snapshot().get("peer_count", 0) or 0) == 2
        assert int(n2.snapshot().get("peer_count", 0) or 0) == 2

        assert leader.remove_peer("n3", wait_commit_s=3.0) is True
        deadline = time.time() + 4.0
        while time.time() < deadline:
            if int(n1.snapshot().get("peer_count", 0) or 0) == 1 and int(n2.snapshot().get("peer_count", 0) or 0) == 1:
                break
            time.sleep(0.05)
        assert int(n1.snapshot().get("peer_count", 0) or 0) == 1
        assert int(n2.snapshot().get("peer_count", 0) or 0) == 1
    finally:
        for n in nodes:
            try:
                n.stop()
            except Exception:
                pass
