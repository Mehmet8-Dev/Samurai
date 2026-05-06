from pathlib import Path

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
