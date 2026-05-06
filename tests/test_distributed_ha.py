from ddos_samurai.control.ha import StaticLeaderElector


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
