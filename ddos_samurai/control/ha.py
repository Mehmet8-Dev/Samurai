"""HA leader election skeleton for distributed master."""

from __future__ import annotations

import socket


def _parse_peers(raw: str) -> list[str]:
    return [x.strip() for x in str(raw or "").split(",") if x.strip()]


class StaticLeaderElector:
    """
    Deterministic leader election skeleton.

    Current strategy: lexical-min node id among {self + peers}.
    This is a bootstrap HA mode, not a consensus-backed distributed lock.
    """

    def __init__(self, node_id: str, peers_csv: str = "") -> None:
        nid = str(node_id or "").strip()
        self.node_id = nid or socket.gethostname()
        self.peers = _parse_peers(peers_csv)
        self.candidates = sorted(set([self.node_id, *self.peers]))
        self.leader_id = self.candidates[0] if self.candidates else self.node_id

    def is_leader(self) -> bool:
        return str(self.node_id) == str(self.leader_id)

    def snapshot(self) -> dict:
        return {
            "mode": "static",
            "node_id": str(self.node_id),
            "leader_id": str(self.leader_id),
            "is_leader": 1 if self.is_leader() else 0,
            "candidates": list(self.candidates),
        }
