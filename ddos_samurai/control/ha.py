"""HA leader election skeleton for distributed master."""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from contextlib import contextmanager


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


class FileLeaseLeaderElector:
    """
    File-backed lease elector.

    The lease file stores: {"owner": "<node_id>", "expires_at": <epoch_seconds>}
    """

    def __init__(
        self,
        node_id: str,
        lease_path: str,
        *,
        lease_seconds: float = 15.0,
    ) -> None:
        self.node_id = str(node_id or "").strip() or socket.gethostname()
        self.lease_path = str(lease_path or "").strip()
        self.lease_seconds = max(1.0, float(lease_seconds or 15.0))
        self._leader = False
        self._stop_evt = threading.Event()
        self._renew_thread = None
        if not self.lease_path:
            raise ValueError("lease_path is required")
        parent = os.path.dirname(self.lease_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    @contextmanager
    def _meta_lock(self):
        import fcntl

        lock_path = f"{self.lease_path}.lock"
        with open(lock_path, "a+", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def _read_lease(self) -> dict:
        try:
            with open(self.lease_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            if not isinstance(payload, dict):
                return {}
            return payload
        except Exception:
            return {}

    def _write_lease(self, owner: str, expires_at: float) -> None:
        tmp = f"{self.lease_path}.tmp.{os.getpid()}"
        payload = {"owner": str(owner), "expires_at": float(expires_at)}
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=True, sort_keys=True)
        os.replace(tmp, self.lease_path)

    def try_acquire(self) -> bool:
        now = time.time()
        with self._meta_lock():
            cur = self._read_lease()
            owner = str(cur.get("owner", "") or "")
            exp = float(cur.get("expires_at", 0.0) or 0.0)
            if owner == self.node_id:
                self._write_lease(self.node_id, now + self.lease_seconds)
                self._leader = True
                return True
            if owner and exp > now:
                self._leader = False
                return False
            self._write_lease(self.node_id, now + self.lease_seconds)
            self._leader = True
            return True

    def renew_once(self) -> bool:
        now = time.time()
        with self._meta_lock():
            cur = self._read_lease()
            owner = str(cur.get("owner", "") or "")
            exp = float(cur.get("expires_at", 0.0) or 0.0)
            if owner != self.node_id or exp <= now:
                self._leader = False
                return False
            self._write_lease(self.node_id, now + self.lease_seconds)
            self._leader = True
            return True

    def start_renew_loop(self, interval_seconds: float = 5.0) -> None:
        iv = max(0.2, float(interval_seconds or 5.0))
        self._stop_evt.clear()

        def _loop():
            while not self._stop_evt.wait(iv):
                if not self.renew_once():
                    break

        self._renew_thread = threading.Thread(target=_loop, daemon=True, name="FileLeaseRenew")
        self._renew_thread.start()

    def stop(self) -> None:
        self._stop_evt.set()
        th = self._renew_thread
        if th is not None:
            th.join(timeout=2.0)
        self.release()

    def release(self) -> None:
        with self._meta_lock():
            cur = self._read_lease()
            owner = str(cur.get("owner", "") or "")
            if owner == self.node_id:
                try:
                    os.remove(self.lease_path)
                except OSError:
                    pass
        self._leader = False

    def is_leader(self) -> bool:
        return bool(self._leader)

    def snapshot(self) -> dict:
        cur = self._read_lease()
        return {
            "mode": "file-lock",
            "node_id": str(self.node_id),
            "leader_id": str(cur.get("owner", "") or ""),
            "is_leader": 1 if self.is_leader() else 0,
            "lease_path": str(self.lease_path),
            "lease_seconds": float(self.lease_seconds),
            "lease_expires_at": float(cur.get("expires_at", 0.0) or 0.0),
        }
