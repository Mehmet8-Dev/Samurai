"""HA leader election skeleton for distributed master."""

from __future__ import annotations

import json
import os
import socket
import threading
import time
import uuid
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


class RedisLeaseLeaderElector:
    """Redis-backed lease elector with fencing epoch."""

    def __init__(
        self,
        node_id: str,
        redis_url: str,
        lease_key: str,
        *,
        lease_seconds: float = 15.0,
    ) -> None:
        self.node_id = str(node_id or "").strip() or socket.gethostname()
        self.redis_url = str(redis_url or "").strip()
        self.lease_key = str(lease_key or "").strip()
        self.lease_seconds = max(1.0, float(lease_seconds or 15.0))
        self.owner_token = f"{self.node_id}:{uuid.uuid4().hex}"
        self._leader = False
        self._leader_epoch = 0
        self._stop_evt = threading.Event()
        self._renew_thread = None
        if not self.redis_url:
            raise ValueError("redis_url is required")
        if not self.lease_key:
            raise ValueError("lease_key is required")
        try:
            import redis  # noqa: F401
        except Exception as exc:
            raise RuntimeError("redis package is required for ha_mode=redis") from exc
        self._redis = __import__("redis").Redis.from_url(self.redis_url, decode_responses=True)

    def _epoch_key(self) -> str:
        return f"{self.lease_key}:epoch"

    def try_acquire(self) -> bool:
        lease_ms = int(self.lease_seconds * 1000.0)
        ok = bool(self._redis.set(self.lease_key, self.owner_token, nx=True, px=lease_ms))
        if ok:
            self._leader = True
            self._leader_epoch = int(self._redis.incr(self._epoch_key()) or 0)
            return True
        if str(self._redis.get(self.lease_key) or "") == self.owner_token:
            self._leader = True
            if self._leader_epoch <= 0:
                self._leader_epoch = int(self._redis.get(self._epoch_key()) or 0)
            return True
        self._leader = False
        return False

    def renew_once(self) -> bool:
        script = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('PEXPIRE', KEYS[1], ARGV[2])
else
  return 0
end
"""
        lease_ms = int(self.lease_seconds * 1000.0)
        res = int(self._redis.eval(script, 1, self.lease_key, self.owner_token, str(lease_ms)) or 0)
        self._leader = res == 1
        if not self._leader:
            return False
        if self._leader_epoch <= 0:
            self._leader_epoch = int(self._redis.get(self._epoch_key()) or 0)
        return True

    def start_renew_loop(self, interval_seconds: float = 5.0) -> None:
        iv = max(0.2, float(interval_seconds or 5.0))
        self._stop_evt.clear()

        def _loop():
            while not self._stop_evt.wait(iv):
                if not self.renew_once():
                    break

        self._renew_thread = threading.Thread(target=_loop, daemon=True, name="RedisLeaseRenew")
        self._renew_thread.start()

    def is_leader(self) -> bool:
        return bool(self._leader)

    @property
    def leader_epoch(self) -> int:
        return int(self._leader_epoch or 0)

    def release(self) -> None:
        script = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
else
  return 0
end
"""
        try:
            _ = self._redis.eval(script, 1, self.lease_key, self.owner_token)
        except Exception:
            pass
        self._leader = False

    def stop(self) -> None:
        self._stop_evt.set()
        th = self._renew_thread
        if th is not None:
            th.join(timeout=2.0)
        self.release()

    def snapshot(self) -> dict:
        leader_token = str(self._redis.get(self.lease_key) or "")
        leader_id = str(leader_token.split(":", 1)[0] if ":" in leader_token else leader_token)
        ttl_ms = int(self._redis.pttl(self.lease_key) or -1)
        return {
            "mode": "redis",
            "node_id": str(self.node_id),
            "leader_id": leader_id,
            "is_leader": 1 if self.is_leader() else 0,
            "lease_key": str(self.lease_key),
            "lease_ttl_ms": ttl_ms,
            "leader_epoch": int(self.leader_epoch),
        }
