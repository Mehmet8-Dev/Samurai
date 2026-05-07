"""HA leader election skeleton for distributed master."""

from __future__ import annotations

import json
import os
import random
import socket
import socketserver
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


class EtcdLeaseLeaderElector:
    """etcd-backed lease elector with fencing epoch."""

    def __init__(
        self,
        node_id: str,
        endpoints_csv: str,
        lease_key: str,
        *,
        lease_seconds: float = 15.0,
        timeout_seconds: float = 3.0,
    ) -> None:
        self.node_id = str(node_id or "").strip() or socket.gethostname()
        self.endpoints_csv = str(endpoints_csv or "").strip()
        self.endpoints = [x.strip() for x in self.endpoints_csv.split(",") if x.strip()]
        self.lease_key = str(lease_key or "").strip()
        self.lease_seconds = max(1.0, float(lease_seconds or 15.0))
        self.timeout_seconds = max(0.5, float(timeout_seconds or 3.0))
        self.owner_token = f"{self.node_id}:{uuid.uuid4().hex}"
        self._leader = False
        self._leader_epoch = 0
        self._lease = None
        if not self.endpoints:
            raise ValueError("etcd endpoints are required")
        if not self.lease_key:
            raise ValueError("lease_key is required")
        try:
            import etcd3  # noqa: F401
        except Exception as exc:
            raise RuntimeError("etcd3 package is required for ha_mode=etcd") from exc
        self._etcd3 = __import__("etcd3")
        self._client = self._build_client()

    def _build_client(self):
        last_exc = None
        for endpoint in self.endpoints:
            host = endpoint
            port = 2379
            if ":" in endpoint:
                host, p = endpoint.rsplit(":", 1)
                port = int(p)
            try:
                cli = self._etcd3.client(host=host, port=port, timeout=self.timeout_seconds)
                _ = cli.status()
                return cli
            except Exception as exc:
                last_exc = exc
                continue
        if last_exc is not None:
            raise RuntimeError(f"unable to connect any etcd endpoint: {self.endpoints}") from last_exc
        raise RuntimeError("unable to create etcd client")

    @staticmethod
    def _to_int(raw) -> int:
        if isinstance(raw, (bytes, bytearray)):
            try:
                return int(raw.decode("utf-8") or "0")
            except Exception:
                return 0
        try:
            return int(raw or 0)
        except Exception:
            return 0

    def _epoch_key(self) -> str:
        return f"{self.lease_key}:epoch"

    def try_acquire(self) -> bool:
        self._lease = self._client.lease(int(self.lease_seconds))
        txn_ok, _responses = self._client.transaction(
            compare=[self._client.transactions.version(self.lease_key) == 0],
            success=[self._client.transactions.put(self.lease_key, self.owner_token, lease=self._lease.id)],
            failure=[],
        )
        if bool(txn_ok):
            self._leader = True
            epoch, _meta = self._client.get(self._epoch_key())
            cur = self._to_int(epoch)
            nxt = cur + 1
            self._client.put(self._epoch_key(), str(nxt))
            self._leader_epoch = nxt
            return True
        val, _meta = self._client.get(self.lease_key)
        token = (val.decode("utf-8") if isinstance(val, (bytes, bytearray)) else str(val or ""))
        if token == self.owner_token:
            self._leader = True
            return True
        self._leader = False
        try:
            self._lease.revoke()
        except Exception:
            pass
        self._lease = None
        return False

    def renew_once(self) -> bool:
        if self._lease is None:
            self._leader = False
            return False
        try:
            val, _meta = self._client.get(self.lease_key)
            token = (val.decode("utf-8") if isinstance(val, (bytes, bytearray)) else str(val or ""))
            if token != self.owner_token:
                self._leader = False
                return False
            _ = self._lease.refresh()
            self._leader = True
            if self._leader_epoch <= 0:
                epoch, _meta = self._client.get(self._epoch_key())
                self._leader_epoch = self._to_int(epoch)
            return True
        except Exception:
            self._leader = False
            return False

    def start_renew_loop(self, interval_seconds: float = 5.0) -> None:
        iv = max(0.2, float(interval_seconds or 5.0))
        self._stop_evt = threading.Event()

        def _loop():
            while not self._stop_evt.wait(iv):
                if not self.renew_once():
                    break

        self._renew_thread = threading.Thread(target=_loop, daemon=True, name="EtcdLeaseRenew")
        self._renew_thread.start()

    def is_leader(self) -> bool:
        return bool(self._leader)

    @property
    def leader_epoch(self) -> int:
        return int(self._leader_epoch or 0)

    def release(self) -> None:
        try:
            val, _meta = self._client.get(self.lease_key)
            token = (val.decode("utf-8") if isinstance(val, (bytes, bytearray)) else str(val or ""))
            if token == self.owner_token:
                self._client.delete(self.lease_key)
        except Exception:
            pass
        try:
            if self._lease is not None:
                self._lease.revoke()
        except Exception:
            pass
        self._leader = False

    def stop(self) -> None:
        evt = getattr(self, "_stop_evt", None)
        if evt is not None:
            evt.set()
        th = getattr(self, "_renew_thread", None)
        if th is not None:
            th.join(timeout=2.0)
        self.release()

    def snapshot(self) -> dict:
        try:
            val, _meta = self._client.get(self.lease_key)
            token = (val.decode("utf-8") if isinstance(val, (bytes, bytearray)) else str(val or ""))
        except Exception:
            token = ""
        leader_id = str(token.split(":", 1)[0] if ":" in token else token)
        return {
            "mode": "etcd",
            "node_id": str(self.node_id),
            "leader_id": leader_id,
            "is_leader": 1 if self.is_leader() else 0,
            "endpoints": list(self.endpoints),
            "lease_key": str(self.lease_key),
            "leader_epoch": int(self.leader_epoch),
        }


def _parse_raft_peers(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in str(raw or "").split(","):
        part = str(item or "").strip()
        if not part:
            continue
        if "@" not in part:
            continue
        node_id, addr = part.split("@", 1)
        node_id = str(node_id or "").strip()
        addr = str(addr or "").strip()
        if node_id and addr and ":" in addr:
            out[node_id] = addr
    return out


class NativeRaftLeaderElector:
    """
    Embedded Raft leader election core (quorum/term/heartbeat based).

    Scope: control-plane leadership consensus, fencing epoch, replicated
    command log, and lightweight snapshot compaction.
    """

    def __init__(
        self,
        node_id: str,
        listen_addr: str,
        peers_csv: str,
        *,
        election_timeout_min_ms: int = 900,
        election_timeout_max_ms: int = 1500,
        heartbeat_interval_ms: int = 250,
        rpc_timeout_s: float = 0.35,
        append_batch_size: int = 128,
        snapshot_threshold: int = 2048,
        snapshot_keep_entries: int = 512,
    ) -> None:
        self.node_id = str(node_id or "").strip() or socket.gethostname()
        self.listen_addr = str(listen_addr or "").strip()
        self.peers = _parse_raft_peers(peers_csv)
        if not self.listen_addr or ":" not in self.listen_addr:
            raise ValueError("raft listen_addr must be host:port")
        self.peers.pop(self.node_id, None)
        self.peer_items = sorted(self.peers.items())
        self.peer_count = len(self.peer_items)
        self.cluster_size = self.peer_count + 1
        self.quorum = (self.cluster_size // 2) + 1

        self.election_timeout_min_ms = max(200, int(election_timeout_min_ms or 900))
        self.election_timeout_max_ms = max(self.election_timeout_min_ms + 100, int(election_timeout_max_ms or 1500))
        self.heartbeat_interval_ms = max(50, int(heartbeat_interval_ms or 250))
        self.rpc_timeout_s = max(0.05, float(rpc_timeout_s or 0.35))
        self.append_batch_size = max(1, int(append_batch_size or 128))
        self.snapshot_threshold = max(64, int(snapshot_threshold or 2048))
        self.snapshot_keep_entries = max(16, int(snapshot_keep_entries or 512))

        self._lock = threading.RLock()
        self._term = 0
        self._voted_for = ""
        self._role = "follower"
        self._leader_id = ""
        self._is_leader = False
        self._leader_epoch = 0
        self._last_leader_contact = time.monotonic()
        self._election_deadline = 0.0
        self._set_new_election_deadline_locked()
        self._log: list[dict] = []
        self._log_start_index = 1
        self._snapshot_last_index = 0
        self._snapshot_last_term = 0
        self._commit_index = 0
        self._last_applied = 0
        self._next_index = {nid: 1 for nid, _ in self.peer_items}
        self._match_index = {nid: 0 for nid, _ in self.peer_items}
        self._applied_commands: list[dict] = []

        self._stop_evt = threading.Event()
        self._renew_thread = None
        self._server = None
        self._server_thread = None
        self._start_rpc_server()

    def _set_new_election_deadline_locked(self) -> None:
        low = int(self.election_timeout_min_ms)
        high = int(self.election_timeout_max_ms)
        jitter_ms = random.randint(low, high)
        self._election_deadline = time.monotonic() + (float(jitter_ms) / 1000.0)

    def _recompute_topology_locked(self) -> None:
        self.peer_items = sorted(self.peers.items())
        self.peer_count = len(self.peer_items)
        self.cluster_size = self.peer_count + 1
        self.quorum = (self.cluster_size // 2) + 1
        for nid, _addr in self.peer_items:
            self._next_index.setdefault(nid, self._last_log_index_locked() + 1)
            self._match_index.setdefault(nid, 0)
        known = {nid for nid, _ in self.peer_items}
        for nid in list(self._next_index.keys()):
            if nid not in known:
                self._next_index.pop(nid, None)
        for nid in list(self._match_index.keys()):
            if nid not in known:
                self._match_index.pop(nid, None)

    def _last_log_index_locked(self) -> int:
        if not self._log:
            return int(self._snapshot_last_index)
        return int(self._log_start_index + len(self._log) - 1)

    def _entry_pos_locked(self, index: int) -> int:
        idx = int(index or 0)
        return int(idx - self._log_start_index)

    def _log_term_at_locked(self, index: int) -> int:
        idx = int(index or 0)
        if idx <= 0:
            return 0
        if idx == self._snapshot_last_index:
            return int(self._snapshot_last_term)
        if idx < self._log_start_index:
            return 0
        pos = self._entry_pos_locked(idx)
        if pos < 0 or pos >= len(self._log):
            return 0
        return int(dict(self._log[pos] or {}).get("term", 0) or 0)

    def _entry_at_locked(self, index: int) -> dict | None:
        idx = int(index or 0)
        if idx < self._log_start_index:
            return None
        pos = self._entry_pos_locked(idx)
        if pos < 0 or pos >= len(self._log):
            return None
        return dict(self._log[pos] or {})

    def _append_entry_locked(self, term: int, command: dict) -> int:
        idx = self._last_log_index_locked() + 1
        self._log.append(
            {
                "index": int(idx),
                "term": int(term),
                "command": dict(command or {}),
            }
        )
        return int(idx)

    def _collect_apply_entries_locked(self) -> list[dict]:
        out = []
        while self._last_applied < self._commit_index:
            self._last_applied += 1
            entry = self._entry_at_locked(self._last_applied)
            if entry is None:
                # already compacted into snapshot
                continue
            rec = {
                "index": int(entry.get("index", self._last_applied) or self._last_applied),
                "term": int(entry.get("term", 0) or 0),
                "command": dict(entry.get("command", {}) or {}),
            }
            self._apply_membership_command_locked(rec)
            self._applied_commands.append(rec)
            out.append(rec)
        self._maybe_compact_locked()
        return out

    def _apply_membership_command_locked(self, rec: dict) -> None:
        cmd = dict(rec.get("command", {}) or {})
        op = str(cmd.get("type", "") or "")
        if op == "__membership_add":
            nid = str(cmd.get("node_id", "") or "").strip()
            addr = str(cmd.get("addr", "") or "").strip()
            if nid and addr and nid != self.node_id and ":" in addr:
                self.peers[nid] = addr
                self._recompute_topology_locked()
        elif op == "__membership_remove":
            nid = str(cmd.get("node_id", "") or "").strip()
            if nid and nid != self.node_id and nid in self.peers:
                self.peers.pop(nid, None)
                self._recompute_topology_locked()

    def _maybe_compact_locked(self) -> None:
        if self._commit_index <= self._snapshot_last_index:
            return
        delta = self._commit_index - self._snapshot_last_index
        if delta < self.snapshot_threshold:
            return
        target = max(self._snapshot_last_index, self._commit_index - self.snapshot_keep_entries)
        if target <= self._snapshot_last_index:
            return
        target_term = self._log_term_at_locked(target)
        if target_term <= 0:
            return
        if target >= self._log_start_index:
            cut = target - self._log_start_index + 1
            if cut > 0:
                del self._log[:cut]
                self._log_start_index = target + 1
        self._snapshot_last_index = int(target)
        self._snapshot_last_term = int(target_term)
        floor_idx = self._snapshot_last_index + 1
        for nid in list(self._next_index.keys()):
            self._next_index[nid] = max(int(self._next_index.get(nid, floor_idx) or floor_idx), floor_idx)
            self._match_index[nid] = max(0, int(self._match_index.get(nid, 0) or 0))

    def _become_follower_locked(self, term: int, leader_id: str = "") -> None:
        if int(term) > int(self._term):
            self._term = int(term)
            self._voted_for = ""
        self._role = "follower"
        self._is_leader = False
        self._leader_id = str(leader_id or self._leader_id or "")
        self._last_leader_contact = time.monotonic()
        self._set_new_election_deadline_locked()

    def _become_leader_locked(self) -> None:
        self._recompute_topology_locked()
        self._role = "leader"
        self._is_leader = True
        self._leader_id = str(self.node_id)
        self._leader_epoch = max(int(self._leader_epoch), int(self._term))
        self._last_leader_contact = time.monotonic()
        next_idx = self._last_log_index_locked() + 1
        for nid in self._next_index.keys():
            self._next_index[nid] = int(next_idx)
        for nid in self._match_index.keys():
            self._match_index[nid] = 0

    def _start_rpc_server(self) -> None:
        host, port_s = self.listen_addr.rsplit(":", 1)
        host = host.strip()
        port = int(port_s)
        elector = self

        class _RaftTCPServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        class _RaftHandler(socketserver.StreamRequestHandler):
            def handle(self):
                raw = self.rfile.readline(65536)
                if not raw:
                    return
                try:
                    req = json.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    res = {"ok": False, "error": "invalid_json"}
                else:
                    res = elector._handle_rpc_request(req)
                out = (json.dumps(res, ensure_ascii=True) + "\n").encode("utf-8")
                self.wfile.write(out)

        self._server = _RaftTCPServer((host, port), _RaftHandler)
        self._server_thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name=f"RaftRPC-{self.node_id}",
        )
        self._server_thread.start()

    def _handle_rpc_request(self, req: dict) -> dict:
        rtype = str(dict(req or {}).get("type", "") or "")
        if rtype == "RequestVote":
            return self._handle_request_vote(req)
        if rtype == "AppendEntries":
            return self._handle_append_entries(req)
        if rtype == "InstallSnapshot":
            return self._handle_install_snapshot(req)
        return {"ok": False, "error": "unknown_type"}

    def _handle_request_vote(self, req: dict) -> dict:
        term = int(dict(req or {}).get("term", 0) or 0)
        candidate = str(dict(req or {}).get("candidate_id", "") or "")
        cand_last_idx = int(dict(req or {}).get("last_log_index", 0) or 0)
        cand_last_term = int(dict(req or {}).get("last_log_term", 0) or 0)
        with self._lock:
            if term < self._term:
                return {"ok": True, "term": int(self._term), "vote_granted": False}
            if term > self._term:
                self._become_follower_locked(term, leader_id="")
            grant = False
            my_last_idx = self._last_log_index_locked()
            my_last_term = self._log_term_at_locked(my_last_idx)
            up_to_date = (cand_last_term > my_last_term) or (
                cand_last_term == my_last_term and cand_last_idx >= my_last_idx
            )
            if self._voted_for in {"", candidate} and up_to_date:
                self._voted_for = candidate
                grant = True
                self._last_leader_contact = time.monotonic()
                self._set_new_election_deadline_locked()
            return {"ok": True, "term": int(self._term), "vote_granted": bool(grant)}

    def _handle_append_entries(self, req: dict) -> dict:
        term = int(dict(req or {}).get("term", 0) or 0)
        leader_id = str(dict(req or {}).get("leader_id", "") or "")
        prev_log_index = int(dict(req or {}).get("prev_log_index", 0) or 0)
        prev_log_term = int(dict(req or {}).get("prev_log_term", 0) or 0)
        leader_commit = int(dict(req or {}).get("leader_commit", 0) or 0)
        entries = list(dict(req or {}).get("entries", []) or [])
        applied = []
        with self._lock:
            if term < self._term:
                return {
                    "ok": True,
                    "term": int(self._term),
                    "success": False,
                    "match_index": int(self._last_log_index_locked()),
                }
            if term > self._term:
                self._become_follower_locked(term, leader_id=leader_id)
            else:
                self._role = "follower"
                self._is_leader = False
                self._leader_id = leader_id
                self._last_leader_contact = time.monotonic()
                self._set_new_election_deadline_locked()
            last_idx = self._last_log_index_locked()
            if prev_log_index < self._snapshot_last_index:
                return {
                    "ok": True,
                    "term": int(self._term),
                    "success": False,
                    "match_index": int(self._snapshot_last_index),
                }
            if prev_log_index > last_idx:
                return {"ok": True, "term": int(self._term), "success": False, "match_index": int(last_idx)}
            if prev_log_index > 0 and self._log_term_at_locked(prev_log_index) != prev_log_term:
                # conflicting prefix, leader should back off and retry from lower index
                return {
                    "ok": True,
                    "term": int(self._term),
                    "success": False,
                    "match_index": int(max(0, prev_log_index - 1)),
                }

            ins_idx = int(prev_log_index)
            for item in entries:
                ins_idx += 1
                eterm = int(dict(item or {}).get("term", 0) or 0)
                ecmd = dict(dict(item or {}).get("command", {}) or {})
                existing = self._entry_at_locked(ins_idx)
                if existing is not None:
                    cur_term = int(existing.get("term", 0) or 0)
                    if cur_term != eterm:
                        pos = self._entry_pos_locked(ins_idx)
                        if pos >= 0:
                            del self._log[pos:]
                        self._log.append({"index": ins_idx, "term": eterm, "command": ecmd})
                else:
                    self._log.append({"index": ins_idx, "term": eterm, "command": ecmd})
            if leader_commit > self._commit_index:
                self._commit_index = min(int(leader_commit), self._last_log_index_locked())
                applied = self._collect_apply_entries_locked()
            match_index = self._last_log_index_locked()
        _ = applied
        return {"ok": True, "term": int(term), "success": True, "match_index": int(match_index)}

    def _handle_install_snapshot(self, req: dict) -> dict:
        term = int(dict(req or {}).get("term", 0) or 0)
        leader_id = str(dict(req or {}).get("leader_id", "") or "")
        last_idx = int(dict(req or {}).get("last_included_index", 0) or 0)
        last_term = int(dict(req or {}).get("last_included_term", 0) or 0)
        with self._lock:
            if term < self._term:
                return {"ok": True, "term": int(self._term), "success": False}
            if term > self._term:
                self._become_follower_locked(term, leader_id=leader_id)
            else:
                self._role = "follower"
                self._is_leader = False
                self._leader_id = leader_id
                self._last_leader_contact = time.monotonic()
                self._set_new_election_deadline_locked()

            if last_idx > self._snapshot_last_index:
                if last_idx >= self._log_start_index:
                    cut = last_idx - self._log_start_index + 1
                    if cut > 0:
                        del self._log[:cut]
                self._log_start_index = max(self._log_start_index, last_idx + 1)
                self._snapshot_last_index = int(last_idx)
                self._snapshot_last_term = int(last_term)
            self._commit_index = max(self._commit_index, self._snapshot_last_index)
            self._last_applied = max(self._last_applied, self._snapshot_last_index)
        return {"ok": True, "term": int(term), "success": True, "match_index": int(last_idx)}

    def _send_rpc(self, addr: str, payload: dict) -> dict:
        host, port_s = str(addr).rsplit(":", 1)
        with socket.create_connection((host, int(port_s)), timeout=self.rpc_timeout_s) as sock:
            sock.sendall((json.dumps(payload, ensure_ascii=True) + "\n").encode("utf-8"))
            sock.settimeout(self.rpc_timeout_s)
            chunks = []
            while True:
                b = sock.recv(4096)
                if not b:
                    break
                chunks.append(b)
                if b"\n" in b:
                    break
            raw = b"".join(chunks).split(b"\n", 1)[0]
            if not raw:
                return {}
            try:
                return dict(json.loads(raw.decode("utf-8")) or {})
            except (ValueError, UnicodeDecodeError):
                return {}

    def _send_append_entries_to_peer(self, peer_id: str, peer_addr: str, term: int) -> tuple[bool, int, int]:
        with self._lock:
            next_idx = int(self._next_index.get(peer_id, self._last_log_index_locked() + 1) or 1)
            next_idx = max(1, next_idx)
            if next_idx <= self._snapshot_last_index:
                snap_payload = {
                    "type": "InstallSnapshot",
                    "term": int(term),
                    "leader_id": str(self.node_id),
                    "last_included_index": int(self._snapshot_last_index),
                    "last_included_term": int(self._snapshot_last_term),
                }
                try:
                    res = self._send_rpc(peer_addr, snap_payload)
                except Exception:
                    return False, int(term), 0
                rterm = int(dict(res or {}).get("term", 0) or 0)
                if rterm > term:
                    return False, int(rterm), 0
                if bool(dict(res or {}).get("success", False)):
                    match_idx = int(dict(res or {}).get("match_index", self._snapshot_last_index) or self._snapshot_last_index)
                    return True, int(term), int(match_idx)
                return False, int(term), int(self._snapshot_last_index)
            prev_idx = next_idx - 1
            prev_term = self._log_term_at_locked(prev_idx)
            leader_commit = int(self._commit_index)
            if next_idx <= self._last_log_index_locked():
                from_pos = max(0, self._entry_pos_locked(next_idx))
                to_pos = from_pos + self.append_batch_size
                slice_items = self._log[from_pos:to_pos]
            else:
                slice_items = []
            entries = [{"term": int(x.get("term", 0) or 0), "command": dict(x.get("command", {}) or {})} for x in slice_items]
        payload = {
            "type": "AppendEntries",
            "term": int(term),
            "leader_id": str(self.node_id),
            "prev_log_index": int(prev_idx),
            "prev_log_term": int(prev_term),
            "entries": entries,
            "leader_commit": int(leader_commit),
        }
        try:
            res = self._send_rpc(peer_addr, payload)
        except Exception:
            return False, int(term), 0
        rterm = int(dict(res or {}).get("term", 0) or 0)
        if rterm > term:
            return False, int(rterm), 0
        if bool(dict(res or {}).get("success", False)):
            match_idx = int(dict(res or {}).get("match_index", prev_idx + len(entries)) or (prev_idx + len(entries)))
            return True, int(term), int(match_idx)
        hint = int(dict(res or {}).get("match_index", max(0, prev_idx - 1)) or max(0, prev_idx - 1))
        return False, int(term), int(hint)

    def _advance_commit_index_locked(self, current_term: int) -> list[dict]:
        match_values = [self._last_log_index_locked()]
        match_values.extend(int(v or 0) for v in self._match_index.values())
        match_values = sorted(match_values)
        quorum_pos = max(0, len(match_values) - self.quorum)
        candidate = int(match_values[quorum_pos])
        if candidate > self._commit_index and self._log_term_at_locked(candidate) == int(current_term):
            self._commit_index = int(candidate)
        return self._collect_apply_entries_locked()

    def _send_heartbeats(self, term: int) -> int:
        acks = 1
        for peer_id, peer_addr in list(self.peer_items):
            ok, rterm, val = self._send_append_entries_to_peer(peer_id, peer_addr, term)
            if rterm > term:
                with self._lock:
                    self._become_follower_locked(rterm, leader_id="")
                return 0
            with self._lock:
                if ok:
                    self._match_index[peer_id] = max(int(self._match_index.get(peer_id, 0) or 0), int(val))
                    self._next_index[peer_id] = int(self._match_index[peer_id]) + 1
                    acks += 1
                else:
                    cur = int(self._next_index.get(peer_id, self._last_log_index_locked() + 1) or 1)
                    if val > 0:
                        self._next_index[peer_id] = max(self._snapshot_last_index + 1, int(val) + 1)
                    else:
                        self._next_index[peer_id] = max(self._snapshot_last_index + 1, cur - 1)
        with self._lock:
            _ = self._advance_commit_index_locked(current_term=term)
        return int(acks)

    def try_acquire(self) -> bool:
        with self._lock:
            if self._is_leader:
                term = int(self._term)
            else:
                term = 0
            deadline = float(self._election_deadline)
        if term > 0:
            acks = self._send_heartbeats(term)
            if acks >= self.quorum:
                return True
            with self._lock:
                self._become_follower_locked(self._term, leader_id="")
            return False

        now = time.monotonic()
        with self._lock:
            if now < deadline and self._leader_id:
                return False
            self._term += 1
            term = int(self._term)
            self._role = "candidate"
            self._is_leader = False
            self._leader_id = ""
            self._voted_for = str(self.node_id)
            last_log_index = self._last_log_index_locked()
            last_log_term = self._log_term_at_locked(last_log_index)
            self._set_new_election_deadline_locked()

        votes = 1
        payload = {
            "type": "RequestVote",
            "term": int(term),
            "candidate_id": str(self.node_id),
            "last_log_index": int(last_log_index),
            "last_log_term": int(last_log_term),
        }
        for peer_id, peer_addr in list(self.peer_items):
            _ = peer_id
            try:
                res = self._send_rpc(peer_addr, payload)
            except Exception:
                continue
            rterm = int(dict(res or {}).get("term", 0) or 0)
            if rterm > term:
                with self._lock:
                    self._become_follower_locked(rterm, leader_id="")
                return False
            if bool(dict(res or {}).get("vote_granted", False)):
                votes += 1

        with self._lock:
            if int(self._term) != term or self._role != "candidate":
                return False
            if votes >= self.quorum:
                self._become_leader_locked()
                term = int(self._term)
            else:
                self._role = "follower"
                self._is_leader = False
                self._set_new_election_deadline_locked()
                return False
        acks = self._send_heartbeats(term)
        if acks < self.quorum:
            with self._lock:
                self._become_follower_locked(self._term, leader_id="")
            return False
        return True

    def renew_once(self) -> bool:
        with self._lock:
            leader = bool(self._is_leader)
            term = int(self._term)
            deadline = float(self._election_deadline)
            now = time.monotonic()
        if leader:
            acks = self._send_heartbeats(term)
            if acks < self.quorum:
                with self._lock:
                    self._become_follower_locked(self._term, leader_id="")
                return False
            return True
        if now >= deadline:
            return bool(self.try_acquire())
        return False

    def start_renew_loop(self, interval_seconds: float = 0.25) -> None:
        iv = max(0.05, float(interval_seconds or 0.25))
        self._stop_evt.clear()

        def _loop():
            while not self._stop_evt.wait(iv):
                try:
                    _ = self.renew_once()
                except Exception:
                    continue

        self._renew_thread = threading.Thread(target=_loop, daemon=True, name=f"RaftRenew-{self.node_id}")
        self._renew_thread.start()

    def is_leader(self) -> bool:
        with self._lock:
            return bool(self._is_leader)

    @property
    def leader_epoch(self) -> int:
        with self._lock:
            return int(self._leader_epoch or 0)

    def replicate_command(self, command: dict, *, wait_commit_s: float = 2.0) -> bool:
        with self._lock:
            if not self._is_leader:
                return False
            term = int(self._term)
            index = self._append_entry_locked(term=term, command=dict(command or {}))
        deadline = time.monotonic() + max(0.05, float(wait_commit_s or 2.0))
        while time.monotonic() < deadline and not self._stop_evt.is_set():
            _ = self._send_heartbeats(term)
            with self._lock:
                if self._commit_index >= index:
                    return True
                if not self._is_leader or int(self._term) != term:
                    return False
            time.sleep(max(0.01, float(self.heartbeat_interval_ms) / 4000.0))
        with self._lock:
            return bool(self._commit_index >= index)

    def get_applied_commands(self) -> list[dict]:
        with self._lock:
            return [dict(x) for x in list(self._applied_commands)]

    def add_peer(self, node_id: str, addr: str, *, wait_commit_s: float = 3.0) -> bool:
        nid = str(node_id or "").strip()
        endpoint = str(addr or "").strip()
        if not nid or not endpoint or ":" not in endpoint or nid == self.node_id:
            return False
        return self.replicate_command(
            {"type": "__membership_add", "node_id": nid, "addr": endpoint},
            wait_commit_s=wait_commit_s,
        )

    def remove_peer(self, node_id: str, *, wait_commit_s: float = 3.0) -> bool:
        nid = str(node_id or "").strip()
        if not nid or nid == self.node_id:
            return False
        return self.replicate_command(
            {"type": "__membership_remove", "node_id": nid},
            wait_commit_s=wait_commit_s,
        )

    def release(self) -> None:
        with self._lock:
            self._is_leader = False
            self._role = "follower"
            self._leader_id = ""
            self._set_new_election_deadline_locked()

    def stop(self) -> None:
        self._stop_evt.set()
        th = self._renew_thread
        if th is not None:
            th.join(timeout=2.0)
        self.release()
        if self._server is not None:
            try:
                self._server.shutdown()
            except Exception:
                pass
            try:
                self._server.server_close()
            except Exception:
                pass
        sth = self._server_thread
        if sth is not None:
            sth.join(timeout=2.0)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "mode": "raft",
                "node_id": str(self.node_id),
                "leader_id": str(self._leader_id or ""),
                "is_leader": 1 if self._is_leader else 0,
                "leader_epoch": int(self._leader_epoch or 0),
                "term": int(self._term or 0),
                "role": str(self._role or "follower"),
                "listen_addr": str(self.listen_addr),
                "peers": [f"{nid}@{addr}" for nid, addr in list(self.peer_items)],
                "peer_count": int(self.peer_count),
                "quorum": int(self.quorum),
                "log_len": int(len(self._log)),
                "last_log_index": int(self._last_log_index_locked()),
                "commit_index": int(self._commit_index),
                "last_applied": int(self._last_applied),
                "snapshot_last_index": int(self._snapshot_last_index),
                "snapshot_last_term": int(self._snapshot_last_term),
            }
