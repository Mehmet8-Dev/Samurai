"""Cross-region multi-master coordination helpers."""

from __future__ import annotations

import json
import time


class RedisMultiMasterCoordinator:
    def __init__(
        self,
        *,
        enabled: bool = False,
        redis_url: str = "redis://127.0.0.1:6379/0",
        namespace: str = "default",
        region_id: str = "",
        node_id: str = "",
        heartbeat_ttl_s: int = 15,
    ) -> None:
        self.enabled = bool(enabled)
        self.redis_url = str(redis_url or "redis://127.0.0.1:6379/0").strip()
        self.namespace = str(namespace or "default").strip() or "default"
        self.region_id = str(region_id or "").strip().lower()
        self.node_id = str(node_id or "").strip() or "master"
        self.heartbeat_ttl_s = max(5, int(heartbeat_ttl_s or 15))
        self._redis = None
        self._err = ""
        if self.enabled:
            self._init_client()

    def _init_client(self) -> None:
        try:
            import redis  # type: ignore
        except Exception as exc:
            self.enabled = False
            self._err = f"redis package missing: {exc}"
            return
        try:
            self._redis = redis.from_url(self.redis_url, decode_responses=True)
            _ = self._redis.ping()
        except Exception as exc:
            self.enabled = False
            self._err = f"redis connect failed: {exc}"

    def _k_region_hb(self, region_id: str, node_id: str) -> str:
        return f"samurai:mm:{self.namespace}:region:{region_id}:node:{node_id}:hb"

    def _k_region_latest(self, region_id: str) -> str:
        return f"samurai:mm:{self.namespace}:region:{region_id}:latest"

    def _k_events(self) -> str:
        return f"samurai:mm:{self.namespace}:events"

    def _k_region_jobs(self, region_id: str) -> str:
        return f"samurai:mm:{self.namespace}:jobs:{region_id}"

    def _now_ms(self) -> int:
        return int(time.time() * 1000)

    def heartbeat(self, payload: dict | None = None) -> bool:
        if not self.enabled or self._redis is None or not self.region_id:
            return False
        item = {"ts_ms": self._now_ms(), "region_id": self.region_id, "node_id": self.node_id}
        item.update(dict(payload or {}))
        try:
            self._redis.setex(
                self._k_region_hb(self.region_id, self.node_id),
                int(self.heartbeat_ttl_s),
                json.dumps(item, ensure_ascii=True),
            )
            return True
        except Exception:
            return False

    def publish_snapshot(self, snapshot: dict) -> bool:
        if not self.enabled or self._redis is None or not self.region_id:
            return False
        item = {"ts_ms": self._now_ms(), "region_id": self.region_id, "node_id": self.node_id, "snapshot": dict(snapshot or {})}
        try:
            self._redis.set(self._k_region_latest(self.region_id), json.dumps(item, ensure_ascii=True), ex=int(max(10, self.heartbeat_ttl_s * 3)))
            return True
        except Exception:
            return False

    def publish_event(self, event: dict) -> bool:
        if not self.enabled or self._redis is None:
            return False
        item = {"ts_ms": self._now_ms(), "region_id": self.region_id, "node_id": self.node_id, "event": dict(event or {})}
        try:
            p = self._redis.pipeline()
            p.lpush(self._k_events(), json.dumps(item, ensure_ascii=True))
            p.ltrim(self._k_events(), 0, 999)
            p.execute()
            return True
        except Exception:
            return False

    def enqueue_job(self, region_id: str, job: dict) -> bool:
        if not self.enabled or self._redis is None:
            return False
        rid = str(region_id or "").strip().lower()
        if not rid:
            return False
        item = {"ts_ms": self._now_ms(), "from_region": self.region_id, "to_region": rid, "job": dict(job or {})}
        try:
            p = self._redis.pipeline()
            p.rpush(self._k_region_jobs(rid), json.dumps(item, ensure_ascii=True))
            p.ltrim(self._k_region_jobs(rid), -5000, -1)
            p.execute()
            return True
        except Exception:
            return False

    def dequeue_jobs(self, *, max_count: int = 3) -> list[dict]:
        if not self.enabled or self._redis is None or not self.region_id:
            return []
        out: list[dict] = []
        n = max(0, int(max_count or 0))
        if n <= 0:
            return out
        key = self._k_region_jobs(self.region_id)
        try:
            for _ in range(n):
                raw = self._redis.lpop(key)
                if raw is None:
                    break
                try:
                    item = json.loads(str(raw))
                except (TypeError, ValueError):
                    continue
                job = dict((dict(item or {})).get("job") or {})
                if not job:
                    continue
                job["_mmr_delegated_from"] = str((dict(item or {})).get("from_region", "") or "")
                out.append(job)
        except Exception:
            return out
        return out

    def regions_state(self) -> list[dict]:
        if not self.enabled or self._redis is None:
            return []
        pattern = f"samurai:mm:{self.namespace}:region:*:node:*:hb"
        out = []
        try:
            keys = list(self._redis.scan_iter(match=pattern, count=200))
        except Exception:
            return out
        for key in keys:
            try:
                raw = self._redis.get(key)
                if not raw:
                    continue
                out.append(dict(json.loads(str(raw)) or {}))
            except (TypeError, ValueError):
                continue
            except Exception:
                continue
        out.sort(key=lambda x: (str(x.get("region_id", "")), str(x.get("node_id", ""))))
        return out

    def latest_region_snapshots(self) -> list[dict]:
        if not self.enabled or self._redis is None:
            return []
        pattern = f"samurai:mm:{self.namespace}:region:*:latest"
        out = []
        try:
            keys = list(self._redis.scan_iter(match=pattern, count=200))
        except Exception:
            return out
        for key in keys:
            try:
                raw = self._redis.get(key)
                if not raw:
                    continue
                out.append(dict(json.loads(str(raw)) or {}))
            except (TypeError, ValueError):
                continue
            except Exception:
                continue
        out.sort(key=lambda x: str(x.get("region_id", "")))
        return out

    def snapshot(self) -> dict:
        return {
            "enabled": bool(self.enabled),
            "namespace": self.namespace,
            "region_id": self.region_id,
            "node_id": self.node_id,
            "heartbeat_ttl_s": int(self.heartbeat_ttl_s),
            "error": str(self._err or ""),
        }
