"""Kubernetes autoscale controller (distributed master side)."""

from __future__ import annotations

import time


class K8sAutoscaleController:
    def __init__(
        self,
        *,
        enabled: bool = False,
        namespace: str = "default",
        target_kind: str = "deployment",
        target_name: str = "",
        min_replicas: int = 1,
        max_replicas: int = 100,
        step: int = 1,
        cooldown_s: float = 15.0,
        shards_per_worker: int = 4,
        idle_scale_down_s: float = 60.0,
    ) -> None:
        self.enabled = bool(enabled)
        self.namespace = str(namespace or "default").strip() or "default"
        self.target_kind = str(target_kind or "deployment").strip().lower() or "deployment"
        self.target_name = str(target_name or "").strip()
        self.min_replicas = max(1, int(min_replicas or 1))
        self.max_replicas = max(self.min_replicas, int(max_replicas or self.min_replicas))
        self.step = max(1, int(step or 1))
        self.cooldown_s = max(1.0, float(cooldown_s or 15.0))
        self.shards_per_worker = max(1, int(shards_per_worker or 4))
        self.idle_scale_down_s = max(5.0, float(idle_scale_down_s or 60.0))
        self._last_scale_ts = 0.0
        self._last_busy_ts = time.time()
        self._current_replicas = self.min_replicas
        self._api = None
        self._init_err = ""

        if self.enabled and self.target_name:
            self._init_client()

    def _init_client(self) -> None:
        try:
            from kubernetes import client, config
        except Exception as exc:
            self._init_err = f"kubernetes package missing: {exc}"
            self.enabled = False
            return
        try:
            try:
                config.load_incluster_config()
            except Exception:
                config.load_kube_config()
            self._api = client.AppsV1Api()
        except Exception as exc:
            self._init_err = f"k8s client init failed: {exc}"
            self.enabled = False

    def _read_replicas(self) -> int:
        if self._api is None:
            return int(self._current_replicas)
        try:
            if self.target_kind == "statefulset":
                obj = self._api.read_namespaced_stateful_set_scale(self.target_name, self.namespace)
            else:
                obj = self._api.read_namespaced_deployment_scale(self.target_name, self.namespace)
            rep = int(getattr(getattr(obj, "spec", None), "replicas", self._current_replicas) or self._current_replicas)
            self._current_replicas = rep
            return rep
        except Exception:
            return int(self._current_replicas)

    def _patch_replicas(self, replicas: int) -> bool:
        if self._api is None:
            self._current_replicas = int(replicas)
            self._last_scale_ts = time.time()
            return True
        body = {"spec": {"replicas": int(replicas)}}
        try:
            if self.target_kind == "statefulset":
                self._api.patch_namespaced_stateful_set_scale(self.target_name, self.namespace, body)
            else:
                self._api.patch_namespaced_deployment_scale(self.target_name, self.namespace, body)
            self._current_replicas = int(replicas)
            self._last_scale_ts = time.time()
            return True
        except Exception:
            return False

    def _desired(self, *, pending_shards: int, inflight_shards: int, workers_count: int) -> int:
        busy = int(pending_shards) + int(inflight_shards)
        if busy > 0:
            self._last_busy_ts = time.time()
            needed_workers = max(1, (busy + self.shards_per_worker - 1) // self.shards_per_worker)
            needed_workers = max(needed_workers, int(workers_count or 0))
            return min(self.max_replicas, max(self.min_replicas, needed_workers))
        if (time.time() - self._last_busy_ts) >= self.idle_scale_down_s:
            return self.min_replicas
        return max(self.min_replicas, min(self.max_replicas, int(workers_count or self.min_replicas)))

    def maybe_scale(self, *, pending_shards: int, inflight_shards: int, workers_count: int) -> dict:
        if not self.enabled or not self.target_name:
            return {"enabled": False, "changed": False, "reason": self._init_err or "disabled"}
        now = time.time()
        if (now - self._last_scale_ts) < self.cooldown_s:
            return {"enabled": True, "changed": False, "reason": "cooldown"}
        cur = self._read_replicas()
        des = self._desired(
            pending_shards=int(pending_shards or 0),
            inflight_shards=int(inflight_shards or 0),
            workers_count=int(workers_count or 0),
        )
        if des == cur:
            return {"enabled": True, "changed": False, "current": cur, "desired": des}
        if des > cur:
            nxt = min(des, cur + self.step)
        else:
            nxt = max(des, cur - self.step)
        ok = self._patch_replicas(nxt)
        return {
            "enabled": True,
            "changed": bool(ok),
            "current": cur,
            "desired": des,
            "applied": int(nxt) if ok else cur,
            "ok": bool(ok),
        }
