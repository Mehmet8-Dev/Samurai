"""Telemetry aggregation for distributed mode."""

from __future__ import annotations


class DistributedAggregator:
    def __init__(self) -> None:
        self._items: list[dict] = []

    def add(self, item: dict) -> None:
        self._items.append(dict(item or {}))

    def snapshot(self) -> dict:
        sent = 0
        errors = 0
        progress = 0
        workers = set()
        shards = set()
        numeric_totals: dict[str, float] = {}
        for item in self._items:
            sent += int(item.get("sent", 0) or 0)
            errors += int(item.get("errors", 0) or 0)
            progress += int(item.get("progress", 0) or 0)
            for key, value in dict(item or {}).items():
                if isinstance(value, bool):
                    continue
                if isinstance(value, (int, float)):
                    numeric_totals[str(key)] = float(numeric_totals.get(str(key), 0.0) + float(value))
            wid = str(item.get("worker_id", "") or "").strip()
            sid = str(item.get("shard_id", "") or "").strip()
            if wid:
                workers.add(wid)
            if sid:
                shards.add(sid)
        return {
            "sent": sent,
            "errors": errors,
            "progress": progress,
            "shards": len(shards) if shards else len(self._items),
            "workers": len(workers),
            "worker_ids": sorted(workers),
            "shard_ids": sorted(shards),
            "numeric_totals": dict(numeric_totals),
            "items": list(self._items),
        }
