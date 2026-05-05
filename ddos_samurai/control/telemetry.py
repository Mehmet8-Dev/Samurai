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
        for item in self._items:
            sent += int(item.get("sent", 0) or 0)
            errors += int(item.get("errors", 0) or 0)
        return {
            "sent": sent,
            "errors": errors,
            "shards": len(self._items),
            "items": list(self._items),
        }
