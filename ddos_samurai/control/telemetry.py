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
        per_shard: dict[str, dict] = {}
        worker_rollup: dict[str, dict] = {}
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
                srec = per_shard.setdefault(
                    sid,
                    {
                        "shard_id": sid,
                        "worker_id": wid,
                        "sent": 0,
                        "errors": 0,
                        "progress": 0,
                        "duration_s_max": 0.0,
                        "last_status": "",
                        "last_exitcode": 0,
                        "updates": 0,
                    },
                )
                srec["worker_id"] = wid or str(srec.get("worker_id", ""))
                srec["sent"] = max(int(srec.get("sent", 0) or 0), int(item.get("sent", 0) or 0))
                srec["errors"] = max(int(srec.get("errors", 0) or 0), int(item.get("errors", 0) or 0))
                srec["progress"] = max(int(srec.get("progress", 0) or 0), int(item.get("progress", 0) or 0))
                srec["duration_s_max"] = max(
                    float(srec.get("duration_s_max", 0.0) or 0.0),
                    float(item.get("duration_s", 0.0) or 0.0),
                )
                srec["last_status"] = str(item.get("status", srec.get("last_status", "")) or srec.get("last_status", ""))
                srec["last_exitcode"] = int(item.get("exitcode", srec.get("last_exitcode", 0)) or 0)
                srec["updates"] = int(srec.get("updates", 0) or 0) + 1
            if wid:
                wrec = worker_rollup.setdefault(
                    wid,
                    {"worker_id": wid, "sent": 0, "errors": 0, "progress": 0, "shard_ids": set(), "updates": 0},
                )
                wrec["sent"] = max(int(wrec.get("sent", 0) or 0), int(item.get("sent", 0) or 0))
                wrec["errors"] = max(int(wrec.get("errors", 0) or 0), int(item.get("errors", 0) or 0))
                wrec["progress"] = max(int(wrec.get("progress", 0) or 0), int(item.get("progress", 0) or 0))
                if sid:
                    wrec["shard_ids"].add(sid)
                wrec["updates"] = int(wrec.get("updates", 0) or 0) + 1

        per_shard_list = sorted(
            per_shard.values(),
            key=lambda x: (
                -int(x.get("errors", 0) or 0),
                -int(x.get("last_exitcode", 0) or 0),
                str(x.get("shard_id", "")),
            ),
        )
        top_error_shards = per_shard_list[:10]
        worker_rollup_list = []
        for w in worker_rollup.values():
            worker_rollup_list.append(
                {
                    "worker_id": str(w.get("worker_id", "")),
                    "sent": int(w.get("sent", 0) or 0),
                    "errors": int(w.get("errors", 0) or 0),
                    "progress": int(w.get("progress", 0) or 0),
                    "shard_count": len(w.get("shard_ids", set()) or set()),
                    "shard_ids": sorted(list(w.get("shard_ids", set()) or set())),
                    "updates": int(w.get("updates", 0) or 0),
                }
            )
        worker_rollup_list.sort(key=lambda x: (-int(x["errors"]), -int(x["sent"]), x["worker_id"]))
        return {
            "sent": sent,
            "errors": errors,
            "progress": progress,
            "shards": len(shards) if shards else len(self._items),
            "workers": len(workers),
            "worker_ids": sorted(workers),
            "shard_ids": sorted(shards),
            "numeric_totals": dict(numeric_totals),
            "per_shard": per_shard_list,
            "top_error_shards": top_error_shards,
            "worker_rollup": worker_rollup_list,
            "items": list(self._items),
        }
