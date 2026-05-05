"""Shard split helpers for distributed jobs."""

from __future__ import annotations


def split_job_to_shards(total_count: int, worker_ids: list[str]) -> list[dict]:
    workers = [w for w in worker_ids if str(w).strip()]
    if not workers:
        return []
    total = max(0, int(total_count or 0))
    base = total // len(workers)
    rem = total % len(workers)
    out = []
    for idx, wid in enumerate(workers):
        count = base + (1 if idx < rem else 0)
        out.append({"shard_id": f"shard-{idx+1}", "worker_id": wid, "packet_count": count})
    return out
