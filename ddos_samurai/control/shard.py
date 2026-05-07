"""Shard split helpers for distributed jobs."""

from __future__ import annotations


def _worker_weight(capabilities: dict | None) -> int:
    caps = dict(capabilities or {})
    weight = 1
    if str(caps.get("gpu_available", "")).strip().lower() in {"1", "true", "yes"}:
        weight += 2
    if str(caps.get("xdp_available", "")).strip().lower() in {"1", "true", "yes"}:
        weight += 1
    raw_score = caps.get("capacity_score")
    try:
        if raw_score is not None:
            weight = max(1, int(raw_score))
    except (TypeError, ValueError):
        pass
    return max(1, int(weight))


def split_job_to_shards(
    total_count: int,
    worker_ids: list[str],
    strategy: str = "equal",
    worker_capabilities: dict[str, dict] | None = None,
    target_region: str = "",
) -> list[dict]:
    workers = [w for w in worker_ids if str(w).strip()]
    if not workers:
        return []
    total = max(0, int(total_count or 0))
    mode = str(strategy or "equal").strip().lower()
    out = []
    if mode == "capability":
        caps_map = dict(worker_capabilities or {})
        weights = [_worker_weight(caps_map.get(wid)) for wid in workers]
        total_weight = max(1, sum(weights))
        counts = [(total * w) // total_weight for w in weights]
        used = sum(counts)
        rem = total - used
        for i in range(rem):
            counts[i % len(counts)] += 1
        for idx, wid in enumerate(workers):
            out.append({"shard_id": f"shard-{idx+1}", "worker_id": wid, "packet_count": int(counts[idx])})
        return out
    if mode == "region":
        caps_map = dict(worker_capabilities or {})
        tr = str(target_region or "").strip().lower()
        weights = []
        for wid in workers:
            caps = dict(caps_map.get(wid) or {})
            wr = str(caps.get("region", "") or "").strip().lower()
            base = _worker_weight(caps)
            if tr and wr == tr:
                base += 5
            elif tr and wr and wr != tr:
                base = max(1, base - 1)
            weights.append(base)
        total_weight = max(1, sum(weights))
        counts = [(total * w) // total_weight for w in weights]
        used = sum(counts)
        rem = total - used
        for i in range(rem):
            counts[i % len(counts)] += 1
        for idx, wid in enumerate(workers):
            out.append({"shard_id": f"shard-{idx+1}", "worker_id": wid, "packet_count": int(counts[idx])})
        return out

    base = total // len(workers)
    rem = total % len(workers)
    for idx, wid in enumerate(workers):
        count = base + (1 if idx < rem else 0)
        out.append({"shard_id": f"shard-{idx+1}", "worker_id": wid, "packet_count": int(count)})
    return out
