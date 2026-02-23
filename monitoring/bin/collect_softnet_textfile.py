#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Dict, List, Tuple


def _read_softnet_stat(path: str = "/proc/net/softnet_stat") -> List[List[int]]:
    rows: List[List[int]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Fields are hex numbers; kernel versions may append more fields over time.
            parts = [p for p in line.split() if p]
            vals: List[int] = []
            for p in parts:
                try:
                    vals.append(int(p, 16))
                except Exception:
                    # Skip non-hex tokens; best-effort.
                    pass
            if vals:
                rows.append(vals)
    return rows


def _sum_fields(rows: List[List[int]]) -> Dict[str, int]:
    # Based on Linux /proc/net/softnet_stat documentation:
    # 0: processed, 1: dropped, 2: time_squeeze, 3: cpu_collision, 4..: may exist
    out = {
        "processed": 0,
        "dropped": 0,
        "time_squeeze": 0,
        "cpu_collision": 0,
    }
    for r in rows:
        if len(r) > 0:
            out["processed"] += int(r[0])
        if len(r) > 1:
            out["dropped"] += int(r[1])
        if len(r) > 2:
            out["time_squeeze"] += int(r[2])
        if len(r) > 3:
            out["cpu_collision"] += int(r[3])
    return out


def _prom(lines: List[str]) -> str:
    return "\n".join(lines) + "\n"


def build_softnet_prom(prefix: str = "samurai") -> Tuple[str, Dict[str, int]]:
    rows = _read_softnet_stat()
    sums = _sum_fields(rows)

    p = prefix.strip() or "samurai"
    lines = [
        "# HELP samurai_softnet_processed_total Packets processed by the softnet layer (sum across CPUs).",
        "# TYPE samurai_softnet_processed_total counter",
        f"{p}_softnet_processed_total {sums['processed']}",
        "# HELP samurai_softnet_dropped_total Packets dropped by the softnet layer (sum across CPUs).",
        "# TYPE samurai_softnet_dropped_total counter",
        f"{p}_softnet_dropped_total {sums['dropped']}",
        "# HELP samurai_softnet_time_squeeze_total softnet time_squeeze counter (sum across CPUs).",
        "# TYPE samurai_softnet_time_squeeze_total counter",
        f"{p}_softnet_time_squeeze_total {sums['time_squeeze']}",
        "# HELP samurai_softnet_cpu_collision_total softnet cpu_collision counter (sum across CPUs).",
        "# TYPE samurai_softnet_cpu_collision_total counter",
        f"{p}_softnet_cpu_collision_total {sums['cpu_collision']}",
    ]
    return _prom(lines), sums


def main() -> int:
    ap = argparse.ArgumentParser(description="Write /proc/net/softnet_stat counters to a node-exporter textfile.")
    ap.add_argument("--out", required=True, help="Output .prom file path (textfile collector directory).")
    ap.add_argument("--prefix", default="samurai", help="Metric prefix (default: samurai).")
    args = ap.parse_args()

    payload, _sums = build_softnet_prom(prefix=str(args.prefix))
    out_path = Path(str(args.out))
    out_path.parent.mkdir(parents=True, exist_ok=True)

    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    tmp.write_text(payload, encoding="utf-8")
    tmp.replace(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

