#!/usr/bin/env python3
"""Simple capacity planning helper for enterprise deployments."""

from __future__ import annotations

import argparse
import json
import math


def main() -> int:
    parser = argparse.ArgumentParser(description="Capacity planner")
    parser.add_argument("--target-rps", type=float, required=True)
    parser.add_argument("--worker-rps", type=float, required=True)
    parser.add_argument("--ha-factor", type=float, default=1.3)
    parser.add_argument("--min-workers", type=int, default=3)
    args = parser.parse_args()

    target_rps = max(0.0, float(args.target_rps))
    worker_rps = max(1.0, float(args.worker_rps))
    ha_factor = max(1.0, float(args.ha_factor))

    baseline = int(math.ceil(target_rps / worker_rps))
    recommended = max(int(args.min_workers), int(math.ceil(baseline * ha_factor)))

    out = {
        "schema": "samurai.capacity.plan.v1",
        "target_rps": target_rps,
        "worker_rps": worker_rps,
        "baseline_workers": baseline,
        "ha_factor": ha_factor,
        "recommended_workers": recommended,
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
