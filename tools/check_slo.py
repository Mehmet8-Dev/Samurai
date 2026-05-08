#!/usr/bin/env python3
"""Check SLO conformance from a summary JSON report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="SLO checker")
    parser.add_argument("--input", required=True, help="Summary JSON path")
    parser.add_argument("--min-job-success-rate", type=float, default=99.0)
    parser.add_argument("--max-control-api-error-rate", type=float, default=1.0)
    args = parser.parse_args()

    p = Path(args.input)
    if not p.is_file():
        raise SystemExit(f"input not found: {p}")
    obj = json.loads(p.read_text(encoding="utf-8"))

    job_success = float(obj.get("job_success_rate_pct", 0.0) or 0.0)
    control_err = float(obj.get("control_api_error_rate_pct", 100.0) or 100.0)

    errs = []
    if job_success < float(args.min_job_success_rate):
        errs.append(f"job_success_rate_pct={job_success} < {args.min_job_success_rate}")
    if control_err > float(args.max_control_api_error_rate):
        errs.append(f"control_api_error_rate_pct={control_err} > {args.max_control_api_error_rate}")

    if errs:
        print("[slo-check] FAIL")
        for e in errs:
            print(f" - {e}")
        return 1

    print("[slo-check] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
