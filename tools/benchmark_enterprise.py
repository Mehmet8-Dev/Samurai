#!/usr/bin/env python3
"""Run enterprise benchmark profile set and produce normalized summary."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Enterprise benchmark runner")
    parser.add_argument("--out", default="artifacts/enterprise_benchmark_summary.json")
    parser.add_argument("--python", default="python")
    args = parser.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        args.python,
        "-m",
        "pytest",
        "tests/test_benchmark_ci.py",
        "tests/test_benchmark_l7_ci.py",
        "-q",
        "-rs",
    ]
    rc = subprocess.run(cmd, check=False).returncode

    summary = {
        "schema": "samurai.enterprise.benchmark.summary.v1",
        "pytest_return_code": int(rc),
        "job_success_rate_pct": 100.0 if rc == 0 else 0.0,
        "control_api_error_rate_pct": 0.0 if rc == 0 else 100.0,
    }
    out_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(str(out_path))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
