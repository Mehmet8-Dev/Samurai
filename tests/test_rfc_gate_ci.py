#!/usr/bin/env python3
"""RFC report quality gate.

Fails with non-zero exit when the RFC negative (or generic RFC) report does not
meet required thresholds.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Validate RFC report against strict CI thresholds.")
    p.add_argument(
        "--report",
        default="artifacts/rfc_negative_report.json",
        help="Path to RFC report JSON (default: artifacts/rfc_negative_report.json)",
    )
    p.add_argument(
        "--min-score",
        type=float,
        default=100.0,
        help="Minimum accepted score (default: 100.0)",
    )
    p.add_argument(
        "--require-all-passed",
        action="store_true",
        default=True,
        help="Require passed == total (default: true)",
    )
    p.add_argument(
        "--critical-check",
        action="append",
        default=[],
        help="Critical check name that must be passed (repeatable).",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report_path = Path(args.report)

    if not report_path.exists():
        print(f"[RFC-GATE] FAIL: report not found: {report_path}")
        return 2

    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[RFC-GATE] FAIL: cannot parse JSON: {report_path} ({exc})")
        return 2

    score = _to_float(data.get("score", 0.0))
    passed = _to_int(data.get("passed", 0))
    total = _to_int(data.get("total", 0))
    checks = data.get("checks") or []

    failed_reasons: list[str] = []

    if score < float(args.min_score):
        failed_reasons.append(f"score<{args.min_score} (actual={score})")

    if args.require_all_passed and total > 0 and passed != total:
        failed_reasons.append(f"passed!=total ({passed}!={total})")

    check_map: dict[str, bool] = {}
    for item in checks:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "") or "").strip()
        if not name:
            continue
        check_map[name] = bool(item.get("passed", False))

    critical = list(args.critical_check or [])
    if not critical:
        critical = [
            "checksum_invalid_detected",
            "tcp_data_offset_invalid_detected",
            "total_length_mismatch_detected",
            "ttl_zero_detected",
            "udp_length_mismatch_detected",
        ]

    for name in critical:
        if name not in check_map:
            failed_reasons.append(f"missing_critical_check:{name}")
            continue
        if not check_map[name]:
            failed_reasons.append(f"critical_failed:{name}")

    if failed_reasons:
        print("[RFC-GATE] FAIL")
        print(f"  report={report_path}")
        print(f"  score={score} passed={passed}/{total}")
        for r in failed_reasons:
            print(f"  - {r}")
        return 1

    print("[RFC-GATE] PASS")
    print(f"  report={report_path}")
    print(f"  score={score} passed={passed}/{total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
