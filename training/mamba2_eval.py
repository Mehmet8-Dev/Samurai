#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Mamba-2 v1 evaluation scaffold.")
    p.add_argument("--checkpoint", type=str, required=True)
    p.add_argument("--eval-parquet", type=str, default="")
    return p


def main() -> int:
    args = build_parser().parse_args()
    ckpt = Path(args.checkpoint)
    result = {
        "checkpoint_exists": ckpt.exists(),
        "checkpoint": str(ckpt),
        "eval_parquet": str(args.eval_parquet or ""),
        "status": "ok" if ckpt.exists() else "missing_checkpoint",
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if ckpt.exists() else 2


if __name__ == "__main__":
    raise SystemExit(main())

