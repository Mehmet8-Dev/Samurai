#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import yaml


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Mamba-2 v1 offline trainer (scaffold).")
    p.add_argument("--config", type=str, default="training/configs/mamba2_v1.yaml")
    p.add_argument("--train-parquet", type=str, default="")
    p.add_argument("--val-parquet", type=str, default="")
    p.add_argument("--out-dir", type=str, default="artifacts/mamba2")
    return p


def main() -> int:
    args = build_parser().parse_args()
    cfg_path = Path(args.config)
    if not cfg_path.exists():
        raise SystemExit(f"Config not found: {cfg_path}")
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    os.makedirs(args.out_dir, exist_ok=True)
    summary = {
        "status": "scaffold",
        "config": cfg,
        "train_parquet": args.train_parquet,
        "val_parquet": args.val_parquet,
    }
    out = Path(args.out_dir) / "train_summary.json"
    out.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Training scaffold completed: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

