#!/usr/bin/env python3
"""Verify append-only RBAC audit hash chain."""

from __future__ import annotations

import argparse
import sys

from ddos_samurai.control.server import MasterControlServer


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify RBAC audit chain integrity")
    parser.add_argument("path", help="Audit JSONL path")
    args = parser.parse_args()
    ok, msg = MasterControlServer.verify_rbac_audit_chain(args.path)
    if ok:
        print(f"[verify_audit_chain] OK: {msg}")
        return 0
    print(f"[verify_audit_chain] FAIL: {msg}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
