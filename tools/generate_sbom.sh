#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-artifacts/sbom}"
mkdir -p "$OUT_DIR"

if command -v syft >/dev/null 2>&1; then
  syft dir:. -o cyclonedx-json > "$OUT_DIR/sbom.cdx.json"
  syft dir:. -o spdx-json > "$OUT_DIR/sbom.spdx.json"
  echo "[sbom] generated with syft -> $OUT_DIR"
  exit 0
fi

# Fallback: lightweight Python dependency SBOM
python - <<'PY' > "$OUT_DIR/sbom.fallback.json"
from __future__ import annotations
import json
from importlib import metadata

rows = []
for d in sorted(metadata.distributions(), key=lambda x: str(x.metadata.get("Name", "")).lower()):
    name = str(d.metadata.get("Name", "") or "").strip()
    ver = str(getattr(d, "version", "") or "").strip()
    if not name:
        continue
    rows.append({"name": name, "version": ver})
print(json.dumps({"schema": "samurai.sbom.fallback.v1", "packages": rows}, indent=2, sort_keys=True))
PY

echo "[sbom] syft missing, fallback generated -> $OUT_DIR/sbom.fallback.json"
