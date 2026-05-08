#!/usr/bin/env bash
set -euo pipefail

ARTIFACT="${1:-}"
if [[ -z "$ARTIFACT" || ! -f "$ARTIFACT" ]]; then
  echo "usage: $0 <artifact-file>" >&2
  exit 2
fi

if command -v cosign >/dev/null 2>&1; then
  cosign sign-blob --yes "$ARTIFACT" --output-signature "${ARTIFACT}.sig" --output-certificate "${ARTIFACT}.crt"
  echo "[sign] cosign signature generated"
  exit 0
fi

sha256sum "$ARTIFACT" | tee "${ARTIFACT}.sha256"
echo "[sign] cosign missing; sha256 checksum generated"
