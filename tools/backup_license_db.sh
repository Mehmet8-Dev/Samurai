#!/usr/bin/env bash
set -euo pipefail

OUT_FILE="${1:-artifacts/backups/license_db_$(date -u +%Y%m%dT%H%M%SZ).sql.gz}"
DB_URL="${LICENSE_DATABASE_URL:-}"
mkdir -p "$(dirname "$OUT_FILE")"

if [[ -z "$DB_URL" ]]; then
  echo "LICENSE_DATABASE_URL is required" >&2
  exit 2
fi

if command -v pg_dump >/dev/null 2>&1; then
  pg_dump "$DB_URL" | gzip -c > "$OUT_FILE"
  echo "$OUT_FILE"
  exit 0
fi

echo "pg_dump not found" >&2
exit 3
