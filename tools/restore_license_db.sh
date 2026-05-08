#!/usr/bin/env bash
set -euo pipefail

BACKUP_FILE="${1:-}"
DB_URL="${LICENSE_DATABASE_URL:-}"
if [[ -z "$BACKUP_FILE" || ! -f "$BACKUP_FILE" ]]; then
  echo "Backup file is required" >&2
  exit 2
fi
if [[ -z "$DB_URL" ]]; then
  echo "LICENSE_DATABASE_URL is required" >&2
  exit 2
fi

if command -v psql >/dev/null 2>&1; then
  gzip -dc "$BACKUP_FILE" | psql "$DB_URL"
  echo "restore complete"
  exit 0
fi

echo "psql not found" >&2
exit 3
