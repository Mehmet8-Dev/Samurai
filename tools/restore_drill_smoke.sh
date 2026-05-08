#!/usr/bin/env bash
set -euo pipefail

BACKUP_FILE="${1:-}"
if [[ -z "$BACKUP_FILE" ]]; then
  echo "usage: $0 <backup.sql.gz>" >&2
  exit 2
fi

bash tools/restore_license_db.sh "$BACKUP_FILE"
python - <<'PY'
from __future__ import annotations
import os
import asyncio
from sqlalchemy import text
from license_server.database import async_session

async def _check():
    async with async_session() as db:
        res = await db.execute(text("select 1"))
        assert int(res.scalar_one()) == 1

asyncio.run(_check())
print('[drill] restore smoke passed')
PY
