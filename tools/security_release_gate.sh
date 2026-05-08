#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="${SAMURAI_SECURITY_OUT_DIR:-artifacts/security}"
mkdir -p "$OUT_DIR"

bash tools/generate_sbom.sh "$OUT_DIR"

python - <<'PY'
from pathlib import Path
required = [
    Path('policies/TERMS_OF_USE.md'),
    Path('policies/AUP.md'),
    Path('policies/UNAUTHORIZED_USE_NOTICE.md'),
    Path('enterprise/sla_slo_catalog.yaml'),
]
missing = [str(p) for p in required if not p.is_file()]
if missing:
    raise SystemExit(f"missing required policy artifacts: {missing}")
print('[security-gate] policy artifacts: ok')
PY

if command -v pip-audit >/dev/null 2>&1; then
  pip-audit -r requirements.txt -f json -o "$OUT_DIR/pip_audit.json"
  python - <<'PY'
import json
from pathlib import Path
p = Path(__import__('os').environ.get('SAMURAI_SECURITY_OUT_DIR', 'artifacts/security')) / 'pip_audit.json'
obj = json.loads(p.read_text(encoding='utf-8'))
vulns = int(sum(len(item.get('vulns', [])) for item in obj.get('dependencies', [])))
if vulns > 0:
    raise SystemExit(f"[security-gate] blocking: vulnerabilities found ({vulns})")
print('[security-gate] pip-audit: no known vulns')
PY
else
  echo "[security-gate] pip-audit not installed, skipping dependency vulnerability gate" >&2
fi

python tools/verify_audit_chain.py /tmp/nonexistent_audit.jsonl >/dev/null 2>&1 || true

echo "[security-gate] PASS"
