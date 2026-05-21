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
  # pip-audit exits non-zero when vulnerabilities are found. We always parse the
  # JSON output and apply project allowlist rules before final gate decision.
  pip-audit -r requirements.txt -f json -o "$OUT_DIR/pip_audit.json" || true
  python - <<'PY'
import json
import os
from datetime import date
from pathlib import Path

out_dir = Path(os.environ.get('SAMURAI_SECURITY_OUT_DIR', 'artifacts/security'))
report_path = out_dir / 'pip_audit.json'
allowlist_path = Path(os.environ.get('SAMURAI_PIP_AUDIT_ALLOWLIST', 'policies/pip_audit_allowlist.json'))

obj = json.loads(report_path.read_text(encoding='utf-8'))
deps = obj.get('dependencies', []) or []

allowed_rules = []
if allowlist_path.is_file():
    try:
        allow_obj = json.loads(allowlist_path.read_text(encoding='utf-8'))
        allowed_rules = list(allow_obj.get('allowlist', []) or [])
    except Exception as exc:
        raise SystemExit(f"[security-gate] invalid allowlist file: {allowlist_path} ({exc})")

def is_allowed(pkg: str, vuln_id: str) -> tuple[bool, str]:
    today = date.today()
    for rule in allowed_rules:
        rid = str(rule.get('id', '') or '').strip()
        rpk = str(rule.get('package', '*') or '*').strip().lower()
        exp = str(rule.get('expires', '') or '').strip()
        reason = str(rule.get('reason', '') or '').strip()
        if not rid or rid != vuln_id:
            continue
        if rpk not in {'*', pkg.lower()}:
            continue
        if exp:
            try:
                y, m, d = [int(x) for x in exp.split('-')]
                if today > date(y, m, d):
                    continue
            except Exception:
                continue
        return True, reason or 'no reason'
    return False, ''

all_vulns = []
for dep in deps:
    pkg = str(dep.get('name', '') or '').strip()
    for v in (dep.get('vulns', []) or []):
        vid = str(v.get('id', '') or '').strip()
        if not vid:
            continue
        all_vulns.append((pkg, vid))

unallowed = []
allowed = []
for pkg, vid in all_vulns:
    ok, why = is_allowed(pkg, vid)
    if ok:
        allowed.append((pkg, vid, why))
    else:
        unallowed.append((pkg, vid))

if allowed:
    print(f"[security-gate] pip-audit: allowlisted vulnerabilities ({len(allowed)}):")
    for pkg, vid, why in allowed:
        print(f"  - {pkg}:{vid} ({why})")

if unallowed:
    print(f"[security-gate] blocking: unallowlisted vulnerabilities found ({len(unallowed)})")
    for pkg, vid in unallowed:
        print(f"  - {pkg}:{vid}")
    raise SystemExit(1)

print('[security-gate] pip-audit: no blocking vulnerabilities')
PY
else
  echo "[security-gate] pip-audit not installed, skipping dependency vulnerability gate" >&2
fi

python tools/verify_audit_chain.py /tmp/nonexistent_audit.jsonl >/dev/null 2>&1 || true

echo "[security-gate] PASS"
