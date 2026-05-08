#!/usr/bin/env bash
set -euo pipefail

mkdir -p artifacts/acceptance

pytest tests/test_target_safety.py \
       tests/test_distributed_rbac_audit.py \
       tests/test_distributed_tenant.py \
       tests/test_distributed_jwt.py -q -rs

python tools/benchmark_enterprise.py --out artifacts/acceptance/benchmark_summary.json
python tools/check_slo.py --input artifacts/acceptance/benchmark_summary.json --min-job-success-rate 99 --max-control-api-error-rate 1

bash tools/security_release_gate.sh

echo "[enterprise-acceptance] PASS"
