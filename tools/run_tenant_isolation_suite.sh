#!/usr/bin/env bash
set -euo pipefail

pytest tests/test_distributed_tenant.py tests/test_distributed_jwt.py tests/test_distributed_management_api.py -q -rs
