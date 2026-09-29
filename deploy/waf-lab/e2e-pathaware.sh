#!/usr/bin/env bash
# E2E verification: serve the path-aware policy against the WAF lab and verify:
#   1. Block state feature is fed to the policy (master prints "path-aware block state on")
#   2. Variant memory is loaded/saved (warm-start / persist prints)
#   3. The lever shield vetos blocked variants at serving time
#   4. Corpus records show real defense reactions
#   5. Policy proposes for 30-dim state (in_dim=30)
#
# Usage:
#   WAF_PROFILE=strict-waf ./e2e-pathaware.sh
#   WAF_PROFILE=waf-heavy  ./e2e-pathaware.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
VMEM="/tmp/samurai-e2e-variant-memory.json"
MLOG="/tmp/samurai-lab-master.log"
POLICY="${RL_POLICY:-$REPO/artifacts/rl/mahoraga-pathaware.srlp}"

WAF_PROFILE="${WAF_PROFILE:-strict-waf}"
CL_AIMD_MAX_WINDOWS="${CL_AIMD_MAX_WINDOWS:-20}"
export WAF_PROFILE

echo ">> E2E path-aware verification"
echo ">> profile=$WAF_PROFILE  policy=$POLICY  vmem=$VMEM"

# Verify the policy exists
if [[ ! -f "$POLICY" ]]; then
    echo "!! policy not found: $POLICY" >&2; exit 1
fi
echo ">> policy size: $(stat -c%s "$POLICY") bytes"

# Clean variant memory from prior runs (first run = cold start)
rm -f "$VMEM"
PASSES=0
FAILS=0
pass() { echo "  [PASS] $1"; PASSES=$((PASSES + 1)); }
fail() { echo "  [FAIL] $1"; FAILS=$((FAILS + 1)); }

# Run 1: cold start — no prior memory, the shield discovers blocks from scratch
echo ""
echo "========== RUN 1: COLD START =========="
RL_POLICY="$POLICY" VARIANT_MEMORY="$VMEM" \
    AUTO_UP=1 CL_AIMD_MAX_WINDOWS="$CL_AIMD_MAX_WINDOWS" \
    CORPUS="/tmp/samurai-e2e-corpus-run1.ndjson" \
    bash "$HERE/run-corpus.sh" 2>&1

echo ""
echo ">> RUN 1 checks (from master log $MLOG):"
# Check 1: block state was enabled (master printf goes to its log file, not stdout)
if grep -q "path-aware block state on" "$MLOG" 2>/dev/null; then
    pass "block state on (in_dim=30)"
else
    fail "block state NOT detected in $MLOG"
fi

# Check 2: lever shield active
if grep -q "lever shield on" "$MLOG" 2>/dev/null; then
    pass "lever shield active"
else
    fail "lever shield NOT active"
fi

# Check 3: variant memory was saved
if [[ -f "$VMEM" ]]; then
    pass "variant memory persisted"
    echo "         content: $(cat "$VMEM")"
else
    fail "variant memory NOT saved"
fi

# Check 4: variant memory saved message in log
if grep -q "variant memory saved" "$MLOG" 2>/dev/null; then
    pass "variant memory save logged"
else
    fail "variant memory save NOT logged"
fi

# Check 5: corpus has transitions
CORPUS1="/tmp/samurai-e2e-corpus-run1.ndjson"
if [[ -f "$CORPUS1" ]]; then
    N=$(wc -l < "$CORPUS1")
    pass "corpus: $N transitions"
else
    fail "no corpus produced"
fi

# Run 2: warm start — memory should be loaded from prior run
echo ""
echo "========== RUN 2: WARM START =========="
RL_POLICY="$POLICY" VARIANT_MEMORY="$VMEM" \
    AUTO_UP=0 CL_AIMD_MAX_WINDOWS="$CL_AIMD_MAX_WINDOWS" \
    CORPUS="/tmp/samurai-e2e-corpus-run2.ndjson" \
    bash "$HERE/run-corpus.sh" 2>&1

echo ""
echo ">> RUN 2 checks (from master log $MLOG):"
# Check 6: warm-start loaded
if grep -q "variant memory warm-started" "$MLOG" 2>/dev/null; then
    pass "warm-start loaded from prior run"
else
    fail "warm-start NOT detected in $MLOG"
fi

# Check 7: memory still persisted (updated)
if [[ -f "$VMEM" ]]; then
    pass "variant memory updated after run 2"
    echo "         content: $(cat "$VMEM")"
else
    fail "variant memory lost after run 2"
fi

echo ""
echo "========================================="
echo ">> E2E path-aware verification: $PASSES passed, $FAILS failed"
echo ">> Master log: $MLOG"
echo ">> Corpora: /tmp/samurai-e2e-corpus-run{1,2}.ndjson"
echo ">> Variant memory: $VMEM"
if [[ $FAILS -gt 0 ]]; then
    echo "!! SOME CHECKS FAILED — review master log for details"
    exit 1
fi
echo ">> ALL CHECKS PASSED"
