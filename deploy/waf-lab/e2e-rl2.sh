#!/usr/bin/env bash
# E2E "the wheel actually turns" verification for the RL² (recurrent, in-context)
# policy against the real WAF lab. This is the live counterpart to the mechanical
# golden/lockstep tests: it trains a recurrent policy on a freshly captured lab
# corpus, serves it, and checks that in-context adaptation is really running — and,
# with A/B on, that it earns its keep over a context-free (feedforward IQL) policy on
# the SAME defended target.
#
# Pipeline:
#   1. capture   — drive the closed-loop against the lab, log an RL corpus
#      (run-corpus.sh). RL_EXPLORE gives the corpus per-window lever variation.
#   2. train     — build_dataset -> train_rl2 -> SRLP v4 (recurrent); with A/B also
#      train_iql -> SRLP v3 (feedforward) on the identical dataset.
#   3. serve+verify — serve the RL² policy (--cl-strategy rl) and assert from the
#      master log that the recurrent context is loaded + reset per episode. With A/B,
#      serve the feedforward policy too and compare mean served throughput (2xx/s).
#
# Usage:
#   WAF_PROFILE=waf-heavy ./e2e-rl2.sh            # RL² only
#   WAF_PROFILE=waf-heavy AB=1 ./e2e-rl2.sh       # + feedforward A/B comparison
#
# Prereqs: lab up (docker compose ... up -d --build), native daemons + L7 worker
# built, and a torch-capable python (PY, default ven311/bin/python).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PY="${PY:-$REPO/ven311/bin/python}"
ART="${ART:-$REPO/artifacts/rl}"
RL2_POLICY="$ART/mahoraga-rl2.srlp"
FF_POLICY="$ART/mahoraga-ff.srlp"
MLOG="/tmp/samurai-lab-master.log"

WAF_PROFILE="${WAF_PROFILE:-waf-heavy}"
AB="${AB:-0}"
SWEEPS="${SWEEPS:-6}"
CL_AIMD_MAX_WINDOWS="${CL_AIMD_MAX_WINDOWS:-20}"
export WAF_PROFILE

PASSES=0
FAILS=0
pass() { echo "  [PASS] $1"; PASSES=$((PASSES + 1)); }
fail() { echo "  [FAIL] $1"; FAILS=$((FAILS + 1)); }

echo ">> E2E RL² (in-context) verification"
echo ">> profile=$WAF_PROFILE  A/B=$AB  py=$PY"
[[ -x "$PY" ]] || { echo "!! python not found/executable: $PY" >&2; exit 1; }
mkdir -p "$ART"

# --- 1. capture a training corpus from the lab -------------------------------------
CORPUS="$REPO/data/rl-corpus/rl2-${WAF_PROFILE}.ndjson"
echo ""
echo "========== CAPTURE (${SWEEPS} sweeps) =========="
AUTO_UP=1 WAF_PROFILE="$WAF_PROFILE" SWEEPS="$SWEEPS" OUT="$CORPUS" \
    bash "$HERE/capture-union.sh"
[[ -s "$CORPUS" ]] && pass "corpus captured: $(wc -l < "$CORPUS") transitions" \
                    || { fail "no corpus captured"; exit 1; }

# --- 2. train the recurrent policy (and, for A/B, a feedforward one) ----------------
echo ""
echo "========== TRAIN =========="
CORPUS="$CORPUS" RL2_POLICY="$RL2_POLICY" FF_POLICY="$FF_POLICY" AB="$AB" "$PY" - <<'PYEOF'
import os
from samurai.models.rl import build_dataset, save_policy
from samurai.models.rl.rl2 import train_rl2, RL2Config
from samurai.models.rl.train import train_iql, IQLConfig

corpus, rl2_out, ff_out, ab = (os.environ["CORPUS"], os.environ["RL2_POLICY"],
                               os.environ["FF_POLICY"], os.environ["AB"] == "1")
ds = build_dataset(corpus)
print(f"   dataset: {len(ds)} transitions, feature_names={ds.feature_names}")
art = train_rl2(ds, RL2Config(seed=0))
save_policy(art, rl2_out)
print(f"   RL²  -> {rl2_out} (recurrent={art.recurrent}, hidden={art.hidden_dim})")
if ab:
    ff = train_iql(ds, IQLConfig(seed=0))
    save_policy(ff, ff_out)
    print(f"   FF   -> {ff_out} (recurrent={ff.recurrent})")
PYEOF
[[ -s "$RL2_POLICY" ]] && pass "RL² policy exported ($(stat -c%s "$RL2_POLICY") bytes)" \
                       || { fail "RL² export failed"; exit 1; }

# --- 3. serve the RL² policy and verify in-context adaptation is live ---------------
serve() {  # $1 = policy path
    RL_POLICY="$1" AUTO_UP=0 WAF_PROFILE="$WAF_PROFILE" \
        CL_AIMD_MAX_WINDOWS="$CL_AIMD_MAX_WINDOWS" \
        CORPUS="/tmp/samurai-e2e-rl2-serve.ndjson" \
        bash "$HERE/run-corpus.sh" 2>&1
}
mean_served() {  # $1 = serve corpus -> mean 2xx/s
    "$PY" - "$1" <<'PYEOF'
import sys, json
tot = n = 0.0
for line in open(sys.argv[1]):
    try:
        r = json.loads(line)
        d = r.get("s2", {}).get("defense", {})
        ws = r.get("window_s", 1) or 1
        if "status_2xx" in d:
            tot += float(d["status_2xx"]) / ws; n += 1
    except Exception:
        pass
print(f"{(tot / n if n else 0.0):.1f}")
PYEOF
}

echo ""
echo "========== SERVE RL² =========="
serve "$RL2_POLICY"
cp -f /tmp/samurai-e2e-rl2-serve.ndjson /tmp/samurai-e2e-rl2-corpus.ndjson 2>/dev/null || true
echo ""
echo ">> RL² serve checks (from $MLOG):"
grep -q "RL policy loaded" "$MLOG" 2>/dev/null && pass "policy loaded" || fail "policy not loaded"
grep -q "RL² recurrent policy" "$MLOG" 2>/dev/null \
    && pass "recurrent policy recognized (v4)" || fail "recurrent NOT recognized — served as feedforward?"
grep -q "resetting context" "$MLOG" 2>/dev/null \
    && pass "GRU context reset per episode (in-context adaptation live)" \
    || fail "context reset NOT logged"
RL2_SERVED="$(mean_served /tmp/samurai-e2e-rl2-corpus.ndjson)"
echo "         RL² mean served throughput: ${RL2_SERVED} req/s (2xx)"

# --- optional A/B: does in-context adaptation beat the context-free policy? ---------
if [[ "$AB" == "1" && -s "$FF_POLICY" ]]; then
    echo ""
    echo "========== SERVE FEEDFORWARD (A/B) =========="
    serve "$FF_POLICY"
    FF_SERVED="$(mean_served /tmp/samurai-e2e-rl2-serve.ndjson)"
    echo ""
    echo ">> A/B: RL²=${RL2_SERVED}  feedforward=${FF_SERVED} req/s served"
    awk "BEGIN{exit !($RL2_SERVED >= $FF_SERVED)}" \
        && pass "RL² served >= feedforward (in-context adaptation earns its keep)" \
        || fail "RL² served < feedforward on this target (review corpus/training)"
fi

echo ""
echo "========================================="
echo ">> E2E RL²: $PASSES passed, $FAILS failed"
echo ">> Master log: $MLOG   RL² serve corpus: /tmp/samurai-e2e-rl2-corpus.ndjson"
[[ $FAILS -gt 0 ]] && { echo "!! SOME CHECKS FAILED — review the master log"; exit 1; }
echo ">> ALL CHECKS PASSED — the wheel turns against the live lab"
