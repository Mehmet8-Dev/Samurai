#!/usr/bin/env bash
# ~45-min feed-forward (FF) accumulate run across >=8 DISTINCT defense profiles.
#
# Captures a fresh corpus against nine genuinely different defenses, appends the
# per-profile files to the pool (accumulate — nothing overwritten), then retrains
# ONLY the feed-forward IQL policy (mahoraga-ff.srlp) on the WHOLE accumulated
# pool. RL² is left untouched. Diverse targets give the policy the
# reaction-conditioning signal (which lever/rate is walled depends on the target),
# the documented antidote to state-marginal overfitting.
#
# Profiles (all must be up and answering /healthz):
#   Coraza+Caddy (:8080, profile-switched, recreated per profile):
#       strict-waf | rate-only | waf-heavy
#   ModSecurity+CRS (:8081)     Anubis PoW gateway (:8082)
#   rate-drop nginx tiers:      r50 (:8084) r100 (:8083) r150 (:8085) r200 (:8086)
#
#   nohup bash deploy/waf-lab/train-run-8profile.sh > /tmp/samurai-train-8p.log 2>&1 &
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"
PY="${PY:-$REPO/ven311/bin/python}"
ART="$REPO/artifacts/rl"
STAMP="$(date +%Y%m%d-%H%M%S)"
export SAMURAI_CLUSTER_SECRET="${SAMURAI_CLUSTER_SECRET:-waf-lab-secret}"

# Time budget: capture until CAP_MIN minutes elapse, then train (a few more min).
CAP_MIN="${CAP_MIN:-37}"
# Per-sweep closed-loop shape (one sweep == one episode / unique run_id).
CL_MIN_RPS="${CL_MIN_RPS:-20}"
CL_MAX_RPS="${CL_MAX_RPS:-800}"
CL_WINDOW_S="${CL_WINDOW_S:-4}"
CL_AIMD_MAX_WINDOWS="${CL_AIMD_MAX_WINDOWS:-18}"
CL_AIMD_INCREASE_RPS="${CL_AIMD_INCREASE_RPS:-40}"
CORAZA_SWEEPS="${CORAZA_SWEEPS:-2}"   # per Coraza profile (each forces a tier recreate)
export CL_MIN_RPS CL_MAX_RPS CL_WINDOW_S CL_AIMD_MAX_WINDOWS CL_AIMD_INCREASE_RPS

# Static (already-running) targets: "label port"; no docker recreate for these.
STATIC_TARGETS=(
  "modsec 8081"
  "anubis 8082"
  "rd-r50 8084"
  "rd-r100 8083"
  "rd-r150 8085"
  "rd-r200 8086"
)
CORAZA_PROFILES=(strict-waf rate-only waf-heavy)

echo "=================================================================="
echo ">> 8+ profile FF accumulate run  $(date)  (stamp=$STAMP)"
echo ">> profiles: coraza{${CORAZA_PROFILES[*]}} + ${STATIC_TARGETS[*]}"
echo ">> capture budget=${CAP_MIN}min  sweep=${CL_WINDOW_S}s x ${CL_AIMD_MAX_WINDOWS}win"
echo "=================================================================="

# Back up the FF artifact we are about to retrain (RL² untouched).
[ -f "$ART/mahoraga-ff.srlp" ] && cp -f "$ART/mahoraga-ff.srlp" "$ART/mahoraga-ff.$STAMP.bak.srlp"

t0=$(date +%s)
deadline=$(( t0 + CAP_MIN * 60 ))

# --- Phase A: Coraza profiles (recreate the tier once each, then a few sweeps) ---
for p in "${CORAZA_PROFILES[@]}"; do
  OUT="$REPO/data/rl-corpus/acc8-coraza-$p-$STAMP.ndjson"
  echo ""; echo ">>>>>> CORAZA profile=$p x $CORAZA_SWEEPS -> $(basename "$OUT")  ($(date))"
  WAF_PROFILE="$p" SWEEPS="$CORAZA_SWEEPS" OUT="$OUT" \
      bash "$HERE/capture-union.sh" || echo "!! coraza/$p had failures (continuing)"
  echo ">> coraza/$p: +$(wc -l < "$OUT" 2>/dev/null || echo 0) transitions"
done

# --- Phase B: round-robin the static targets until the capture deadline ---
declare -A SEED
for entry in "${STATIC_TARGETS[@]}"; do SEED["$entry"]=0; done
round=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  round=$(( round + 1 ))
  for entry in "${STATIC_TARGETS[@]}"; do
    [ "$(date +%s)" -ge "$deadline" ] && break
    label="${entry%% *}"; port="${entry##* }"
    SEED["$entry"]=$(( ${SEED["$entry"]} + 1 ))
    seed="${SEED[$entry]}"
    OUT="$REPO/data/rl-corpus/acc8-$label-$STAMP.ndjson"
    tmp="$(mktemp)"
    echo ">> [$label:$port] round $round seed $seed  ($(date +%H:%M:%S))"
    WAF_LAB_PORT="$port" AUTO_UP=0 RL_EXPLORE=1 RL_EXPLORE_SEED="$seed" \
        CORPUS="$tmp" bash "$HERE/run-corpus.sh" >/tmp/samurai-8p-sweep.log 2>&1 \
        || echo "   ($label sweep $seed failed, skipping)"
    cat "$tmp" >> "$OUT" 2>/dev/null || true
    rm -f "$tmp"
  done
done

t_cap=$(date +%s); echo ""; echo ">> capture done in $(( (t_cap - t0) / 60 )) min"
echo ">> new files this run:"; ls -la "$REPO"/data/rl-corpus/acc8-*-"$STAMP".ndjson 2>/dev/null | awk '{print "   "$NF" ("$5"B)"}'

# --- Phase C: retrain ONLY the FF policy on the whole accumulated pool ---
echo ""; echo ">>>>>> RETRAIN FF on the WHOLE accumulated pool (data/rl-corpus/*.ndjson)"
"$PY" - "$ART" <<'PYEOF'
import sys, glob
import numpy as np
from samurai.models.rl import build_dataset, save_policy
from samurai.models.rl.action_spec import MAHORAGA
from samurai.models.rl.reward import EffectiveThroughputReward
from samurai.models.rl.config import RLConfig
from samurai.models.rl.train import train_iql, IQLConfig
from samurai.models.rl.ope import evaluate_policy

art = sys.argv[1]
files = sorted(glob.glob("data/rl-corpus/*.ndjson"))
cfg = RLConfig()
ds = build_dataset(files, cfg, reward_fn=EffectiveThroughputReward(cfg), action_spec=MAHORAGA)
n_eps = int(np.unique(ds.episode_ids).size)
print(f"   pool: {len(files)} files -> {len(ds)} transitions, {n_eps} episodes")

ff = train_iql(ds, IQLConfig(seed=0))
save_policy(ff, f"{art}/mahoraga-ff.srlp")
print(f"   saved -> {art}/mahoraga-ff.srlp (in_dim={ff.input_dim}, action_dim={ff.action_dim})")

r_ff = evaluate_policy(ds, ff)
print("")
print("   ===== OPE (FQE) gate — FF on full accumulated pool =====")
print(f"   behavior (AIMD) : {r_ff.behavior_return:+.3f}")
print(f"   FF   fqe={r_ff.fqe_value:+.3f} gate={r_ff.gate_pass} "
      f"imp_ci=[{r_ff.improvement_ci_low:+.3f},{r_ff.improvement_ci_high:+.3f}]")
PYEOF

t_end=$(date +%s)
echo ""; echo ">> DONE total $(( (t_end - t0) / 60 )) min  ($(date))"
echo ">> FF weights: $ART/mahoraga-ff.srlp   (pre-run backup: $ART/mahoraga-ff.$STAMP.bak.srlp)"
