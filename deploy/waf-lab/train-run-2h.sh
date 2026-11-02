#!/usr/bin/env bash
# ~2-hour full Mahoraga training run across all WAF/IDS targets + L2/L3/L4 Telco extensions.
#
# 1. Multi-target live capture against 8+ defense profiles with 7D action exploration:
#    - Coraza (strict-waf, rate-only, waf-heavy)
#    - ModSecurity + CRS (:8081)
#    - Anubis PoW (:8082)
#    - Rate-drop tiers (:8083, :8084, :8085, :8086)
#    - L2/L3/L4 telco integration runs
# 2. Train both RL² (recurrent GRU) and Feedforward IQL with the expanded 7D action space:
#    (rps, concurrency, request_mix[12], source_rotation, pacing_mode, auth_mode, evasion_tactic)
# 3. Comprehensive OPE / FQE policy evaluation & model parameter export.
#
# Safe to run in background via subagent.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"
PY="${PY:-$REPO/ven311/bin/python}"
ART="$REPO/artifacts/rl"
STAMP="$(date +%Y%m%d-%H%M%S)"
mkdir -p "$ART" "$REPO/data/rl-corpus"
export SAMURAI_CLUSTER_SECRET="${SAMURAI_CLUSTER_SECRET:-waf-lab-secret}"
export CONTROL_EP="${CONTROL_EP:-tcp://127.0.0.1:5599}"

# Time budget: ~105 minutes capture, ~15 minutes multi-model training/evaluation
CAP_MIN="${CAP_MIN:-105}"

CL_MIN_RPS="${CL_MIN_RPS:-20}"
CL_MAX_RPS="${CL_MAX_RPS:-1000}"
CL_WINDOW_S="${CL_WINDOW_S:-4}"
CL_AIMD_MAX_WINDOWS="${CL_AIMD_MAX_WINDOWS:-20}"
CL_AIMD_INCREASE_RPS="${CL_AIMD_INCREASE_RPS:-50}"
CORAZA_SWEEPS="${CORAZA_SWEEPS:-4}"
export CL_MIN_RPS CL_MAX_RPS CL_WINDOW_S CL_AIMD_MAX_WINDOWS CL_AIMD_INCREASE_RPS

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
echo ">> 2-Hour Mahoraga (7D Action + L2/L3/L4) Training Run: $(date)"
echo ">> Stamp: $STAMP"
echo ">> Capture Budget: ${CAP_MIN} minutes"
echo "=================================================================="

# Backup existing artifacts
[ -f "$ART/mahoraga-ff.srlp" ] && cp -f "$ART/mahoraga-ff.srlp" "$ART/mahoraga-ff.$STAMP.bak.srlp"
[ -f "$ART/mahoraga-rl2.srlp" ] && cp -f "$ART/mahoraga-rl2.srlp" "$ART/mahoraga-rl2.$STAMP.bak.srlp"

t0=$(date +%s)
deadline=$(( t0 + CAP_MIN * 60 ))

# --- Phase 1: Coraza Profiles ---
for p in "${CORAZA_PROFILES[@]}"; do
  OUT="$REPO/data/rl-corpus/train2h-coraza-$p-$STAMP.ndjson"
  echo ""; echo ">>>>>> [Coraza: $p] sweeps=$CORAZA_SWEEPS -> $(basename "$OUT") ($(date +%H:%M:%S))"
  WAF_PROFILE="$p" SWEEPS="$CORAZA_SWEEPS" OUT="$OUT" \
      bash "$HERE/capture-union.sh" || echo "!! coraza/$p had partial failures (continuing)"
  echo ">> coraza/$p transitions: $(wc -l < "$OUT" 2>/dev/null || echo 0)"
done

# --- Phase 2: Round-robin Static Targets until capture deadline ---
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
    OUT="$REPO/data/rl-corpus/train2h-$label-$STAMP.ndjson"
    tmp="$(mktemp)"
    echo ">> [$label:$port] Round $round (Seed $seed) - $(date +%H:%M:%S)"
    WAF_LAB_PORT="$port" AUTO_UP=0 RL_EXPLORE=1 RL_EXPLORE_SEED="$seed" \
        CORPUS="$tmp" bash "$HERE/run-corpus.sh" >/tmp/samurai-2h-sweep.log 2>&1 \
        || echo "   ($label sweep $seed skipped/failed)"
    cat "$tmp" >> "$OUT" 2>/dev/null || true
    rm -f "$tmp"
  done
done

t_cap=$(date +%s)
echo ""
echo ">> Live capture finished in $(( (t_cap - t0) / 60 )) min"

# --- Phase 3: Train RL² and Feedforward IQL with 7D Action Space ---
echo ""
echo ">>>>>> RETRAINING MAHORAGA (RL² & FeedForward) ON FULL CORPUS ($(date +%H:%M:%S))"
"$PY" - "$ART" <<'PYEOF'
import sys, glob
import numpy as np
from ddos_samurai.models.rl import build_dataset, save_policy
from ddos_samurai.models.rl.action_spec import MAHORAGA
from ddos_samurai.models.rl.reward import EffectiveThroughputReward
from ddos_samurai.models.rl.config import RLConfig
from ddos_samurai.models.rl.rl2 import train_rl2, RL2Config
from ddos_samurai.models.rl.train import train_iql, IQLConfig
from ddos_samurai.models.rl.ope import evaluate_policy

art = sys.argv[1]
files = sorted(glob.glob("data/rl-corpus/*.ndjson"))
cfg = RLConfig()
ds = build_dataset(files, cfg, reward_fn=EffectiveThroughputReward(cfg), action_spec=MAHORAGA)
n_eps = int(np.unique(ds.episode_ids).size)
print(f"   Accumulated corpus: {len(files)} files -> {len(ds)} transitions, {n_eps} episodes")
print(f"   Action space ({ds.action_dim}D): {MAHORAGA.names}")
print(f"   Action kinds: {ds.action_kinds}")

print("\n   [1/2] Training Recurrent RL² (GRU)...", flush=True)
try:
    rl2 = train_rl2(ds, RL2Config(seed=42, critic_steps=3000, actor_steps=3000))
    save_policy(rl2, f"{art}/mahoraga-rl2.srlp")
    print(f"   -> Saved: {art}/mahoraga-rl2.srlp (action_dim={rl2.action_dim}, hidden={rl2.hidden_dim})")
    r_rl2 = evaluate_policy(ds, rl2)
    print(f"   RL² OPE: fqe={r_rl2.fqe_value:+.3f} gate_pass={r_rl2.gate_pass} imp_ci=[{r_rl2.improvement_ci_low:+.3f},{r_rl2.improvement_ci_high:+.3f}]")
except Exception as e:
    print(f"   RL² training notice: {e}")

print("\n   [2/2] Training Feedforward IQL (7D Multi-head)...", flush=True)
ff = train_iql(ds, IQLConfig(seed=42, steps=3000))
save_policy(ff, f"{art}/mahoraga-ff.srlp")
print(f"   -> Saved: {art}/mahoraga-ff.srlp (action_dim={ff.action_dim})")
r_ff = evaluate_policy(ds, ff)
print(f"   FF  OPE: fqe={r_ff.fqe_value:+.3f} gate_pass={r_ff.gate_pass} imp_ci=[{r_ff.improvement_ci_low:+.3f},{r_ff.improvement_ci_high:+.3f}]")

print("\n   Model training & parameter updates complete!")
PYEOF

t_end=$(date +%s)
echo ""
echo "=================================================================="
echo ">> 2-HOUR RUN COMPLETE: $(date) (Total elapsed: $(( (t_end - t0) / 60 )) min)"
echo ">> Updated Models: $ART/mahoraga-rl2.srlp and $ART/mahoraga-ff.srlp"
echo "=================================================================="
