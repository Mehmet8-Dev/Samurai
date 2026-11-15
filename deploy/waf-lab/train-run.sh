#!/usr/bin/env bash
# One-shot ~1h Mahoraga training run against the local WAF lab.
#
#   capture (3 profiles x N sweeps, exploration on) -> union corpus
#     -> train_rl2 (SRLP v4) + train_iql (SRLP v3) -> OPE gate for both.
#
# Everything is logged; artifacts land in artifacts/rl/. Safe to run in background:
#   nohup bash deploy/waf-lab/train-run.sh > /tmp/samurai-train.log 2>&1 &
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"
PY="${PY:-$REPO/ven311/bin/python}"
ART="$REPO/artifacts/rl"
mkdir -p "$ART" "$REPO/data/rl-corpus"
export SAMURAI_CLUSTER_SECRET="${SAMURAI_CLUSTER_SECRET:-waf-lab-secret}"

PROFILES=(strict-waf rate-only waf-heavy)
SWEEPS="${SWEEPS:-12}"
CL_MIN_RPS="${CL_MIN_RPS:-20}"
CL_MAX_RPS="${CL_MAX_RPS:-800}"
CL_WINDOW_S="${CL_WINDOW_S:-4}"
CL_AIMD_MAX_WINDOWS="${CL_AIMD_MAX_WINDOWS:-20}"
CL_AIMD_INCREASE_RPS="${CL_AIMD_INCREASE_RPS:-40}"

echo "=================================================================="
echo ">> Mahoraga training run  $(date)"
echo ">> profiles=${PROFILES[*]}  sweeps/profile=$SWEEPS  window=${CL_WINDOW_S}s x $CL_AIMD_MAX_WINDOWS"
echo "=================================================================="

t0=$(date +%s)
for p in "${PROFILES[@]}"; do
    echo ""; echo ">>>>>> CAPTURE profile=$p  ($(date))"
    WAF_PROFILE="$p" SWEEPS="$SWEEPS" \
        CL_MIN_RPS="$CL_MIN_RPS" CL_MAX_RPS="$CL_MAX_RPS" \
        CL_WINDOW_S="$CL_WINDOW_S" CL_AIMD_MAX_WINDOWS="$CL_AIMD_MAX_WINDOWS" \
        CL_AIMD_INCREASE_RPS="$CL_AIMD_INCREASE_RPS" \
        OUT="$REPO/data/rl-corpus/$p.ndjson" \
        bash "$HERE/capture-union.sh" || echo "!! capture for $p had failures (continuing)"
    echo ">> $p corpus: $(wc -l < "$REPO/data/rl-corpus/$p.ndjson" 2>/dev/null || echo 0) transitions"
done
t_cap=$(date +%s); echo ""; echo ">> capture done in $(( (t_cap - t0) / 60 )) min"

echo ""; echo ">>>>>> TRAIN (union of 3 profiles)  ($(date))"
"$PY" - "$ART" "$REPO/data/rl-corpus/strict-waf.ndjson" \
                "$REPO/data/rl-corpus/rate-only.ndjson" \
                "$REPO/data/rl-corpus/waf-heavy.ndjson" <<'PYEOF'
import sys
import numpy as np
from samurai.models.rl import build_dataset, save_policy
from samurai.models.rl.action_spec import MAHORAGA
from samurai.models.rl.reward import EffectiveThroughputReward
from samurai.models.rl.config import RLConfig
from samurai.models.rl.rl2 import train_rl2, RL2Config
from samurai.models.rl.train import train_iql, IQLConfig
from samurai.models.rl.ope import evaluate_policy

art, paths = sys.argv[1], [p for p in sys.argv[2:]]
cfg = RLConfig()  # base state (no block/ban) — RL²'s GRU subsumes that memory
ds = build_dataset(paths, cfg, reward_fn=EffectiveThroughputReward(cfg),
                   action_spec=MAHORAGA)
n_eps = int(np.unique(ds.episode_ids).size)
print(f"   union dataset: {len(ds)} transitions, {n_eps} episodes")
print(f"   features ({len(ds.feature_names)}): {ds.feature_names}")

print("   training RL² (recurrent GRU)…", flush=True)
rl2 = train_rl2(ds, RL2Config(seed=0))
save_policy(rl2, f"{art}/mahoraga-rl2.srlp")
print(f"   -> {art}/mahoraga-rl2.srlp (recurrent={rl2.recurrent}, hidden={rl2.hidden_dim})")

print("   training feedforward IQL (A/B baseline)…", flush=True)
ff = train_iql(ds, IQLConfig(seed=0))
save_policy(ff, f"{art}/mahoraga-ff.srlp")

r_rl2 = evaluate_policy(ds, rl2)
r_ff = evaluate_policy(ds, ff)
print("")
print("   ===== OPE (FQE) gate =====")
print(f"   behavior (AIMD) return : {r_rl2.behavior_return:+.3f}")
print(f"   RL²  fqe={r_rl2.fqe_value:+.3f}  gate_pass={r_rl2.gate_pass}  "
      f"imp_ci=[{r_rl2.improvement_ci_low:+.3f},{r_rl2.improvement_ci_high:+.3f}]")
print(f"   FF   fqe={r_ff.fqe_value:+.3f}  gate_pass={r_ff.gate_pass}  "
      f"imp_ci=[{r_ff.improvement_ci_low:+.3f},{r_ff.improvement_ci_high:+.3f}]")
print(f"   RL² vs FF (fqe): {r_rl2.fqe_value - r_ff.fqe_value:+.3f}")
PYEOF

t_end=$(date +%s)
echo ""
echo "=================================================================="
echo ">> DONE  ($(date))   total $(( (t_end - t0) / 60 )) min "
echo ">> policy: $ART/mahoraga-rl2.srlp   baseline: $ART/mahoraga-ff.srlp"
echo ">> serve it:  RL_POLICY=$ART/mahoraga-rl2.srlp WAF_PROFILE=waf-heavy bash $HERE/run-corpus.sh"
echo "=================================================================="
