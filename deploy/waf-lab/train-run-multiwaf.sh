#!/usr/bin/env bash
# ~2h multi-engine accumulate run: capture BOTH defense engines — Caddy+Coraza (3
# profiles, :8080) AND ModSecurity+CRS (:8081, distinct blocked-variant map) — append
# to the corpus pool, then retrain RL²/FF on the WHOLE accumulated pool. Two genuinely
# different engines give the policy reaction-conditioning signal (which lever is walled
# depends on the target), the documented antidote to state-marginal overfitting.
#
#   nohup bash deploy/waf-lab/train-run-multiwaf.sh > /tmp/samurai-train-mw.log 2>&1 &
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"
PY="${PY:-$REPO/ven311/bin/python}"
ART="$REPO/artifacts/rl"
STAMP="$(date +%Y%m%d-%H%M%S)"
export SAMURAI_CLUSTER_SECRET="${SAMURAI_CLUSTER_SECRET:-waf-lab-secret}"

CORAZA_PROFILES=(strict-waf rate-only waf-heavy)
CORAZA_SWEEPS="${CORAZA_SWEEPS:-14}"     # per Coraza profile
MODSEC_SWEEPS="${MODSEC_SWEEPS:-30}"     # ModSecurity engine (:8081)
CL_MIN_RPS="${CL_MIN_RPS:-20}"
CL_MAX_RPS="${CL_MAX_RPS:-800}"
CL_WINDOW_S="${CL_WINDOW_S:-4}"
CL_AIMD_MAX_WINDOWS="${CL_AIMD_MAX_WINDOWS:-20}"
CL_AIMD_INCREASE_RPS="${CL_AIMD_INCREASE_RPS:-40}"

echo "=================================================================="
echo ">> Multi-engine accumulate run  $(date)  (stamp=$STAMP)"
echo ">> Coraza: ${CORAZA_PROFILES[*]} x $CORAZA_SWEEPS   ModSecurity(:8081): x $MODSEC_SWEEPS"
echo "=================================================================="

for w in mahoraga-rl2 mahoraga-ff; do
    [ -f "$ART/$w.srlp" ] && cp -f "$ART/$w.srlp" "$ART/$w.$STAMP.bak.srlp"
done

t0=$(date +%s)

# --- Engine 1: Caddy + Coraza, 3 profiles (recreates its own lab tier per profile) ---
for p in "${CORAZA_PROFILES[@]}"; do
    OUT="$REPO/data/rl-corpus/acc-coraza-$p-$STAMP.ndjson"
    echo ""; echo ">>>>>> CORAZA profile=$p -> $(basename "$OUT")  ($(date))"
    WAF_PROFILE="$p" SWEEPS="$CORAZA_SWEEPS" \
        CL_MIN_RPS="$CL_MIN_RPS" CL_MAX_RPS="$CL_MAX_RPS" \
        CL_WINDOW_S="$CL_WINDOW_S" CL_AIMD_MAX_WINDOWS="$CL_AIMD_MAX_WINDOWS" \
        CL_AIMD_INCREASE_RPS="$CL_AIMD_INCREASE_RPS" \
        OUT="$OUT" bash "$HERE/capture-union.sh" || echo "!! coraza/$p had failures (continuing)"
    echo ">> coraza/$p: +$(wc -l < "$OUT" 2>/dev/null || echo 0) transitions"
done

# --- Engine 2: ModSecurity + CRS on :8081 (zoo already up; do NOT recreate anything) ---
MODSEC_OUT="$REPO/data/rl-corpus/acc-modsec-$STAMP.ndjson"
: > "$MODSEC_OUT"
echo ""; echo ">>>>>> MODSECURITY engine (:8081) x $MODSEC_SWEEPS sweeps  ($(date))"
if ! curl -fsS "http://127.0.0.1:8081/healthz" >/dev/null 2>&1; then
    echo "!! modsec ingress :8081 not responding — is the zoo up? (docker compose -f $HERE/docker-compose.zoo.yml up -d)"
else
    for i in $(seq 1 "$MODSEC_SWEEPS"); do
        tmp="$(mktemp)"
        WAF_LAB_PORT=8081 AUTO_UP=0 RL_EXPLORE=1 RL_EXPLORE_SEED="$i" \
            CL_MIN_RPS="$CL_MIN_RPS" CL_MAX_RPS="$CL_MAX_RPS" \
            CL_WINDOW_S="$CL_WINDOW_S" CL_AIMD_MAX_WINDOWS="$CL_AIMD_MAX_WINDOWS" \
            CL_AIMD_INCREASE_RPS="$CL_AIMD_INCREASE_RPS" \
            CORPUS="$tmp" bash "$HERE/run-corpus.sh" >/tmp/samurai-modsec-sweep.log 2>&1 \
            || echo "   (modsec sweep $i failed, skipping)"
        cat "$tmp" >> "$MODSEC_OUT" 2>/dev/null || true
        rm -f "$tmp"
        [ $(( i % 5 )) -eq 0 ] && echo "   modsec sweep $i/$MODSEC_SWEEPS (total $(wc -l < "$MODSEC_OUT"))"
    done
fi
echo ">> modsec: +$(wc -l < "$MODSEC_OUT" 2>/dev/null || echo 0) transitions"

t_cap=$(date +%s); echo ""; echo ">> capture done in $(( (t_cap - t0) / 60 )) min"

echo ""; echo ">>>>>> RETRAIN on the WHOLE accumulated pool (data/rl-corpus/*.ndjson)"
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
print(f"   pool: {len(files)} files -> {len(ds)} transitions, {n_eps} episodes")

rl2 = train_rl2(ds, RL2Config(seed=0))
save_policy(rl2, f"{art}/mahoraga-rl2.srlp")
ff = train_iql(ds, IQLConfig(seed=0))
save_policy(ff, f"{art}/mahoraga-ff.srlp")
print(f"   saved -> {art}/mahoraga-rl2.srlp (recurrent={rl2.recurrent}, hidden={rl2.hidden_dim})")

r_rl2 = evaluate_policy(ds, rl2)
r_ff = evaluate_policy(ds, ff)
print("")
print("   ===== OPE (FQE) gate — full multi-engine pool =====")
print(f"   behavior (AIMD) : {r_rl2.behavior_return:+.3f}")
print(f"   RL²  fqe={r_rl2.fqe_value:+.3f} gate={r_rl2.gate_pass} "
      f"imp_ci=[{r_rl2.improvement_ci_low:+.3f},{r_rl2.improvement_ci_high:+.3f}]")
print(f"   FF   fqe={r_ff.fqe_value:+.3f} gate={r_ff.gate_pass} "
      f"imp_ci=[{r_ff.improvement_ci_low:+.3f},{r_ff.improvement_ci_high:+.3f}]")
print(f"   RL² - FF (fqe): {r_rl2.fqe_value - r_ff.fqe_value:+.3f}")
PYEOF

t_end=$(date +%s)
echo ""; echo ">> DONE total $(( (t_end - t0) / 60 )) min  ($(date))"
echo ">> weights: $ART/mahoraga-rl2.srlp   (backup this run: $ART/mahoraga-rl2.$STAMP.bak.srlp)"
