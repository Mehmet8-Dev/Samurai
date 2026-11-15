#!/usr/bin/env bash
# ~30 min continuation run: capture WITHIN-EPISODE regime shifts (the WAF defense
# personality changes mid-episode) so a memoryless policy is caught flat-footed and
# the recurrent RL²'s in-context memory has something to exploit — then retrain on
# the ACCUMULATED corpus (existing 3-profile capture + these shift episodes).
#
# Each sweep: bring caddy up on START profile, launch the closed loop, and at the
# midpoint hot-swap caddy to the TARGET profile (its blocked variants / rate change).
# The same episode thus straddles two defense regimes.
#
#   nohup bash deploy/waf-lab/train-run-shift.sh > /tmp/samurai-train-shift.log 2>&1 &
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"
PY="${PY:-$REPO/ven311/bin/python}"
ART="$REPO/artifacts/rl"
COMPOSE="$HERE/docker-compose.yml"
SHIFT_CORPUS="$REPO/data/rl-corpus/regime-shift.ndjson"
export SAMURAI_CLUSTER_SECRET="${SAMURAI_CLUSTER_SECRET:-waf-lab-secret}"
export WAF_LAB_PORT="${WAF_LAB_PORT:-8080}"

SWEEPS="${SWEEPS:-16}"
CL_MIN_RPS="${CL_MIN_RPS:-20}"
CL_MAX_RPS="${CL_MAX_RPS:-800}"
CL_WINDOW_S="${CL_WINDOW_S:-4}"
CL_AIMD_MAX_WINDOWS="${CL_AIMD_MAX_WINDOWS:-18}"
CL_AIMD_INCREASE_RPS="${CL_AIMD_INCREASE_RPS:-40}"
# Rotating (START -> TARGET) regime pairs; each sweep straddles one pair.
PAIRS=("rate-only:waf-heavy" "waf-heavy:strict-waf" "strict-waf:rate-only")

echo "=================================================================="
echo ">> Regime-shift continuation run  $(date)"
echo ">> sweeps=$SWEEPS  window=${CL_WINDOW_S}s x $CL_AIMD_MAX_WINDOWS  (~mid-episode WAF swap)"
echo "=================================================================="

wait_ingress() {
    for _ in $(seq 1 40); do
        curl -fsS "http://127.0.0.1:${WAF_LAB_PORT}/healthz" >/dev/null 2>&1 && return 0
        sleep 0.5
    done
    return 1
}
recreate_caddy() {  # $1 = profile
    WAF_PROFILE="$1" docker compose -f "$COMPOSE" up -d --force-recreate \
        nginx caddy whoami >/dev/null 2>&1 || true
}

: > "$SHIFT_CORPUS"
t0=$(date +%s)
switch_after=$(( CL_AIMD_MAX_WINDOWS * CL_WINDOW_S / 2 ))

for i in $(seq 1 "$SWEEPS"); do
    pair="${PAIRS[$(( (i - 1) % ${#PAIRS[@]} ))]}"
    START="${pair%%:*}"; TARGET="${pair##*:}"
    echo ""; echo ">> sweep $i/$SWEEPS : $START --($switch_after s)--> $TARGET"

    recreate_caddy "$START"
    if ! wait_ingress; then echo "   (ingress down, skip)"; continue; fi

    tmp="$(mktemp)"
    # Launch the closed loop on START in the background…
    AUTO_UP=0 WAF_PROFILE="$START" RL_EXPLORE=1 RL_EXPLORE_SEED="$i" \
        CL_MIN_RPS="$CL_MIN_RPS" CL_MAX_RPS="$CL_MAX_RPS" \
        CL_WINDOW_S="$CL_WINDOW_S" CL_AIMD_MAX_WINDOWS="$CL_AIMD_MAX_WINDOWS" \
        CL_AIMD_INCREASE_RPS="$CL_AIMD_INCREASE_RPS" \
        CORPUS="$tmp" bash "$HERE/run-corpus.sh" >/tmp/samurai-shift-sweep.log 2>&1 &
    sweep_pid=$!

    # …and hot-swap the defense to TARGET at the midpoint (the within-episode shift).
    sleep "$switch_after"
    echo "   >> shifting defense: $START -> $TARGET"
    WAF_PROFILE="$TARGET" docker compose -f "$COMPOSE" up -d --force-recreate \
        caddy >/dev/null 2>&1 || true

    wait "$sweep_pid" 2>/dev/null || echo "   (sweep $i had issues, keeping partial)"
    n=$(wc -l < "$tmp" 2>/dev/null || echo 0)
    cat "$tmp" >> "$SHIFT_CORPUS" 2>/dev/null || true
    rm -f "$tmp"
    echo "   sweep $i: +$n transitions (total $(wc -l < "$SHIFT_CORPUS"))"
done
t_cap=$(date +%s); echo ""; echo ">> shift capture done in $(( (t_cap - t0) / 60 )) min: $(wc -l < "$SHIFT_CORPUS") transitions"

echo ""; echo ">>>>>> RETRAIN on accumulated corpus (existing 3 profiles + regime-shift)"
"$PY" - "$ART" \
    "$REPO/data/rl-corpus/strict-waf.ndjson" \
    "$REPO/data/rl-corpus/rate-only.ndjson" \
    "$REPO/data/rl-corpus/waf-heavy.ndjson" \
    "$SHIFT_CORPUS" <<'PYEOF'
import sys
import numpy as np
from samurai.models.rl import build_dataset, save_policy
from samurai.models.rl.action_spec import MAHORAGA
from samurai.models.rl.reward import EffectiveThroughputReward
from samurai.models.rl.config import RLConfig
from samurai.models.rl.rl2 import train_rl2, RL2Config
from samurai.models.rl.train import train_iql, IQLConfig
from samurai.models.rl.ope import evaluate_policy

art, paths = sys.argv[1], list(sys.argv[2:])
cfg = RLConfig()
ds = build_dataset(paths, cfg, reward_fn=EffectiveThroughputReward(cfg), action_spec=MAHORAGA)
n_eps = int(np.unique(ds.episode_ids).size)
print(f"   accumulated dataset: {len(ds)} transitions, {n_eps} episodes")

rl2 = train_rl2(ds, RL2Config(seed=0))
save_policy(rl2, f"{art}/mahoraga-rl2.srlp")
ff = train_iql(ds, IQLConfig(seed=0))
save_policy(ff, f"{art}/mahoraga-ff.srlp")
print(f"   saved -> {art}/mahoraga-rl2.srlp (recurrent={rl2.recurrent}, hidden={rl2.hidden_dim})")

r_rl2 = evaluate_policy(ds, rl2)
r_ff = evaluate_policy(ds, ff)
print("")
print("   ===== OPE (FQE) gate — accumulated + regime-shift =====")
print(f"   behavior (AIMD) : {r_rl2.behavior_return:+.3f}")
print(f"   RL²  fqe={r_rl2.fqe_value:+.3f} gate={r_rl2.gate_pass} "
      f"imp_ci=[{r_rl2.improvement_ci_low:+.3f},{r_rl2.improvement_ci_high:+.3f}]")
print(f"   FF   fqe={r_ff.fqe_value:+.3f} gate={r_ff.gate_pass} "
      f"imp_ci=[{r_ff.improvement_ci_low:+.3f},{r_ff.improvement_ci_high:+.3f}]")
print(f"   RL² - FF (fqe): {r_rl2.fqe_value - r_ff.fqe_value:+.3f}  "
      f"(>0 => memory advantage now visible in OPE)")
PYEOF

t_end=$(date +%s)
echo ""; echo ">> DONE total $(( (t_end - t0) / 60 )) min  ($(date))"
echo ">> weights: $ART/mahoraga-rl2.srlp  (prev backup: $ART/mahoraga-rl2.prev.srlp)"
