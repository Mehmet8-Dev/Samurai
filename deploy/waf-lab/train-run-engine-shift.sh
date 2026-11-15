#!/usr/bin/env bash
# Engine-shift run: combine the TWO axes that each helped separately —
#   (a) multi-ENGINE diversity  (Coraza :8080  vs  ModSecurity :8081, different
#       engines AND different blocked-variant maps), and
#   (b) WITHIN-episode non-stationarity (the RL²'s recurrent memory only pays when the
#       target changes mid-episode).
# A host socat proxy on :8090 is the single target the closed loop hits; at the episode
# midpoint we re-point it from one engine to the OTHER, so a single episode straddles
# two distinct engines. This is the natural experiment after multi-waf (cross-episode
# only, RL²-FF stayed negative) and regime-shift (within-episode, RL²-FF went +0.37).
#
#   nohup bash deploy/waf-lab/train-run-engine-shift.sh > /tmp/samurai-train-es.log 2>&1 &
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"
PY="${PY:-$REPO/ven311/bin/python}"
ART="$REPO/artifacts/rl"
STAMP="$(date +%Y%m%d-%H%M%S)"
ES_CORPUS="$REPO/data/rl-corpus/engine-shift-$STAMP.ndjson"
export SAMURAI_CLUSTER_SECRET="${SAMURAI_CLUSTER_SECRET:-waf-lab-secret}"
export WAF_LAB_PORT=8090   # the switchable proxy port the closed loop targets

SWEEPS="${SWEEPS:-24}"
CL_MIN_RPS="${CL_MIN_RPS:-20}"
CL_MAX_RPS="${CL_MAX_RPS:-800}"
CL_WINDOW_S="${CL_WINDOW_S:-4}"
CL_AIMD_MAX_WINDOWS="${CL_AIMD_MAX_WINDOWS:-18}"
CL_AIMD_INCREASE_RPS="${CL_AIMD_INCREASE_RPS:-40}"
# name -> backend port
declare -A ENGINE=( [coraza]=8080 [modsec]=8081 )
PAIRS=("coraza:modsec" "modsec:coraza")

echo "=================================================================="
echo ">> Engine-shift run  $(date)  (stamp=$STAMP)"
echo ">> sweeps=$SWEEPS  window=${CL_WINDOW_S}s x $CL_AIMD_MAX_WINDOWS  (mid-episode engine swap via :8090)"
echo "=================================================================="

SOCAT_PID=""
proxy_to() {  # $1 = backend port
    # SIGKILL (not TERM) so a wedged socat always dies; else the reap `wait` hangs forever.
    if [ -n "$SOCAT_PID" ]; then kill -9 "$SOCAT_PID" 2>/dev/null; wait "$SOCAT_PID" 2>/dev/null; fi
    socat TCP-LISTEN:8090,fork,reuseaddr "TCP:127.0.0.1:$1" >/dev/null 2>&1 &
    SOCAT_PID=$!
}
proxy_down() { if [ -n "$SOCAT_PID" ]; then kill -9 "$SOCAT_PID" 2>/dev/null; wait "$SOCAT_PID" 2>/dev/null; fi; SOCAT_PID=""; }
wait_proxy() { for _ in $(seq 1 40); do curl -fsS "http://127.0.0.1:8090/healthz" >/dev/null 2>&1 && return 0; sleep 0.5; done; return 1; }
cleanup() { proxy_down; }
trap cleanup EXIT

for w in mahoraga-rl2 mahoraga-ff; do
    [ -f "$ART/$w.srlp" ] && cp -f "$ART/$w.srlp" "$ART/$w.$STAMP.bak.srlp"
done

: > "$ES_CORPUS"
t0=$(date +%s)
switch_after=$(( CL_AIMD_MAX_WINDOWS * CL_WINDOW_S / 2 ))

for i in $(seq 1 "$SWEEPS"); do
    pair="${PAIRS[$(( (i - 1) % ${#PAIRS[@]} ))]}"
    START="${pair%%:*}"; TARGET="${pair##*:}"
    echo ""; echo ">> sweep $i/$SWEEPS : $START(:${ENGINE[$START]}) --($switch_after s)--> $TARGET(:${ENGINE[$TARGET]})"

    proxy_to "${ENGINE[$START]}"
    if ! wait_proxy; then echo "   (proxy down, skip)"; continue; fi

    tmp="$(mktemp)"
    AUTO_UP=0 RL_EXPLORE=1 RL_EXPLORE_SEED="$i" \
        CL_MIN_RPS="$CL_MIN_RPS" CL_MAX_RPS="$CL_MAX_RPS" \
        CL_WINDOW_S="$CL_WINDOW_S" CL_AIMD_MAX_WINDOWS="$CL_AIMD_MAX_WINDOWS" \
        CL_AIMD_INCREASE_RPS="$CL_AIMD_INCREASE_RPS" \
        CORPUS="$tmp" bash "$HERE/run-corpus.sh" >/tmp/samurai-es-sweep.log 2>&1 &
    sweep_pid=$!

    sleep "$switch_after"
    echo "   >> shifting engine: $START -> $TARGET"
    proxy_to "${ENGINE[$TARGET]}"   # re-point the SAME :8090 to the other engine

    wait "$sweep_pid" 2>/dev/null || echo "   (sweep $i issues, keeping partial)"
    proxy_down
    n=$(wc -l < "$tmp" 2>/dev/null || echo 0)
    cat "$tmp" >> "$ES_CORPUS" 2>/dev/null || true
    rm -f "$tmp"
    echo "   sweep $i: +$n transitions (total $(wc -l < "$ES_CORPUS"))"
done
t_cap=$(date +%s); echo ""; echo ">> engine-shift capture done in $(( (t_cap - t0) / 60 )) min: $(wc -l < "$ES_CORPUS") transitions"

echo ""; echo ">>>>>> RETRAIN on the WHOLE accumulated pool (data/rl-corpus/*.ndjson)"
"$PY" - "$ART" <<'PYEOF'
import sys, glob
import numpy as np
from samurai.models.rl import build_dataset, save_policy
from samurai.models.rl.action_spec import MAHORAGA
from samurai.models.rl.reward import EffectiveThroughputReward
from samurai.models.rl.config import RLConfig
from samurai.models.rl.rl2 import train_rl2, RL2Config
from samurai.models.rl.train import train_iql, IQLConfig
from samurai.models.rl.ope import evaluate_policy

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
print("   ===== OPE (FQE) gate — pool incl. engine-shift =====")
print(f"   behavior (AIMD) : {r_rl2.behavior_return:+.3f}")
print(f"   RL²  fqe={r_rl2.fqe_value:+.3f} gate={r_rl2.gate_pass} "
      f"imp_ci=[{r_rl2.improvement_ci_low:+.3f},{r_rl2.improvement_ci_high:+.3f}]")
print(f"   FF   fqe={r_ff.fqe_value:+.3f} gate={r_ff.gate_pass} "
      f"imp_ci=[{r_ff.improvement_ci_low:+.3f},{r_ff.improvement_ci_high:+.3f}]")
print(f"   RL² - FF (fqe): {r_rl2.fqe_value - r_ff.fqe_value:+.3f}  "
      f"(>0 => memory advantage visible; combines multi-engine + within-episode shift)")
PYEOF

t_end=$(date +%s)
echo ""; echo ">> DONE total $(( (t_end - t0) / 60 )) min  ($(date))"
echo ">> weights: $ART/mahoraga-rl2.srlp   (backup this run: $ART/mahoraga-rl2.$STAMP.bak.srlp)"
