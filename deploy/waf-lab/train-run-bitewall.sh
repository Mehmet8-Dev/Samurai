#!/usr/bin/env bash
# Biting-wall capture + retrain — the root-cause fix for the lever-backfire defect.
#
# The whole accumulated pool (data/rl-corpus/*) was captured against a DELAYED rate
# limiter (queued, then 200), so the policy never saw that its concurrency/bursty-pacing
# levers overflow a REJECTING limiter and cost honored throughput. It learned those
# levers were "free". This captures a FRESH, isolated pool against biting (nodelay)
# limiters at several ceilings {50,100,200} plus the WAF+rate Coraza edge, with
# mid-episode rate-drops for non-stationarity, so the EffectiveThroughput reward finally
# punishes the backfiring levers. :8085 (150 r/s) is HELD OUT for the generalization gate.
#
#   nohup bash deploy/waf-lab/train-run-bitewall.sh > /tmp/samurai-bitewall.log 2>&1 &
#
# Prereqs: main lab (:8080 Coraza waf-heavy, nginx nodelay) + rate substrate up
# (docker compose -f deploy/waf-lab/docker-compose.ratedrop.yml up -d), daemons+worker
# built, torch python (PY). Trains to SUFFIXED weights (-bw) so the champion is intact.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"
PY="${PY:-$REPO/ven311/bin/python}"
ART="$REPO/artifacts/rl"
export SAMURAI_CLUSTER_SECRET="${SAMURAI_CLUSTER_SECRET:-waf-lab-secret}"

BITE_DIR="${BITE_DIR:-$REPO/data/rl-corpus-bitewall}"
SUFFIX="${SUFFIX:-bw}"
STATIC_SWEEPS="${STATIC_SWEEPS:-6}"
SHIFT_SWEEPS="${SHIFT_SWEEPS:-6}"
CL_WINDOW_S="${CL_WINDOW_S:-4}"
CL_AIMD_MAX_WINDOWS="${CL_AIMD_MAX_WINDOWS:-18}"
CL_MIN_RPS="${CL_MIN_RPS:-20}"
CL_MAX_RPS="${CL_MAX_RPS:-800}"
# Pushback SLO: treat a rate-limited window as a breach so the loop settles at the
# honored ceiling (0 = off). Captured into the corpus so the policy learns from the
# ceiling-finding dynamics, not blind maxing.
CL_SLO_MAX_PUSHBACK_PCT="${CL_SLO_MAX_PUSHBACK_PCT:-20.0}"
# Training targets (NOT :8085 — that is the held-out generalization ceiling).
# Env-overridable for a wider profile set; default is the pure-rate {100,50,200}+Coraza.
#   BW_STATIC_TARGETS="8084 8083 8086 8080 8081" for the 5-profile diversity set.
read -ra STATIC_TARGETS <<< "${BW_STATIC_TARGETS:-8083 8084 8086 8080}"
read -ra SHIFT_PAIRS <<< "${BW_SHIFT_PAIRS:-8083:8084 8086:8083}"   # rate-drops

mkdir -p "$BITE_DIR"
echo "=================================================================="
echo ">> Biting-wall capture+retrain  $(date)"
echo ">> static targets=${STATIC_TARGETS[*]} x $STATIC_SWEEPS  shift pairs=${SHIFT_PAIRS[*]} x $SHIFT_SWEEPS"
echo ">> pool: $BITE_DIR   window=${CL_WINDOW_S}s x $CL_AIMD_MAX_WINDOWS"
echo "=================================================================="

SOCAT_PID=""
proxy_to()   { [ -n "$SOCAT_PID" ] && kill "$SOCAT_PID" 2>/dev/null && wait "$SOCAT_PID" 2>/dev/null
               socat TCP-LISTEN:8090,fork,reuseaddr "TCP:127.0.0.1:$1" >/dev/null 2>&1 &
               SOCAT_PID=$!; }
proxy_down() { [ -n "$SOCAT_PID" ] && kill "$SOCAT_PID" 2>/dev/null && wait "$SOCAT_PID" 2>/dev/null; SOCAT_PID=""; }
wait_proxy() { for _ in $(seq 1 40); do curl -fsS "http://127.0.0.1:8090/healthz" >/dev/null 2>&1 && return 0; sleep 0.5; done; return 1; }
trap proxy_down EXIT

capture() {  # $1=port $2=corpus $3=seed
    AUTO_UP=0 WAF_LAB_PORT="$1" TARGET_HOST=127.0.0.1 \
        RL_EXPLORE=1 RL_EXPLORE_SEED="$3" \
        CL_STRATEGY=aimd CL_WINDOW_S="$CL_WINDOW_S" CL_AIMD_MAX_WINDOWS="$CL_AIMD_MAX_WINDOWS" \
        CL_MIN_RPS="$CL_MIN_RPS" CL_MAX_RPS="$CL_MAX_RPS" \
        CL_SLO_MAX_PUSHBACK_PCT="$CL_SLO_MAX_PUSHBACK_PCT" \
        CORPUS="$2" bash "$HERE/run-corpus.sh" >/tmp/samurai-bitewall-sweep.log 2>&1
}

t0=$(date +%s); seed=0
STAMP="$(date +%Y%m%d-%H%M%S)"

# --- static multi-ceiling capture ---------------------------------------------------
for tgt in "${STATIC_TARGETS[@]}"; do
    curl -fsS "http://127.0.0.1:$tgt/healthz" >/dev/null 2>&1 || { echo "   (:$tgt down, skip)"; continue; }
    for s in $(seq 1 "$STATIC_SWEEPS"); do
        seed=$((seed + 1))
        out="$BITE_DIR/bw-static-$tgt-$STAMP-$s.ndjson"
        capture "$tgt" "$out" "$seed"
        echo "   static :$tgt sweep $s -> $(wc -l < "$out" 2>/dev/null || echo 0) tr"
    done
done

# --- mid-episode rate-drop capture (non-stationarity for the recurrent policy) -------
switch_after=$(( CL_AIMD_MAX_WINDOWS * CL_WINDOW_S / 2 ))
for pair in "${SHIFT_PAIRS[@]}"; do
    a="${pair%%:*}"; b="${pair##*:}"
    for s in $(seq 1 "$SHIFT_SWEEPS"); do
        seed=$((seed + 1))
        # alternate direction so both drops and rises are seen
        if (( s % 2 == 1 )); then start="$a"; other="$b"; else start="$b"; other="$a"; fi
        out="$BITE_DIR/bw-shift-${start}_${other}-$STAMP-$s.ndjson"
        proxy_to "$start"; wait_proxy || { echo "   (proxy down, skip)"; continue; }
        AUTO_UP=0 WAF_LAB_PORT=8090 TARGET_HOST=127.0.0.1 \
            RL_EXPLORE=1 RL_EXPLORE_SEED="$seed" \
            CL_STRATEGY=aimd CL_WINDOW_S="$CL_WINDOW_S" CL_AIMD_MAX_WINDOWS="$CL_AIMD_MAX_WINDOWS" \
            CL_MIN_RPS="$CL_MIN_RPS" CL_MAX_RPS="$CL_MAX_RPS" \
            CL_SLO_MAX_PUSHBACK_PCT="$CL_SLO_MAX_PUSHBACK_PCT" \
            CORPUS="$out" bash "$HERE/run-corpus.sh" >/tmp/samurai-bitewall-sweep.log 2>&1 &
        pid=$!
        sleep "$switch_after"; proxy_to "$other"       # mid-episode rate drop/rise
        wait "$pid" 2>/dev/null || true; proxy_down
        echo "   shift :$start->:$other sweep $s -> $(wc -l < "$out" 2>/dev/null || echo 0) tr"
    done
done
echo ">> capture done in $(( ($(date +%s) - t0) / 60 )) min"

# --- train on the isolated biting-wall pool (lambda=1.0, the true objective) --------
echo ""; echo ">>>>>> TRAIN on biting-wall pool ($BITE_DIR)"
BITE_DIR="$BITE_DIR" SUFFIX="$SUFFIX" ART="$ART" "$PY" - <<'PYEOF'
import os, glob
import numpy as np
from ddos_samurai.models.rl import build_dataset, save_policy
from ddos_samurai.models.rl.action_spec import MAHORAGA
from ddos_samurai.models.rl.reward import EffectiveThroughputReward
from ddos_samurai.models.rl.config import RLConfig
from ddos_samurai.models.rl.rl2 import train_rl2, RL2Config
from ddos_samurai.models.rl.train import train_iql, IQLConfig
from ddos_samurai.models.rl.ope import evaluate_policy

art = os.environ["ART"]; suffix = os.environ["SUFFIX"]; bite = os.environ["BITE_DIR"]
cfg = RLConfig()  # lambda_defense=1.0 — matches the fixed evaluation yardstick
files = sorted(glob.glob(f"{bite}/*.ndjson"))
ds = build_dataset(files, cfg, reward_fn=EffectiveThroughputReward(cfg), action_spec=MAHORAGA)
n_eps = int(np.unique(ds.episode_ids).size)
print(f"   pool: {len(files)} files -> {len(ds)} transitions, {n_eps} episodes")

rl2 = train_rl2(ds, RL2Config(seed=0)); save_policy(rl2, f"{art}/mahoraga-rl2-{suffix}.srlp")
ff = train_iql(ds, IQLConfig(seed=0));  save_policy(ff,  f"{art}/mahoraga-ff-{suffix}.srlp")
print(f"   saved -> mahoraga-rl2-{suffix}.srlp / mahoraga-ff-{suffix}.srlp")
r2 = evaluate_policy(ds, rl2); rf = evaluate_policy(ds, ff)
print(f"   OPE(traj): AIMD {r2.behavior_return:+.3f}  RL² {r2.fqe_value:+.3f}  FF {rf.fqe_value:+.3f}  RL²-FF {r2.fqe_value-rf.fqe_value:+.3f}")
PYEOF
echo ""; echo ">> DONE total $(( ($(date +%s) - t0) / 60 )) min  ($(date))"
echo ">> next: A/B gate with RL2_POLICY=$ART/mahoraga-rl2-$SUFFIX.srlp FF_POLICY=$ART/mahoraga-ff-$SUFFIX.srlp"
