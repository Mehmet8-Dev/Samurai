#!/usr/bin/env bash
# Live on-policy A/B: three arms (AIMD / feedforward-IQL / recurrent-RL²) each DRIVE
# the real WAF lab head-to-head, and we measure served throughput + SLO adherence
# ONLINE — the counterfactual-free evaluation that offline OPE structurally cannot do
# (see memory: OPE feeds a recurrent policy the LOGGED behavior's context, never its
# own). Here each policy builds its OWN context from its OWN actions, exactly as it
# ships.
#
# Why a mid-run engine shift: RL²'s only edge over FF is WITHIN-episode adaptation, so
# a fair test must run the regime where memory can pay. All three arms face the SAME
# schedule — a socat proxy on :8090 that re-points from one engine to the other at the
# run midpoint (Coraza :8080 <-> ModSecurity :8081). Set SHIFT=0 for the static null
# regime (single engine, no swap) as a contrast.
#
# Runs are INTERLEAVED (rep1: aimd,ff,rl2 ; rep2: aimd,ff,rl2 ; ...) so lab drift hits
# every arm equally and the pairwise comparison can be paired by rep.
#
#   nohup bash deploy/waf-lab/ab-live.sh > /tmp/samurai-ablive.log 2>&1 &
#
# Prereqs: lab + zoo up (:8080 Coraza, :8081 ModSec), native daemons + L7 worker built,
# trained policies present (artifacts/rl/mahoraga-rl2.srlp + mahoraga-ff.srlp), socat.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"
PY="${PY:-$REPO/ven311/bin/python}"
ART="${ART:-$REPO/artifacts/rl}"
RL2_POLICY="${RL2_POLICY:-$ART/mahoraga-rl2.srlp}"
FF_POLICY="${FF_POLICY:-$ART/mahoraga-ff.srlp}"
export SAMURAI_CLUSTER_SECRET="${SAMURAI_CLUSTER_SECRET:-waf-lab-secret}"

REPS="${REPS:-5}"
SHIFT="${SHIFT:-1}"
CL_WINDOW_S="${CL_WINDOW_S:-4}"
CL_AIMD_MAX_WINDOWS="${CL_AIMD_MAX_WINDOWS:-18}"
CL_MIN_RPS="${CL_MIN_RPS:-20}"
CL_MAX_RPS="${CL_MAX_RPS:-800}"
CL_SLO_MAX_ERROR_PCT="${CL_SLO_MAX_ERROR_PCT:-2.0}"
CL_SLO_MAX_PUSHBACK_PCT="${CL_SLO_MAX_PUSHBACK_PCT:-0.0}"  # >0 => rate-limit 429 counts as SLO breach
STAMP="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="${RUN_DIR:-$REPO/data/rl-corpus/ablive-$STAMP}"
# Ports are parameterized so one harness runs every regime:
#   static      : SHIFT=0 STATIC_PORT=8080                  (find/respect a fixed ceiling)
#   engine-shift: SHIFT=1 SHIFT_A_PORT=8080 SHIFT_B_PORT=8081 (Coraza <-> ModSec, default)
#   rate-drop   : SHIFT=1 SHIFT_A_PORT=8083 SHIFT_B_PORT=8084 (rate100 <-> rate50)
STATIC_PORT="${STATIC_PORT:-8080}"
SHIFT_A_PORT="${SHIFT_A_PORT:-8080}"
SHIFT_B_PORT="${SHIFT_B_PORT:-8081}"
# alternate which side each rep STARTS on, so start-side bias cancels across reps
PAIRS=("$SHIFT_A_PORT:$SHIFT_B_PORT" "$SHIFT_B_PORT:$SHIFT_A_PORT")
ARMS=(aimd ff rl2)

mkdir -p "$RUN_DIR"
echo "=================================================================="
echo ">> Live on-policy A/B  $(date)  (stamp=$STAMP)"
if [[ "$SHIFT" == "1" ]]; then TGT="shift ${SHIFT_A_PORT}<->${SHIFT_B_PORT}"; else TGT="static :${STATIC_PORT}"; fi
echo ">> arms=${ARMS[*]}  reps=$REPS  target=$TGT  window=${CL_WINDOW_S}s x $CL_AIMD_MAX_WINDOWS"
echo ">> run dir: $RUN_DIR"
echo "=================================================================="

for pol in "$RL2_POLICY" "$FF_POLICY"; do
    [[ -s "$pol" ]] || { echo "!! missing policy: $pol — train first (train-run*.sh)"; exit 1; }
done

SOCAT_PID=""
proxy_to()   { [ -n "$SOCAT_PID" ] && kill "$SOCAT_PID" 2>/dev/null && wait "$SOCAT_PID" 2>/dev/null
               socat TCP-LISTEN:8090,fork,reuseaddr "TCP:127.0.0.1:$1" >/dev/null 2>&1 &
               SOCAT_PID=$!; }
proxy_down() { [ -n "$SOCAT_PID" ] && kill "$SOCAT_PID" 2>/dev/null && wait "$SOCAT_PID" 2>/dev/null; SOCAT_PID=""; }
wait_proxy() { for _ in $(seq 1 40); do curl -fsS "http://127.0.0.1:8090/healthz" >/dev/null 2>&1 && return 0; sleep 0.5; done; return 1; }
trap proxy_down EXIT

switch_after=$(( CL_AIMD_MAX_WINDOWS * CL_WINDOW_S / 2 ))

# one arm run against the (possibly shifting) target -> corpus at $out
run_arm() {  # $1=arm  $2=out_corpus  $3=start_port  $4=target_port
    local arm="$1" out="$2" start_port="$3" target_port="$4"
    local env_arm=()
    case "$arm" in
        aimd) env_arm=(CL_STRATEGY=aimd) ;;
        ff)   env_arm=(RL_POLICY="$FF_POLICY") ;;
        rl2)  env_arm=(RL_POLICY="$RL2_POLICY") ;;
    esac

    if [[ "$SHIFT" == "1" ]]; then
        proxy_to "$start_port"; wait_proxy || { echo "   (proxy down, skip)"; return 1; }
        env AUTO_UP=0 WAF_LAB_PORT=8090 TARGET_HOST=127.0.0.1 \
            "${env_arm[@]}" \
            CL_WINDOW_S="$CL_WINDOW_S" CL_AIMD_MAX_WINDOWS="$CL_AIMD_MAX_WINDOWS" \
            CL_MIN_RPS="$CL_MIN_RPS" CL_MAX_RPS="$CL_MAX_RPS" \
            CL_SLO_MAX_ERROR_PCT="$CL_SLO_MAX_ERROR_PCT" \
            CL_SLO_MAX_PUSHBACK_PCT="$CL_SLO_MAX_PUSHBACK_PCT" \
            CORPUS="$out" bash "$HERE/run-corpus.sh" >/tmp/samurai-ablive-run.log 2>&1 &
        local pid=$!
        sleep "$switch_after"
        proxy_to "$target_port"          # mid-run engine swap, same schedule for all arms
        wait "$pid" 2>/dev/null || true
        proxy_down
    else
        env AUTO_UP=0 WAF_LAB_PORT="$start_port" TARGET_HOST=127.0.0.1 \
            "${env_arm[@]}" \
            CL_WINDOW_S="$CL_WINDOW_S" CL_AIMD_MAX_WINDOWS="$CL_AIMD_MAX_WINDOWS" \
            CL_MIN_RPS="$CL_MIN_RPS" CL_MAX_RPS="$CL_MAX_RPS" \
            CL_SLO_MAX_ERROR_PCT="$CL_SLO_MAX_ERROR_PCT" \
            CL_SLO_MAX_PUSHBACK_PCT="$CL_SLO_MAX_PUSHBACK_PCT" \
            CORPUS="$out" bash "$HERE/run-corpus.sh" >/tmp/samurai-ablive-run.log 2>&1
    fi
    local n; n=$(wc -l < "$out" 2>/dev/null || echo 0)
    echo "   $arm rep: $n transitions -> $(basename "$out")"
}

t0=$(date +%s)
for r in $(seq 1 "$REPS"); do
    if [[ "$SHIFT" == "1" ]]; then
        pair="${PAIRS[$(( (r - 1) % ${#PAIRS[@]} ))]}"
        start="${pair%%:*}"; target="${pair##*:}"
    else
        start="$STATIC_PORT"; target="$STATIC_PORT"
    fi
    echo ""; echo ">> rep $r/$REPS : :${start} --> :${target} (shift=$SHIFT)"
    for arm in "${ARMS[@]}"; do
        run_arm "$arm" "$RUN_DIR/arm=$arm.rep=$r.ndjson" "$start" "$target"
    done
done
echo ""; echo ">> all runs done in $(( ($(date +%s) - t0) / 60 )) min"

echo ""; echo ">>>>>> ANALYSIS"
"$PY" "$HERE/ab_report.py" "$RUN_DIR"
echo ""; echo ">> DONE  ($(date))   run dir: $RUN_DIR"
