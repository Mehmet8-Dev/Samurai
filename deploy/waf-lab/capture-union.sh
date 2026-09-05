#!/usr/bin/env bash
# Capture a multi-episode corpus for one defense profile by sweeping the
# closed-loop several times with different exploration seeds (each run = one
# episode with a unique run_id), appending them into a single per-profile file.
#
# Usage:  WAF_PROFILE=rate-only SWEEPS=8 CL_MAX_RPS=1200 ./capture-union.sh
# Then union the per-profile files for training (build_dataset accepts a glob/list).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

WAF_PROFILE="${WAF_PROFILE:-strict-waf}"
SWEEPS="${SWEEPS:-8}"
OUT="${OUT:-$REPO/data/rl-corpus/${WAF_PROFILE}.ndjson}"
export WAF_PROFILE

echo ">> [$WAF_PROFILE] recreating lab tier once"
WAF_PROFILE="$WAF_PROFILE" docker compose -f "$HERE/docker-compose.yml" \
    up -d --force-recreate nginx caddy whoami >/dev/null
sleep 3

: > "$OUT"   # truncate the union target
for i in $(seq 1 "$SWEEPS"); do
    tmp="$(mktemp)"
    echo ">> [$WAF_PROFILE] sweep $i/$SWEEPS (seed=$i) -> $tmp"
    AUTO_UP=0 WAF_PROFILE="$WAF_PROFILE" \
        RL_EXPLORE=1 RL_EXPLORE_SEED="$i" \
        CL_MIN_RPS="${CL_MIN_RPS:-20}" CL_MAX_RPS="${CL_MAX_RPS:-800}" \
        CL_WINDOW_S="${CL_WINDOW_S:-4}" CL_AIMD_MAX_WINDOWS="${CL_AIMD_MAX_WINDOWS:-20}" \
        CL_AIMD_INCREASE_RPS="${CL_AIMD_INCREASE_RPS:-40}" \
        CORPUS="$tmp" "$HERE/run-corpus.sh" >/dev/null 2>&1 || echo "   (sweep $i failed, skipping)"
    cat "$tmp" >> "$OUT" 2>/dev/null || true
    rm -f "$tmp"
done
echo ">> [$WAF_PROFILE] done: $(wc -l < "$OUT") transitions in $OUT"
