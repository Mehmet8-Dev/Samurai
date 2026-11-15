#!/usr/bin/env bash
# Drive the closed-loop autopilot against the WAF lab and capture an RL corpus.
#
# Prereqs:
#   1. The lab is up:   docker compose -f deploy/waf-lab/docker-compose.yml up -d --build
#   2. The native daemons + an L7 worker are built (see build/).
#
# This brings up one L7 worker + the master with --closed-loop --rl-corpus pointed
# at the lab ingress, so every measured window is logged as an (s,a,s') transition
# carrying the lab's defense reactions (429 / 403 / 503 / connection drops). Feed
# the resulting NDJSON to samurai/models/rl (build_dataset).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
BIN_DAEMON="${BIN_DAEMON:-$REPO/build/control/daemon}"
BIN_WORKER="${BIN_WORKER:-$REPO/build/zmq}"

WAF_LAB_PORT="${WAF_LAB_PORT:-8080}"
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
# Dataplane transport. custom_tcp (userspace TCP) exposes the flow-level counters
# (tcp_peer_rst / connect_timeout / retransmit / timeout_close) that the flow-level
# IPS/NSM features consume; kernel_socket does not. Recorded in the corpus so the
# offline pipeline can gate those features by transport.
TRANSPORT="${TRANSPORT:-kernel_socket}"
# The L7 worker job is a fixed BINARY envelope (JobEnvelopeV2) with no transport
# field, so the master's --transport only LABELS the corpus — it does not reach the
# worker's datapath. The worker's real transport knob is the SAMURAI_L7_TRANSPORT
# env, which slave-spawned shard workers inherit. Export it here so --transport is
# actually honored end-to-end (otherwise custom_tcp silently runs on kernel_socket).
export SAMURAI_L7_TRANSPORT="$TRANSPORT"
CONTROL_EP="${CONTROL_EP:-tcp://127.0.0.1:5099}"
# Defense profile (strict-waf|rate-only|waf-heavy) — selects the compose tier and
# labels the corpus so the union is traceable. AUTO_UP=1 (re)creates the nginx/caddy
# tier for this profile before capture (needs docker + the image already built).
WAF_PROFILE="${WAF_PROFILE:-strict-waf}"
AUTO_UP="${AUTO_UP:-0}"
export WAF_PROFILE
CORPUS="${CORPUS:-$REPO/data/rl-corpus/waf-lab-${WAF_PROFILE}-$(date +%Y%m%d-%H%M%S).ndjson}"
CLUSTER_SECRET="${SAMURAI_CLUSTER_SECRET:-waf-lab-secret}"
export SAMURAI_CLUSTER_SECRET="$CLUSTER_SECRET"

# Closed-loop / SLO knobs. Defaults sit around the lab's 200 r/s limiter so the
# search actually walks into the defense wall. Override via env as needed.
CL_STRATEGY="${CL_STRATEGY:-aimd}"
CL_MIN_RPS="${CL_MIN_RPS:-50}"
CL_MAX_RPS="${CL_MAX_RPS:-2000}"
CL_WINDOW_S="${CL_WINDOW_S:-5}"
CL_SLO_MAX_ERROR_PCT="${CL_SLO_MAX_ERROR_PCT:-2.0}"
# Defense-pushback SLO: (4xx+5xx)/responses*100 <= X (0 = off). Set >0 so the loop
# treats ramping into a rate wall as a breach and settles at the honored ceiling.
CL_SLO_MAX_PUSHBACK_PCT="${CL_SLO_MAX_PUSHBACK_PCT:-0.0}"
CL_AIMD_MAX_WINDOWS="${CL_AIMD_MAX_WINDOWS:-40}"
CL_AIMD_INCREASE_RPS="${CL_AIMD_INCREASE_RPS:-0}"  # 0 => controller default step

# Exploration: perturb the Mahoraga shaping levers per window so the corpus has
# variation to learn from (RL_EXPLORE=1 to enable; RL_EXPLORE_SEED for repeats).
RL_EXPLORE="${RL_EXPLORE:-0}"
RL_EXPLORE_SEED="${RL_EXPLORE_SEED:-0}"
EXPLORE_ARGS=()
if [[ "$RL_EXPLORE" == "1" ]]; then
	EXPLORE_ARGS=(--rl-explore --rl-explore-seed "$RL_EXPLORE_SEED")
fi

# Serving mode: point at a trained SRLP policy to run kRl (RL proposes, shields
# dispose). RL_POLICY sets --rl-policy; LEVER_SHIELD (0|1) toggles the online
# request_mix veto. Setting RL_POLICY also forces CL_STRATEGY=rl.
RL_POLICY="${RL_POLICY:-}"
SERVE_ARGS=()
if [[ -n "$RL_POLICY" ]]; then
	CL_STRATEGY="rl"
	SERVE_ARGS=(--rl-policy "$RL_POLICY")
	if [[ -n "${LEVER_SHIELD:-}" ]]; then
		SERVE_ARGS+=(--cl-lever-shield "$LEVER_SHIELD")
	fi
	# VARIANT_MEMORY: persist/warm-start the per-target block memory across runs.
	# With a block-aware policy (in_dim 30) this also feeds the block state feature.
	# Seed it from a fingerprint prior before serving so episode 1 already knows the
	# target's path-blocked variants (no rediscovery window):
	#   python -m samurai.models.rl.variant_prior \
	#       --corpus data/rl-corpus/<profile>.ndjson --target "$TARGET_HOST:$WAF_LAB_PORT" \
	#       --variants 5 --out "$VARIANT_MEMORY"
	if [[ -n "${VARIANT_MEMORY:-}" ]]; then
		SERVE_ARGS+=(--cl-variant-memory "$VARIANT_MEMORY")
	fi
	# BAN_MEMORY: persist/warm-start the per-target persistent-ban pressure across
	# runs (a ban-aware policy, in_dim +2). A run against an already-banned target
	# starts armed instead of re-folding the ban from zero.
	if [[ -n "${BAN_MEMORY:-}" ]]; then
		SERVE_ARGS+=(--cl-ban-memory "$BAN_MEMORY")
	fi
fi

echo ">> defense profile: $WAF_PROFILE"
# Optionally (re)create the rate-limit + WAF tier for this profile. nginx re-reads
# its config on recreate; caddy picks up the profile's waf-rules.conf bind-mount.
if [[ "$AUTO_UP" == "1" ]]; then
	echo ">> bringing up lab tier for profile '$WAF_PROFILE' (docker compose up -d)"
	WAF_PROFILE="$WAF_PROFILE" docker compose -f "$HERE/docker-compose.yml" up -d \
		--force-recreate nginx caddy whoami >/dev/null
	sleep 2
fi

echo ">> checking lab ingress http://$TARGET_HOST:$WAF_LAB_PORT/healthz"
if ! curl -fsS "http://$TARGET_HOST:$WAF_LAB_PORT/healthz" >/dev/null 2>&1; then
	echo "!! lab ingress not responding — start it first:" >&2
	echo "   docker compose -f $HERE/docker-compose.yml up -d --build" >&2
	exit 1
fi

mkdir -p "$(dirname "$CORPUS")"

# Ordering matters: the master owns the control-plane listen socket, so it must
# be up before the slave tries to register. Start worker + master first, wait
# for the master's control port to accept, then bring up the slave.
echo ">> starting L7 worker"
"$BIN_WORKER/samurai_l7_worker" >/tmp/samurai-lab-worker.log 2>&1 &
WORKER_PID=$!

echo ">> starting master (closed-loop); corpus -> $CORPUS"
"$BIN_DAEMON/samurai_master" \
	--control-listen "$CONTROL_EP" \
	--target "$TARGET_HOST" --port "$WAF_LAB_PORT" --protocol http \
	--transport "$TRANSPORT" \
	--worker l7 --count "$(( CL_MAX_RPS * CL_WINDOW_S ))" \
	--expect-workers 1 --wait-workers-s 60 \
	--closed-loop --cl-strategy "$CL_STRATEGY" \
	--cl-window-s "$CL_WINDOW_S" \
	--cl-min-rps "$CL_MIN_RPS" --cl-max-rps "$CL_MAX_RPS" \
	--cl-slo-max-error-pct "$CL_SLO_MAX_ERROR_PCT" \
	--cl-slo-max-pushback-pct "$CL_SLO_MAX_PUSHBACK_PCT" \
	--cl-aimd-max-windows "$CL_AIMD_MAX_WINDOWS" \
	--cl-aimd-increase-rps "$CL_AIMD_INCREASE_RPS" \
	"${EXPLORE_ARGS[@]}" \
	"${SERVE_ARGS[@]}" \
	--rl-corpus "$CORPUS" >/tmp/samurai-lab-master.log 2>&1 &
MASTER_PID=$!
SLAVE_PID=""

cleanup() { kill "$WORKER_PID" "$SLAVE_PID" "$MASTER_PID" 2>/dev/null || true; }
trap cleanup EXIT

CONTROL_PORT="${CONTROL_EP##*:}"
echo ">> waiting for master control port :$CONTROL_PORT"
for _ in $(seq 1 30); do
	if (exec 3<>"/dev/tcp/127.0.0.1/$CONTROL_PORT") 2>/dev/null; then exec 3>&- 3<&-; break; fi
	sleep 0.5
done

echo ">> starting slave (registers + runs shards)"
# Pass the full tcp:// endpoint — the control client hands it straight to
# zmq_connect, which requires the transport scheme.
"$BIN_DAEMON/samurai_slave" \
	--control-endpoints "$CONTROL_EP" \
	--worker l7 --worker-dir "$BIN_WORKER" \
	>/tmp/samurai-lab-slave.log 2>&1 &
SLAVE_PID=$!

echo ">> capture running; waiting for the closed-loop to finish"
wait "$MASTER_PID"

echo ">> done. transitions:"
wc -l "$CORPUS" || true
echo ">> build a dataset:"
echo "   python -c \"from samurai.models.rl import build_dataset; d=build_dataset('$CORPUS'); print(len(d), d.feature_names)\""
