#!/usr/bin/env bash
# Retrain RL² + FF on the accumulated pool with a tunable defense penalty
# (lambda_defense), to probe the under-drive defect the live A/B surfaced: with the
# default lambda_defense=1.0 the learned policies sit at ~1/4 of the honored ceiling
# because any 429 is penalized hard. Lowering it trades a little pushback for more
# served throughput. Trains to SUFFIXED weight files so the lambda=1.0 champion is
# left intact for a head-to-head A/B.
#
#   LAMBDA_DEFENSE=0.3 bash deploy/waf-lab/retrain-lambda.sh
#
# Scoring stays at the default lambda=1.0 (ab_report.py) — the fixed product yardstick
# — so the question is: does relaxing the TRAINING penalty yield a policy that does
# better on the true objective, not just one that serves more into the wall.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"
PY="${PY:-$REPO/ven311/bin/python}"
ART="$REPO/artifacts/rl"
LAMBDA_DEFENSE="${LAMBDA_DEFENSE:-0.3}"
SUFFIX="${SUFFIX:-ld$(echo "$LAMBDA_DEFENSE" | tr -d '.')}"   # 0.3 -> ld03

echo ">> retrain on pool with lambda_defense=$LAMBDA_DEFENSE -> suffix '$SUFFIX'"
LAMBDA_DEFENSE="$LAMBDA_DEFENSE" SUFFIX="$SUFFIX" ART="$ART" "$PY" - <<'PYEOF'
import os, glob
import numpy as np
from ddos_samurai.models.rl import build_dataset, save_policy
from ddos_samurai.models.rl.action_spec import MAHORAGA
from ddos_samurai.models.rl.reward import EffectiveThroughputReward
from ddos_samurai.models.rl.config import RLConfig
from ddos_samurai.models.rl.rl2 import train_rl2, RL2Config
from ddos_samurai.models.rl.train import train_iql, IQLConfig
from ddos_samurai.models.rl.ope import evaluate_policy

art = os.environ["ART"]; suffix = os.environ["SUFFIX"]
ld = float(os.environ["LAMBDA_DEFENSE"])
cfg = RLConfig(lambda_defense=ld)
files = sorted(glob.glob("data/rl-corpus/*.ndjson"))
ds = build_dataset(files, cfg, reward_fn=EffectiveThroughputReward(cfg), action_spec=MAHORAGA)
n_eps = int(np.unique(ds.episode_ids).size)
print(f"   pool: {len(files)} files -> {len(ds)} transitions, {n_eps} episodes  (lambda_defense={ld})")

rl2 = train_rl2(ds, RL2Config(seed=0)); save_policy(rl2, f"{art}/mahoraga-rl2-{suffix}.srlp")
ff = train_iql(ds, IQLConfig(seed=0));  save_policy(ff,  f"{art}/mahoraga-ff-{suffix}.srlp")
print(f"   saved -> mahoraga-rl2-{suffix}.srlp / mahoraga-ff-{suffix}.srlp")

# OPE (trajectory) for a quick sanity read; live A/B is the real gate.
r2 = evaluate_policy(ds, rl2); rf = evaluate_policy(ds, ff)
print(f"   OPE(traj): AIMD {r2.behavior_return:+.3f}  RL² {r2.fqe_value:+.3f}  FF {rf.fqe_value:+.3f}  RL²-FF {r2.fqe_value-rf.fqe_value:+.3f}")
PYEOF
echo ">> done. A/B these with:  RL2_POLICY=$ART/mahoraga-rl2-$SUFFIX.srlp FF_POLICY=$ART/mahoraga-ff-$SUFFIX.srlp bash deploy/waf-lab/ab-live.sh"
