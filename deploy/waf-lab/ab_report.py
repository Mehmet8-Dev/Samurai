#!/usr/bin/env python3
"""Analyze a live on-policy A/B run directory (see ab-live.sh).

Reads per-run serve corpora named ``arm=<aimd|ff|rl2>.rep=<n>.ndjson`` and reports,
per arm, the PRIMARY metric — mean per-window EffectiveThroughput reward, the exact
objective the policies are trained on (served 2xx minus overshoot / defense-pushback /
SLO penalties) — plus the descriptive served throughput (2xx/s) and SLO adherence.
Everything is aggregated across reps with a bootstrap CI, and pairwise differences are
paired by rep (the reps are interleaved so each arm faces the same schedule). The
verdict is the product decision: does the recurrent RL² earn its extra complexity over
the feedforward policy on a live, self-driven target — the question offline OPE cannot
answer.

Measuring EffectiveThroughput, not raw 2xx/s, is deliberate: raw served throughput
rewards whichever arm ramps rps hardest regardless of efficiency, so on a target it
never overloads, blind AIMD "wins" by brute force. EffectiveThroughput is the same
ruler the "+3-4 beats AIMD" offline number used, so live and offline are comparable.

Uses build_dataset + EffectiveThroughputReward (numpy; no torch needed for the reward).
"""

from __future__ import annotations

import glob
import json
import os
import re
import sys

import numpy as np

# Run as a script (sys.path[0] is this file's dir, not the repo root), so add the repo
# root explicitly to import the ddos_samurai package.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from ddos_samurai.models.rl import build_dataset
from ddos_samurai.models.rl.action_spec import MAHORAGA
from ddos_samurai.models.rl.config import RLConfig
from ddos_samurai.models.rl.reward import EffectiveThroughputReward

ARMS = ("aimd", "ff", "rl2")
LABEL = {"aimd": "AIMD  ", "ff": "FF    ", "rl2": "RL²   "}
_NAME = re.compile(r"arm=(?P<arm>\w+)\.rep=(?P<rep>\d+)\.ndjson$")

_CFG = RLConfig()
_REWARD = EffectiveThroughputReward(_CFG)


def run_metrics(path: str) -> tuple[float, float, float, int] | None:
    """(mean EffectiveThroughput, mean served 2xx/s, SLO-adherence, #windows), or None.

    EffectiveThroughput is the trained objective, computed over the SAME reward pipeline
    training used (build_dataset + EffectiveThroughputReward on the Mahoraga action
    space); served/SLO are read straight off the corpus for color."""
    served: list[float] = []
    healthy: list[float] = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        d = r.get("s2", {}).get("defense", {})
        ws = r.get("window_s", 1) or 1
        if "status_2xx" in d:
            served.append(float(d["status_2xx"]) / ws)
            healthy.append(1.0 if r.get("healthy", False) else 0.0)
    if not served:
        return None
    try:
        ds = build_dataset([path], _CFG, reward_fn=_REWARD, action_spec=MAHORAGA)
        eff = float(ds.rewards.mean()) if len(ds) else 0.0
    except Exception as exc:  # a malformed run should not sink the whole report
        print(f"   (warn: reward build failed for {os.path.basename(path)}: {exc})")
        eff = 0.0
    return eff, float(np.mean(served)), float(np.mean(healthy)), len(served)


def _boot_mean_ci(x: np.ndarray, n_boot: int, alpha: float, seed: int) -> tuple[float, float]:
    if x.size == 0:
        return 0.0, 0.0
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, x.size, size=(n_boot, x.size))
    m = x[idx].mean(axis=1)
    return (float(np.percentile(m, 100 * alpha / 2)),
            float(np.percentile(m, 100 * (1 - alpha / 2))))


def _paired_diff_ci(a: np.ndarray, b: np.ndarray, n_boot: int, alpha: float,
                    seed: int) -> tuple[float, float, float]:
    """mean(a-b) and its CI, resampling paired reps together."""
    n = min(a.size, b.size)
    a, b = a[:n], b[:n]
    d = a - b
    if n == 0:
        return 0.0, 0.0, 0.0
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, n, size=(n_boot, n))
    m = d[idx].mean(axis=1)
    return (float(d.mean()),
            float(np.percentile(m, 100 * alpha / 2)),
            float(np.percentile(m, 100 * (1 - alpha / 2))))


def main() -> int:
    run_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    n_boot = int(os.environ.get("AB_NBOOT", "5000"))
    alpha = float(os.environ.get("AB_ALPHA", "0.10"))  # 90% CI

    by_arm: dict[str, list[tuple[int, float, float, float]]] = {a: [] for a in ARMS}
    for path in sorted(glob.glob(os.path.join(run_dir, "arm=*.rep=*.ndjson"))):
        m = _NAME.search(os.path.basename(path))
        if not m or m["arm"] not in by_arm:
            continue
        met = run_metrics(path)
        if met is None:
            continue
        eff, served, slo, _w = met
        by_arm[m["arm"]].append((int(m["rep"]), eff, served, slo))

    eff: dict[str, np.ndarray] = {}
    served: dict[str, np.ndarray] = {}
    slo: dict[str, np.ndarray] = {}
    for a in ARMS:
        rows = sorted(by_arm[a])  # by rep, so arms align for pairing
        eff[a] = np.array([x[1] for x in rows], dtype=np.float64)
        served[a] = np.array([x[2] for x in rows], dtype=np.float64)
        slo[a] = np.array([x[3] for x in rows], dtype=np.float64)

    print("   ===== per-arm EffectiveThroughput (trained objective) + served/SLO =====")
    print(f"   {'arm':<8}{'reps':>5}{'eff_mean':>11}{'eff_CI90':>20}"
          f"{'served/s':>11}{'slo_ok':>9}")
    for a in ARMS:
        e = eff[a]
        if e.size == 0:
            print(f"   {LABEL[a]}    (no runs)")
            continue
        lo, hi = _boot_mean_ci(e, n_boot, alpha, seed=0)
        print(f"   {LABEL[a]}{e.size:>5}{e.mean():>11.3f}"
              f"{f'[{lo:.3f}, {hi:.3f}]':>20}{served[a].mean():>11.1f}{slo[a].mean():>9.1%}")

    print("")
    print("   ===== pairwise EffectiveThroughput differences (paired by rep, 90% CI) =====")
    pairs = [("rl2", "ff"), ("rl2", "aimd"), ("ff", "aimd")]
    diffs: dict[tuple[str, str], tuple[float, float, float]] = {}
    for x, y in pairs:
        if eff[x].size == 0 or eff[y].size == 0:
            continue
        d, lo, hi = _paired_diff_ci(eff[x], eff[y], n_boot, alpha, seed=0)
        diffs[(x, y)] = (d, lo, hi)
        sig = "  (CI clears 0)" if lo > 0 else ("  (CI below 0)" if hi < 0 else "  (CI spans 0)")
        print(f"   {LABEL[x].strip()} - {LABEL[y].strip():<5} : {d:+8.3f}  "
              f"CI90=[{lo:+.3f}, {hi:+.3f}]{sig}")

    # Verdict: the product decision on RL² vs FF, on the trained objective.
    print("")
    print("   ===== verdict =====")
    if ("rl2", "ff") in diffs:
        d, lo, hi = diffs[("rl2", "ff")]
        if lo > 0:
            print(f"   RL² BEATS FF live by {d:+.3f} EffThroughput (CI lower bound {lo:+.3f} > 0).")
            print("   => the in-context advantage is REAL on a self-driven target;")
            print("      investing in RL² capacity (deeper/longer context) is justified.")
        elif hi < 0:
            print(f"   FF BEATS RL² live by {-d:.3f} EffThroughput (CI upper bound {hi:+.3f} < 0).")
            print("   => ship the feedforward policy; RL²'s complexity is not paying off.")
        else:
            print(f"   RL² vs FF is a TIE live ({d:+.3f} EffThroughput, CI spans 0).")
            print("   => ship the simpler feedforward policy; no evidence RL² earns its keep")
            print("      in this regime. Revisit only if a harder shift regime separates them.")
    for k in (("rl2", "aimd"), ("ff", "aimd")):
        if k in diffs:
            d, lo, _hi = diffs[k]
            verdict = "beats" if lo > 0 else "does NOT beat"
            print(f"   {LABEL[k[0]].strip()} {verdict} AIMD ({d:+.3f} EffThroughput, CI low {lo:+.3f}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
