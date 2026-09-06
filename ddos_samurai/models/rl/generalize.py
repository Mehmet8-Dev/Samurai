"""Leave-one-profile-out generalization eval for the offline-RL policy.

The union corpus mixes distinct defense profiles (strict-waf / rate-only / waf-heavy
— labeled in the capture filename, see deploy/waf-lab/run-corpus.sh). Scoring a policy
on the same data it trained on says nothing about whether it learned a *transferable*
defense response or just memorized the training mix. This measures the former: for
each profile, train on the OTHER profiles and FQE-score the held-out one. A policy that
generalizes clears the (pessimistic) gate on a profile it never trained on; a large gap
between the in-distribution and held-out improvement is overfit.

Training + FQE need torch (imported lazily), so this stays importable torch-free for
the pure filename-grouping helpers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .action_spec import MAHORAGA, ActionSpec
from .config import RLConfig
from .dataset import build_dataset
from .reward import EffectiveThroughputReward, RewardFn

# Capture files are named waf-lab-<profile>-<timestamp>.ndjson (run-corpus.sh). Pull
# the profile token out; fall back to the whole stem for anything off-pattern.
_PROFILE_RE = re.compile(r"waf-lab-(?P<profile>.+?)-\d{8}(?:-\d{6})?\b")


def profile_of(path: str | Path) -> str:
    """Profile label for a corpus file, inferred from its name."""
    stem = Path(path).name
    m = _PROFILE_RE.search(stem)
    if m:
        return m.group("profile")
    # Off-pattern: strip a trailing timestamp/extension, else use the bare stem.
    return Path(path).stem


def group_by_profile(
    paths: Iterable[str | Path],
) -> dict[str, list[Path]]:
    """Group corpus files by inferred profile, preserving input order per profile."""
    groups: dict[str, list[Path]] = {}
    for p in paths:
        groups.setdefault(profile_of(p), []).append(Path(p))
    return groups


@dataclass(frozen=True)
class FoldResult:
    held_out: str          # the profile left out of training
    n_train_episodes: int
    n_eval_episodes: int
    in_dist: "object"      # OPEResult on the training union (in-distribution reference)
    transfer: "object"     # OPEResult on the held-out profile (generalization)

    @property
    def gap(self) -> float:
        """In-distribution minus held-out improvement — the overfit gap (>=0 typical;
        large means the policy leans on the training mix and transfers poorly)."""
        return self.in_dist.improvement - self.transfer.improvement

    @property
    def generalizes(self) -> bool:
        """The held-out profile clears the same (pessimistic) gate as in-distribution."""
        return bool(self.transfer.gate_pass)


@dataclass(frozen=True)
class GeneralizationResult:
    folds: tuple[FoldResult, ...]

    @property
    def mean_transfer_improvement(self) -> float:
        if not self.folds:
            return 0.0
        return sum(f.transfer.improvement for f in self.folds) / len(self.folds)

    @property
    def worst_transfer_improvement(self) -> float:
        return min((f.transfer.improvement for f in self.folds), default=0.0)

    @property
    def all_generalize(self) -> bool:
        """Every held-out profile cleared its gate — the policy transfers everywhere."""
        return bool(self.folds) and all(f.generalizes for f in self.folds)

    def format_report(self) -> str:
        lines = ["leave-one-profile-out generalization:",
                 f"  {'held-out':<14} {'transfer_imp':>12} {'in_dist_imp':>12} "
                 f"{'gap':>8} {'gate':>6}"]
        for f in self.folds:
            lines.append(
                f"  {f.held_out:<14} {f.transfer.improvement:>12.3f} "
                f"{f.in_dist.improvement:>12.3f} {f.gap:>8.3f} "
                f"{'PASS' if f.generalizes else 'FAIL':>6}")
        lines.append(f"  mean transfer improvement: {self.mean_transfer_improvement:.3f} "
                     f"(worst {self.worst_transfer_improvement:.3f}); "
                     f"all-generalize={self.all_generalize}")
        return "\n".join(lines)


def leave_one_profile_out(
    paths_by_profile: dict[str, list[str | Path]],
    *,
    cfg: RLConfig | None = None,
    action_spec: ActionSpec | None = None,
    reward_fn: RewardFn | None = None,
    iql_config: "object" = None,
    fqe_config: "object" = None,
) -> GeneralizationResult:
    """Train on all-but-one profile and FQE-score the held-out one, per profile.

    Defaults target the defense-aware lab setting: EffectiveThroughputReward + the full
    Mahoraga action. Every fold builds train/eval datasets with the SAME cfg/action_spec
    so the trained policy's input width matches the held-out dataset it is scored on.
    """
    from .train import IQLConfig, train_iql   # torch
    from .ope import FQEConfig, evaluate_policy

    cfg = cfg or RLConfig()
    action_spec = action_spec or MAHORAGA
    reward_fn = reward_fn or EffectiveThroughputReward(cfg)
    iql_config = iql_config or IQLConfig()
    fqe_config = fqe_config or FQEConfig()

    profiles = sorted(paths_by_profile)
    if len(profiles) < 2:
        raise ValueError(
            f"leave-one-profile-out needs >=2 profiles, got {profiles}")

    folds: list[FoldResult] = []
    for held in profiles:
        train_paths = [p for prof in profiles if prof != held
                       for p in paths_by_profile[prof]]
        eval_paths = list(paths_by_profile[held])

        train_ds = build_dataset(train_paths, cfg, reward_fn=reward_fn,
                                 action_spec=action_spec)
        eval_ds = build_dataset(eval_paths, cfg, reward_fn=reward_fn,
                                action_spec=action_spec)

        artifact = train_iql(train_ds, iql_config)
        in_dist = evaluate_policy(train_ds, artifact, fqe_config)
        transfer = evaluate_policy(eval_ds, artifact, fqe_config)

        folds.append(FoldResult(
            held_out=held,
            n_train_episodes=in_dist.n_episodes,
            n_eval_episodes=transfer.n_episodes,
            in_dist=in_dist,
            transfer=transfer,
        ))
    return GeneralizationResult(tuple(folds))


def _main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--corpus", nargs="+", required=True,
                    help="corpus files across >=2 profiles (profile inferred from name)")
    ap.add_argument("--variants", type=int, default=5, help="request_mix cardinality")
    ap.add_argument("--block", action="store_true",
                    help="enable the path-aware variant-block state feature")
    ap.add_argument("--ban", action="store_true",
                    help="enable the persistent-ban state feature")
    ap.add_argument("--rps-scale", type=float, default=0.0,
                    help="fixed reward rps_scale across profiles (0 = per-record max_rps)")
    args = ap.parse_args(argv)

    groups = group_by_profile(args.corpus)
    cfg = RLConfig(
        variant_block_features=args.block,
        ban_state_features=args.ban,
        request_variant_count=args.variants,
        rps_scale=args.rps_scale,
    )
    print(f">> profiles: {', '.join(f'{k}({len(v)})' for k, v in sorted(groups.items()))}")
    res = leave_one_profile_out(groups, cfg=cfg)
    print(res.format_report())
    return 0 if res.all_generalize else 1


if __name__ == "__main__":
    raise SystemExit(_main())
