from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RLConfig:
    """Feature layout, reward shaping, and imputation for the offline-RL pipeline.

    Reward (computed offline so it can be retuned without recapturing the corpus):

        r = progress - lambda_slo * slo_overshoot - step_cost

      progress      = max(0, s2.rps - s.rps) / rps_scale   when the window is SLO-green,
                      0 otherwise. Advancing the *sustainable* load is the only gain.
      slo_overshoot = worst normalized breach across the active SLO rules
                      (error / loss / rate-accuracy / latency), 0 when green.
      step_cost     = flat per-window cost; rewards fast convergence to the ceiling.

    rps_scale defaults to the run's max_rps (progress lands in ~[-1, 1]); set
    rps_scale > 0 to override with a fixed scale across heterogeneous runs.
    """

    # State feature order fed to the policy. Unknown (<0) raw fields are imputed to
    # `impute_value` and flagged by a companion "*_known" mask feature when
    # `mask_unknown` is set, so the policy can tell "0ms p99" from "no p99 signal".
    feature_names: tuple[str, ...] = field(
        default=(
            "rps_norm",       # s.rps / max_rps (realized operating point)
            "error_pct",      # effective error percent
            "loss_pct",
            "rate_accuracy_pct",
            "p99_ms",
            "step_norm",      # win / step_horizon
            # Mahoraga defense-reaction features (derived ratios; see DefenseSignals).
            "rate_limited_ratio",   # 4xx share — 429/403 under rate-limit / WAF
            "overload_ratio",       # 5xx share — 503 as the SUT sheds load
            "conn_drop_ratio",      # IPS/WAF refusing/resetting connections
            "reset_pressure",       # HTTP/2 stream-reset ratio
            "challenge_rate",       # WAF challenge / unexpected-response rate
        )
    )
    mask_unknown: bool = True
    impute_value: float = 0.0
    step_horizon: float = 32.0  # normalizer for the window index feature

    # Reward shaping.
    lambda_slo: float = 2.0
    step_cost: float = 0.02
    rps_scale: float = 0.0  # <=0 => per-record max_rps
    # Defense penalty weight (EffectiveThroughputReward): how hard rate-limiting /
    # overload pushback (4xx/5xx share) is penalized. This is what makes the RL
    # objective differ from AIMD — it discourages blasting past the defense wall
    # into wasted, rejected load instead of maximizing *served* throughput.
    lambda_defense: float = 1.0

    # Corpus hygiene.
    drop_leading: bool = True  # drop the s_valid=False first window of every episode
    drop_no_traffic: bool = True  # drop windows whose s2 attempted <= 0

    @property
    def feature_count(self) -> int:
        base = len(self.feature_names)
        if not self.mask_unknown:
            return base
        # One mask bit per maskable raw field (the four that can be unknown).
        return base + len(self.maskable_features)

    @property
    def maskable_features(self) -> tuple[str, ...]:
        return (
            "error_pct",
            "loss_pct",
            "rate_accuracy_pct",
            "p99_ms",
            "rate_limited_ratio",
            "overload_ratio",
            "conn_drop_ratio",
            "reset_pressure",
            "challenge_rate",
        )
