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

    # Path-aware state: append a per-variant "block" memory to the state so the
    # policy can SEE which request_mix variants the target is path-blocking THIS
    # episode and learn to avoid them, instead of regressing to a defense-blind
    # marginal (which is why the model-free LeverShield veto was needed). For each
    # of `request_variant_count` variants we add two features, appended after the
    # mask bits: variant{v}_block = 1 - best-observed-success-so-far (causal: only
    # windows strictly before the current one), and a companion variant{v}_known
    # bit (0 until the variant has been tried this episode). The running estimate
    # resets per episode and, at serving, is warm-started from the per-target
    # persistent store — identical feature semantics either way.
    variant_block_features: bool = False
    request_variant_count: int = 5  # categorical cardinality of request_mix

    # Persistent-defense (ban) state: expose a cross-window "ban pressure" signal so
    # the policy can condition on a fail2ban/IPS ban that PERSISTS — the single-window
    # conn_drop_ratio can't distinguish a transient drop from a sustained ban that
    # carries across episodes (the union-corpus non-stationarity). ban_pressure is a
    # causal EWMA of conn_drop_ratio (persistence-weighted: a one-window spike decays,
    # a sustained ban stays elevated), appended after the block features as two dims:
    # ban_pressure (imputed 0 if never observed) and a companion ban_known bit. Like
    # the block memory it resets per episode and, at serving, is warm-started from the
    # per-target persistent store — identical semantics either way. ban_ewma_alpha is
    # the smoothing weight; the C++ serving path (rl_policy) must use the same value.
    ban_state_features: bool = False
    ban_ewma_alpha: float = 0.5

    # Flow-level (IPS/NSM) state: expose per-window connection-layer defense
    # reactions that a HTTP-status-only state cannot see — an inline IPS (Suricata,
    # conntrack) drops/resets packets rather than returning 429/403, so the signal
    # lives in the userspace-TCP counters (tcp_peer_rst / connect_timeout /
    # retransmit / timeout_close), each normalized per connection-attempt. These are
    # only meaningful when the load is driven over a flow-capable transport
    # (custom_tcp / dpdk / af_xdp / af_packet); the kernel-socket path does not
    # expose them, so on a kernel_socket (or transport-less legacy) corpus they are
    # masked. Appended AFTER the ban features as 5 dims: four flow rates then ONE
    # shared flow_known bit (the four are known-or-unknown together, gated by the
    # transport — unlike the base ratios they cannot be independently unknown). The
    # shared bit also keeps the width unambiguous (5 doesn't collide with the
    # block/ban combos, so the serving decoder can still recover which groups are on).
    flow_state_features: bool = False
    # Transports whose userspace TCP stack actually measures the flow counters.
    flow_capable_transports: tuple[str, ...] = ("custom_tcp", "dpdk", "af_xdp", "af_packet")

    # Reward shaping.
    lambda_slo: float = 2.0
    step_cost: float = 0.02
    rps_scale: float = 0.0  # <=0 => per-record max_rps
    # Defense penalty weight (EffectiveThroughputReward): how hard rate-limiting /
    # overload pushback (4xx/5xx share) is penalized. This is what makes the RL
    # objective differ from AIMD — it discourages blasting past the defense wall
    # into wasted, rejected load instead of maximizing *served* throughput.
    lambda_defense: float = 1.0
    # Flow-level (network) defense penalty weight. rate_limited/overload are HTTP
    # statuses; a pure connection-level IPS (RST/drop, JS-less) returns no status,
    # so conn_drop_ratio + reset_pressure are penalized separately here. Defaults to
    # lambda_defense so both defense classes weigh equally out of the box; retune
    # when a target leans on one class (e.g. Suricata/fail2ban) more than the other.
    lambda_flow: float = 1.0

    # Corpus hygiene.
    drop_leading: bool = True  # drop the s_valid=False first window of every episode
    drop_no_traffic: bool = True  # drop windows whose s2 attempted <= 0

    @property
    def feature_count(self) -> int:
        """Width the FeatureExtractor emits per window (base features + mask bits).
        The path-aware block features are appended at dataset level, so they are
        counted by ``block_feature_count`` / ``state_dim`` instead, not here."""
        base = len(self.feature_names)
        if not self.mask_unknown:
            return base
        # One mask bit per maskable raw field (the four that can be unknown).
        return base + len(self.maskable_features)

    @property
    def state_dim(self) -> int:
        """Full policy input width: extractor + block + ban + flow features."""
        return (self.feature_count + self.block_feature_count
                + self.ban_feature_count + self.flow_feature_count)

    @property
    def block_feature_count(self) -> int:
        """Extra state dims from the path-aware variant-block memory (2 per variant:
        the block ratio and its known bit), 0 when the feature is disabled."""
        return 2 * self.request_variant_count if self.variant_block_features else 0

    def block_feature_names(self) -> tuple[str, ...]:
        """Names for the appended block features, in wire order: all block ratios
        then all known bits (mirrors the value-then-mask-bit layout above)."""
        if not self.variant_block_features:
            return ()
        v = self.request_variant_count
        return tuple(f"variant{i}_block" for i in range(v)) + tuple(
            f"variant{i}_known" for i in range(v)
        )

    @property
    def ban_feature_count(self) -> int:
        """Extra state dims from the persistent-ban memory (ban_pressure + known bit),
        0 when disabled. Appended AFTER the block features so old (block-only or
        legacy) policies keep their exact input width."""
        return 2 if self.ban_state_features else 0

    def ban_feature_names(self) -> tuple[str, ...]:
        """Names for the appended ban features, in wire order: pressure then known."""
        return ("ban_pressure", "ban_known") if self.ban_state_features else ()

    @property
    def flow_feature_count(self) -> int:
        """Extra state dims from the flow-level IPS memory: four flow rates + one
        shared known bit (5), 0 when disabled. Appended AFTER the ban features so
        older (flow-less) policies keep their exact input width."""
        return 5 if self.flow_state_features else 0

    def flow_feature_names(self) -> tuple[str, ...]:
        """Names for the appended flow features, in wire order: the four rates then
        the single shared known bit."""
        if not self.flow_state_features:
            return ()
        return (
            "rst_rate",
            "connect_timeout_rate",
            "retransmit_rate",
            "timeout_close_rate",
            "flow_known",
        )

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
