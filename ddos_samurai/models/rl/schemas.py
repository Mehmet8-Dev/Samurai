from __future__ import annotations

from dataclasses import dataclass, field

# Sentinel for "signal not present in this run" — every derived ratio returns it
# when its inputs are missing, so the feature extractor can mask it per run.
UNKNOWN = -1.0


@dataclass(frozen=True)
class DefenseSignals:
    """How the SUT's defenses (WAF/IPS/rate-limiter/overload) pushed back.

    Raw counters as logged by the master (a subset of numeric_totals); the
    Mahoraga features the policy actually consumes are the *ratios* derived here,
    each returning UNKNOWN when its inputs are absent so they can be masked.
    """

    raw: dict[str, float] = field(default_factory=dict)

    @classmethod
    def from_json(cls, o: dict | None) -> "DefenseSignals":
        if not o:
            return cls(raw={})
        return cls(raw={str(k): float(v) for k, v in o.items()})

    def _ratio(self, num_key: str, den_key: str = "responses_total") -> float:
        num = self.raw.get(num_key)
        den = self.raw.get(den_key)
        if num is None or den is None or den <= 0.0:
            return UNKNOWN
        return num / den

    @property
    def rate_limited_ratio(self) -> float:
        """4xx share — 429 (rate limit) / 403 (WAF block) dominate under defense."""
        return self._ratio("status_4xx")

    @property
    def overload_ratio(self) -> float:
        """5xx share — 503 (overload / circuit-break) as the SUT sheds load."""
        return self._ratio("status_5xx")

    @property
    def success_ratio(self) -> float:
        return self._ratio("status_2xx")

    @property
    def challenge_rate(self) -> float:
        """Unexpected/challenge responses — WAF interstitials, JS challenges, etc."""
        return self._ratio("l7_expectation_failures")

    @property
    def conn_drop_ratio(self) -> float:
        """1 - established/attempted — IPS/WAF refusing or resetting connections."""
        att = self.raw.get("l7_conn_attempted")
        est = self.raw.get("l7_conn_established")
        if att is None or est is None or att <= 0.0:
            return UNKNOWN
        return max(0.0, 1.0 - est / att)

    @property
    def reset_pressure(self) -> float:
        """HTTP/2 stream-reset ratio — already normalized; server-side shedding."""
        v = self.raw.get("h2_stream_reset_ratio")
        return UNKNOWN if v is None else v

    def _flow_rate(self, count_key: str) -> float:
        """A userspace-TCP flow counter normalized per connection-attempt. UNKNOWN
        when the counter or l7_conn_attempted is absent (kernel-socket path). Note
        the counter can be present-but-zero on a flow-capable transport (a clean
        window under an IPS that did not react) — that is a real 0, not unknown; the
        transport-gated shared known bit (set in the dataset) distinguishes the two."""
        num = self.raw.get(count_key)
        att = self.raw.get("l7_conn_attempted")
        if num is None or att is None or att <= 0.0:
            return UNKNOWN
        return num / att

    @property
    def rst_rate(self) -> float:
        """Peer/IPS RST injections per connection-attempt (active reset)."""
        return self._flow_rate("tcp_peer_rst_count")

    @property
    def connect_timeout_rate(self) -> float:
        """SYN-drop / blackhole: connections that never established, per attempt."""
        return self._flow_rate("tcp_connect_timeout_count")

    @property
    def retransmit_rate(self) -> float:
        """Mid-flow packet loss / throttling, per connection-attempt."""
        return self._flow_rate("tcp_retransmit_count")

    @property
    def timeout_close_rate(self) -> float:
        """Idle/forced connection closes, per connection-attempt."""
        return self._flow_rate("tcp_timeout_close_count")


@dataclass(frozen=True)
class Action:
    """The policy's Mahoraga action vector. Levers not driven this run are -1."""

    rps: float
    pacing_mode: int = -1
    concurrency: int = -1
    connections: int = -1
    request_mix: int = -1
    source_rotation: int = -1

    @classmethod
    def from_json(cls, o: dict | None, *, fallback_rps: float = 0.0) -> "Action":
        o = o or {}
        return cls(
            rps=float(o.get("rps", fallback_rps)),
            pacing_mode=int(o.get("pacing_mode", -1)),
            concurrency=int(o.get("concurrency", -1)),
            connections=int(o.get("connections", -1)),
            request_mix=int(o.get("request_mix", -1)),
            source_rotation=int(o.get("source_rotation", -1)),
        )

    def value(self, field_name: str) -> float:
        """One action dimension's value by field name (see action_spec.ACTION_FIELDS)."""
        return float(getattr(self, field_name))


@dataclass(frozen=True)
class RawState:
    """One measured closed-loop window as logged to the corpus.

    Fields left < 0 by the master are "unknown" (the SLO rule that consumes them
    was inert for this run). ``error_pct`` is derived from errors/attempted when
    the master did not compute it. Imputation/masking is the dataset builder's job.
    """

    valid: bool
    rps: float
    attempted: float
    errors: float
    error_pct: float
    loss_pct: float
    rate_accuracy_pct: float
    p99_ms: float
    defense: DefenseSignals = field(default_factory=DefenseSignals)

    @classmethod
    def from_json(cls, o: dict) -> "RawState":
        return cls(
            valid=bool(o.get("valid", False)),
            rps=float(o.get("rps", 0.0)),
            attempted=float(o.get("attempted", 0.0)),
            errors=float(o.get("errors", 0.0)),
            error_pct=float(o.get("error_pct", -1.0)),
            loss_pct=float(o.get("loss_pct", -1.0)),
            rate_accuracy_pct=float(o.get("rate_accuracy_pct", -1.0)),
            p99_ms=float(o.get("p99_ms", -1.0)),
            defense=DefenseSignals.from_json(o.get("defense")),
        )

    @property
    def effective_error_pct(self) -> float:
        """error_pct as logged, or derived from errors/attempted if unknown."""
        if self.error_pct >= 0.0:
            return self.error_pct
        if self.attempted > 0.0:
            return 100.0 * self.errors / self.attempted
        return -1.0


@dataclass(frozen=True)
class SloThresholds:
    """Active SLO knobs for the run. A rule is enabled only when its knob > 0."""

    max_error_pct: float
    max_loss_pct: float
    min_rate_accuracy_pct: float
    max_latency_ms: float

    @classmethod
    def from_json(cls, o: dict) -> "SloThresholds":
        return cls(
            max_error_pct=float(o.get("max_error_pct", 0.0)),
            max_loss_pct=float(o.get("max_loss_pct", 0.0)),
            min_rate_accuracy_pct=float(o.get("min_rate_accuracy_pct", 0.0)),
            max_latency_ms=float(o.get("max_latency_ms", 0.0)),
        )


@dataclass(frozen=True)
class Transition:
    """One (s, a, s') corpus record. Reward is computed downstream (see dataset)."""

    run_id: str
    win: int
    ts_ms: int
    transport: str  # dataplane backend for this run; "" (legacy) => flow-incapable
    strategy: str
    min_rps: float
    max_rps: float
    window_s: int
    slo: SloThresholds
    action_rps: float
    action: Action
    s_valid: bool  # False on the leading window (no prior state) -> dropped by builder
    s: RawState
    s2: RawState
    healthy: bool
    phase: str
    done: bool

    @classmethod
    def from_json(cls, o: dict) -> "Transition":
        action_rps = float(o.get("action_rps", 0.0))
        return cls(
            run_id=str(o.get("run_id", "")),
            win=int(o.get("win", 0)),
            ts_ms=int(o.get("ts_ms", 0)),
            transport=str(o.get("transport", "")),
            strategy=str(o.get("strategy", "aimd")),
            min_rps=float(o.get("min_rps", 0.0)),
            max_rps=float(o.get("max_rps", 0.0)),
            window_s=int(o.get("window_s", 0)),
            slo=SloThresholds.from_json(o.get("slo", {}) or {}),
            action_rps=action_rps,
            action=Action.from_json(o.get("action"), fallback_rps=action_rps),
            s_valid=bool(o.get("s_valid", False)),
            s=RawState.from_json(o.get("s", {}) or {}),
            s2=RawState.from_json(o.get("s2", {}) or {}),
            healthy=bool(o.get("healthy", False)),
            phase=str(o.get("phase", "")),
            done=bool(o.get("done", False)),
        )
