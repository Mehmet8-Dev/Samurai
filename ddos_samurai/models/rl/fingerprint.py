"""Passive defense fingerprinting — the target-side network-intelligence layer.

The RL policy *reacts* to per-window defense signals; this layer *understands*
them, distilling a corpus of (offered rps, request variant) -> (defense reaction)
observations into a structured DefenseProfile: where the target starts rejecting
load, the throughput it will actually sustain, whether rejection is uniform (a
rate limiter) or path-specific (a WAF), a coarse limiter-type guess, and any
network-layer (flow) pushback.

It is passive and behavioral — no active probing, no fingerprint database. Every
field is inferred from how the target responded to load we already generated, so
it stays honest about what the black box revealed. The profile is an analysis /
prior artifact (a human-facing report, and a reward-scale hint for training); it
is deliberately NOT fed into the RL feature vector, which stays frozen for the
native serving contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean
from typing import Iterable

from .corpus import iter_transitions
from .schemas import UNKNOWN, Transition

# A defense signal counts as "present" once its share crosses this floor, so
# measurement noise near zero does not fabricate an onset.
_ONSET = 0.05


@dataclass
class _Row:
    offered_rps: float
    request_mix: int
    served_rps: float          # 2xx / window_s — load the target actually honored
    reject_ratio: float        # 4xx share (rate-limit + WAF, lumped by the emu)
    success_ratio: float       # 2xx share — path-block drives this to ~0 at any rps
    responses: float           # responses_total (weight / validity)
    overload_ratio: float      # 5xx share
    conn_drop_ratio: float     # 1 - established/attempted
    flow_events: float         # RST + connect-timeout + retransmit + timeout-close


@dataclass
class DefenseProfile:
    n_windows: int = 0
    rps_span: tuple[float, float] = (0.0, 0.0)

    served_ceiling_rps: float = 0.0        # max sustained 2xx throughput seen
    rate_limit_threshold_rps: float = 0.0  # enforced rate (~ served ceiling)
    saturation_offered_rps: float = UNKNOWN  # offered rps needed to reach that ceiling
    rejection_onset_rps: float = UNKNOWN   # lowest offered rps that draws 4xx
    overload_onset_rps: float = UNKNOWN    # lowest offered rps that draws 5xx
    conn_refusal_onset_rps: float = UNKNOWN  # lowest offered rps that drops connections

    # Uniform (rate-limiter) vs path-specific (WAF) rejection. `variant_block` is
    # each request_mix's blocked fraction at ITS OWN low load (1 - success_ratio);
    # `blocked_variants` are those blocked even below the rate wall (WAF-blocked).
    path_sensitivity: float = 0.0
    variant_block: dict[int, float] = field(default_factory=dict)
    blocked_variants: list[int] = field(default_factory=list)

    limiter_type_hint: str = "unknown"
    transition_band_rps: float = UNKNOWN   # rps width over which reject goes .1->.9

    flow_defense: bool = False             # network-layer resets/drops observed?
    flow_note: str = ""

    confidence: str = "low"

    def format_report(self) -> str:
        lo, hi = self.rps_span
        L: list[str] = []
        L.append("=== Target defense intelligence (passive fingerprint) ===")
        L.append(f"observations : {self.n_windows} windows over rps {lo:.0f}..{hi:.0f}"
                 f"  (confidence: {self.confidence})")
        L.append(f"served ceiling      : ~{self.served_ceiling_rps:.0f} req/s honored (2xx) "
                 f"= enforced rate limit")
        L.append(f"saturation point    : {self._fmt(self.saturation_offered_rps)} req/s offered "
                 f"to drive the target to that ceiling")
        L.append(f"rejection onset     : {self._fmt(self.rejection_onset_rps)} req/s (first 4xx)")
        L.append(f"overload onset      : {self._fmt(self.overload_onset_rps)} req/s (first 5xx)")
        L.append(f"conn-refusal onset  : {self._fmt(self.conn_refusal_onset_rps)} req/s (conn drops)")
        L.append(f"limiter type (guess): {self.limiter_type_hint}"
                 + (f"  [transition band ~{self.transition_band_rps:.0f} rps]"
                    if self.transition_band_rps is not UNKNOWN and self.transition_band_rps >= 0 else ""))
        if self.blocked_variants:
            vs = ", ".join(str(v) for v in self.blocked_variants)
            L.append(f"path sensitivity    : PATH-SPECIFIC (WAF-like); variant(s) {vs} "
                     f"blocked (~0% served at any rps) — not rate-limited")
        else:
            L.append("path sensitivity    : uniform across request variants "
                     "(rate-limiter dominates, no strong path/method WAF blocking)")
        L.append(f"flow-level defense  : {self.flow_note}")
        return "\n".join(L)

    @staticmethod
    def _fmt(v: float) -> str:
        return "none" if v is UNKNOWN or v < 0 else f"~{v:.0f}"

    def variant_best_success(self, n_variants: int) -> list[float]:
        """Per-variant best-observed success, as a warm-start prior for the serving
        loop (LeverShield veto + block-state feature).

        This is the bridge from the human-facing fingerprint into the policy loop:
        for each variant the corpus exercised, best-success = 1 - variant_block[v]
        (variant_block is 1 - max success, so this recovers the max success we saw);
        variants never exercised stay UNKNOWN (-1). Written to the VariantMemory JSON
        store, it lets a fresh episode start from the discovered walls instead of
        rediscovering them — WITHOUT adding any feature to the frozen SRLP contract
        (the block-state feature, when enabled, already consumes exactly this array).
        """
        out = [UNKNOWN] * n_variants
        for v, block in self.variant_block.items():
            if 0 <= v < n_variants:
                out[v] = max(0.0, min(1.0, 1.0 - block))
        return out


def _rows(transitions: Iterable[Transition]) -> list[_Row]:
    rows: list[_Row] = []
    for t in transitions:
        d = t.s2.defense
        raw = d.raw or {}
        ws = t.window_s if t.window_s > 0 else 1
        served = float(raw.get("status_2xx", 0.0)) / ws
        flow = sum(
            float(raw.get(k, 0.0))
            for k in ("tcp_peer_rst_count", "tcp_connect_timeout_count",
                      "tcp_retransmit_count", "tcp_timeout_close_count")
        )
        rows.append(_Row(
            offered_rps=float(t.action.rps),
            request_mix=int(t.action.request_mix),
            served_rps=served,
            reject_ratio=d.rate_limited_ratio if d.rate_limited_ratio >= 0 else 0.0,
            success_ratio=d.success_ratio if d.success_ratio >= 0 else 0.0,
            responses=float(raw.get("responses_total", 0.0)),
            overload_ratio=d.overload_ratio if d.overload_ratio >= 0 else 0.0,
            conn_drop_ratio=d.conn_drop_ratio if d.conn_drop_ratio >= 0 else 0.0,
            flow_events=flow,
        ))
    return rows


def _first_onset(rows: list[_Row], key) -> float:
    """Lowest offered rps at which `key(row)` first crosses the onset floor."""
    hits = sorted((r.offered_rps for r in rows if key(r) > _ONSET))
    return hits[0] if hits else UNKNOWN


def fingerprint(transitions: Iterable[Transition]) -> DefenseProfile:
    rows = _rows(transitions)
    p = DefenseProfile()
    if not rows:
        return p
    p.n_windows = len(rows)
    offered = [r.offered_rps for r in rows]
    p.rps_span = (min(offered), max(offered))

    p.served_ceiling_rps = max(r.served_rps for r in rows)
    # A rate limiter caps served throughput at (roughly) its enforced rate, so the
    # ceiling of the honored 2xx throughput IS the threshold the target enforces —
    # offer more than this and the surplus is rejected. (Distinct from the *offered*
    # load needed to saturate that ceiling, which is higher and not what an
    # operator cares about.)
    p.rate_limit_threshold_rps = p.served_ceiling_rps
    # Offered rps at which honored throughput plateaus near the ceiling (context).
    near = 0.9 * p.served_ceiling_rps
    at_ceiling = sorted(r.offered_rps for r in rows if r.served_rps >= near)
    p.saturation_offered_rps = at_ceiling[0] if at_ceiling else UNKNOWN

    p.rejection_onset_rps = _first_onset(rows, lambda r: r.reject_ratio)
    p.overload_onset_rps = _first_onset(rows, lambda r: r.overload_ratio)
    p.conn_refusal_onset_rps = _first_onset(rows, lambda r: r.conn_drop_ratio)

    # Path sensitivity: is a variant blocked *beyond* what rate-limiting explains?
    # Keying on the 4xx share alone conflates the two — 4xx rises with rps for every
    # variant, so a variant merely sampled at higher rps looks "path-specific". The
    # honest discriminator is the SUCCESS ratio at each variant's OWN low load: below
    # the rate wall a limiter honors traffic (success ~1), while a WAF-blocked path
    # returns ~0 served at any rps. So we score each variant by how blocked it is
    # across its lowest-load third, which decouples the judgment from where in the
    # rps ramp the variant happened to be exercised.
    variants = sorted({r.request_mix for r in rows if r.request_mix >= 0})
    if len(variants) >= 2:
        # A rate limiter honors every variant at low enough rps, so a non-blocked
        # variant is served in at least one window (its best success ~ 1). A WAF
        # path-block returns ~0 served at EVERY rps, so its best window is still ~0.
        # Scoring by (1 - best success) is thus robust to how each variant happened
        # to be sampled across the rps ramp — unlike a 4xx mean, which just tracks rps.
        block: dict[int, float] = {}
        for v in variants:
            vr = [r for r in rows if r.request_mix == v and r.responses > 0]
            if not vr:
                continue
            block[v] = 1.0 - max(r.success_ratio for r in vr)
        if block:
            p.variant_block = {v: round(b, 3) for v, b in block.items()}
            # Blocked at its own best-case load => WAF/path policy, not rate-limiting.
            # The 0.5 floor admits only near-total blocks (real WAF ~1.0), rejecting
            # the partial dips a small, unlucky sample can produce.
            p.blocked_variants = sorted(v for v, b in block.items() if b >= 0.5)
            p.path_sensitivity = round(max(block.values()) - min(block.values()), 3)

    # Limiter-type heuristic from how sharply rejection turns on. A hard threshold
    # (fixed/sliding window) flips over a narrow rps band; a token bucket bleeds in
    # gradually as burst credit drains. Purely a shape guess — labelled as such.
    rej_sorted = sorted(rows, key=lambda r: r.offered_rps)
    lo_band = next((r.offered_rps for r in rej_sorted if r.reject_ratio >= 0.1), UNKNOWN)
    hi_band = next((r.offered_rps for r in rej_sorted if r.reject_ratio >= 0.8), UNKNOWN)
    ceil = max(1.0, p.served_ceiling_rps)
    if p.rejection_onset_rps is UNKNOWN:
        p.limiter_type_hint = "no rate limiting observed in this rps range"
    elif p.rejection_onset_rps <= p.rps_span[0] + 1e-9:
        # Rejection is already underway at the lowest rps we offered: the enforced
        # rate sits at/below the probed range — a hard cap near the served ceiling.
        p.limiter_type_hint = (f"hard threshold at/below ~{ceil:.0f} req/s "
                               f"(probe floor already rejected; lower min-rps to bracket it)")
    elif lo_band is not UNKNOWN and hi_band is not UNKNOWN and hi_band >= lo_band:
        band = hi_band - lo_band
        p.transition_band_rps = band
        if band <= 0.5 * ceil:
            p.limiter_type_hint = "hard threshold (fixed/sliding-window rate limit)"
        else:
            p.limiter_type_hint = "burst-tolerant (token-bucket-like)"
    else:
        p.limiter_type_hint = "rate limit present (transition band outside probed range)"

    total_flow = sum(r.flow_events for r in rows)
    p.flow_defense = total_flow > 0
    if p.flow_defense:
        p.flow_note = (f"network-layer pushback observed ({total_flow:.0f} RST/timeout/"
                       f"retransmit events) — active IPS / conntrack-style defense")
    else:
        p.flow_note = ("none observed (no RST/timeout/retransmit signal; expected on the "
                       "kernel-socket transport, which cedes the connection to the OS)")

    # Confidence from coverage: enough windows and rps spread to trust the knees.
    span = p.rps_span[1] - p.rps_span[0]
    if p.n_windows >= 100 and span >= 300:
        p.confidence = "high"
    elif p.n_windows >= 30 and span >= 150:
        p.confidence = "medium"
    return p


def fingerprint_corpus(paths) -> DefenseProfile:
    """Fingerprint one or more corpus files (NDJSON of RL transitions)."""
    if isinstance(paths, (str, Path)):
        paths = [paths]
    txs: list[Transition] = []
    for pth in paths:
        txs.extend(iter_transitions(pth))
    return fingerprint(txs)
