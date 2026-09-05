"""Passive defense-fingerprint inference from a synthetic corpus."""

from __future__ import annotations

import json

from ddos_samurai.models.rl import fingerprint_corpus
from ddos_samurai.models.rl.schemas import UNKNOWN

WINDOW_S = 1
THRESHOLD = 200  # the synthetic target honors ~200 req/s, rejects the surplus


def _rec(rps: float, request_mix: int, *, waf_variant: int | None = None,
         flow_rst: int = 0) -> dict:
    """A window offering `rps` for one second against a hard 200 r/s limiter.

    Served 2xx caps at THRESHOLD; the surplus is 4xx. `waf_variant` (if it matches
    request_mix) blocks an extra 30% as a path-specific WAF would.
    """
    responses = rps
    served = min(rps, THRESHOLD)
    if waf_variant is not None and request_mix == waf_variant:
        blocked = 0.3 * responses
        served = max(0.0, min(served, responses - blocked))
    rejected = responses - served
    defense = {
        "responses_total": responses,
        "status_2xx": served,
        "status_3xx": 0,
        "status_4xx": rejected,
        "status_5xx": 0,
        "l7_conn_attempted": responses,
        "l7_conn_established": responses,
        "tcp_peer_rst_count": flow_rst,
    }
    state = {
        "valid": True, "rps": served, "attempted": responses, "errors": 0.0,
        "error_pct": -1.0, "loss_pct": -1.0, "rate_accuracy_pct": -1.0, "p99_ms": -1.0,
        "defense": defense,
    }
    return {
        "run_id": "ep1", "win": int(rps), "ts_ms": 1, "strategy": "aimd",
        "min_rps": 100.0, "max_rps": 1600.0, "window_s": WINDOW_S,
        "slo": {"max_error_pct": 0.0, "max_loss_pct": 0.0,
                "min_rate_accuracy_pct": 0.0, "max_latency_ms": 0.0},
        "action_rps": rps,
        "action": {"rps": rps, "pacing_mode": 1, "concurrency": 1, "connections": -1,
                   "request_mix": request_mix, "source_rotation": -1},
        "s_valid": True,
        "s": dict(state, rps=0.0),
        "s2": state,
        "healthy": True, "phase": "aimd", "done": False,
    }


def _write(tmp_path, records) -> str:
    p = tmp_path / "corpus.ndjson"
    p.write_text("".join(json.dumps(r) + "\n" for r in records))
    return str(p)


def test_fingerprint_recovers_rate_limit_ceiling(tmp_path):
    # Sweep offered rps across the 200 r/s threshold, uniform across variants.
    recs = [_rec(rps, mix) for rps in range(100, 1300, 100) for mix in range(5)]
    p = fingerprint_corpus(_write(tmp_path, recs))

    # The enforced rate ~ the served ceiling ~ the true threshold.
    assert abs(p.served_ceiling_rps - THRESHOLD) <= 20
    assert abs(p.rate_limit_threshold_rps - THRESHOLD) <= 20
    # Rejection begins just past the threshold, not before it.
    assert p.rejection_onset_rps is not UNKNOWN
    assert p.rejection_onset_rps >= THRESHOLD
    # No 5xx / conn drops / flow events in this synthetic limiter.
    assert p.overload_onset_rps is UNKNOWN
    assert p.conn_refusal_onset_rps is UNKNOWN
    assert p.flow_defense is False
    # Uniform limiter => low path sensitivity.
    assert p.path_sensitivity < 0.05


def test_fingerprint_flags_path_specific_waf_and_flow_defense(tmp_path):
    # Variant 3 is blocked an extra 30% (a path/method WAF rule); flows draw RSTs.
    recs = [
        _rec(rps, mix, waf_variant=3, flow_rst=5)
        for rps in range(100, 1300, 100)
        for mix in range(5)
    ]
    p = fingerprint_corpus(_write(tmp_path, recs))

    assert p.path_sensitivity >= 0.05
    assert p.variant_block[3] == max(p.variant_block.values())
    assert p.flow_defense is True
    assert "IPS" in p.flow_note or "conntrack" in p.flow_note


def test_fingerprint_fully_blocked_variant_is_named(tmp_path):
    # A hard WAF block: variant 2 returns ~0 served at every rps (403 on the path),
    # while others are only rate-limited. Must be reported as a blocked variant, not
    # confused with the rate limiter — even though 4xx rises with rps for everyone.
    recs = []
    for rps in range(100, 1300, 100):
        for mix in range(5):
            if mix == 2:
                # fully blocked: no 2xx at any rps
                recs.append(_fully_blocked(rps, mix))
            else:
                recs.append(_rec(rps, mix))
    p = fingerprint_corpus(_write(tmp_path, recs))
    assert p.blocked_variants == [2]
    assert p.variant_block[2] >= 0.9
    # Honored variants are NOT flagged as path-blocked despite heavy 4xx at high rps.
    assert all(v not in p.blocked_variants for v in (0, 1, 3, 4))


def _fully_blocked(rps: float, request_mix: int) -> dict:
    r = _rec(rps, request_mix)
    d = r["s2"]["defense"]
    d["status_2xx"] = 0
    d["status_4xx"] = d["responses_total"]  # 403 on every request to this path
    r["s2"]["rps"] = 0.0
    return r
