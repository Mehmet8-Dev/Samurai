"""Open-vocabulary novelty scan — the offline complement to the native detector.

Pins the unexplained-loss math and the signature vocabulary against the same
definitions the C++ NoveltyDetector serves, on synthetic corpora shaped like the
three regimes: a known (rate-limited) defense, a silent (out-of-dictionary) one, and
an under-explained one.
"""

from __future__ import annotations

import json

from ddos_samurai.models.rl import scan_corpus, unexplained_loss
from ddos_samurai.models.rl.novelty import scan, signature
from ddos_samurai.models.rl.schemas import DefenseSignals, Transition


def _defense(**counts) -> DefenseSignals:
    return DefenseSignals.from_json(counts)


def test_unexplained_loss_known_defense_is_zero():
    # success 0.02, 4xx 0.98 -> fully explained by rate-limiting -> no novelty.
    d = _defense(responses_total=100, status_2xx=2, status_4xx=98)
    assert abs(unexplained_loss(d) - 0.0) < 1e-9
    assert signature(d) == "under-explained:rate_limit"  # only meaningful when flagged


def test_unexplained_loss_silent_defense_is_high():
    # success 0.1, no known signal at all -> 0.9 unexplained -> silent phenomenon.
    d = _defense(responses_total=100, status_2xx=10)
    assert abs(unexplained_loss(d) - 0.9) < 1e-9
    assert signature(d) == "silent-success-loss"


def test_unexplained_loss_none_without_success_signal():
    d = _defense()  # no responses_total -> success_ratio unknown
    assert unexplained_loss(d) is None


def _corpus(path, mode: str, *, episodes=4, windows=8):
    """mode: 'known' (rate-limited), 'silent' (unexplained), 'partial' (under-explained)."""
    with open(path, "w", encoding="utf-8") as fh:
        for ep in range(episodes):
            rps = 300.0
            for w in range(windows):
                resp = 500.0
                if mode == "known":
                    dfn = {"responses_total": resp, "status_2xx": resp * 0.02,
                           "status_4xx": resp * 0.98}
                elif mode == "silent":
                    dfn = {"responses_total": resp, "status_2xx": resp * 0.1}
                else:  # partial: some conn_drop but nowhere near enough
                    dfn = {"responses_total": resp, "status_2xx": resp * 0.1,
                           "l7_conn_attempted": 100, "l7_conn_established": 80}
                fh.write(json.dumps({
                    "run_id": f"cl-{ep}", "win": w, "ts_ms": w, "strategy": "rl",
                    "min_rps": 50.0, "max_rps": 2000.0, "window_s": 5,
                    "slo": {"max_error_pct": 100.0}, "action_rps": rps,
                    "action": {"rps": rps, "request_mix": 0},
                    "s_valid": w > 0,
                    "s": {"valid": True, "rps": rps - 50, "attempted": resp, "errors": 0,
                          "error_pct": 0.0, "loss_pct": -1, "rate_accuracy_pct": -1,
                          "p99_ms": -1, "defense": {}},
                    "s2": {"valid": True, "rps": rps, "attempted": resp, "errors": 0,
                           "error_pct": 0.0, "loss_pct": -1, "rate_accuracy_pct": -1,
                           "p99_ms": -1, "defense": dfn},
                    "healthy": True, "phase": "probe", "done": w == windows - 1,
                }) + "\n")
                rps += 50.0
    return path


def test_scan_known_defense_finds_no_novelty(tmp_path):
    rep = scan_corpus(_corpus(tmp_path / "known.ndjson", "known"))
    assert rep.n_judged > 0
    assert rep.n_novel == 0
    assert rep.vocabulary == {}


def test_scan_silent_defense_opens_new_axis(tmp_path):
    rep = scan_corpus(_corpus(tmp_path / "silent.ndjson", "silent"))
    assert rep.n_novel == rep.n_judged  # every window is out-of-dictionary
    assert rep.vocabulary == {"silent-success-loss": rep.n_novel}
    assert rep.novelty_rate == 1.0
    # The report names the discovered axis and lists worst offenders.
    txt = rep.format_report()
    assert "silent-success-loss" in txt
    assert "open vocabulary" in txt


def test_scan_partial_defense_tags_dominant_axis(tmp_path):
    rep = scan_corpus(_corpus(tmp_path / "partial.ndjson", "partial"))
    assert rep.n_novel > 0
    assert "under-explained:conn_drop" in rep.vocabulary


def test_threshold_gates_flagging(tmp_path):
    # With the threshold above the unexplained loss (0.9), nothing is flagged.
    rep = scan_corpus(_corpus(tmp_path / "silent.ndjson", "silent"), residual_threshold=0.95)
    assert rep.n_novel == 0
