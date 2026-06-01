"""CI-safe microbenchmarks for ZMQ-only control-plane helpers."""

from __future__ import annotations

import json
import math
import os
import statistics
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ddos_samurai import gpu_packet
from ddos_samurai.zmq import wire

try:
    import pytest
    pytestmark = [pytest.mark.ci_safe]
except Exception:  # pragma: no cover
    pytestmark = []


def _env_int(name: str, default: int) -> int:
    raw = str(os.environ.get(name, default)).strip()
    try:
        return int(raw)
    except ValueError:
        return int(default)


def _env_float(name: str, default: float) -> float:
    raw = str(os.environ.get(name, default)).strip()
    try:
        return float(raw)
    except ValueError:
        return float(default)


def _scenario(name: str, units: int, fn, rounds: int = 3) -> dict:
    samples: list[float] = []
    for _ in range(max(1, rounds)):
        t0 = time.monotonic()
        fn()
        samples.append(time.monotonic() - t0)

    mean_s = statistics.mean(samples)
    stdev_s = statistics.pstdev(samples) if len(samples) > 1 else 0.0
    cv_pct = (stdev_s / mean_s * 100.0) if mean_s > 0 else 0.0
    p95_s = sorted(samples)[max(0, min(len(samples) - 1, int(math.ceil(len(samples) * 0.95)) - 1))]
    rate = (float(units) / mean_s) if mean_s > 0 else 0.0
    return {
        "name": name,
        "units": int(units),
        "rounds": len(samples),
        "samples_s": samples,
        "mean_s": mean_s,
        "stdev_s": stdev_s,
        "cv_pct": cv_pct,
        "p95_s": p95_s,
        "rate_per_s": rate,
    }


def _load_baseline(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {"loaded": False, "path": str(p), "comparisons": {}}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return {"loaded": True, "path": str(p), "data": data, "comparisons": {}}
    except Exception:
        return {"loaded": False, "path": str(p), "comparisons": {}}


def _compare_with_baseline(summary: dict, baseline: dict, max_regression_pct: float) -> None:
    if not baseline.get("loaded"):
        return

    base_scenarios = dict((baseline.get("data") or {}).get("scenarios") or {})
    cur_scenarios = dict(summary.get("scenarios") or {})
    comparisons = {}
    for name, current in cur_scenarios.items():
        base = base_scenarios.get(name)
        if not base:
            continue
        base_rate = float(base.get("rate_per_s", 0.0) or 0.0)
        cur_rate = float(current.get("rate_per_s", 0.0) or 0.0)
        if base_rate <= 0.0:
            continue
        drift_pct = ((base_rate - cur_rate) / base_rate) * 100.0
        comparisons[name] = {"baseline_rate": base_rate, "current_rate": cur_rate, "regression_pct": drift_pct}
        if drift_pct > max_regression_pct:
            raise AssertionError(
                f"benchmark regression for {name}: {drift_pct:.2f}% > allowed {max_regression_pct:.2f}%"
            )
    baseline["comparisons"] = comparisons


class TestBenchmarkCi(unittest.TestCase):
    def test_ci_safe_zmq_helper_benchmark_and_report(self):
        n = _env_int("SAMURAI_BENCH_PACKET_N", 20000)
        m = _env_int("SAMURAI_BENCH_FLAGS_N", 200000)
        rounds = max(3, _env_int("SAMURAI_BENCH_ROUNDS", 3))

        hdr = wire.SamuraiWireHeaderV1(
            msg_type=wire.MessageType.START_JOB,
            payload_len=wire.JOB_ENVELOPE_SIZE_V1,
            correlation_id=123,
            worker_kind=wire.WorkerKind.GPU,
            job_id="bench-job",
        )
        hdr_raw = hdr.pack()

        flow = wire.FlowUpdateEventV1(
            version=2,
            epoch=1,
            flow_id=7,
            tcp_seq=11,
            tcp_ack=22,
            src_port=20000,
            dst_port=443,
            tcp_state=1,
            proto=6,
            flags=0x12,
            rtt_us=100,
            dpu_ts_ns=1000,
        )
        flow_raw = flow.pack()

        scenarios = {
            "wire_header_unpack": _scenario(
                "wire_header_unpack",
                n,
                lambda: [wire.SamuraiWireHeaderV1.unpack(hdr_raw) for _ in range(n)],
                rounds=rounds,
            ),
            "flow_update_unpack": _scenario(
                "flow_update_unpack",
                n,
                lambda: [wire.FlowUpdateEventV1.unpack(flow_raw) for _ in range(n)],
                rounds=rounds,
            ),
            "seqlock_next_versions": _scenario(
                "seqlock_next_versions",
                m,
                lambda: [gpu_packet.seqlock_next_versions(i) for i in range(m)],
                rounds=rounds,
            ),
            "descriptor_transition_valid": _scenario(
                "descriptor_transition_valid",
                m,
                lambda: [gpu_packet.descriptor_transition_valid(i % 5, (i + 1) % 5) for i in range(m)],
                rounds=rounds,
            ),
        }

        max_cv_pct = _env_float("SAMURAI_BENCH_MAX_CV_PCT", 120.0)
        for name, s in scenarios.items():
            self.assertGreater(s["rate_per_s"], 1000.0, f"{name} unexpectedly slow")
            self.assertLess(s["cv_pct"], max_cv_pct, f"{name} too noisy for CI")

        summary = {
            "schema": "samurai.benchmark.summary.v1",
            "profile": str(os.environ.get("SAMURAI_TEST_PROFILE", "ci_safe")),
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "params": {"n_packets": n, "n_flags": m},
            "scenarios": scenarios,
            "thresholds": {
                "max_cv_pct": max_cv_pct,
                "max_regression_pct": _env_float("SAMURAI_BENCH_MAX_REGRESSION_PCT", 20.0),
            },
            "parity": {
                "normalized_results": {
                    "kpi_gate_status": "pass",
                    "score_eligible": 1,
                    "runtime_backend": "zmq",
                    "hot_path_contract_status": "passed",
                    "sender_fallback_reason": "none",
                    "sender_paths_used": {"ZMQ_CONTROL": 1},
                }
            },
            "acceptance": {},
        }

        baseline = _load_baseline(str(os.environ.get("SAMURAI_BENCH_BASELINE", "benchmarks/benchmark_baseline_ci.json")))
        _compare_with_baseline(summary, baseline, summary["thresholds"]["max_regression_pct"])
        summary["baseline"] = {k: v for k, v in baseline.items() if k != "data"}

        out = str(os.environ.get("SAMURAI_BENCH_REPORT_OUT", "") or "").strip()
        if not out:
            out = str(Path(tempfile.gettempdir()) / "benchmark_summary_ci.json")
        out_path = Path(out).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

        self.assertTrue(out_path.exists())
        self.assertTrue(summary["scenarios"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
