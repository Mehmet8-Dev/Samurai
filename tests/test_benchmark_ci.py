"""CI-safe benchmark suite for CPU packet generation paths.

This suite is deterministic enough for CI and avoids privileged/GPU-only datapaths.
"""

from __future__ import annotations

import json
import os
import statistics
import tempfile
import time
import tracemalloc
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ddos_samurai.cpu_packet_engine import PacketConfig, create_packet, generate_packet_pool, parse_tcp_flags

try:
    import pytest
    pytestmark = [pytest.mark.benchmark, pytest.mark.ci_safe]
except Exception:  # pragma: no cover - unittest-only environments
    pytestmark = []


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "on"}


def _write_json_with_fallback(preferred: Path, payload: dict, fallback_name: str) -> Path:
    content = json.dumps(payload, indent=2, sort_keys=True)
    candidates = [
        preferred,
        Path.cwd() / ".pytest_artifacts" / fallback_name,
        Path(tempfile.gettempdir()) / ".pytest_artifacts" / fallback_name,
    ]
    seen = set()
    for cand in candidates:
        key = str(cand)
        if key in seen:
            continue
        seen.add(key)
        try:
            cand.parent.mkdir(parents=True, exist_ok=True)
            cand.write_text(content, encoding="utf-8")
            return cand
        except PermissionError:
            continue
    raise PermissionError(f"Unable to write benchmark report to any candidate path: {candidates}")


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    idx = max(0, min(len(values) - 1, int(round((pct / 100.0) * (len(values) - 1)))))
    s = sorted(values)
    return float(s[idx])


def _scenario(name: str, units: int, fn, rounds: int = 3) -> dict:
    samples = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        fn()
        dt = max(1e-9, time.perf_counter() - t0)
        samples.append(dt)

    mean_s = statistics.mean(samples)
    stdev_s = statistics.pstdev(samples)
    cv_pct = (stdev_s / mean_s * 100.0) if mean_s > 0 else 0.0
    rate = float(units) / mean_s

    return {
        "name": name,
        "units": int(units),
        "rounds": int(rounds),
        "samples_s": [float(x) for x in samples],
        "mean_s": float(mean_s),
        "stdev_s": float(stdev_s),
        "cv_pct": float(cv_pct),
        "p95_s": float(_percentile(samples, 95.0)),
        "rate_per_s": float(rate),
    }


class _BenchState:
    summary: dict | None = None


class TestCISafeBenchmarks(unittest.TestCase):
    """Benchmark core CPU generation paths under CI-safe constraints."""

    def test_ci_safe_benchmark_matrix(self):
        thresholds = {
            "max_cv_pct": 5.0,
            "max_regression_pct": 10.0,
            "max_pool_peak_over_buf": 4.0,
        }

        n_packets = 20000
        n_flags = 200000

        cfg_syn = PacketConfig("10.0.0.1", 80, protocol="tcp", tcp_flags="S")
        cfg_pa = PacketConfig("10.0.0.1", 80, protocol="tcp", tcp_flags="PA", payload=b"x" * 32)
        cfg_udp = PacketConfig("10.0.0.1", 53, protocol="udp", payload=b"x" * 32)

        scenarios = {
            "create_packet_tcp_syn": _scenario(
                "create_packet_tcp_syn", n_packets,
                lambda: [create_packet(cfg_syn) for _ in range(n_packets)],
            ),
            "create_packet_tcp_pa": _scenario(
                "create_packet_tcp_pa", n_packets,
                lambda: [create_packet(cfg_pa) for _ in range(n_packets)],
            ),
            "create_packet_udp": _scenario(
                "create_packet_udp", n_packets,
                lambda: [create_packet(cfg_udp) for _ in range(n_packets)],
            ),
            "generate_packet_pool": _scenario(
                "generate_packet_pool", n_packets,
                lambda: generate_packet_pool(cfg_syn, n_packets, low_peak_memory=True),
            ),
            "parse_tcp_flags": _scenario(
                "parse_tcp_flags", n_flags,
                lambda: [parse_tcp_flags("SYNACK") for _ in range(n_flags)],
            ),
        }

        # Memory peak measurement for low-peak pool mode.
        tracemalloc.start()
        pool_buf, pool_pkt_size = generate_packet_pool(cfg_syn, n_packets, low_peak_memory=True)
        _cur, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        pool_buf_len = len(pool_buf)
        peak_over_buf = (float(peak) / float(pool_buf_len)) if pool_buf_len else 0.0

        for info in scenarios.values():
            self.assertLessEqual(
                info["cv_pct"],
                thresholds["max_cv_pct"],
                f"High variance in {info['name']}: cv={info['cv_pct']:.2f}%",
            )

        self.assertLessEqual(
            peak_over_buf,
            thresholds["max_pool_peak_over_buf"],
            f"Pool peak memory ratio too high: {peak_over_buf:.2f}",
        )

        summary = {
            "schema": "samurai.benchmark.summary.v1",
            "profile": "ci_safe",
            "generated_utc": _utc_now_iso(),
            "thresholds": thresholds,
            "params": {
                "n_packets": n_packets,
                "n_flags": n_flags,
                "pool_pkt_size": int(pool_pkt_size),
            },
            "scenarios": scenarios,
            "memory": {
                "pool_buffer_len": int(pool_buf_len),
                "pool_peak_bytes": int(peak),
                "pool_peak_over_buffer_ratio": float(peak_over_buf),
            },
            "baseline": {
                "path": str(os.environ.get("SAMURAI_BENCH_BASELINE", "") or ""),
                "loaded": False,
                "comparisons": {},
            },
        }

        baseline_path = str(os.environ.get("SAMURAI_BENCH_BASELINE", "") or "").strip()
        if baseline_path and Path(baseline_path).exists():
            try:
                baseline = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
                summary["baseline"]["loaded"] = True
                for name, info in scenarios.items():
                    base_rate = float(
                        ((baseline.get("scenarios") or {}).get(name) or {}).get("rate_per_s", 0.0) or 0.0
                    )
                    curr_rate = float(info.get("rate_per_s", 0.0) or 0.0)
                    if base_rate <= 0:
                        continue
                    drop_pct = max(0.0, ((base_rate - curr_rate) * 100.0) / base_rate)
                    summary["baseline"]["comparisons"][name] = {
                        "base_rate_per_s": base_rate,
                        "curr_rate_per_s": curr_rate,
                        "drop_pct": drop_pct,
                    }
                    self.assertLessEqual(
                        drop_pct,
                        thresholds["max_regression_pct"],
                        f"Regression in {name}: drop={drop_pct:.2f}% > {thresholds['max_regression_pct']}%",
                    )
            except Exception as exc:  # pragma: no cover
                summary["baseline"]["load_error"] = f"{type(exc).__name__}: {exc}"

        _BenchState.summary = summary


class TestZZ_WriteBenchmarkReport(unittest.TestCase):
    def test_write_benchmark_report(self):
        summary = _BenchState.summary
        self.assertIsInstance(summary, dict, "Benchmark summary is missing")

        out_path = str(os.environ.get("SAMURAI_BENCH_REPORT_OUT", "") or "").strip()
        if not out_path:
            out_path = str(Path(tempfile.gettempdir()) / "benchmark_summary.json")
        out = _write_json_with_fallback(
            Path(out_path).resolve(),
            summary,
            "benchmark_summary.json",
        )

        # Optional baseline refresh.
        baseline_path = str(os.environ.get("SAMURAI_BENCH_BASELINE", "") or "").strip()
        if baseline_path and _truthy(os.environ.get("SAMURAI_BENCH_UPDATE_BASELINE")):
            _write_json_with_fallback(
                Path(baseline_path).resolve(),
                summary,
                "benchmark_baseline.json",
            )

        self.assertTrue(out.exists())
