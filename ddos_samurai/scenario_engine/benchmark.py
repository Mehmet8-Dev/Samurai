from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import time
import tracemalloc
from pathlib import Path
from typing import Any

from .compiler import scenario_spec_from_dict, scenario_spec_to_dict
from .native import build_worker_session_plans
from .types import ScenarioSpec


@dataclass(frozen=True)
class ScenarioBenchRow:
    vus: int
    workers: int
    elapsed_s: float
    peak_mem_bytes: int
    sessions_started: int
    step_attempted: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "vus": int(self.vus),
            "workers": int(self.workers),
            "elapsed_s": float(self.elapsed_s),
            "peak_mem_bytes": int(self.peak_mem_bytes),
            "sessions_started": int(self.sessions_started),
            "step_attempted": int(self.step_attempted),
        }


def _worker_counts_for(total_vus: int, workers: int) -> list[int]:
    w = max(1, int(workers))
    total = max(1, int(total_vus))
    per = total // w
    rem = total % w
    out = [per] * w
    for i in range(rem):
        out[i] += 1
    return out


def run_compile_benchmark(
    spec: dict[str, Any] | ScenarioSpec,
    *,
    scales: list[int] | None = None,
    workers: int = 16,
    seed: int = 1337,
) -> dict[str, Any]:
    rows: list[ScenarioBenchRow] = []
    raw = scenario_spec_to_dict(spec) if isinstance(spec, ScenarioSpec) else dict(spec or {})
    scale_values = list(scales or [10_000, 100_000, 300_000, 1_000_000])
    for vus in scale_values:
        row_spec = dict(raw)
        lm = dict(row_spec.get("load_model") or {})
        lm["concurrent_vus"] = int(vus)
        row_spec["load_model"] = lm
        parsed = scenario_spec_from_dict(row_spec)
        wc = _worker_counts_for(vus, workers)
        tracemalloc.start()
        t0 = time.perf_counter()
        plans, metrics = build_worker_session_plans(parsed, wc, seed)
        elapsed = max(0.0, float(time.perf_counter() - t0))
        _cur, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        sessions_started = int(sum(len(x) for x in list(plans or [])))
        rows.append(
            ScenarioBenchRow(
                vus=int(vus),
                workers=int(workers),
                elapsed_s=elapsed,
                peak_mem_bytes=int(peak),
                sessions_started=sessions_started,
                step_attempted=int((metrics or {}).get("step_attempted", 0) or 0),
            )
        )
    best_1m = next((r for r in rows if int(r.vus) == 1_000_000), None)
    derived_rows = []
    for r in rows:
        per_session_peak = float(r.peak_mem_bytes) / max(1.0, float(r.sessions_started))
        derived_rows.append(
            {
                **r.to_dict(),
                "per_session_peak_mem_bytes": float(per_session_peak),
            }
        )
    return {
        "schema": "samurai.scenario.benchmark.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rows": derived_rows,
        "summary": {
            "target_1m_elapsed_s": float(best_1m.elapsed_s) if best_1m is not None else None,
            "target_1m_peak_mem_bytes": int(best_1m.peak_mem_bytes) if best_1m is not None else None,
            "target_1m_per_session_peak_mem_bytes": (
                float(best_1m.peak_mem_bytes) / max(1.0, float(best_1m.sessions_started))
            ) if best_1m is not None else None,
        },
    }


def write_compile_benchmark_report(report: dict[str, Any], out_path: str | Path) -> str:
    p = Path(out_path).expanduser().resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(report, ensure_ascii=True, indent=2), encoding="utf-8")
    return str(p)


def write_memory_profile_report(report: dict[str, Any], out_path: str | Path) -> str:
    p = Path(out_path).expanduser().resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    rows = list(report.get("rows", []) or [])
    lines = [
        "# Scenario Compile Memory Profile",
        "",
        f"- schema: `{report.get('schema', '')}`",
        f"- generated_at: `{report.get('generated_at', '')}`",
        "",
        "| VUs | Workers | Elapsed (s) | Peak Mem (bytes) | Per-Session Peak (bytes) |",
        "|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            "| {vus} | {workers} | {elapsed:.6f} | {peak} | {per:.3f} |".format(
                vus=int(row.get("vus", 0) or 0),
                workers=int(row.get("workers", 0) or 0),
                elapsed=float(row.get("elapsed_s", 0.0) or 0.0),
                peak=int(row.get("peak_mem_bytes", 0) or 0),
                per=float(row.get("per_session_peak_mem_bytes", 0.0) or 0.0),
            )
        )
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(p)
