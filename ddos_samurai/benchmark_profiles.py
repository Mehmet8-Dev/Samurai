from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Tuple


_PROFILE_ALIASES: Dict[str, str] = {
    "developer_fallback": "ci_safe",
    "full": "dedicated_lab",
}


def _default_profiles_path() -> Path:
    return (Path(__file__).resolve().parents[1] / "benchmarks" / "benchmark_profiles.json").resolve()


def _default_parity_path() -> Path:
    return (Path(__file__).resolve().parents[1] / "benchmarks" / "parity_matrix.json").resolve()


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_profiles(profiles_path: str | Path | None = None) -> Tuple[Path, Dict[str, Any]]:
    path = Path(profiles_path).resolve() if profiles_path else _default_profiles_path()
    payload = _load_json(path)
    profiles = payload.get("profiles") or {}
    if not isinstance(profiles, dict) or not profiles:
        raise ValueError(f"invalid benchmark profiles file: {path}")
    return path, payload


def resolve_profile_name(name: str, profiles: Dict[str, Any]) -> str:
    raw = str(name or "").strip().lower()
    mapped = _PROFILE_ALIASES.get(raw, raw)
    if mapped not in profiles:
        valid = ", ".join(sorted(profiles.keys()))
        raise KeyError(f"unknown profile '{name}', valid: {valid}")
    return mapped


def load_parity_gates(profile_name: str, parity_matrix_path: str | Path | None = None) -> Dict[str, Any]:
    path = Path(parity_matrix_path).resolve() if parity_matrix_path else _default_parity_path()
    data = _load_json(path)
    profiles = data.get("profiles") or {}
    gates = ((profiles.get(profile_name) or {}).get("gates") or {})
    return dict(gates) if isinstance(gates, dict) else {}


def _artifact_dir(profile_name: str, artifact_root: str | Path) -> Path:
    return (Path(artifact_root).resolve() / profile_name).resolve()


def _summary_filename(profile_spec: Dict[str, Any]) -> str:
    raw = str(profile_spec.get("summary_file", "") or "").strip()
    return raw or "benchmark_summary.json"


def build_profile_runtime(
    profile_name: str,
    profile_spec: Dict[str, Any],
    *,
    artifact_root: str | Path,
    python_bin: str,
) -> Dict[str, Any]:
    adir = _artifact_dir(profile_name, artifact_root)
    required_files = list(((profile_spec.get("artifact_standard") or {}).get("required_files") or []))
    summary_file = _summary_filename(profile_spec)
    summary_path = (adir / summary_file).resolve()

    env = dict(os.environ)
    env["SAMURAI_TEST_PROFILE"] = str(profile_spec.get("test_profile", "ci_safe") or "ci_safe")
    env["SAMURAI_PARITY_PROFILE"] = str(profile_spec.get("parity_profile", profile_name) or profile_name)
    env["SAMURAI_KPI_GATE_PROFILE"] = str(profile_spec.get("kpi_gate_profile", profile_name) or profile_name)
    env["SAMURAI_BENCH_REPORT_OUT"] = str(summary_path)

    for key, value in dict(profile_spec.get("env") or {}).items():
        env[str(key)] = str(value)

    if "loss_telemetry_full.json" in required_files:
        env["SAMURAI_LOSS_REPORT_OUT"] = str((adir / "loss_telemetry_full.json").resolve())

    pytest_args = list(profile_spec.get("pytest_args") or [])
    if not pytest_args:
        raise ValueError(f"profile '{profile_name}' missing pytest_args")

    command = [str(python_bin)] + [str(x) for x in pytest_args]

    export_keys = [
        "SAMURAI_TEST_PROFILE",
        "SAMURAI_PARITY_PROFILE",
        "SAMURAI_KPI_GATE_PROFILE",
        "SAMURAI_BENCH_REPORT_OUT",
        "SAMURAI_BENCH_BASELINE",
        "SAMURAI_BENCH_UPDATE_BASELINE",
        "SAMURAI_LOSS_FAIL_PCT",
        "SAMURAI_LOSS_REPORT_OUT",
        "SAMURAI_STATEFUL_RUNTIME_BACKEND",
        "SAMURAI_L7_CAPABILITY_STRICT",
        "SAMURAI_CUSTOM_TCP_MODE",
        "SAMURAI_CUSTOM_TCP_BACKEND",
    ]
    export_env = {k: env[k] for k in export_keys if k in env}

    env_prefix = " ".join(f"{k}={shlex.quote(v)}" for k, v in export_env.items())
    cmd_string = " ".join(shlex.quote(part) for part in command)
    rendered = f"{env_prefix} {cmd_string}".strip()

    return {
        "profile": profile_name,
        "artifact_dir": str(adir),
        "summary_file": summary_file,
        "summary_path": str(summary_path),
        "required_files": required_files,
        "required_summary_fields": list(((profile_spec.get("artifact_standard") or {}).get("required_summary_fields") or [])),
        "command": command,
        "command_string": rendered,
        "env": env,
        "export_env": export_env,
    }


def _validate_artifacts(runtime: Dict[str, Any], *, ignore_meta: bool = False) -> Tuple[bool, list[str]]:
    adir = Path(str(runtime["artifact_dir"]))
    missing: list[str] = []
    for rel in list(runtime.get("required_files") or []):
        if ignore_meta and str(rel).strip() == "benchmark_meta.json":
            continue
        f = (adir / str(rel)).resolve()
        if not f.exists():
            missing.append(str(f))

    summary_fields = list(runtime.get("required_summary_fields") or [])
    summary_path_raw = str(runtime.get("summary_path", "") or "").strip()
    if summary_path_raw:
        summary_path = Path(summary_path_raw).resolve()
    else:
        summary_file = str(runtime.get("summary_file", "") or "").strip() or "benchmark_summary.json"
        summary_path = (adir / summary_file).resolve()
    if summary_fields and summary_path.exists():
        try:
            payload = json.loads(summary_path.read_text(encoding="utf-8"))
            for field in summary_fields:
                if str(field) not in payload:
                    missing.append(f"{summary_path}::field::{field}")
        except Exception as exc:
            missing.append(f"{summary_path}::parse_error::{type(exc).__name__}: {exc}")
    if summary_path.exists():
        try:
            payload = json.loads(summary_path.read_text(encoding="utf-8"))
            normalized = ((payload.get("parity") or {}).get("normalized_results") or {})
            acceptance = (payload.get("acceptance") or {})
            gate_status = str(normalized.get("kpi_gate_status", "") or "").strip().lower()
            score_eligible_raw = normalized.get("score_eligible", 0)
            try:
                score_eligible = int(score_eligible_raw)
            except Exception:
                score_eligible = -1
            if gate_status != "pass":
                missing.append(f"{summary_path}::kpi_gate_status::{gate_status or 'missing'}")
            if score_eligible != 1:
                missing.append(f"{summary_path}::score_eligible::{score_eligible_raw}")
            live_perf_status = str(acceptance.get("live_perf_gate_status", "") or "").strip().lower()
            live_perf_required = int(acceptance.get("live_perf_required", 0) or 0)
            if live_perf_required == 1 and live_perf_status != "pass":
                missing.append(f"{summary_path}::live_perf_gate_status::{live_perf_status or 'missing'}")
            profile_name = str(runtime.get("profile", "") or "").strip().lower()
            if profile_name == "dedicated_lab":
                sender_fallback_reason = str(normalized.get("sender_fallback_reason", "") or "").strip().lower()
                if sender_fallback_reason not in {"", "none"}:
                    missing.append(f"{summary_path}::sender_fallback_reason::{sender_fallback_reason}")
                runtime_backend = str(normalized.get("runtime_backend", "") or "").strip().lower()
                if runtime_backend != "afxdp":
                    missing.append(f"{summary_path}::runtime_backend::{runtime_backend or 'missing'}")
                runtime_hot_path_level = str(normalized.get("runtime_hot_path_level", "") or "").strip()
                if runtime_hot_path_level != "phase1_hybrid_afxdp_custom_tcp":
                    missing.append(f"{summary_path}::runtime_hot_path_level::{runtime_hot_path_level or 'missing'}")
                legacy_path_used_raw = normalized.get("legacy_path_used", 1)
                try:
                    legacy_path_used = int(legacy_path_used_raw)
                except Exception:
                    legacy_path_used = 1
                if legacy_path_used != 0:
                    missing.append(f"{summary_path}::legacy_path_used::{legacy_path_used_raw}")
                preflight_status = str(normalized.get("stateful_runtime_preflight_status", "") or "").strip().lower()
                if preflight_status != "passed":
                    missing.append(f"{summary_path}::stateful_runtime_preflight_status::{preflight_status or 'missing'}")
                runtime_transport_backend = str(normalized.get("runtime_transport_backend", "") or "").strip().lower()
                if runtime_transport_backend != "custom_tcp":
                    missing.append(f"{summary_path}::runtime_transport_backend::{runtime_transport_backend or 'missing'}")
                stateful_runtime_status = str(normalized.get("stateful_runtime_status", "") or "").strip().lower()
                if stateful_runtime_status != "ready":
                    missing.append(f"{summary_path}::stateful_runtime_status::{stateful_runtime_status or 'missing'}")
                preflight_xdp_enabled_raw = normalized.get("stateful_runtime_preflight_xdp_enabled", 0)
                try:
                    preflight_xdp_enabled = int(preflight_xdp_enabled_raw)
                except Exception:
                    preflight_xdp_enabled = 0
                if preflight_xdp_enabled != 1:
                    missing.append(
                        f"{summary_path}::stateful_runtime_preflight_xdp_enabled::{preflight_xdp_enabled_raw}"
                    )
                sender_paths_used = normalized.get("sender_paths_used")
                if not isinstance(sender_paths_used, dict):
                    missing.append(f"{summary_path}::sender_paths_used::non_dict")
                else:
                    active_paths = []
                    for key, raw_count in sender_paths_used.items():
                        try:
                            cnt = float(raw_count)
                        except Exception:
                            continue
                        if cnt > 0:
                            active_paths.append(str(key or "").strip())
                    active_paths = [p for p in active_paths if p]
                    if len(active_paths) != 1:
                        missing.append(f"{summary_path}::sender_path_drift::{len(active_paths)}")
                    elif str(active_paths[0]).upper() == "MIXED":
                        missing.append(f"{summary_path}::sender_path_drift::MIXED")
            elif profile_name == "l7_dataplane_ci":
                required_h2_fields = (
                    "l7_h2_lane_reuse_ratio",
                    "l7_h2_active_streams_peak",
                    "h2_goaway_replacements",
                    "h2_drain_evictions",
                    "h2_replace_now_decisions",
                    "h2_replace_after_idle_decisions",
                    "h2_stream_pool_reuse_hits",
                    "runtime_backend",
                    "runtime_hot_path_level",
                    "legacy_path_used",
                    "runtime_transport_backend",
                    "h1_conn_rate_cv_pct",
                    "h2_conn_rate_cv_pct",
                    "l7_conn_rate_cv_pct",
                )
                for key in required_h2_fields:
                    if key not in normalized:
                        missing.append(f"{summary_path}::{key}::missing")
                numeric_h2_fields = (
                    "l7_h2_lane_reuse_ratio",
                    "l7_h2_active_streams_peak",
                    "h2_goaway_replacements",
                    "h2_drain_evictions",
                    "h2_replace_now_decisions",
                    "h2_replace_after_idle_decisions",
                    "h2_stream_pool_reuse_hits",
                    "h1_conn_rate_cv_pct",
                    "h2_conn_rate_cv_pct",
                    "l7_conn_rate_cv_pct",
                )
                for key in numeric_h2_fields:
                    if key not in normalized:
                        continue
                    raw = normalized.get(key, 0)
                    try:
                        value = float(raw)
                    except Exception:
                        missing.append(f"{summary_path}::{key}::non_numeric::{raw}")
                        continue
                    if value < 0:
                        missing.append(f"{summary_path}::{key}::negative::{raw}")
                runtime_backend = str(normalized.get("runtime_backend", "") or "").strip().lower()
                if runtime_backend != "afxdp":
                    missing.append(f"{summary_path}::runtime_backend::{runtime_backend or 'missing'}")
                runtime_hot_path_level = str(normalized.get("runtime_hot_path_level", "") or "").strip()
                if runtime_hot_path_level != "phase1_hybrid_afxdp_custom_tcp":
                    missing.append(f"{summary_path}::runtime_hot_path_level::{runtime_hot_path_level or 'missing'}")
                runtime_transport_backend = str(normalized.get("runtime_transport_backend", "") or "").strip().lower()
                if runtime_transport_backend != "custom_tcp":
                    missing.append(f"{summary_path}::runtime_transport_backend::{runtime_transport_backend or 'missing'}")
                legacy_path_used_raw = normalized.get("legacy_path_used", 1)
                try:
                    legacy_path_used = int(legacy_path_used_raw)
                except Exception:
                    legacy_path_used = 1
                if legacy_path_used != 0:
                    missing.append(f"{summary_path}::legacy_path_used::{legacy_path_used_raw}")
                for key in ("h1_conn_rate_cv_pct", "h2_conn_rate_cv_pct", "l7_conn_rate_cv_pct"):
                    try:
                        cv = float(normalized.get(key, 100.0) or 100.0)
                    except Exception:
                        missing.append(f"{summary_path}::{key}::non_numeric")
                        continue
                    if cv > 5.0:
                        missing.append(f"{summary_path}::{key}::too_high::{cv}")
        except Exception as exc:
            missing.append(f"{summary_path}::pipeline_parse_error::{type(exc).__name__}: {exc}")

    return len(missing) == 0, missing


def _write_meta(
    runtime: Dict[str, Any],
    *,
    expected_kpi: Dict[str, Any],
    return_code: int,
    artifact_ok: bool,
    missing_artifacts: list[str],
) -> Path:
    adir = Path(str(runtime["artifact_dir"]))
    adir.mkdir(parents=True, exist_ok=True)
    out = (adir / "benchmark_meta.json").resolve()
    payload = {
        "schema": "samurai.benchmark.profile.run.v1",
        "profile": runtime.get("profile"),
        "command": runtime.get("command"),
        "command_string": runtime.get("command_string"),
        "export_env": runtime.get("export_env"),
        "expected_kpi_thresholds": expected_kpi,
        "artifact_standard": {
            "artifact_dir": str(adir),
            "required_files": runtime.get("required_files"),
            "required_summary_fields": runtime.get("required_summary_fields"),
            "artifact_ok": bool(artifact_ok),
            "missing": list(missing_artifacts),
        },
        "return_code": int(return_code),
    }
    out.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return out


def run_profile(
    profile_name: str,
    *,
    profiles_path: str | Path | None = None,
    parity_matrix_path: str | Path | None = None,
    artifact_root: str | Path = "artifacts/benchmarks",
    python_bin: str = sys.executable,
) -> int:
    _path, matrix = load_profiles(profiles_path)
    profiles = matrix.get("profiles") or {}
    resolved = resolve_profile_name(profile_name, profiles)
    spec = dict(profiles.get(resolved) or {})

    runtime = build_profile_runtime(
        resolved,
        spec,
        artifact_root=artifact_root,
        python_bin=python_bin,
    )
    expected_kpi = load_parity_gates(str(spec.get("parity_profile", resolved)), parity_matrix_path=parity_matrix_path)

    try:
        Path(str(runtime["artifact_dir"])).mkdir(parents=True, exist_ok=True)
    except PermissionError:
        fallback_roots = [
            (Path.cwd() / ".pytest_artifacts" / "benchmarks").resolve(),
            (Path("/tmp") / ".pytest_artifacts" / "benchmarks").resolve(),
        ]
        last_error: Exception | None = None
        for root in fallback_roots:
            runtime = build_profile_runtime(
                resolved,
                spec,
                artifact_root=root,
                python_bin=python_bin,
            )
            try:
                Path(str(runtime["artifact_dir"])).mkdir(parents=True, exist_ok=True)
                last_error = None
                break
            except PermissionError as exc:
                last_error = exc
                continue
        if last_error is not None:
            raise last_error
    proc = subprocess.run(runtime["command"], env=runtime["env"], check=False)

    # Validate required artifacts that should be produced by benchmark command itself.
    artifact_ok, missing = _validate_artifacts(runtime, ignore_meta=True)
    _write_meta(
        runtime,
        expected_kpi=expected_kpi,
        return_code=int(proc.returncode),
        artifact_ok=artifact_ok,
        missing_artifacts=missing,
    )
    # Re-check after writing benchmark_meta.json to enforce full artifact contract.
    artifact_ok, missing = _validate_artifacts(runtime, ignore_meta=False)
    _write_meta(
        runtime,
        expected_kpi=expected_kpi,
        return_code=int(proc.returncode),
        artifact_ok=artifact_ok,
        missing_artifacts=missing,
    )
    if int(proc.returncode) != 0:
        return int(proc.returncode)
    return 0 if artifact_ok else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run productized benchmark profiles.")
    parser.add_argument("--profile", type=str, default="ci_safe", help="Profile name: dev|ci_safe|dedicated_lab")
    parser.add_argument("--profiles-path", type=str, default="", help="Override benchmark profiles JSON path.")
    parser.add_argument("--parity-matrix-path", type=str, default="", help="Override parity matrix JSON path.")
    parser.add_argument("--artifact-root", type=str, default="artifacts/benchmarks", help="Artifact root directory.")
    parser.add_argument("--python-bin", type=str, default=sys.executable, help="Python executable for pytest command.")
    parser.add_argument("--run", action="store_true", help="Execute the selected benchmark profile.")
    parser.add_argument("--list", action="store_true", help="List available profiles and exit.")
    args = parser.parse_args(argv)

    path, matrix = load_profiles(args.profiles_path or None)
    profiles = matrix.get("profiles") or {}

    if args.list:
        print(f"profiles_file={path}")
        for name in sorted(profiles.keys()):
            desc = str(((profiles.get(name) or {}).get("description") or "")).strip()
            print(f"- {name}: {desc}")
        return 0

    resolved = resolve_profile_name(args.profile, profiles)
    spec = dict(profiles.get(resolved) or {})
    runtime = build_profile_runtime(
        resolved,
        spec,
        artifact_root=args.artifact_root,
        python_bin=args.python_bin,
    )
    expected_kpi = load_parity_gates(
        str(spec.get("parity_profile", resolved)),
        parity_matrix_path=args.parity_matrix_path or None,
    )

    print(f"profile={resolved}")
    print(f"command={runtime['command_string']}")
    print(f"artifact_dir={runtime['artifact_dir']}")
    print("expected_kpi_thresholds=" + json.dumps(expected_kpi, sort_keys=True))
    print("artifact_standard=" + json.dumps({
        "required_files": runtime.get("required_files", []),
        "required_summary_fields": runtime.get("required_summary_fields", []),
    }, sort_keys=True))

    if not args.run:
        return 0

    return run_profile(
        resolved,
        profiles_path=args.profiles_path or None,
        parity_matrix_path=args.parity_matrix_path or None,
        artifact_root=args.artifact_root,
        python_bin=args.python_bin,
    )


if __name__ == "__main__":
    raise SystemExit(main())
