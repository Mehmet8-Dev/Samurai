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


def build_profile_runtime(
    profile_name: str,
    profile_spec: Dict[str, Any],
    *,
    artifact_root: str | Path,
    python_bin: str,
) -> Dict[str, Any]:
    adir = _artifact_dir(profile_name, artifact_root)
    required_files = list(((profile_spec.get("artifact_standard") or {}).get("required_files") or []))

    env = dict(os.environ)
    env["SAMURAI_TEST_PROFILE"] = str(profile_spec.get("test_profile", "ci_safe") or "ci_safe")
    env["SAMURAI_PARITY_PROFILE"] = str(profile_spec.get("parity_profile", profile_name) or profile_name)
    env["SAMURAI_KPI_GATE_PROFILE"] = str(profile_spec.get("kpi_gate_profile", profile_name) or profile_name)
    env["SAMURAI_BENCH_REPORT_OUT"] = str((adir / "benchmark_summary.json").resolve())

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
    ]
    export_env = {k: env[k] for k in export_keys if k in env}

    env_prefix = " ".join(f"{k}={shlex.quote(v)}" for k, v in export_env.items())
    cmd_string = " ".join(shlex.quote(part) for part in command)
    rendered = f"{env_prefix} {cmd_string}".strip()

    return {
        "profile": profile_name,
        "artifact_dir": str(adir),
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
    summary_path = (adir / "benchmark_summary.json").resolve()
    if summary_fields and summary_path.exists():
        try:
            payload = json.loads(summary_path.read_text(encoding="utf-8"))
            for field in summary_fields:
                if str(field) not in payload:
                    missing.append(f"{summary_path}::field::{field}")
        except Exception as exc:
            missing.append(f"{summary_path}::parse_error::{type(exc).__name__}: {exc}")

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
