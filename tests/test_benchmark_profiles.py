import tempfile
import unittest
from pathlib import Path
import json

from ddos_samurai import benchmark_profiles


class TestBenchmarkProfiles(unittest.TestCase):
    def test_profiles_file_has_fixed_profiles(self):
        path, payload = benchmark_profiles.load_profiles()
        self.assertTrue(path.exists())
        profiles = payload.get("profiles") or {}
        self.assertIn("dev", profiles)
        self.assertIn("ci_safe", profiles)
        self.assertIn("l7_dataplane_ci", profiles)
        self.assertIn("dedicated_lab", profiles)

    def test_resolve_profile_aliases(self):
        _path, payload = benchmark_profiles.load_profiles()
        profiles = payload.get("profiles") or {}
        self.assertEqual(benchmark_profiles.resolve_profile_name("developer_fallback", profiles), "ci_safe")
        self.assertEqual(benchmark_profiles.resolve_profile_name("full", profiles), "dedicated_lab")

    def test_runtime_renders_single_command(self):
        _path, payload = benchmark_profiles.load_profiles()
        profiles = payload.get("profiles") or {}
        with tempfile.TemporaryDirectory() as td:
            for name in ("dev", "ci_safe", "l7_dataplane_ci", "dedicated_lab"):
                runtime = benchmark_profiles.build_profile_runtime(
                    name,
                    dict(profiles[name]),
                    artifact_root=td,
                    python_bin="/usr/bin/python3",
                )
                cmd = str(runtime.get("command_string", ""))
                self.assertIn("pytest", cmd)
                self.assertIn("SAMURAI_BENCH_REPORT_OUT", cmd)
                self.assertTrue(str(runtime.get("artifact_dir", "")).startswith(str(Path(td).resolve())))
                self.assertTrue(str(runtime.get("summary_path", "")).startswith(str(Path(td).resolve())))

    def test_dedicated_lab_runtime_exports_stateful_runtime_env(self):
        _path, payload = benchmark_profiles.load_profiles()
        profiles = payload.get("profiles") or {}
        with tempfile.TemporaryDirectory() as td:
            runtime = benchmark_profiles.build_profile_runtime(
                "dedicated_lab",
                dict(profiles["dedicated_lab"]),
                artifact_root=td,
                python_bin="/usr/bin/python3",
            )
            export_env = dict(runtime.get("export_env") or {})
            self.assertEqual(export_env["SAMURAI_STATEFUL_RUNTIME_BACKEND"], "afxdp")
            self.assertEqual(export_env["SAMURAI_L7_CAPABILITY_STRICT"], "1")
            self.assertEqual(export_env["SAMURAI_CUSTOM_TCP_MODE"], "required")
            self.assertEqual(export_env["SAMURAI_CUSTOM_TCP_BACKEND"], "af_xdp")

    def test_l7_runtime_uses_profile_specific_summary_file(self):
        _path, payload = benchmark_profiles.load_profiles()
        profiles = payload.get("profiles") or {}
        with tempfile.TemporaryDirectory() as td:
            runtime = benchmark_profiles.build_profile_runtime(
                "l7_dataplane_ci",
                dict(profiles["l7_dataplane_ci"]),
                artifact_root=td,
                python_bin="/usr/bin/python3",
            )
            self.assertTrue(str(runtime.get("summary_path", "")).endswith("benchmark_l7_summary.json"))
            self.assertTrue(str(runtime["env"]["SAMURAI_BENCH_REPORT_OUT"]).endswith("benchmark_l7_summary.json"))

    def test_expected_kpi_thresholds_exist_for_all_profiles(self):
        _path, payload = benchmark_profiles.load_profiles()
        profiles = payload.get("profiles") or {}
        for name in ("dev", "ci_safe", "dedicated_lab"):
            parity_profile = str((profiles.get(name) or {}).get("parity_profile") or name)
            gates = benchmark_profiles.load_parity_gates(parity_profile)
            self.assertEqual(str(gates.get("run_quality", "")), "valid")
            self.assertIn("send_success_ratio_pct_min", gates)
            self.assertIn("wire_loss_est_pct_max", gates)

    def test_artifact_validation_meta_flow(self):
        with tempfile.TemporaryDirectory() as td:
            artifact_dir = Path(td).resolve()
            payload = {
                "parity": {
                    "normalized_results": {
                        "kpi_gate_status": "pass",
                        "score_eligible": 1,
                    }
                }
            }
            (artifact_dir / "benchmark_summary.json").write_text(json.dumps(payload), encoding="utf-8")
            runtime = {
                "artifact_dir": str(artifact_dir),
                "required_files": ["benchmark_summary.json", "benchmark_meta.json"],
                "required_summary_fields": [],
            }
            ok_ignore, _missing_ignore = benchmark_profiles._validate_artifacts(runtime, ignore_meta=True)
            ok_full_before, _missing_before = benchmark_profiles._validate_artifacts(runtime, ignore_meta=False)
            self.assertTrue(ok_ignore)
            self.assertFalse(ok_full_before)
            (artifact_dir / "benchmark_meta.json").write_text("{}", encoding="utf-8")
            ok_full_after, _missing_after = benchmark_profiles._validate_artifacts(runtime, ignore_meta=False)
            self.assertTrue(ok_full_after)

    def test_artifact_validation_uses_custom_summary_path(self):
        with tempfile.TemporaryDirectory() as td:
            artifact_dir = Path(td).resolve()
            summary_path = artifact_dir / "benchmark_l7_summary.json"
            payload = {
                "schema": "samurai.benchmark.summary.v1",
                "profile": "l7_dataplane_ci",
                "generated_utc": "2026-04-08T00:00:00Z",
                "scenarios": {},
                "parity": {
                    "normalized_results": {
                        "kpi_gate_status": "pass",
                        "score_eligible": 1,
                        "runtime_backend": "afxdp",
                        "runtime_hot_path_level": "phase1_hybrid_afxdp_custom_tcp",
                        "legacy_path_used": 0,
                        "runtime_transport_backend": "custom_tcp",
                        "l7_h2_lane_reuse_ratio": 0.75,
                        "l7_h2_active_streams_peak": 8,
                        "h2_goaway_replacements": 1,
                        "h2_drain_evictions": 1,
                        "h2_replace_now_decisions": 1,
                        "h2_replace_after_idle_decisions": 2,
                        "h2_stream_pool_reuse_hits": 6,
                        "h1_conn_rate_cv_pct": 1.0,
                        "h2_conn_rate_cv_pct": 1.0,
                        "l7_conn_rate_cv_pct": 1.0,
                    }
                },
                "acceptance": {},
            }
            summary_path.write_text(json.dumps(payload), encoding="utf-8")
            (artifact_dir / "benchmark_meta.json").write_text("{}", encoding="utf-8")
            runtime = {
                "artifact_dir": str(artifact_dir),
                "summary_path": str(summary_path),
                "required_files": ["benchmark_l7_summary.json", "benchmark_meta.json"],
                "required_summary_fields": ["schema", "profile", "generated_utc", "scenarios", "parity", "acceptance"],
            }
            ok_full, missing = benchmark_profiles._validate_artifacts(runtime, ignore_meta=False)
            self.assertTrue(ok_full, missing)

    def test_artifact_validation_requires_pass_and_score_eligible(self):
        with tempfile.TemporaryDirectory() as td:
            artifact_dir = Path(td).resolve()
            payload = {
                "parity": {
                    "normalized_results": {
                        "kpi_gate_status": "warn",
                        "score_eligible": 0,
                    }
                }
            }
            (artifact_dir / "benchmark_summary.json").write_text(json.dumps(payload), encoding="utf-8")
            (artifact_dir / "benchmark_meta.json").write_text("{}", encoding="utf-8")
            runtime = {
                "artifact_dir": str(artifact_dir),
                "required_files": ["benchmark_summary.json", "benchmark_meta.json"],
                "required_summary_fields": [],
            }
            ok_full, missing = benchmark_profiles._validate_artifacts(runtime, ignore_meta=False)
            self.assertFalse(ok_full)
            self.assertTrue(any("kpi_gate_status" in str(item) for item in missing))
            self.assertTrue(any("score_eligible" in str(item) for item in missing))

    def test_dedicated_artifact_validation_fails_on_sender_path_drift(self):
        with tempfile.TemporaryDirectory() as td:
            artifact_dir = Path(td).resolve()
            payload = {
                "parity": {
                    "normalized_results": {
                        "kpi_gate_status": "pass",
                        "score_eligible": 1,
                        "sender_fallback_reason": "none",
                        "sender_paths_used": {"TX_RING_L2": 1, "C_EXT_L3": 1},
                    }
                }
            }
            (artifact_dir / "benchmark_summary.json").write_text(json.dumps(payload), encoding="utf-8")
            (artifact_dir / "benchmark_meta.json").write_text("{}", encoding="utf-8")
            runtime = {
                "profile": "dedicated_lab",
                "artifact_dir": str(artifact_dir),
                "required_files": ["benchmark_summary.json", "benchmark_meta.json"],
                "required_summary_fields": [],
            }
            ok_full, missing = benchmark_profiles._validate_artifacts(runtime, ignore_meta=False)
            self.assertFalse(ok_full)
            self.assertTrue(any("sender_path_drift" in str(item) for item in missing))

    def test_dedicated_artifact_validation_fails_on_sender_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            artifact_dir = Path(td).resolve()
            payload = {
                "parity": {
                    "normalized_results": {
                        "kpi_gate_status": "pass",
                        "score_eligible": 1,
                        "sender_fallback_reason": "txring_unavailable",
                        "sender_paths_used": {"TX_RING_L2": 1},
                    }
                }
            }
            (artifact_dir / "benchmark_summary.json").write_text(json.dumps(payload), encoding="utf-8")
            (artifact_dir / "benchmark_meta.json").write_text("{}", encoding="utf-8")
            runtime = {
                "profile": "dedicated_lab",
                "artifact_dir": str(artifact_dir),
                "required_files": ["benchmark_summary.json", "benchmark_meta.json"],
                "required_summary_fields": [],
            }
            ok_full, missing = benchmark_profiles._validate_artifacts(runtime, ignore_meta=False)
            self.assertFalse(ok_full)
            self.assertTrue(any("sender_fallback_reason" in str(item) for item in missing))

    def test_dedicated_artifact_validation_fails_when_runtime_backend_is_not_afxdp(self):
        with tempfile.TemporaryDirectory() as td:
            artifact_dir = Path(td).resolve()
            payload = {
                "parity": {
                    "normalized_results": {
                        "kpi_gate_status": "pass",
                        "score_eligible": 1,
                        "sender_fallback_reason": "none",
                        "runtime_backend": "legacy",
                        "legacy_path_used": 1,
                        "sender_paths_used": {"L7_EMU_HTTP1": 1},
                    }
                }
            }
            (artifact_dir / "benchmark_summary.json").write_text(json.dumps(payload), encoding="utf-8")
            (artifact_dir / "benchmark_meta.json").write_text("{}", encoding="utf-8")
            runtime = {
                "profile": "dedicated_lab",
                "artifact_dir": str(artifact_dir),
                "required_files": ["benchmark_summary.json", "benchmark_meta.json"],
                "required_summary_fields": [],
            }
            ok_full, missing = benchmark_profiles._validate_artifacts(runtime, ignore_meta=False)
            self.assertFalse(ok_full)
            self.assertTrue(any("runtime_backend" in str(item) for item in missing))
            self.assertTrue(any("legacy_path_used" in str(item) for item in missing))

    def test_dedicated_artifact_validation_fails_when_preflight_is_not_passed(self):
        with tempfile.TemporaryDirectory() as td:
            artifact_dir = Path(td).resolve()
            payload = {
                "parity": {
                    "normalized_results": {
                        "kpi_gate_status": "pass",
                        "score_eligible": 1,
                        "sender_fallback_reason": "none",
                        "runtime_backend": "afxdp",
                        "runtime_hot_path_level": "phase1_hybrid_afxdp_custom_tcp",
                        "legacy_path_used": 0,
                        "stateful_runtime_preflight_status": "failed",
                        "stateful_runtime_preflight_xdp_enabled": 0,
                        "sender_paths_used": {"L7_EMU_HTTP1": 1},
                    }
                }
            }
            (artifact_dir / "benchmark_summary.json").write_text(json.dumps(payload), encoding="utf-8")
            (artifact_dir / "benchmark_meta.json").write_text("{}", encoding="utf-8")
            runtime = {
                "profile": "dedicated_lab",
                "artifact_dir": str(artifact_dir),
                "required_files": ["benchmark_summary.json", "benchmark_meta.json"],
                "required_summary_fields": [],
            }
            ok_full, missing = benchmark_profiles._validate_artifacts(runtime, ignore_meta=False)
            self.assertFalse(ok_full)
            self.assertTrue(any("stateful_runtime_preflight_status" in str(item) for item in missing))
            self.assertTrue(any("stateful_runtime_preflight_xdp_enabled" in str(item) for item in missing))

    def test_l7_dataplane_ci_artifact_validation_requires_h2_parity_fields(self):
        with tempfile.TemporaryDirectory() as td:
            artifact_dir = Path(td).resolve()
            payload = {
                "parity": {
                    "normalized_results": {
                        "kpi_gate_status": "pass",
                        "score_eligible": 1,
                        "l7_h2_lane_reuse_ratio": 0.7,
                        "h2_goaway_replacements": 1,
                    }
                }
            }
            (artifact_dir / "benchmark_l7_summary.json").write_text(json.dumps(payload), encoding="utf-8")
            (artifact_dir / "benchmark_meta.json").write_text("{}", encoding="utf-8")
            runtime = {
                "profile": "l7_dataplane_ci",
                "artifact_dir": str(artifact_dir),
                "summary_path": str((artifact_dir / "benchmark_l7_summary.json").resolve()),
                "required_files": ["benchmark_l7_summary.json", "benchmark_meta.json"],
                "required_summary_fields": [],
            }
            ok_full, missing = benchmark_profiles._validate_artifacts(runtime, ignore_meta=False)
            self.assertFalse(ok_full)
            self.assertTrue(any("l7_h2_active_streams_peak" in str(item) for item in missing))


if __name__ == "__main__":
    unittest.main()
