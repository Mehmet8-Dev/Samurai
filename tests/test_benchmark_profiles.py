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
            for name in ("dev", "ci_safe", "dedicated_lab"):
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


if __name__ == "__main__":
    unittest.main()
