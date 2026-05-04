import unittest


class TestL7NativeScenarioTrace(unittest.TestCase):
    def test_native_run_profile_emits_scenario_step_results(self):
        try:
            from ddos_samurai import _l7_emu_native as native
        except Exception:
            self.skipTest("native module unavailable")
        from ddos_samurai.l7_emu import compile_l7_profile
        from ddos_samurai.gpu_cuda_payload import H2RequestPlan, H2RequestPlanItem

        plan = H2RequestPlan(
            items=[
                H2RequestPlanItem(
                    method="GET",
                    path="/",
                    headers={
                        "x-scenario-flow": "trace_flow",
                        "x-scenario-vu-id": "42",
                    },
                )
            ]
        )
        profile_obj = compile_l7_profile(
            protocol="http1",
            target_ip="127.0.0.1",
            target_port=1,
            scheme="http",
            transport_backend="custom_tcp",
            stateful_runtime_backend="afxdp",
            stateful_runtime_strict=False,
            legacy_mode=True,
            template_mode="compat",
            compat_mode="http1_stateful",
            verify=False,
            timeout_s=0.2,
            concurrency=1,
            http_method="GET",
            http_path="/",
            payloads=[],
            request_plan=plan,
            session_repeats=1,
        )
        profile = profile_obj.as_dict()
        cfg = {"concurrency": 1, "profile_l7": 0, "profile_sample_limit": 0}
        out = dict(native.run_profile(profile, cfg) or {})
        rows = list(out.get("scenario_step_results", []) or [])
        self.assertGreaterEqual(len(rows), 1)
        self.assertEqual(str(rows[0].get("flow", "")), "trace_flow")
        self.assertEqual(str(rows[0].get("vu_id", "")), "42")
        self.assertIn("success", rows[0])
