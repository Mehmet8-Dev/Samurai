import unittest

from ddos_samurai.gpu_cuda_payload import H2RequestPlan, H2RequestPlanItem
from ddos_samurai.senders import _scenario_step_results_from_plan


class TestScenarioStepResults(unittest.TestCase):
    def test_step_results_include_flow_vu_and_timeout(self):
        plan = H2RequestPlan(
            items=[
                H2RequestPlanItem(method="GET", path="/a", headers={"x-scenario-flow": "f1", "x-scenario-vu-id": "1", "x-scenario-on-failure": "abort"}),
                H2RequestPlanItem(method="GET", path="/b", headers={"x-scenario-flow": "f1", "x-scenario-vu-id": "1"}),
                H2RequestPlanItem(method="GET", path="/c", headers={"x-scenario-flow": "f2", "x-scenario-vu-id": "2"}),
            ]
        )
        rows = _scenario_step_results_from_plan(plan, sent=1, errors=2, timeout_count=1)
        self.assertEqual(len(rows), 3)
        self.assertTrue(rows[0]["success"])
        self.assertFalse(rows[1]["success"])
        self.assertTrue(rows[1]["timeout"])
        self.assertFalse(rows[2]["success"])
        self.assertEqual(rows[2]["flow"], "f2")
        self.assertEqual(rows[2]["vu_id"], "2")
        self.assertEqual(rows[0]["on_failure"], "abort")
        self.assertEqual(rows[1]["on_failure"], "retry")
