import unittest

from ddos_samurai.l7.dispatch import build_route_decision
from ddos_samurai.l7.types import L7RouteRequest


class TestL7Dispatch(unittest.TestCase):
    def test_http1_uses_global_l7_engine(self):
        route = build_route_decision(
            L7RouteRequest(
                protocol="http1",
                l7_engine="c_state",
                fallback_policy="allow",
            )
        )
        self.assertEqual(route.engine, "c_state")
        self.assertEqual(route.l7_engine_path_used, "C_STATE_HTTP1")

    def test_http2_auto_prefers_c_state(self):
        route = build_route_decision(
            L7RouteRequest(
                protocol="http2",
                l7_engine="python",
                protocol_engine="auto",
                fallback_policy="allow",
            )
        )
        self.assertEqual(route.engine, "c_state")
        self.assertEqual(route.l7_engine_path_used, "C_STATE_H2")
        self.assertTrue(route.allow_python_fallback)

    def test_http1_allow_policy_keeps_python_fallback_open(self):
        route = build_route_decision(
            L7RouteRequest(
                protocol="http1",
                l7_engine="c_state",
                protocol_engine="auto",
                fallback_policy="allow",
            )
        )
        self.assertTrue(route.allow_python_fallback)

    def test_capability_strict_disables_fallback(self):
        route = build_route_decision(
            L7RouteRequest(
                protocol="quic",
                protocol_engine="auto",
                fallback_policy="allow",
                capability_strict=True,
            )
        )
        self.assertEqual(route.engine, "c_state")
        self.assertFalse(route.allow_python_fallback)
