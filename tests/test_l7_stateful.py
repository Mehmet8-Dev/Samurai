"""
L7 Stateful Correctness Tests — Phased Regression & Feature Tests

Phase 1: WebSocket count distribution, HTTP retries, QUIC request semantics
Phase 2: VirtualUser engine, stateful workflow, L7 metrics
Phase 3: H2 transport, WS scenarios, PCAP flow tracking
"""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

from ddos_samurai import senders as senders_module
from ddos_samurai import virtual_user as vu_module


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------
def _run(coro):
    """Run an async function synchronously."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    raise RuntimeError("_run() cannot be used while an event loop is already running")


class _FakeResponse:
    """Minimal response stub for httpx."""
    def __init__(self, status_code=200):
        self.status_code = status_code


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 1 — WebSocket Count Distribution
# ═══════════════════════════════════════════════════════════════════════════

class TestWebSocketCountDistribution(unittest.TestCase):
    """Verifies that websocket_sender distributes count fairly without remainder loss."""

    @patch.object(senders_module, "WEBSOCKETS_AVAILABLE", True)
    @patch("ddos_samurai.senders.websockets", create=True)
    def test_count_100_concurrency_3_no_remainder_loss(self, mock_ws_module):
        """count=100, concurrency=3 → attempted must be exactly 100."""
        ws_mock = AsyncMock()
        ws_mock.send = AsyncMock()

        # websockets.connect returns an async context manager
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=ws_mock)
        cm.__aexit__ = AsyncMock(return_value=False)
        mock_ws_module.connect = MagicMock(return_value=cm)

        stats = _run(senders_module.websocket_sender(
            target_ip="127.0.0.1", target_port=8080,
            count=100, concurrency=3,
            ws_path="/ws", ws_message="ping",
            verbose=False
        ))
        self.assertEqual(stats["attempted"], 100, "attempted must equal count exactly (no remainder loss)")
        self.assertEqual(stats["sent"], 100)
        self.assertEqual(ws_mock.send.call_count, 100)

    @patch.object(senders_module, "WEBSOCKETS_AVAILABLE", True)
    @patch("ddos_samurai.senders.websockets", create=True)
    def test_count_10_concurrency_50_no_overconcurrency(self, mock_ws_module):
        """count=10, concurrency=50 → only 10 workers should run, attempted=10."""
        ws_mock = AsyncMock()
        ws_mock.send = AsyncMock()

        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=ws_mock)
        cm.__aexit__ = AsyncMock(return_value=False)
        mock_ws_module.connect = MagicMock(return_value=cm)

        stats = _run(senders_module.websocket_sender(
            target_ip="127.0.0.1", target_port=443,
            count=10, concurrency=50,
            ws_path="/ws", ws_message="hello",
            verbose=False
        ))
        self.assertEqual(stats["attempted"], 10, "attempted must not exceed count")
        self.assertEqual(stats["sent"], 10)
        # connect should be called exactly 10 times (not 50)
        self.assertEqual(mock_ws_module.connect.call_count, 10)

    @patch.object(senders_module, "WEBSOCKETS_AVAILABLE", True)
    @patch("ddos_samurai.senders.websockets", create=True)
    def test_count_7_concurrency_3_fair_split(self, mock_ws_module):
        """count=7, concurrency=3 → workers get 3,2,2 (not 2,2,2=6)."""
        ws_mock = AsyncMock()
        ws_mock.send = AsyncMock()

        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=ws_mock)
        cm.__aexit__ = AsyncMock(return_value=False)
        mock_ws_module.connect = MagicMock(return_value=cm)

        stats = _run(senders_module.websocket_sender(
            target_ip="127.0.0.1", target_port=8080,
            count=7, concurrency=3,
            ws_path="/ws", ws_message="test",
            verbose=False
        ))
        self.assertEqual(stats["attempted"], 7)
        self.assertEqual(stats["sent"], 7)
        self.assertEqual(ws_mock.send.call_count, 7)


class TestWebSocketScenarioEngine(unittest.TestCase):
    """Phase 3: connect/auth/subscribe/ping-pong scenario flow."""

    @patch.object(senders_module, "WEBSOCKETS_AVAILABLE", True)
    @patch("ddos_samurai.senders.websockets", create=True)
    def test_websocket_scenario_state_machine(self, mock_ws_module):
        ws_mock = AsyncMock()
        ws_mock.send = AsyncMock()
        ws_mock.recv = AsyncMock(return_value="ok")

        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=ws_mock)
        cm.__aexit__ = AsyncMock(return_value=False)
        mock_ws_module.connect = MagicMock(return_value=cm)

        stats = _run(senders_module.websocket_scenario_sender(
            target_ip="127.0.0.1",
            target_port=8080,
            count=2,
            concurrency=1,
            ws_path="/ws",
            verbose=False,
            auth_message="AUTH",
            subscribe_messages=["SUB_A", "SUB_B"],
            ping_message="PING",
            ping_count=2,
            await_response=True,
        ))

        self.assertEqual(stats["attempted"], 2)
        self.assertEqual(stats["sent"], 2)
        self.assertEqual(stats["errors"], 0)
        self.assertEqual(stats["ws_auth_sent"], 2)
        self.assertEqual(stats["ws_subscribe_sent"], 4)
        self.assertEqual(stats["ws_ping_sent"], 4)
        self.assertEqual(stats["ws_pong_received"], 10)
        self.assertEqual(ws_mock.send.call_count, 10)
        self.assertEqual(ws_mock.recv.call_count, 10)

    @patch.object(senders_module, "WEBSOCKETS_AVAILABLE", True)
    @patch("ddos_samurai.senders.websockets", create=True)
    def test_websocket_scenario_request_plan_paths_are_used(self, mock_ws_module):
        ws_mock = AsyncMock()
        ws_mock.send = AsyncMock()
        ws_mock.recv = AsyncMock(return_value="ok")

        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=ws_mock)
        cm.__aexit__ = AsyncMock(return_value=False)
        mock_ws_module.connect = MagicMock(return_value=cm)

        class _PlanItem:
            def __init__(self, path):
                self.path = path
                self.method = "GET"
                self.user_agent = ""
                self.ws_auth_message = f"AUTH:{path}"
                self.ws_subscribe_message = f"SUB:{path}"
                self.ws_ping_message = f"PING:{path}"

        class _Plan:
            def __init__(self, items):
                self.items = items

        plan = _Plan([_PlanItem("/ws/a"), _PlanItem("/ws/b")])

        stats = _run(senders_module.websocket_scenario_sender(
            target_ip="127.0.0.1",
            target_port=8080,
            count=2,
            concurrency=1,
            ws_path="/ws/default",
            verbose=False,
            auth_message="AUTH",
            subscribe_messages=[],
            ping_message="PING",
            ping_count=1,
            await_response=False,
            request_plan=plan,
        ))

        self.assertEqual(stats["attempted"], 2)
        self.assertEqual(stats["sent"], 2)
        called_uris = [str(c.args[0]) for c in mock_ws_module.connect.call_args_list]
        self.assertIn("ws://127.0.0.1:8080/ws/a", called_uris)
        self.assertIn("ws://127.0.0.1:8080/ws/b", called_uris)
        sent_values = [str(c.args[0]) for c in ws_mock.send.call_args_list if c.args]
        self.assertTrue(any(v.startswith("AUTH:/ws/a") for v in sent_values))
        self.assertTrue(any(v.startswith("SUB:/ws/b") for v in sent_values))
        self.assertTrue(any(v.startswith("PING:/ws/a") for v in sent_values))


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 1 — HTTP Retry Implementation
# ═══════════════════════════════════════════════════════════════════════════

class TestHttpRetryParameter(unittest.TestCase):
    """Verifies that --http-retries parameter is actually used."""

    @patch.object(senders_module, "HTTPX_AVAILABLE", True)
    def test_retries_0_single_attempt_on_success(self):
        """retries=0 → exactly 1 attempt per request on success."""
        fake_resp = _FakeResponse(200)

        with patch("ddos_samurai.senders.httpx") as mock_httpx:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=fake_resp)

            cm = AsyncMock()
            cm.__aenter__ = AsyncMock(return_value=mock_client)
            cm.__aexit__ = AsyncMock(return_value=False)
            mock_httpx.AsyncClient = MagicMock(return_value=cm)
            mock_httpx.Limits = MagicMock()
            mock_httpx.ConnectError = ConnectionError
            mock_httpx.ReadTimeout = TimeoutError
            mock_httpx.WriteTimeout = TimeoutError
            mock_httpx.ConnectTimeout = TimeoutError
            mock_httpx.PoolTimeout = TimeoutError

            stats = _run(senders_module.http_app_sender(
                target_ip="127.0.0.1", target_port=80,
                count=3, concurrency=3,
                http_method="GET", http_path="/",
                payloads=None, verbose=False,
                retries=0
            ))
            self.assertEqual(stats["attempted"], 3)
            self.assertEqual(stats["sent"], 3)
            # Each request called exactly once (no retries)
            self.assertEqual(mock_client.request.call_count, 3)

    @patch.object(senders_module, "HTTPX_AVAILABLE", True)
    def test_retries_2_recovers_after_transient_failure(self):
        """retries=2 → on transient error, retries up to 2 more times."""
        call_count = 0

        async def _side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise ConnectionError("transient")
            return _FakeResponse(200)

        with patch("ddos_samurai.senders.httpx") as mock_httpx:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(side_effect=_side_effect)

            cm = AsyncMock()
            cm.__aenter__ = AsyncMock(return_value=mock_client)
            cm.__aexit__ = AsyncMock(return_value=False)
            mock_httpx.AsyncClient = MagicMock(return_value=cm)
            mock_httpx.Limits = MagicMock()
            mock_httpx.ConnectError = ConnectionError
            mock_httpx.ReadTimeout = TimeoutError
            mock_httpx.WriteTimeout = TimeoutError
            mock_httpx.ConnectTimeout = TimeoutError
            mock_httpx.PoolTimeout = TimeoutError

            stats = _run(senders_module.http_app_sender(
                target_ip="127.0.0.1", target_port=80,
                count=1, concurrency=1,
                http_method="GET", http_path="/",
                payloads=None, verbose=False,
                retries=2, timeout_s=1.0
            ))
            # Should have attempted 3 calls (1 original + 2 retries)
            self.assertEqual(call_count, 3, "Should attempt 1 + 2 retries = 3 calls")
            self.assertEqual(stats["sent"], 1, "Request should succeed on 3rd attempt")
            self.assertGreater(stats.get("retry_attempt_total", 0), 0, "retry_attempt_total should be tracked")
            self.assertGreater(stats.get("retry_success_count", 0), 0, "retry_success_count should be tracked")

    @patch.object(senders_module, "HTTPX_AVAILABLE", True)
    def test_retries_exhausted_counts_as_error(self):
        """When all retries fail, the request should count as error."""
        async def _always_fail(*args, **kwargs):
            raise ConnectionError("permanent failure")

        with patch("ddos_samurai.senders.httpx") as mock_httpx:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(side_effect=_always_fail)

            cm = AsyncMock()
            cm.__aenter__ = AsyncMock(return_value=mock_client)
            cm.__aexit__ = AsyncMock(return_value=False)
            mock_httpx.AsyncClient = MagicMock(return_value=cm)
            mock_httpx.Limits = MagicMock()
            mock_httpx.ConnectError = ConnectionError
            mock_httpx.ReadTimeout = TimeoutError
            mock_httpx.WriteTimeout = TimeoutError
            mock_httpx.ConnectTimeout = TimeoutError
            mock_httpx.PoolTimeout = TimeoutError

            stats = _run(senders_module.http_app_sender(
                target_ip="127.0.0.1", target_port=80,
                count=1, concurrency=1,
                http_method="GET", http_path="/",
                payloads=None, verbose=False,
                retries=1, timeout_s=0.1
            ))
            # 1 original + 1 retry = 2 total, but the request_with_retry raises
            self.assertEqual(stats["errors"], 1, "Failed request after exhausted retries should be error")
            self.assertEqual(stats["sent"], 0)


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 1 — QUIC/H3 Request Semantics
# ═══════════════════════════════════════════════════════════════════════════

class TestQuicSenderSemantics(unittest.TestCase):
    """Verifies QUIC sender sends real H3 requests and honors count."""

    @patch.object(senders_module, "AIOQUIC_AVAILABLE", True)
    def test_quic_path_and_method_are_used(self):
        """quic_path and quic_method must appear in H3 headers."""
        captured_headers = []

        mock_h3 = MagicMock()
        mock_h3.get_next_available_stream_id = MagicMock(return_value=0)

        def _capture_send_headers(stream_id, headers, end_stream=True):
            captured_headers.append(headers)

        mock_h3.send_headers = MagicMock(side_effect=_capture_send_headers)

        mock_protocol = MagicMock()
        mock_protocol._quic = mock_h3

        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_protocol)
        cm.__aexit__ = AsyncMock(return_value=False)

        with patch("ddos_samurai.senders.connect", return_value=cm):
            with patch("ddos_samurai.senders.QuicConfiguration"):
                stats = _run(senders_module.quic_sender(
                    target_ip="10.0.0.1", target_port=443,
                    count=2, concurrency=1,
                    quic_path="/api/test", quic_method="POST",
                    verbose=False
                ))

        self.assertEqual(len(captured_headers), 2, "Should send exactly 2 H3 requests")

        # Verify pseudo-headers contain path and method
        first_req = dict(captured_headers[0])
        self.assertEqual(first_req[b":method"], b"POST")
        self.assertEqual(first_req[b":path"], b"/api/test")
        self.assertEqual(first_req[b":scheme"], b"https")

    @patch.object(senders_module, "AIOQUIC_AVAILABLE", True)
    def test_quic_request_plan_overrides_method_and_path(self):
        captured_headers = []

        mock_h3 = MagicMock()
        _stream_id = 0

        def _next_stream():
            nonlocal _stream_id
            _stream_id += 4
            return _stream_id

        def _capture_send_headers(stream_id, headers, end_stream=True):
            del stream_id, end_stream
            captured_headers.append(dict(headers))

        mock_h3.get_next_available_stream_id = MagicMock(side_effect=_next_stream)
        mock_h3.send_headers = MagicMock(side_effect=_capture_send_headers)

        mock_protocol = MagicMock()
        mock_protocol._quic = mock_h3

        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_protocol)
        cm.__aexit__ = AsyncMock(return_value=False)

        class _PlanItem:
            def __init__(self, method, path):
                self.method = method
                self.path = path
                self.user_agent = ""

        class _Plan:
            def __init__(self, items):
                self.items = items

        plan = _Plan([_PlanItem("POST", "/gpu/a"), _PlanItem("PUT", "/gpu/b")])

        with patch("ddos_samurai.senders.connect", return_value=cm):
            with patch("ddos_samurai.senders.QuicConfiguration"):
                stats = _run(senders_module.quic_sender(
                    target_ip="10.0.0.1", target_port=443,
                    count=2, concurrency=1,
                    quic_path="/ignored", quic_method="GET",
                    verbose=False,
                    request_plan=plan,
                ))

        self.assertEqual(stats["attempted"], 2)
        self.assertEqual(stats["sent"], 2)
        self.assertEqual(captured_headers[0][b":method"], b"POST")
        self.assertEqual(captured_headers[0][b":path"], b"/gpu/a")
        self.assertEqual(captured_headers[1][b":method"], b"PUT")
        self.assertEqual(captured_headers[1][b":path"], b"/gpu/b")

    @patch.object(senders_module, "AIOQUIC_AVAILABLE", True)
    def test_quic_count_honored_not_concurrency(self):
        """count=5, concurrency=2 → exactly 5 requests, not 2."""
        request_count = 0

        mock_h3 = MagicMock()
        _stream_id = 0

        def _next_stream():
            nonlocal _stream_id
            _stream_id += 4
            return _stream_id

        mock_h3.get_next_available_stream_id = MagicMock(side_effect=_next_stream)

        def _count_send(*args, **kwargs):
            nonlocal request_count
            request_count += 1

        mock_h3.send_headers = MagicMock(side_effect=_count_send)

        mock_protocol = MagicMock()
        mock_protocol._quic = mock_h3

        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_protocol)
        cm.__aexit__ = AsyncMock(return_value=False)

        with patch("ddos_samurai.senders.connect", return_value=cm):
            with patch("ddos_samurai.senders.QuicConfiguration"):
                stats = _run(senders_module.quic_sender(
                    target_ip="10.0.0.1", target_port=443,
                    count=5, concurrency=2,
                    quic_path="/", quic_method="GET",
                    verbose=False
                ))

        self.assertEqual(stats["attempted"], 5)
        self.assertEqual(stats["sent"], 5)
        self.assertEqual(request_count, 5, "Must send exactly count=5 H3 requests")

    @patch.object(senders_module, "AIOQUIC_AVAILABLE", True)
    def test_quic_connection_failure_counts_all_as_errors(self):
        """If QUIC connect fails, all assigned requests should be errors."""
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(side_effect=ConnectionError("QUIC handshake failed"))
        cm.__aexit__ = AsyncMock(return_value=False)

        with patch("ddos_samurai.senders.connect", return_value=cm):
            with patch("ddos_samurai.senders.QuicConfiguration"):
                stats = _run(senders_module.quic_sender(
                    target_ip="10.0.0.1", target_port=443,
                    count=10, concurrency=2,
                    quic_path="/", quic_method="GET",
                    verbose=False
                ))

        self.assertEqual(stats["attempted"], 10)
        self.assertEqual(stats["errors"], 10, "All requests should be errors on connection failure")
        self.assertEqual(stats["sent"], 0)

    @patch.object(senders_module, "AIOQUIC_AVAILABLE", False)
    def test_quic_unavailable_returns_all_errors(self):
        """If aioquic is not installed, return all errors gracefully."""
        stats = _run(senders_module.quic_sender(
            target_ip="10.0.0.1", target_port=443,
            count=5, concurrency=2,
            quic_path="/", quic_method="GET",
            verbose=False
        ))
        self.assertEqual(stats["attempted"], 5)
        self.assertEqual(stats["errors"], 5)


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 2 — VirtualUser Engine & L7 Metrics
# ═══════════════════════════════════════════════════════════════════════════

@unittest.skipUnless(vu_module._HTTPX, "httpx is required for VirtualUser tests")
class TestVirtualUserEngine(unittest.TestCase):
    """Verifies per-VU state isolation, redirect handling and token propagation."""

    def test_virtual_user_workflow_extracts_tokens_and_injects_headers(self):
        class _FakeVUResponse:
            def __init__(self, status_code=200, headers=None, cookies=None, text=""):
                self.status_code = int(status_code)
                self.headers = dict(headers or {})
                self.cookies = dict(cookies or {})
                self.text = str(text or "")

        class _FakeVUClient:
            calls = []

            def __init__(self, *args, **kwargs):
                del args, kwargs

            async def request(self, method, path, content=None, headers=None, timeout=None):
                del timeout
                _FakeVUClient.calls.append((method, path, headers, content))
                if path == "/login":
                    return _FakeVUResponse(
                        status_code=302,
                        headers={"location": "/landing"},
                        cookies={"sessionid": "abc123"},
                    )
                if path == "/landing":
                    return _FakeVUResponse(
                        status_code=200,
                        headers={"X-CSRF-Token": "hdr-token-1"},
                        text='<html><input name="csrf_token" value="body-token-1"></html>',
                    )
                if path == "/action":
                    hdrs = headers or {}
                    if "X-CSRF-Token" not in hdrs:
                        raise AssertionError("token header missing")
                    return _FakeVUResponse(status_code=201, text="ok")
                return _FakeVUResponse(status_code=200)

            async def aclose(self):
                return None

        metrics = vu_module.L7Metrics(total_vus=1)
        vu = vu_module.VirtualUser(
            user_id=7,
            base_url="http://127.0.0.1:8080",
            verify=False,
            timeout_s=2.0,
            user_agent="UT-UA/1.0",
            metrics=metrics,
        )
        steps = [
            vu_module.WorkflowStep(
                name="login",
                method="GET",
                path="/login",
                expected_status=(200, 399),
                follow_redirects=True,
                extract=[
                    vu_module.ExtractRule(field_name="X-CSRF-Token", source="header", header_name="X-CSRF-Token"),
                    vu_module.ExtractRule(field_name="csrf_token", source="body_regex", regex_pattern=r'value="([^"]+)"'),
                    vu_module.ExtractRule(field_name="sessionid", source="cookie", cookie_name="sessionid"),
                ],
                max_retries=0,
            ),
            vu_module.WorkflowStep(
                name="action",
                method="POST",
                path="/action",
                body='{"token":"{{csrf_token}}"}',
                expected_status=(200, 299),
                inject_tokens=["X-CSRF-Token:csrf_token"],
            ),
        ]

        with patch("ddos_samurai.virtual_user.httpx.AsyncClient", _FakeVUClient):
            result = _run(vu.execute_workflow(steps))
            _run(vu.close())

        self.assertEqual(result.steps_ok, 2)
        self.assertEqual(result.steps_failed, 0)
        self.assertIn("csrf_token", vu.tokens)
        self.assertEqual(vu.tokens["csrf_token"], "body-token-1")
        self.assertGreaterEqual(len(vu.redirect_history), 1)
        self.assertGreater(metrics.tokens_extracted, 0)
        self.assertGreater(metrics.tokens_injected, 0)
        self.assertGreater(metrics.cookies_captured, 0)
        self.assertGreater(metrics.cookies_applied, 0)

    def test_run_vu_pool_completes_all_users(self):
        async def _fake_exec(self, steps):
            del steps
            return vu_module.WorkflowResult(
                user_id=self.user_id,
                steps_total=2,
                steps_ok=2,
                steps_failed=0,
            )

        async def _fake_close(self):
            return None

        with patch.object(vu_module.VirtualUser, "execute_workflow", _fake_exec):
            with patch.object(vu_module.VirtualUser, "close", _fake_close):
                results, metrics = _run(vu_module.run_vu_pool(
                    vu_count=25,
                    base_url="http://127.0.0.1:8080",
                    steps=[vu_module.WorkflowStep(name="x")],
                    concurrency=3,
                ))

        self.assertEqual(len(results), 25)
        self.assertEqual(metrics.total_vus, 25)
        self.assertEqual(metrics.workflows_completed, 25)
        self.assertEqual(metrics.workflows_failed, 0)

    def test_run_vu_pool_applies_steps_provider(self):
        seen_paths = []

        async def _fake_exec(self, steps):
            seen_paths.append((int(self.user_id), [str(s.path) for s in list(steps or [])]))
            return vu_module.WorkflowResult(
                user_id=self.user_id,
                steps_total=1,
                steps_ok=1,
                steps_failed=0,
            )

        async def _fake_close(self):
            return None

        def _provider(uid, rep_idx):
            return [vu_module.WorkflowStep(name="x", path=f"/u{uid}/r{rep_idx}")]

        with patch.object(vu_module.VirtualUser, "execute_workflow", _fake_exec):
            with patch.object(vu_module.VirtualUser, "close", _fake_close):
                results, metrics = _run(vu_module.run_vu_pool(
                    vu_count=2,
                    base_url="http://127.0.0.1:8080",
                    steps=[vu_module.WorkflowStep(name="fallback", path="/default")],
                    steps_provider=_provider,
                    session_repeats=2,
                    concurrency=2,
                ))

        self.assertEqual(len(results), 4)
        self.assertEqual(metrics.workflows_completed, 4)
        flat_paths = [p for _uid, plist in seen_paths for p in plist]
        self.assertIn("/u0/r0", flat_paths)
        self.assertIn("/u1/r1", flat_paths)


class TestHttpStatefulSender(unittest.TestCase):
    """Verifies senders.http_stateful_sender integration and metric propagation."""

    def test_http_stateful_sender_uses_default_workflow_and_exports_metrics(self):
        captured = {"steps": None}

        async def _fake_run_vu_pool(**kwargs):
            captured["steps"] = kwargs.get("steps")
            metrics = vu_module.L7Metrics(total_vus=2)
            metrics.workflows_completed = 2
            metrics.steps_ok = 6
            metrics.cookies_captured = 4
            metrics.cookies_applied = 4
            metrics.tokens_extracted = 2
            metrics.tokens_injected = 2
            metrics.redirects_followed = 2
            results = [
                vu_module.WorkflowResult(user_id=0, steps_total=3, steps_ok=3, steps_failed=0, retries_used=1),
                vu_module.WorkflowResult(user_id=1, steps_total=3, steps_ok=3, steps_failed=0, retries_used=0),
            ]
            return results, metrics

        with patch("ddos_samurai.virtual_user.run_vu_pool", side_effect=_fake_run_vu_pool):
            stats = _run(senders_module.http_stateful_sender(
                target_ip="127.0.0.1",
                target_port=8080,
                vu_count=2,
                concurrency=2,
                workflow_steps=None,
                verbose=False,
                scheme="http",
                retries=1,
                http_method="POST",
                http_path=["/login", "/dashboard", "/submit"],
                payloads=['{"a":1}'],
            ))

        self.assertEqual(stats["attempted"], 6)
        self.assertEqual(stats["sent"], 6)
        self.assertEqual(stats["errors"], 0)
        self.assertEqual(stats["total_vus"], 2)
        self.assertGreater(stats["session_success_rate"], 0.0)
        self.assertGreater(stats["cookie_set_apply_rate"], 0.0)
        self.assertEqual(stats["retries_used"], 1)
        self.assertIsNotNone(captured["steps"])
        self.assertEqual(len(captured["steps"]), 3)
        self.assertEqual(captured["steps"][2].method, "POST")
        self.assertEqual(captured["steps"][2].path, "/submit")

    def test_http_stateful_sender_request_plan_shapes_default_workflow(self):
        captured = {"steps": None, "steps_provider": None}

        async def _fake_run_vu_pool(**kwargs):
            captured["steps"] = kwargs.get("steps")
            captured["steps_provider"] = kwargs.get("steps_provider")
            metrics = vu_module.L7Metrics(total_vus=1)
            metrics.workflows_completed = 1
            metrics.steps_ok = 3
            results = [vu_module.WorkflowResult(user_id=0, steps_total=3, steps_ok=3, steps_failed=0)]
            return results, metrics

        class _PlanItem:
            def __init__(self, method, path):
                self.method = method
                self.path = path
                self.user_agent = "GPU-UA/1.0"
                self.headers = {"accept": "application/json", "x-gpu-plan-seed": "deadbeef"}
                self.body = b'{"source":"gpu"}'
                self.content_type = "application/json"

        class _Plan:
            def __init__(self, items):
                self.items = items

        plan = _Plan([_PlanItem("PATCH", "/gpu/bootstrap"), _PlanItem("PATCH", "/gpu/action")])

        with patch("ddos_samurai.virtual_user.run_vu_pool", side_effect=_fake_run_vu_pool):
            stats = _run(senders_module.http_stateful_sender(
                target_ip="127.0.0.1",
                target_port=8080,
                vu_count=1,
                concurrency=1,
                workflow_steps=None,
                verbose=False,
                scheme="http",
                retries=0,
                http_method="GET",
                http_path="/legacy",
                payloads=[],
                request_plan=plan,
            ))

        self.assertEqual(stats["sent"], 3)
        self.assertEqual(captured["steps"][0].path, "/gpu/bootstrap")
        self.assertEqual(captured["steps"][2].method, "PATCH")
        self.assertTrue(callable(captured["steps_provider"]))
        planned_steps = captured["steps_provider"](0, 0)
        self.assertEqual(planned_steps[2].body, b'{"source":"gpu"}')
        self.assertEqual(planned_steps[2].headers.get("Content-Type"), "application/json")
        self.assertEqual(planned_steps[2].headers.get("x-gpu-plan-seed"), "deadbeef")


if __name__ == "__main__":
    unittest.main()
