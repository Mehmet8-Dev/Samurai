import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from ddos_samurai import senders


class _FakeResponse:
    def __init__(self, status_code: int):
        self.status_code = int(status_code)


class _FakeLimits:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class _FakeAsyncClient:
    response_plan = []
    requests = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self._transport = object()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def request(self, method, path, headers=None):
        self.requests.append((method, path, headers))
        item = self.response_plan.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class _FakeHttpx:
    AsyncClient = _FakeAsyncClient
    Limits = _FakeLimits
    ReadError = RuntimeError
    RemoteProtocolError = RuntimeError
    ConnectError = RuntimeError


class TestHttp2Sender(unittest.IsolatedAsyncioTestCase):
    async def test_http2_sender_status_counters(self):
        _FakeAsyncClient.requests = []
        _FakeAsyncClient.response_plan = [
            _FakeResponse(200),
            _FakeResponse(404),
            _FakeResponse(503),
        ]
        with patch.object(senders, "HTTPX_AVAILABLE", True), patch.object(senders, "httpx", _FakeHttpx):
            out = await senders.http2_sender(
                target_ip="127.0.0.1",
                target_port=443,
                count=3,
                concurrency=2,
                http_path="/",
                http_method="GET",
                verbose=False,
                scheme="https",
                h2_profile_name="none",
            )

        self.assertEqual(out["attempted"], 3)
        self.assertEqual(out["sent"], 3)
        self.assertEqual(out["errors"], 0)
        self.assertEqual(out["responses_total"], 3)
        self.assertEqual(out["status_2xx"], 1)
        self.assertEqual(out["status_4xx"], 1)
        self.assertEqual(out["status_5xx"], 1)
        self.assertEqual(out["h2_profile_disabled"], 1)
        self.assertEqual(out["h2_profile_applied"], 0)
        self.assertEqual(len(_FakeAsyncClient.requests), 3)

    async def test_http2_sender_error_path_does_not_raise_nameerror(self):
        _FakeAsyncClient.requests = []
        _FakeAsyncClient.response_plan = [
            _FakeResponse(200),
            RuntimeError("boom"),
            _FakeResponse(503),
        ]
        with patch.object(senders, "HTTPX_AVAILABLE", True), patch.object(senders, "httpx", _FakeHttpx):
            out = await senders.http2_sender(
                target_ip="127.0.0.1",
                target_port=443,
                count=3,
                concurrency=3,
                http_path="/",
                http_method="GET",
                verbose=False,
                scheme="https",
                h2_profile_name="chrome_120",
            )

        self.assertEqual(out["attempted"], 3)
        self.assertEqual(out["sent"], 2)
        self.assertEqual(out["errors"], 1)
        self.assertEqual(out["responses_total"], 2)
        self.assertEqual(out["status_2xx"], 1)
        self.assertEqual(out["status_4xx"], 0)
        self.assertEqual(out["status_5xx"], 1)
        self.assertEqual(out["h2_profile_apply_failed"], 1)
        self.assertEqual(len(_FakeAsyncClient.requests), 3)

    async def test_http2_sender_consumes_request_plan_and_keeps_backward_compatible_fallback(self):
        _FakeAsyncClient.requests = []
        _FakeAsyncClient.response_plan = [
            _FakeResponse(200),
            _FakeResponse(201),
        ]
        request_plan = SimpleNamespace(
            items=[
                SimpleNamespace(method="POST", path="/submit", user_agent="Plan-UA-1"),
                SimpleNamespace(method="GET", path="/health", user_agent="Plan-UA-2"),
            ]
        )
        with patch.object(senders, "HTTPX_AVAILABLE", True), patch.object(senders, "httpx", _FakeHttpx):
            out = await senders.http2_sender(
                target_ip="127.0.0.1",
                target_port=443,
                count=99,
                concurrency=4,
                http_path="/",
                http_method="GET",
                verbose=False,
                scheme="https",
                h2_profile_name="none",
                request_plan=request_plan,
            )

        self.assertEqual(out["attempted"], 2)
        self.assertEqual(out["sent"], 2)
        self.assertEqual(out["errors"], 0)
        self.assertEqual(_FakeAsyncClient.requests[0][0], "POST")
        self.assertEqual(_FakeAsyncClient.requests[0][1], "/submit")
        self.assertEqual(_FakeAsyncClient.requests[0][2], {"User-Agent": "Plan-UA-1"})
        self.assertEqual(_FakeAsyncClient.requests[1][0], "GET")
        self.assertEqual(_FakeAsyncClient.requests[1][1], "/health")

    async def test_http2_sender_uses_hyper_h2_transport_when_requested(self):
        fake_h2_transport = SimpleNamespace(
            send_h2_requests=AsyncMock(
                return_value={
                    "attempted": 2,
                    "sent": 2,
                    "errors": 0,
                    "responses_total": 2,
                    "status_2xx": 2,
                    "status_4xx": 0,
                    "status_5xx": 0,
                }
            )
        )
        with patch.object(senders, "HTTPX_AVAILABLE", True), \
             patch.object(senders, "HYPER_H2_AVAILABLE", True), \
             patch.object(senders, "_h2_transport", fake_h2_transport):
            out = await senders.http2_sender(
                target_ip="127.0.0.1",
                target_port=443,
                count=2,
                concurrency=2,
                http_path="/",
                http_method="GET",
                verbose=False,
                scheme="https",
                h2_profile_name="chrome_120",
                h2_transport_name="hyper-h2",
            )

        fake_h2_transport.send_h2_requests.assert_awaited_once()
        self.assertEqual(out["attempted"], 2)
        self.assertEqual(out["sent"], 2)
        self.assertEqual(out["errors"], 0)
        self.assertEqual(out["h2_profile_applied"], 1)
        self.assertEqual(out["h2_transport"], "hyper-h2")
