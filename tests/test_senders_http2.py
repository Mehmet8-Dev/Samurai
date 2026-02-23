import unittest
from unittest.mock import patch

from ddos_samurai import senders


class _FakeResponse:
    def __init__(self, status_code: int):
        self.status_code = int(status_code)


class _FakeLimits:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class _FakeAsyncClient:
    response_plan = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self._transport = object()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def request(self, method, path):
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

    async def test_http2_sender_error_path_does_not_raise_nameerror(self):
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
