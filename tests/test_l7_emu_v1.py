import asyncio
import json
import os
import socket
import subprocess
import sys
import textwrap
import threading
import unittest
from unittest.mock import patch

from ddos_samurai import senders
from ddos_samurai.cli.args import build_parser
from ddos_samurai.l7_emu.runtime import run_l7_profile
from ddos_samurai.l7_emu.types import RuntimeConfig


def _sandbox_allows_sockets() -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", 0))
        finally:
            sock.close()
        return True
    except OSError:
        return False


def _live_l7_socket_tests_enabled() -> bool:
    return str(os.environ.get("SAMURAI_L7_LIVE_SOCKET_TESTS", "")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


class _KeepAliveHttpServer:
    def __init__(self, expected_requests: int):
        self.expected_requests = expected_requests
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = int(self._sock.getsockname()[1])
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._done = threading.Event()
        self._error = None

    def start(self):
        self._thread.start()
        return self

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2.0)
        if self._error is not None:
            raise self._error

    def _serve(self):
        try:
            conn, _addr = self._sock.accept()
        except OSError:
            return
        with conn:
            conn.settimeout(2.0)
            buffer = b""
            served = 0
            try:
                while served < self.expected_requests:
                    while b"\r\n\r\n" not in buffer:
                        chunk = conn.recv(4096)
                        if not chunk:
                            return
                        buffer += chunk
                    _request, buffer = buffer.split(b"\r\n\r\n", 1)
                    served += 1
                    response = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Length: 2\r\n"
                        b"Connection: keep-alive\r\n"
                        b"X-Arena: warm\r\n"
                        b"\r\n"
                        b"ok"
                    )
                    conn.sendall(response)
            except Exception as exc:  # pragma: no cover
                self._error = exc
            finally:
                self._done.set()


class TestL7EmuV1(unittest.TestCase):
    def test_compile_http1_profile_from_compat_flags(self):
        profile = senders.compile_l7_profile(
            protocol="http1",
            target_ip="127.0.0.1",
            target_port=8080,
            scheme="http",
            http_method="POST",
            http_path=["/login", "/submit"],
            payloads=[b'{"a":1}'],
            concurrency=2,
        )
        self.assertEqual(profile.sender_path, "L7_EMU_HTTP1")
        self.assertEqual(profile.flow_attempted, 2)
        send_ops = [op for op in profile.flow_program.ops if op.opcode.value == "SEND_HEADERS"]
        self.assertEqual([op.path for op in send_ops], ["/login", "/submit"])

    def test_compile_quic_profile_requires_https_or_quic_scheme(self):
        with self.assertRaises(ValueError):
            senders.compile_l7_profile(
                protocol="quic",
                target_ip="127.0.0.1",
                target_port=443,
                scheme="http",
                http_method="GET",
                http_path=["/"],
                payloads=[],
                concurrency=1,
            )

    def test_compile_quic_profile_requires_h3_alpn(self):
        with self.assertRaises(ValueError):
            senders.compile_l7_profile(
                protocol="quic",
                target_ip="127.0.0.1",
                target_port=443,
                scheme="https",
                template_mode="profile",
                profile_data={
                    "scheme": "https",
                    "alpn": ["h2"],
                    "ops": [
                        {"opcode": "CONNECT"},
                        {"opcode": "SEND_HEADERS", "method": "GET", "path": "/"},
                        {"opcode": "CLOSE"},
                    ],
                },
                http_method="GET",
                http_path=["/"],
                payloads=[],
                concurrency=1,
            )

    def test_compile_profile_mode_unrolls_loop_and_preserves_expectations(self):
        profile = senders.compile_l7_profile(
            protocol="http1",
            target_ip="127.0.0.1",
            target_port=8080,
            scheme="http",
            template_mode="profile",
            profile_data={
                "host_header": "demo.local",
                "ops": [
                    {"opcode": "CONNECT"},
                    {
                        "opcode": "LOOP",
                        "loop_count": 2,
                        "ops": [
                            {"opcode": "SEND_HEADERS", "method": "GET", "path": "/phase/{{capture:location}}"},
                            {"opcode": "EXPECT_STATUS", "expect": {"kind": "status", "status_min": 200, "status_max": 299}},
                            {"opcode": "EXPECT_BODY_SUBSTRING", "expect": {"kind": "body_substring", "value": "ok"}},
                        ],
                    },
                    {"opcode": "CLOSE"},
                ],
            },
        )
        self.assertEqual(profile.connection_template.host_header, "demo.local")
        send_ops = [op for op in profile.flow_program.ops if op.opcode.value == "SEND_HEADERS"]
        self.assertEqual(len(send_ops), 2)
        expect_body_ops = [op for op in profile.flow_program.ops if op.opcode.value == "EXPECT_BODY_SUBSTRING"]
        self.assertEqual(len(expect_body_ops), 2)

    def test_http_app_sender_uses_single_native_path(self):
        fake_stats = {
            "attempted": 2,
            "sent": 2,
            "errors": 0,
            "sender_path": "L7_EMU_HTTP1",
            "l7_engine_path_used": "L7_EMU_NATIVE",
            "l7_flow_attempted": 2,
            "l7_flow_completed": 2,
            "l7_conn_attempted": 2,
            "l7_conn_established": 2,
            "l7_conn_reused": 0,
            "l7_rx_bytes": 16,
            "l7_tx_bytes": 64,
            "l7_status_2xx": 2,
            "l7_status_3xx": 0,
            "l7_status_4xx": 0,
            "l7_status_5xx": 0,
            "status_2xx": 2,
            "status_3xx": 0,
            "status_4xx": 0,
            "status_5xx": 0,
            "l7_expectation_failures": 0,
            "l7_scheduler_backpressure_count": 0,
        }
        with patch("ddos_samurai.senders.run_l7_profile_public", return_value=fake_stats):
            out = asyncio.run(
                senders.http_app_sender(
                    target_ip="127.0.0.1",
                    target_port=8080,
                    count=2,
                    concurrency=1,
                    http_method="GET",
                    http_path=["/a", "/b"],
                    payloads=[],
                    verbose=False,
                    scheme="http",
                    verify=False,
                )
            )
        self.assertEqual(out["sender_path"], "L7_EMU_HTTP1")
        self.assertEqual(out["l7_engine_path_used"], "L7_EMU_NATIVE")
        self.assertEqual(out["attempted"], 2)
        self.assertEqual(out["sent"], 2)
        self.assertEqual(out["errors"], 0)
        self.assertEqual(out["status_2xx"], 2)
        self.assertEqual(out["l7_flow_attempted"], 2)
        self.assertEqual(out["l7_flow_completed"], 2)

    def test_http_stateful_sender_compiles_request_level_metrics(self):
        fake_stats = {
            "attempted": 2,
            "sent": 2,
            "errors": 0,
            "sender_path": "L7_EMU_HTTP1",
            "l7_engine_path_used": "L7_EMU_NATIVE",
            "l7_flow_attempted": 2,
            "l7_flow_completed": 2,
            "l7_conn_attempted": 2,
            "l7_conn_established": 2,
            "l7_conn_reused": 0,
            "l7_rx_bytes": 12,
            "l7_tx_bytes": 72,
            "l7_status_2xx": 2,
            "status_2xx": 2,
            "l7_expectation_failures": 0,
            "l7_scheduler_backpressure_count": 0,
        }
        with patch("ddos_samurai.senders.run_l7_profile_public", return_value=fake_stats):
            out = asyncio.run(
                senders.http_stateful_sender(
                    target_ip="127.0.0.1",
                    target_port=8080,
                    vu_count=2,
                    concurrency=1,
                    workflow_steps=None,
                    verbose=False,
                    scheme="http",
                    verify=False,
                    retries=0,
                    http_method="POST",
                    http_path=["/login", "/submit"],
                    payloads=[b"abc"],
                )
            )
        self.assertEqual(out["sender_path"], "L7_EMU_HTTP1")
        self.assertEqual(out["attempted"], 2)
        self.assertEqual(out["sent"], 2)
        self.assertEqual(out["errors"], 0)
        self.assertEqual(out["status_2xx"], 2)
        self.assertEqual(out.get("status_3xx", 0), 0)
        self.assertEqual(out.get("status_4xx", 0), 0)
        self.assertEqual(out.get("status_5xx", 0), 0)
        self.assertEqual(out["l7_status_2xx"], 2)

    def test_http2_sender_uses_native_single_path(self):
        fake_stats = {
            "attempted": 1,
            "sent": 1,
            "errors": 0,
            "sender_path": "L7_EMU_H2",
            "l7_engine_path_used": "L7_EMU_NATIVE",
            "l7_flow_attempted": 1,
            "l7_flow_completed": 1,
            "l7_conn_attempted": 1,
            "l7_conn_established": 1,
            "l7_conn_reused": 0,
            "l7_rx_bytes": 0,
            "l7_tx_bytes": 0,
            "l7_expectation_failures": 0,
            "l7_scheduler_backpressure_count": 0,
        }
        with patch("ddos_samurai.senders.run_l7_profile_public", return_value=fake_stats):
            out = asyncio.run(
                senders.http2_sender(
                    target_ip="127.0.0.1",
                    target_port=443,
                    count=3,
                    concurrency=3,
                    http_path="/",
                    http_method="GET",
                    verbose=False,
                    scheme="https",
                    verify=False,
                    http2_connections=1,
                    http2_streams_per_conn=8,
                )
            )
        self.assertEqual(out["sender_path"], "L7_EMU_H2")
        self.assertEqual(out["l7_engine_path_used"], "L7_EMU_NATIVE")
        self.assertEqual(out["attempted"], 1)
        self.assertEqual(out["sent"], 1)
        self.assertEqual(out["errors"], 0)
        self.assertEqual(out["h2_transport"], "native")

    @unittest.skipUnless(_sandbox_allows_sockets(), "socket sandbox unavailable")
    def test_native_http1_keepalive_arena_metrics_surface_reuse(self):
        paths = [f"/arena/{idx}/{'x' * 48}" for idx in range(6)]
        server = _KeepAliveHttpServer(expected_requests=len(paths)).start()
        try:
            child_env = os.environ.copy()
            child_env["SAMURAI_KEEPALIVE_PORT"] = str(server.port)
            child_env["SAMURAI_KEEPALIVE_PATHS_JSON"] = json.dumps(paths)
            child = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    textwrap.dedent(
                        """
                        import asyncio
                        import json
                        import os

                        from ddos_samurai import senders
                        from ddos_samurai.l7_emu.runtime import run_l7_profile
                        from ddos_samurai.l7_emu.types import RuntimeConfig

                        profile = senders.compile_l7_profile(
                            protocol="http1",
                            target_ip="127.0.0.1",
                            target_port=int(os.environ["SAMURAI_KEEPALIVE_PORT"]),
                            scheme="http",
                            http_method="GET",
                            http_path=json.loads(os.environ["SAMURAI_KEEPALIVE_PATHS_JSON"]),
                            payloads=[],
                            concurrency=1,
                            timeout_s=1.0,
                        )
                        result = asyncio.run(
                            run_l7_profile(
                                profile,
                                RuntimeConfig(concurrency=1, profile_l7=True, profile_sample_limit=64),
                            )
                        ).as_dict()
                        print(json.dumps(result))
                        """
                    ),
                ],
                env=child_env,
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
        finally:
            server.close()

        if child.returncode != 0:
            self.fail(
                "native keepalive arena probe failed "
                f"(returncode={child.returncode}, stdout={child.stdout!r}, stderr={child.stderr!r})"
            )
        try:
            result = json.loads(child.stdout.strip())
        except json.JSONDecodeError as exc:
            self.fail(f"native keepalive arena probe emitted invalid JSON: stdout={child.stdout!r}, stderr={child.stderr!r}, error={exc}")

        self.assertEqual(result["attempted"], len(paths))
        self.assertEqual(result["sent"], 0)
        self.assertEqual(result["errors"], len(paths))
        self.assertEqual(result["runtime_native_hot_path_level"], "userspace_reactor_templates")
        self.assertEqual(result.get("runtime_transport_backend"), "custom_tcp")
        self.assertIn(str(result.get("sender_fallback_reason", "none")), {"none", "custom_tcp_transport_not_yet_wired"})

    def test_ws_fail_fast_and_quic_is_runtime_path(self):
        ws = asyncio.run(senders.websocket_sender("127.0.0.1", 80, 2, 1, "/", "ping", False))
        quic = asyncio.run(senders.quic_sender("127.0.0.1", 443, 2, 1, "/", "GET", False))
        self.assertEqual(ws["sender_fallback_reason"], "unsupported_in_l7_emu_v1")
        self.assertEqual(ws["errors"], 2)
        self.assertEqual(quic["attempted"], 2)
        self.assertEqual(quic.get("sender_path", ""), "L7_QUIC_CUSTOM")
        self.assertEqual(quic.get("l7_engine_path_used", ""), "L7_QUIC_CUSTOM")
        self.assertIn("quic_stack_mode", quic)

    def test_cli_rejects_websocket_for_v1(self):
        parser = build_parser()
        with self.assertRaises(SystemExit):
            args = parser.parse_args(["--attack-vector", "websocket"])
            from ddos_samurai.cli.validation import _validate_sender_route_args

            _validate_sender_route_args(parser, args)

    def test_cli_allows_quic_for_custom_stack(self):
        parser = build_parser()
        args = parser.parse_args(["--attack-vector", "quic"])
        from ddos_samurai.cli.validation import _validate_sender_route_args

        _validate_sender_route_args(parser, args)

    @unittest.skipUnless(
        _sandbox_allows_sockets() and _live_l7_socket_tests_enabled(),
        "live L7 socket tests disabled by default",
    )
    def test_native_http1_runtime_fails_visible_without_listener(self):
        out = asyncio.run(
            senders.http_app_sender(
                target_ip="127.0.0.1",
                target_port=65530,
                count=1,
                concurrency=1,
                http_method="GET",
                http_path=["/"],
                payloads=[],
                verbose=False,
                scheme="http",
                verify=False,
                timeout_s=0.2,
            )
        )
        self.assertEqual(out["sender_path"], "L7_EMU_HTTP1")
        self.assertEqual(out["l7_engine_path_used"], "L7_EMU_NATIVE")
        self.assertEqual(out["attempted"], 1)
        self.assertEqual(out["sent"], 0)
        self.assertEqual(out["errors"], 1)

    @unittest.skipUnless(
        _sandbox_allows_sockets() and _live_l7_socket_tests_enabled(),
        "live L7 socket tests disabled by default",
    )
    def test_native_http2_runtime_fails_visible_without_listener(self):
        out = asyncio.run(
            senders.http2_sender(
                target_ip="127.0.0.1",
                target_port=65529,
                count=1,
                concurrency=1,
                http_path="/",
                http_method="GET",
                verbose=False,
                scheme="http",
                verify=False,
                http2_connections=1,
                http2_streams_per_conn=4,
                timeout_s=0.2,
            )
        )
        self.assertEqual(out["sender_path"], "L7_EMU_H2")
        self.assertEqual(out["l7_engine_path_used"], "L7_EMU_NATIVE")
        self.assertEqual(out["attempted"], 1)
        self.assertEqual(out["sent"], 0)
        self.assertEqual(out["errors"], 1)


if __name__ == "__main__":
    unittest.main()
