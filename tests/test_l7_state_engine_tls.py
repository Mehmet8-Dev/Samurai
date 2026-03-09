import base64
import hashlib
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest


try:
    from ddos_samurai import l7_state_engine as l7_core
except Exception:  # pragma: no cover
    l7_core = None


class _SimpleTLSServer:
    def __init__(self, cert_path, key_path, response, expected_connections=1, validator=None):
        self.cert_path = cert_path
        self.key_path = key_path
        self.response = response
        self.expected_connections = expected_connections
        self.validator = validator
        self._stop = threading.Event()
        self._thread = None
        self._sock = None
        self.port = 0
        self.handled = 0
        self.validation_failures = 0

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self._sock.settimeout(0.2)
        self.port = int(self._sock.getsockname()[1])
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _serve(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
        while not self._stop.is_set() and self.handled < self.expected_connections:
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                tls_conn = ctx.wrap_socket(conn, server_side=True)
            except ssl.SSLError:
                conn.close()
                continue
            with tls_conn:
                tls_conn.settimeout(2.0)
                data = b""
                while b"\r\n\r\n" not in data and len(data) < 8192:
                    try:
                        chunk = tls_conn.recv(4096)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    data += chunk
                if self.validator is not None and not self.validator(data):
                    self.validation_failures += 1
                try:
                    resp = self.response(data) if callable(self.response) else self.response
                    tls_conn.sendall(resp)
                except OSError:
                    pass
                self.handled += 1


@unittest.skipIf(l7_core is None, "l7_state_engine extension unavailable")
class TestL7StateEngineTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not hasattr(l7_core, "tls_supported") or not bool(l7_core.tls_supported()):
            raise unittest.SkipTest("l7_state_engine built without OpenSSL TLS support")
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.close()
        except PermissionError:
            raise unittest.SkipTest("sandbox does not allow opening TCP sockets for local TLS test server")
        if shutil.which("openssl") is None:
            raise unittest.SkipTest("openssl binary is required for TLS test cert generation")
        cls._tmpdir = tempfile.TemporaryDirectory(prefix="samurai_tls_test_")
        cls._cert = os.path.join(cls._tmpdir.name, "cert.pem")
        cls._key = os.path.join(cls._tmpdir.name, "key.pem")
        cmd = [
            "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
            "-keyout", cls._key, "-out", cls._cert, "-days", "1",
            "-subj", "/CN=localhost",
        ]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "_tmpdir"):
            cls._tmpdir.cleanup()

    def test_https_stateful_success(self):
        srv = _SimpleTLSServer(
            self._cert,
            self._key,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
            expected_connections=2,
        )
        srv.start()
        handle = l7_core.open({})
        try:
            out = l7_core.run_http1_stateful(
                handle,
                {
                    "target_ip": "127.0.0.1",
                    "target_port": int(srv.port),
                    "count": 2,
                    "concurrency": 1,
                    "scheme": "https",
                    "verify": False,
                    "timeout_s": 2.0,
                    "http_method": "GET",
                    "http_path": "/",
                },
            )
        finally:
            l7_core.close(handle)
            srv.stop()

        self.assertEqual(int(out.get("sent", -1)), 2)
        self.assertEqual(int(out.get("errors", -1)), 0)
        self.assertEqual(str(out.get("sender_fallback_reason", "")), "none")

    def test_wss_upgrade_success(self):
        def _ws_upgrade_response(req: bytes) -> bytes:
            ws_key = b""
            for line in req.split(b"\r\n"):
                if line.lower().startswith(b"sec-websocket-key:"):
                    ws_key = line.split(b":", 1)[1].strip()
                    break
            accept = base64.b64encode(
                hashlib.sha1(ws_key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
            )
            return (
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n"
            )

        srv = _SimpleTLSServer(
            self._cert,
            self._key,
            _ws_upgrade_response,
            expected_connections=1,
            validator=lambda req: b"Upgrade: websocket" in req and b"GET /ws HTTP/1.1" in req,
        )
        srv.start()
        handle = l7_core.open({})
        try:
            out = l7_core.run_websocket_stateful(
                handle,
                {
                    "target_ip": "127.0.0.1",
                    "target_port": int(srv.port),
                    "count": 1,
                    "concurrency": 1,
                    "scheme": "wss",
                    "verify": False,
                    "timeout_s": 2.0,
                    "ws_path": "/ws",
                },
            )
        finally:
            l7_core.close(handle)
            srv.stop()

        self.assertEqual(int(out.get("sent", -1)), 1)
        self.assertEqual(int(out.get("errors", -1)), 0)
        self.assertEqual(int(srv.validation_failures), 0)
