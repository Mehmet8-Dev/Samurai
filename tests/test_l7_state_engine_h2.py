import socket
import threading
import unittest


try:
    from ddos_samurai import l7_state_engine as l7_core
except Exception:  # pragma: no cover
    l7_core = None

try:
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import RequestReceived

    H2_AVAILABLE = True
except Exception:  # pragma: no cover
    H2_AVAILABLE = False


class _H2CServer:
    def __init__(self, expected_requests: int):
        self.expected_requests = max(1, int(expected_requests))
        self.handled_requests = 0
        self.validation_failures = 0
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._sock = None
        self._thread = None
        self.port = 0

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
        if self._sock is None:
            return
        while not self._stop.is_set():
            if self.handled_requests >= self.expected_requests:
                return
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with conn:
                conn.settimeout(2.0)
                h2_conn = H2Connection(config=H2Configuration(client_side=False, header_encoding="utf-8"))
                h2_conn.initiate_connection()
                try:
                    conn.sendall(h2_conn.data_to_send())
                except OSError:
                    self.validation_failures += 1
                    continue

                while not self._stop.is_set():
                    if self.handled_requests >= self.expected_requests:
                        return
                    try:
                        data = conn.recv(65535)
                    except socket.timeout:
                        continue
                    except OSError:
                        self.validation_failures += 1
                        break
                    if not data:
                        break

                    try:
                        events = h2_conn.receive_data(data)
                    except Exception:
                        self.validation_failures += 1
                        break

                    for event in events:
                        if isinstance(event, RequestReceived):
                            stream_id = int(event.stream_id)
                            h2_conn.send_headers(
                                stream_id,
                                [
                                    (":status", "200"),
                                    ("content-length", "2"),
                                ],
                            )
                            h2_conn.send_data(stream_id, b"OK", end_stream=True)
                            with self._lock:
                                self.handled_requests += 1

                    payload = h2_conn.data_to_send()
                    if payload:
                        try:
                            conn.sendall(payload)
                        except OSError:
                            self.validation_failures += 1
                            break


class _InvalidH2Server:
    def __init__(self):
        self._stop = threading.Event()
        self._sock = None
        self._thread = None
        self.port = 0

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
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
        if self._sock is None:
            return
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with conn:
                conn.settimeout(1.0)
                try:
                    _ = conn.recv(4096)
                except OSError:
                    pass
                try:
                    conn.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 0\\r\\n\\r\\n")
                except OSError:
                    pass
                return


@unittest.skipIf(l7_core is None, "l7_state_engine extension unavailable")
class TestL7StateEngineHTTP2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.close()
        except PermissionError:
            raise unittest.SkipTest("sandbox does not allow opening TCP sockets for local h2 tests")

    def test_http2_stateful_success_or_capability_unavailable(self):
        if not H2_AVAILABLE:
            self.skipTest("python-h2 dependency unavailable in test environment")

        srv = _H2CServer(expected_requests=4)
        srv.start()
        handle = l7_core.open({})
        try:
            out = l7_core.run_http2_stateful(
                handle,
                {
                    "target_ip": "127.0.0.1",
                    "target_port": int(srv.port),
                    "count": 4,
                    "concurrency": 4,
                    "h2_connections": 2,
                    "h2_streams_per_conn": 2,
                    "scheme": "http",
                    "http_method": "GET",
                    "http_path": "/",
                    "timeout_s": 2.0,
                },
            )
        finally:
            l7_core.close(handle)
            srv.stop()

        reason = str(out.get("sender_fallback_reason", ""))
        if reason == "h2_capability_unavailable":
            self.assertEqual(int(out.get("sent", -1)), 0)
            self.assertEqual(int(out.get("errors", -1)), 4)
            if hasattr(l7_core, "h2_supported"):
                self.assertFalse(bool(l7_core.h2_supported()))
            return

        self.assertEqual(int(out.get("sent", -1)), 4, msg=f"unexpected h2 result: {out}")
        self.assertEqual(int(out.get("errors", -1)), 0, msg=f"unexpected h2 result: {out}")
        self.assertEqual(reason, "none")
        self.assertEqual(int(out.get("h2_goaway_count", -1)), 0)
        self.assertAlmostEqual(float(out.get("h2_stream_reset_ratio", -1.0)), 0.0, places=6)
        self.assertEqual(srv.validation_failures, 0)
        self.assertEqual(srv.handled_requests, 4)
        if hasattr(l7_core, "h2_supported"):
            self.assertTrue(bool(l7_core.h2_supported()))

    def test_http2_protocol_error_or_capability_unavailable(self):
        srv = _InvalidH2Server()
        srv.start()
        handle = l7_core.open({})
        try:
            out = l7_core.run_http2_stateful(
                handle,
                {
                    "target_ip": "127.0.0.1",
                    "target_port": int(srv.port),
                    "count": 1,
                    "concurrency": 1,
                    "h2_connections": 1,
                    "h2_streams_per_conn": 1,
                    "scheme": "http",
                    "http_method": "GET",
                    "http_path": "/",
                    "timeout_s": 2.0,
                },
            )
        finally:
            l7_core.close(handle)
            srv.stop()

        reason = str(out.get("sender_fallback_reason", ""))
        if reason == "h2_capability_unavailable":
            self.assertEqual(int(out.get("sent", -1)), 0)
            self.assertEqual(int(out.get("errors", -1)), 1)
            return

        self.assertEqual(int(out.get("sent", -1)), 0, msg=f"unexpected h2 protocol result: {out}")
        self.assertEqual(int(out.get("errors", -1)), 1, msg=f"unexpected h2 protocol result: {out}")
        self.assertEqual(reason, "h2_protocol_error", msg=f"unexpected h2 protocol result: {out}")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
