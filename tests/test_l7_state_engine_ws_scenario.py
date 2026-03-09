import base64
import hashlib
import socket
import threading
import unittest


try:
    from ddos_samurai import l7_state_engine as l7_core
except Exception:  # pragma: no cover
    l7_core = None


class _SimpleWebSocketScenarioServer:
    def __init__(self, expected_messages, *, path="/ws", send_ack=True, force_invalid_accept=False):
        self.expected_messages = [str(x) for x in list(expected_messages or [])]
        self.path = str(path or "/ws")
        self.send_ack = bool(send_ack)
        self.force_invalid_accept = bool(force_invalid_accept)
        self.received_messages = []
        self.validation_failures = 0
        self._sock = None
        self._thread = None
        self._stop = threading.Event()
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

    def _recv_exact(self, conn, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = conn.recv(size - len(data))
            if not chunk:
                raise ConnectionError("socket closed while reading frame")
            data += chunk
        return data

    def _recv_client_text_frame(self, conn) -> str:
        head = self._recv_exact(conn, 2)
        b1 = head[0]
        b2 = head[1]
        opcode = b1 & 0x0F
        if opcode != 0x1:
            raise ValueError(f"unexpected opcode={opcode}")
        masked = bool(b2 & 0x80)
        payload_len = b2 & 0x7F
        if payload_len == 126:
            payload_len = int.from_bytes(self._recv_exact(conn, 2), "big")
        elif payload_len == 127:
            payload_len = int.from_bytes(self._recv_exact(conn, 8), "big")
        mask_key = self._recv_exact(conn, 4) if masked else b""
        payload = self._recv_exact(conn, payload_len)
        if masked:
            payload = bytes(payload[i] ^ mask_key[i % 4] for i in range(len(payload)))
        return payload.decode("utf-8", errors="replace")

    def _send_server_text_frame(self, conn, text: str):
        payload = text.encode("utf-8")
        if len(payload) >= 126:
            raise ValueError("test ack payload too long")
        frame = bytes([0x81, len(payload)]) + payload
        conn.sendall(frame)

    def _serve(self):
        if self._sock is None:
            return
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(2.5)
                req = b""
                while b"\r\n\r\n" not in req and len(req) < 8192:
                    chunk = conn.recv(2048)
                    if not chunk:
                        break
                    req += chunk
                if (f"GET {self.path} HTTP/1.1".encode() not in req) or (b"Upgrade: websocket" not in req):
                    self.validation_failures += 1
                    continue
                ws_key = b""
                for line in req.split(b"\r\n"):
                    if line.lower().startswith(b"sec-websocket-key:"):
                        ws_key = line.split(b":", 1)[1].strip()
                        break
                if not ws_key:
                    self.validation_failures += 1
                    continue
                if self.force_invalid_accept:
                    accept = b"invalidaccept=="
                else:
                    accept = base64.b64encode(
                        hashlib.sha1(ws_key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
                    )
                conn.sendall(
                    b"HTTP/1.1 101 Switching Protocols\r\n"
                    b"Upgrade: websocket\r\n"
                    b"Connection: Upgrade\r\n"
                    b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n"
                )
                try:
                    for idx in range(len(self.expected_messages)):
                        msg = self._recv_client_text_frame(conn)
                        self.received_messages.append(msg)
                        if self.send_ack:
                            self._send_server_text_frame(conn, f"ack-{idx}")
                except Exception:
                    self.validation_failures += 1
                return


@unittest.skipIf(l7_core is None, "l7_state_engine extension unavailable")
class TestL7StateEngineWebSocketScenario(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.close()
        except PermissionError:
            raise unittest.SkipTest("sandbox does not allow opening TCP sockets for local websocket scenario server")

    def test_ws_scenario_auth_subscribe_ping_with_await_response(self):
        expected = ["AUTH", "SUB_A", "SUB_B", "PING", "PING"]
        srv = _SimpleWebSocketScenarioServer(expected_messages=expected, path="/ws", send_ack=True)
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
                    "scheme": "ws",
                    "timeout_s": 2.0,
                    "ws_path": "/ws",
                    "ws_scenario_enabled": True,
                    "ws_auth_message": "AUTH",
                    "ws_subscribe_count": 2,
                    "ws_subscribe_messages": "SUB_A\x1fSUB_B",
                    "ws_ping_message": "PING",
                    "ws_ping_count": 2,
                    "ws_await_response": True,
                },
            )
        finally:
            l7_core.close(handle)
            srv.stop()

        self.assertEqual(int(out.get("sent", -1)), 1, msg=f"unexpected ws scenario result: {out}")
        self.assertEqual(int(out.get("errors", -1)), 0, msg=f"unexpected ws scenario result: {out}")
        self.assertEqual(str(out.get("sender_fallback_reason", "")), "none")
        self.assertEqual(int(out.get("ws_scenario_enabled", 0)), 1)
        self.assertEqual(int(out.get("ws_step_count", -1)), 5)
        self.assertEqual(srv.validation_failures, 0)
        self.assertEqual(srv.received_messages, expected)

    def test_ws_upgrade_rejects_invalid_accept_header(self):
        srv = _SimpleWebSocketScenarioServer(
            expected_messages=[],
            path="/ws",
            send_ack=False,
            force_invalid_accept=True,
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
                    "scheme": "ws",
                    "timeout_s": 2.0,
                    "ws_path": "/ws",
                    "ws_scenario_enabled": False,
                },
            )
        finally:
            l7_core.close(handle)
            srv.stop()

        self.assertEqual(int(out.get("sent", -1)), 0, msg=f"unexpected ws result: {out}")
        self.assertEqual(int(out.get("errors", -1)), 1, msg=f"unexpected ws result: {out}")
