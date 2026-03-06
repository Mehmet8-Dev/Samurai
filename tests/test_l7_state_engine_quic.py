import socket
import threading
import unittest


try:
    from ddos_samurai import l7_state_engine as l7_core
except Exception:  # pragma: no cover
    l7_core = None


class _FakeQuicUdpServer:
    def __init__(self, mode: str = "ok"):
        self.mode = str(mode or "ok")
        self._stop = threading.Event()
        self._sock = None
        self._thread = None
        self._lock = threading.Lock()
        self.port = 0
        self.handshake_packets = 0
        self.stream_packets = 0
        self.stream_fail_once_budget = 1

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
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
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            msg = data.decode("utf-8", errors="replace")
            if msg.startswith("QHS"):
                with self._lock:
                    self.handshake_packets += 1
                if self.mode == "tls_bad":
                    reply = b"BADHS"
                else:
                    reply = b"QHS-OK"
                try:
                    self._sock.sendto(reply, addr)
                except OSError:
                    return
                continue

            if msg.startswith("QST"):
                with self._lock:
                    self.stream_packets += 1
                if self.mode == "stream_fail":
                    continue
                if self.mode == "stream_fail_once":
                    with self._lock:
                        if self.stream_fail_once_budget > 0:
                            self.stream_fail_once_budget -= 1
                            continue
                try:
                    self._sock.sendto(b"QST-OK", addr)
                except OSError:
                    return


@unittest.skipIf(l7_core is None, "l7_state_engine extension unavailable")
class TestL7StateEngineQuic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.close()
        except PermissionError:
            raise unittest.SkipTest("sandbox does not allow opening UDP sockets for local quic tests")

    def test_quic_success_or_capability_unavailable(self):
        srv = _FakeQuicUdpServer(mode="ok")
        srv.start()
        handle = l7_core.open({})
        try:
            out = l7_core.run_quic_stateful(
                handle,
                {
                    "target_ip": "127.0.0.1",
                    "target_port": int(srv.port),
                    "count": 3,
                    "concurrency": 2,
                    "retries": 0,
                    "timeout_s": 0.3,
                    "scheme": "https",
                    "verify": False,
                    "quic_method": "GET",
                    "quic_path": "/",
                },
            )
        finally:
            l7_core.close(handle)
            srv.stop()

        reason = str(out.get("sender_fallback_reason", ""))
        if reason in {"quic_capability_unavailable", "capability_unavailable"}:
            self.assertEqual(int(out.get("sent", -1)), 0)
            self.assertEqual(int(out.get("errors", -1)), 3)
            return

        self.assertEqual(reason, "none", msg=f"unexpected quic result: {out}")
        self.assertEqual(int(out.get("sent", -1)), 3, msg=f"unexpected quic result: {out}")
        self.assertEqual(int(out.get("errors", -1)), 0, msg=f"unexpected quic result: {out}")
        self.assertAlmostEqual(float(out.get("quic_handshake_fail_ratio", -1.0)), 0.0, places=6)
        self.assertAlmostEqual(float(out.get("quic_stream_fail_ratio", -1.0)), 0.0, places=6)

    def test_quic_tls_fail_or_capability_unavailable(self):
        srv = _FakeQuicUdpServer(mode="tls_bad")
        srv.start()
        handle = l7_core.open({})
        try:
            out = l7_core.run_quic_stateful(
                handle,
                {
                    "target_ip": "127.0.0.1",
                    "target_port": int(srv.port),
                    "count": 1,
                    "concurrency": 1,
                    "retries": 0,
                    "timeout_s": 0.3,
                    "scheme": "https",
                    "verify": True,
                    "quic_method": "GET",
                    "quic_path": "/",
                },
            )
        finally:
            l7_core.close(handle)
            srv.stop()

        reason = str(out.get("sender_fallback_reason", ""))
        if reason in {"quic_capability_unavailable", "capability_unavailable"}:
            self.assertEqual(int(out.get("sent", -1)), 0)
            self.assertEqual(int(out.get("errors", -1)), 1)
            return

        self.assertEqual(reason, "tls_fail", msg=f"unexpected quic tls result: {out}")
        self.assertEqual(int(out.get("sent", -1)), 0)
        self.assertEqual(int(out.get("errors", -1)), 1)
        self.assertAlmostEqual(float(out.get("quic_handshake_fail_ratio", -1.0)), 1.0, places=6)

    def test_quic_stream_fail_or_capability_unavailable(self):
        srv = _FakeQuicUdpServer(mode="stream_fail")
        srv.start()
        handle = l7_core.open({})
        try:
            out = l7_core.run_quic_stateful(
                handle,
                {
                    "target_ip": "127.0.0.1",
                    "target_port": int(srv.port),
                    "count": 1,
                    "concurrency": 1,
                    "retries": 0,
                    "timeout_s": 0.3,
                    "scheme": "https",
                    "verify": False,
                    "quic_method": "GET",
                    "quic_path": "/",
                },
            )
        finally:
            l7_core.close(handle)
            srv.stop()

        reason = str(out.get("sender_fallback_reason", ""))
        if reason in {"quic_capability_unavailable", "capability_unavailable"}:
            self.assertEqual(int(out.get("sent", -1)), 0)
            self.assertEqual(int(out.get("errors", -1)), 1)
            return

        self.assertEqual(reason, "stream_fail", msg=f"unexpected quic stream result: {out}")
        self.assertEqual(int(out.get("sent", -1)), 0)
        self.assertEqual(int(out.get("errors", -1)), 1)
        self.assertAlmostEqual(float(out.get("quic_stream_fail_ratio", -1.0)), 1.0, places=6)

    def test_quic_retry_budget_or_capability_unavailable(self):
        srv = _FakeQuicUdpServer(mode="stream_fail_once")
        srv.start()
        handle = l7_core.open({})
        try:
            out = l7_core.run_quic_stateful(
                handle,
                {
                    "target_ip": "127.0.0.1",
                    "target_port": int(srv.port),
                    "count": 1,
                    "concurrency": 1,
                    "retries": 1,
                    "timeout_s": 0.3,
                    "scheme": "https",
                    "verify": False,
                    "quic_method": "GET",
                    "quic_path": "/",
                },
            )
        finally:
            l7_core.close(handle)
            srv.stop()

        reason = str(out.get("sender_fallback_reason", ""))
        if reason in {"quic_capability_unavailable", "capability_unavailable"}:
            self.assertEqual(int(out.get("sent", -1)), 0)
            self.assertEqual(int(out.get("errors", -1)), 1)
            return

        self.assertEqual(reason, "none", msg=f"unexpected quic retry result: {out}")
        self.assertEqual(int(out.get("sent", -1)), 1)
        self.assertEqual(int(out.get("errors", -1)), 0)
        self.assertGreaterEqual(int(out.get("retry_attempts", 0)), 1)
        self.assertGreaterEqual(int(out.get("retry_successes", 0)), 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
