import http.server
import os
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


class _KeepAliveHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True

    def do_GET(self):
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _ReusableThreadingHttpServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class TestRfcSuiteEngine(unittest.TestCase):
    def test_samurai_cli_rfc_suite_requires_live_confirmation(self):
        cli_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../build/cli/samurai"))
        if os.path.exists(cli_path):
            res = subprocess.run(
                [cli_path, "--run-rfc-suite", "all"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("--confirm", res.stderr)

    def test_samurai_cli_rfc_suite_run(self):
        cli_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../build/cli/samurai"))
        if os.path.exists(cli_path):
            srv = _ReusableThreadingHttpServer(("127.0.0.1", 0), _KeepAliveHandler)
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            try:
                with tempfile.TemporaryDirectory() as td:
                    html_out = os.path.join(td, "benchmark_report.html")
                    cmd = [
                        cli_path,
                        "--run-rfc-suite", "all",
                        "--worker", "l7",
                        "--protocol", "http1",
                        "--keepalive",
                        "--concurrency", "4",
                        "--target", "127.0.0.1",
                        "--port", str(port),
                        "--rps", "200",
                        "--count", "40",
                        "--confirm",
                        "--rfc-report-out", html_out,
                    ]
                    res = subprocess.run(cmd, capture_output=True, text=True)
                    self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                    self.assertIn("LIVE_DATAPLANE", res.stdout)
                    self.assertIn("Samurai Executive RFC Benchmark Report", res.stdout)
                    self.assertIn("RFC 2544 Maximum Zero-Loss Throughput", res.stdout)

                    # Verify HTML Report file generation
                    self.assertTrue(os.path.exists(html_out))
                    with open(html_out, "r", encoding="utf-8") as f:
                        content = f.read()
                        self.assertIn("<title>Samurai RFC 2544 / 3511 / 8219 Benchmark Report</title>", content)
                        self.assertIn("LIVE_DATAPLANE", content)
                        self.assertIn("PASSED (100%)", content)
            finally:
                srv.shutdown()
                srv.server_close()


if __name__ == "__main__":
    unittest.main()
