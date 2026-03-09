import unittest

from ddos_samurai.h2_transport import _sanitize_h2_headers


class TestH2TransportHeaderSanitization(unittest.TestCase):
    def test_forbidden_connection_specific_headers_are_dropped(self):
        out = _sanitize_h2_headers(
            {
                "Connection": "keep-alive",
                "Upgrade": "h2c",
                "Proxy-Connection": "close",
                "Keep-Alive": "timeout=5",
                "Transfer-Encoding": "chunked",
                "Host": "example.com",
                "x-ok": "1",
            }
        )
        self.assertEqual(out, [("x-ok", "1")])

    def test_header_names_lowercased_and_pseudo_headers_dropped(self):
        out = _sanitize_h2_headers(
            {
                "X-Custom-Header": "abc",
                ":authority": "bad",
                "user-agent": "ua",
            }
        )
        self.assertIn(("x-custom-header", "abc"), out)
        self.assertIn(("user-agent", "ua"), out)
        self.assertFalse(any(name.startswith(":") for name, _ in out))

    def test_te_allows_only_trailers(self):
        out = _sanitize_h2_headers({"te": "gzip", "TE": "trailers"})
        self.assertEqual(out, [("te", "trailers")])

    def test_crlf_injection_values_are_dropped(self):
        out = _sanitize_h2_headers({"x-test": "ok\r\nbad: 1", "x-good": "value"})
        self.assertEqual(out, [("x-good", "value")])
