import unittest

from ddos_samurai.stealth import apply_evasion, create_smuggled_request


class TestStealth(unittest.TestCase):
    def test_create_smuggled_request_cl_te(self):
        req = create_smuggled_request("testhost.com", 80, "CL.TE")
        self.assertIn(b"Content-Length:", req)
        self.assertIn(b"Transfer-Encoding: chunked", req)
        self.assertIn(b"GET /404-not-found", req)

    def test_create_smuggled_request_te_cl(self):
        req = create_smuggled_request("testhost.com", 80, "TE.CL")
        self.assertIn(b"Content-Length: 4", req)
        self.assertIn(b"Transfer-Encoding: chunked", req)
        self.assertIn(b"GET /404-not-found", req)

    def test_apply_evasion(self):
        payload = "select * from users"

        ev_case = apply_evasion(payload, ["case"])
        self.assertNotEqual(ev_case, payload)
        self.assertIn("SELECT", ev_case.upper())

        ev_url = apply_evasion(payload, ["url"])
        self.assertNotEqual(ev_url, payload)
        self.assertIn("%", ev_url)

        ev_comment = apply_evasion(payload, ["comment"])
        self.assertNotEqual(ev_comment, payload)
        self.assertIn("/*", ev_comment)
        self.assertIn("*/", ev_comment)

