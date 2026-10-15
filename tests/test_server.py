import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from panther import i18n, server


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def get(self, path, headers=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", headers=headers or {})
        try:
            return urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as e:
            return e

    def test_security_headers_on_every_answer(self):
        for path in ("/", "/app.js", "/api/state", "/absent"):
            r = self.get(path)
            h = r.headers
            self.assertIn("default-src 'self'", h["Content-Security-Policy"], path)
            self.assertEqual((h["X-Content-Type-Options"], h["X-Frame-Options"]), ("nosniff", "DENY"), path)
            self.assertNotIn("unsafe-inline", h["Content-Security-Policy"])
            self.assertNotIn("script-src", h["Content-Security-Policy"].replace("default-src", ""))

    def test_state_is_json_and_a_foreign_host_header_is_refused(self):
        self.assertIsInstance(json.loads(self.get("/api/state").read()), dict)
        self.assertEqual(self.get("/api/state", {"Host": "evil.example"}).code, 403)    # protection contre le DNS rebinding
        self.assertEqual(self.get("/", {"Origin": "http://evil.example"}).code, 403)

    def test_strings_follow_the_active_language(self):
        try:
            i18n.set_language("en")
            en = json.loads(self.get("/api/strings").read())
            i18n.set_language("fr")
            fr = json.loads(self.get("/api/strings").read())
        finally:
            i18n.set_language("fr")
        self.assertEqual((en["lang"], fr["lang"]), ("en", "fr"))
        self.assertEqual(en["scan"], "Start scan")
        self.assertEqual(en["labels"]["router"], "Router / box")
        self.assertEqual(fr["labels"]["router"], "Routeur / box")
        self.assertIn("{cidr}", en["network"])                                          # le navigateur remplit les champs
        self.assertEqual(set(en), set(fr))

    def test_path_traversal_is_not_possible(self):
        self.assertEqual(self.get("/../scanner.py").code, 404)
        self.assertEqual(self.get("/..%2fscanner.py").code, 404)

    def test_page_has_no_inline_script_or_style_that_the_policy_would_block(self):
        page = self.get("/").read().decode()
        self.assertNotIn("onclick=", page); self.assertNotIn("<style", page)


if __name__ == "__main__":
    unittest.main()
