import http.server
import os
import socket
import tempfile
import threading
import unittest

from panther import fingerprint, ouiupdate, wol


class WolTests(unittest.TestCase):
    def test_magic_packet_structure(self):
        p = wol.magic_packet("AA:bb:CC:dd:EE:ff")
        self.assertEqual((len(p), p[:6], p[6:12]), (102, b"\xff" * 6, bytes.fromhex("aabbccddeeff")))
        self.assertEqual(p[6:], bytes.fromhex("aabbccddeeff") * 16)

    def test_accepted_mac_formats(self):
        ref = wol.magic_packet("aa:bb:cc:dd:ee:ff")
        for m in ("aa-bb-cc-dd-ee-ff", "AABBCCDDEEFF", " aa:bb:cc:dd:ee:ff "):
            self.assertEqual(wol.magic_packet(m), ref, m)

    def test_invalid_macs_are_refused(self):
        for bad in ("", None, "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00", "zz:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:f", "pas une mac", "aa:bb:cc:dd:ee:ff; rm -rf /"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                wol.magic_packet(bad)

    def test_broadcast_addresses(self):
        self.assertEqual(wol.broadcast_for("192.168.1.0/24"), "192.168.1.255")
        self.assertEqual(wol.broadcast_for("192.168.1.77/24"), "192.168.1.255")
        self.assertEqual(wol.broadcast_for("10.0.0.0/22"), "10.0.3.255")
        with self.assertRaises(ValueError):
            wol.broadcast_for("pas un réseau")

    def test_packet_is_really_sent_over_udp(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); srv.bind(("127.0.0.1", 0)); srv.settimeout(2)
        port = srv.getsockname()[1]
        n = wol.send("aa:bb:cc:dd:ee:ff", ("127.0.0.1",), ports=(port,))
        data, _ = srv.recvfrom(1024)
        srv.close()
        self.assertEqual((n, data), (1, wol.magic_packet("aa:bb:cc:dd:ee:ff")))

    def test_send_with_an_invalid_mac_sends_nothing_and_raises(self):
        with self.assertRaises(ValueError):
            wol.send("nope", ("127.0.0.1",), ports=(9,))

    def test_unreachable_broadcast_does_not_crash(self):
        self.assertIsInstance(wol.send("aa:bb:cc:dd:ee:ff", ("203.0.113.255",), ports=(9,)), int)


def csv_text(n=1500, extra=""):
    lines = ["Registry,Assignment,Organization Name,Organization Address"]
    lines += [f"MA-L,{i:06X},\"Fabricant {i}, Inc.\",Quelque part" for i in range(n)]
    lines += ["MA-L,3C0754,\"Apple, Inc.\",Cupertino", "MA-L,ZZZZZZ,Mauvais,x", "MA-L,12,Court,x", "MA-L,001BA9,Brother industries; LTD.,Nagoya"]
    return "\n".join(lines) + "\n" + extra


def serve(body, status=200):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(status); self.end_headers(); self.wfile.write(body if isinstance(body, bytes) else body.encode())
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/oui.csv"


class OuiUpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dest = os.path.join(self.tmp.name, "sub", "oui.txt")
        self.saved = dict(fingerprint.OUI)

    def tearDown(self):
        fingerprint.OUI.clear(); fingerprint.OUI.update(self.saved)
        self.tmp.cleanup()

    def run_update(self, body, **kw):
        srv, url = serve(body, **kw)
        try:
            return ouiupdate.update(url, self.dest, timeout=5)
        finally:
            srv.shutdown(); srv.server_close()

    def test_download_converts_writes_and_takes_effect_immediately(self):
        n = self.run_update(csv_text())
        self.assertEqual(n, 1502)                                                      # 1500 + Apple + Brother ; lignes invalides ignorées
        with open(self.dest, encoding="utf-8") as f:
            lines = f.read().splitlines()
        self.assertIn("3C0754;Apple", lines)
        self.assertIn("001BA9;Brother", lines)                                         # « ; » dans le nom remplacé, nom raccourci
        self.assertEqual(lines, sorted(lines))
        self.assertEqual(fingerprint.vendor_of("3c:07:54:00:00:01"), "Apple")

    def test_too_small_download_is_refused_and_leaves_the_existing_file_alone(self):
        os.makedirs(os.path.dirname(self.dest))
        with open(self.dest, "w") as f:
            f.write("AAAAAA;Ancien\n")
        with self.assertRaises(ouiupdate.UpdateError) as cm:
            self.run_update(csv_text(10))
        self.assertIn("base inchangée", str(cm.exception))
        with open(self.dest) as f:
            self.assertEqual(f.read(), "AAAAAA;Ancien\n")
        self.assertEqual(os.listdir(os.path.dirname(self.dest)), ["oui.txt"])           # aucun fichier temporaire oublié

    def test_html_error_page_or_http_error_never_replaces_the_base(self):
        with self.assertRaises(ouiupdate.UpdateError):
            self.run_update("<html><body>Maintenance</body></html>")
        with self.assertRaises(ouiupdate.UpdateError) as cm:
            self.run_update("Not found", status=404)
        self.assertIn("téléchargement impossible", str(cm.exception))
        self.assertFalse(os.path.exists(self.dest))

    def test_unreachable_server_gives_a_clear_error(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
        with self.assertRaises(ouiupdate.UpdateError):
            ouiupdate.update(f"http://127.0.0.1:{port}/x.csv", self.dest, timeout=2)

    def test_oversized_download_is_refused(self):
        old = ouiupdate.MAX_BYTES
        ouiupdate.MAX_BYTES = 1000
        try:
            with self.assertRaises(ouiupdate.UpdateError) as cm:
                self.run_update(csv_text())
        finally:
            ouiupdate.MAX_BYTES = old
        self.assertIn("gros", str(cm.exception))

    def test_user_database_is_loaded_after_the_bundled_one_and_overrides_it(self):
        pkg = os.path.join(self.tmp.name, "pkg"); os.makedirs(pkg)
        with open(os.path.join(pkg, "oui.txt"), "w") as f:
            f.write("ABCDEF;Livré\nABCDE0;Livré aussi\n")
        user = os.path.join(self.tmp.name, "user.txt")
        with open(user, "w") as f:
            f.write("ABCDEF;Corrigé par l'utilisateur\n")
        old = ouiupdate.USER_PATH
        ouiupdate.USER_PATH = user
        try:
            fingerprint.load_all_oui(pkg)
        finally:
            ouiupdate.USER_PATH = old
        self.assertEqual((fingerprint.vendor_of("ab:cd:ef:00:00:01"), fingerprint.vendor_of("ab:cd:e0:00:00:01")), ("Corrigé par l'utilisateur", "Livré aussi"))

    def test_missing_user_file_is_fine(self):
        fingerprint.load_all_oui(os.path.join(self.tmp.name, "rien"))


if __name__ == "__main__":
    unittest.main()
