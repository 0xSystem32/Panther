import http.server
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

from panther import scanner


class Handler(http.server.BaseHTTPRequestHandler):
    server_version, sys_version = "Debut/1.0", ""          # en-tête « Server » du serveur de test
    page = b"<html><head><title>Brother HL-L2350DW series</title></head><body>x</body></html>"
    headers_extra = {}
    status = 200
    chunked_delay = 0

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(self.status)
        for k, v in self.headers_extra.items():
            self.send_header(k, v)
        self.end_headers()
        if self.chunked_delay:
            self.wfile.write(self.page[:8]); self.wfile.flush(); time.sleep(self.chunked_delay); self.wfile.write(self.page[8:])
        else:
            self.wfile.write(self.page)


def serve(handler, tls=None):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(*tls)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


class HttpSummaryTests(unittest.TestCase):
    def test_server_title_and_realm(self):
        head = 'HTTP/1.0 401 Unauthorized\r\nServer: Boa/0.94\r\nWWW-Authenticate: Basic realm="DCS-930L"\r\n'
        self.assertEqual(scanner.http_summary(head, "<title>Camera</title>"), "Boa/0.94 | Camera | realm DCS-930L")
        self.assertEqual(scanner.http_summary("HTTP/1.0 200 OK\r\nServer: nginx", ""), "nginx")
        self.assertEqual(scanner.http_summary("HTTP/1.0 200 OK", "<TITLE lang=fr>  Routeur  </TITLE>"), "Routeur")
        self.assertEqual(scanner.http_summary("", ""), "")

    def test_untrusted_text_is_cleaned_and_bounded(self):
        s = scanner.http_summary("Server: x\x00\x1b[31mrouge\r\n", "<title>a&amp;b &lt;script&gt;" + "y" * 500 + "</title>")
        self.assertNotIn("\x1b", s); self.assertNotIn("\x00", s)
        self.assertIn("a&b <script>", s)                       # décodé en TEXTE : jamais interprété ailleurs (tout est affiché en texte brut)
        self.assertLessEqual(len(s), 60 + 3 + 60)

    def test_binary_garbage_does_not_crash(self):
        scanner.http_summary("\xff\xfe" * 100, "\x00" * 100)


class GrabBannerTests(unittest.TestCase):
    def setUp(self):
        self.handler = type("H", (Handler,), {})

    def grab(self, handler=None, **kw):
        srv, port = serve(handler or self.handler)
        try:
            scanner.HTTP_PORTS += (port,)
            return scanner.grab_banner("127.0.0.1", port, **kw)
        finally:
            scanner.HTTP_PORTS = scanner.HTTP_PORTS[:-1]
            srv.shutdown(); srv.server_close()

    def test_reads_server_and_title(self):
        self.assertEqual(self.grab(), "Debut/1.0 | Brother HL-L2350DW series")

    def test_realm_of_a_protected_page(self):
        h = type("H", (Handler,), {"status": 401, "headers_extra": {"WWW-Authenticate": 'Basic realm="Hikvision DS-2CD2043"'}, "page": b""})
        self.assertEqual(self.grab(h), "Debut/1.0 | realm Hikvision DS-2CD2043")

    def test_title_arriving_in_a_second_chunk_is_still_found(self):
        h = type("H", (Handler,), {"chunked_delay": 0.3})
        self.assertIn("Brother", self.grab(h))

    def test_title_after_a_long_head_is_found(self):
        h = type("H", (Handler,), {"page": b"<!-- " + b"x" * 3000 + b" --><title>Tard</title>"})
        self.assertIn("Tard", self.grab(h))

    def test_closed_port_and_silent_service_give_nothing(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
        self.assertEqual(scanner.grab_banner("127.0.0.1", port), "")
        quiet = socket.socket(); quiet.bind(("127.0.0.1", 0)); quiet.listen(1)
        try:
            scanner.HTTP_PORTS += (quiet.getsockname()[1],)
            t = time.time()
            self.assertEqual(scanner.grab_banner("127.0.0.1", quiet.getsockname()[1], timeout=0.5), "")
            self.assertLess(time.time() - t, 2.0)
        finally:
            scanner.HTTP_PORTS = scanner.HTTP_PORTS[:-1]; quiet.close()

    def test_non_web_service_returns_only_its_first_line(self):
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        port = srv.getsockname()[1]
        def serve_once():
            c, _ = srv.accept(); c.sendall(b"SSH-2.0-OpenSSH_9.2p1 Debian\r\nsecond line\r\n"); c.close()
        threading.Thread(target=serve_once, daemon=True).start()
        try:
            self.assertEqual(scanner.grab_banner("127.0.0.1", port), "SSH-2.0-OpenSSH_9.2p1 Debian")
        finally:
            srv.close()

    @unittest.skipUnless(shutil.which("openssl"), "openssl absent : test HTTPS ignoré")
    def test_https_with_a_self_signed_certificate_is_read_without_verification(self):
        with tempfile.TemporaryDirectory() as d:
            key, crt = os.path.join(d, "k.pem"), os.path.join(d, "c.pem")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-days", "1",
                            "-subj", "/CN=appareil-local"], check=True, capture_output=True)
            srv, port = serve(self.handler, tls=(crt, key))
            try:
                scanner.TLS_PORTS += (port,)
                self.assertEqual(scanner.grab_banner("127.0.0.1", port), "Debut/1.0 | Brother HL-L2350DW series")
            finally:
                scanner.TLS_PORTS = scanner.TLS_PORTS[:-1]
                srv.shutdown(); srv.server_close()

    def test_https_port_speaking_plain_http_does_not_crash(self):
        srv, port = serve(self.handler)
        try:
            scanner.TLS_PORTS += (port,)
            self.assertEqual(scanner.grab_banner("127.0.0.1", port, timeout=1.0), "")            # échec de la négociation TLS : vide
        finally:
            scanner.TLS_PORTS = scanner.TLS_PORTS[:-1]; srv.shutdown(); srv.server_close()


if __name__ == "__main__":
    unittest.main()
