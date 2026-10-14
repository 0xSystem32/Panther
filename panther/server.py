"""Serveur HTTP local (127.0.0.1 uniquement) : API JSON + interface web."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .scanner import Scanner

STATIC = os.path.join(os.path.dirname(__file__), "static")
TYPES = {".html": "text/html", ".js": "text/javascript", ".css": "text/css"}
scanner = Scanner()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _local_only(self):
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
        origin = self.headers.get("Origin")
        ok = host in ("127.0.0.1", "localhost") and (
            origin is None or origin.startswith(("http://127.0.0.1", "http://localhost")))
        if not ok:
            self._send(403, {"error": "accès refusé"})
        return ok

    def do_GET(self):
        if not self._local_only():
            return
        if self.path == "/api/state":
            return self._send(200, scanner.snapshot())
        name = "index.html" if self.path in ("/", "") else os.path.basename(self.path)
        path = os.path.join(STATIC, name)
        ext = os.path.splitext(name)[1]
        if ext in TYPES and os.path.isfile(path):
            return self._send(200, open(path, "rb").read(), TYPES[ext])
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._local_only():
            return
        if self.path == "/api/scan":
            return self._send(200, {"started": scanner.start()})
        self._send(404, {"error": "not found"})


def serve(port=8765):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Panther → http://127.0.0.1:{port}  (Ctrl+C pour quitter)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
