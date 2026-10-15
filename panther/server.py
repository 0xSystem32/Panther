"""Serveur HTTP local (127.0.0.1 uniquement) : API JSON + interface web."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .scanner import Scanner
from . import i18n
from .i18n import tr
from .labels import TYPE_LABELS

STATIC = os.path.join(os.path.dirname(__file__), "static")
TYPES = {".html": "text/html", ".js": "text/javascript", ".css": "text/css"}
scanner = Scanner()


def strings():
    """Textes de l'interface web dans la langue active (les gabarits gardent leurs {champs} : le navigateur les remplit)."""
    return {"lang": i18n.language(), "labels": dict(TYPE_LABELS.items()), "scan": tr("Lancer le scan"),
            "hint": tr("Cliquez sur un appareil pour voir ses détails."), "this_machine": tr("cette machine"),
            "type": tr("Type"), "ip": tr("Adresse IP"), "mac": tr("Adresse MAC"), "vendor": tr("Fabricant"), "os": tr("Système"),
            "services": tr("Services"), "banners": tr("Bannières"), "network": tr("{cidr} · passerelle {gateway}"),
            "count": tr("{n} appareil(s)"), "scanning": tr("Scan en cours… {progress}%"), "error": tr("Erreur : {error}"),
            "scan_hint": tr("Scan en cours, les appareils apparaissent au fur et à mesure.")}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # défense en profondeur : les noms et bannières affichés viennent du réseau (non fiables)
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _local_only(self):
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
        origin = self.headers.get("Origin")
        ok = host in ("127.0.0.1", "localhost") and (
            origin is None or origin.startswith(("http://127.0.0.1", "http://localhost")))
        if not ok:
            self._send(403, {"error": tr("accès refusé")})
        return ok

    def do_GET(self):
        if not self._local_only():
            return
        if self.path == "/api/state":
            return self._send(200, scanner.snapshot())
        if self.path == "/api/strings":
            return self._send(200, strings())
        name = "index.html" if self.path in ("/", "") else os.path.basename(self.path)
        path = os.path.join(STATIC, name)
        ext = os.path.splitext(name)[1]
        if ext in TYPES and os.path.isfile(path):
            with open(path, "rb") as f:
                return self._send(200, f.read(), TYPES[ext])
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._local_only():
            return
        if self.path == "/api/scan":
            return self._send(200, {"started": scanner.start()})
        self._send(404, {"error": "not found"})


def serve(port=8765):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(tr("Panther → http://127.0.0.1:{port}  (Ctrl+C pour quitter)", port=port))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
