import http.server
import json
import os
import shutil
import socketserver
import ssl
import stat
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from panther import alerts, secrets


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        secrets.PATH = os.path.join(self.tmp.name, "secrets.json")
        alerts.PATH = os.path.join(self.tmp.name, "alerts.json")
        self._tool = secrets._tool
        secrets._tool = lambda: None                                   # par défaut : pas de trousseau, repli sur le fichier privé

    def tearDown(self):
        secrets._tool = self._tool
        self.tmp.cleanup()


class SecretsFileTests(Base):
    def test_roundtrip_overwrite_and_delete(self):
        self.assertIsNone(secrets.get("x"))
        secrets.set("x", "un"); self.assertEqual(secrets.get("x"), "un")
        secrets.set("x", "deux"); self.assertEqual(secrets.get("x"), "deux")
        secrets.set("x", ""); self.assertIsNone(secrets.get("x"))                           # une valeur vide supprime
        secrets.set("y", "v"); secrets.delete("y"); secrets.delete("inexistant")
        self.assertIsNone(secrets.get("y"))

    def test_file_is_private_and_atomic(self):
        secrets.set("webhook", "https://exemple.org/secret")
        mode = stat.S_IMODE(os.stat(secrets.PATH).st_mode)
        self.assertEqual(mode, 0o600)                                                        # lisible par l'utilisateur seul
        self.assertEqual(os.listdir(os.path.dirname(secrets.PATH)), ["secrets.json"])         # aucun fichier temporaire oublié

    def test_corrupt_file_is_treated_as_empty(self):
        with open(secrets.PATH, "w") as f:
            f.write("{pas du json")
        self.assertIsNone(secrets.get("x"))
        secrets.set("x", "ok")
        self.assertEqual(secrets.get("x"), "ok")

    def test_backend_label(self):
        self.assertIn("fichier", secrets.backend())
        secrets._tool = lambda: "/usr/bin/secret-tool"
        self.assertIn("trousseau", secrets.backend())


class SecretToolTests(Base):
    def setUp(self):
        super().setUp()
        secrets._tool = lambda: "/usr/bin/secret-tool"
        self.calls, self.store = [], {}
        self._run = secrets.RUN

        def fake(cmd, input=None, **kw):
            self.calls.append((cmd, input))
            action, acct = cmd[1], cmd[cmd.index("account") + 1] if "account" in cmd else None
            if action == "store":
                self.store[acct] = input
            elif action == "clear":
                self.store.pop(acct, None)
            elif action == "lookup":
                return subprocess.CompletedProcess(cmd, 0 if acct in self.store else 1, stdout=(self.store.get(acct, "") + "\n") if acct in self.store else "", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        secrets.RUN = fake

    def tearDown(self):
        secrets.RUN = self._run
        super().tearDown()

    def test_secret_goes_through_stdin_never_the_command_line(self):
        secrets.set("alerts-smtp-password", "MOT-DE-PASSE-SECRET")
        cmd, stdin = self.calls[0]
        self.assertEqual(stdin, "MOT-DE-PASSE-SECRET")
        self.assertFalse(any("MOT-DE-PASSE-SECRET" in part for part in cmd))                  # invisible dans `ps`
        self.assertEqual(secrets.get("alerts-smtp-password"), "MOT-DE-PASSE-SECRET")          # le saut de ligne final est retiré
        self.assertFalse(os.path.exists(secrets.PATH))                                       # aucune copie en clair

    def test_a_plaintext_copy_from_the_fallback_is_removed_once_the_keyring_works(self):
        secrets._tool = lambda: None
        secrets.set("x", "ancien")
        secrets._tool = lambda: "/usr/bin/secret-tool"
        secrets.set("x", "nouveau")
        self.assertNotIn("x", json.load(open(secrets.PATH)))

    def test_keyring_failure_falls_back_to_the_private_file(self):
        secrets.RUN = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, stdout="", stderr="no session")
        self.assertIn("fichier", secrets.set("x", "v"))
        self.assertEqual(secrets.get("x"), "v")

    def test_missing_binary_is_not_an_error(self):
        def boom(*a, **k):
            raise FileNotFoundError("secret-tool")
        secrets.RUN = boom
        secrets.set("x", "v")
        self.assertEqual(secrets.get("x"), "v")

    def test_delete_clears_both_places(self):
        secrets.set("x", "v"); secrets.delete("x")
        self.assertIsNone(secrets.get("x"))


class ConfigTests(Base):
    def test_defaults_and_non_dict_input(self):
        for raw in (None, [], "x", 5, {}):
            self.assertEqual(alerts.validate(raw), alerts.DEFAULTS)

    def test_values_are_coerced_and_bounded(self):
        c = alerts.validate({"enabled": 1, "events": {"exposure_min": "inconnu", "new_device": 0}, "webhook": {"enabled": True, "format": "teams"},
                             "email": {"enabled": True, "host": "smtp.x\r\nBcc: a@b.c", "port": 99999, "security": "tls", "to": "a@b.fr, c@d.fr"}})
        self.assertTrue(c["enabled"])
        self.assertEqual((c["events"]["exposure_min"], c["events"]["new_device"]), ("élevé", False))
        self.assertEqual(c["webhook"]["format"], "generic")
        self.assertEqual((c["email"]["port"], c["email"]["security"], c["email"]["to"]), (587, "starttls", ["a@b.fr", "c@d.fr"]))
        self.assertNotIn("\n", c["email"]["host"])

    def test_invalid_email_addresses_are_refused(self):
        for bad in ("pas-une-adresse", "a@b", "a b@c.fr", "a@b.fr\nBcc: x@y.fr", "<a@b.fr>"):
            with self.assertRaises(alerts.AlertError, msg=bad):
                alerts.validate({"email": {"to": [bad]}})
        with self.assertRaises(alerts.AlertError):
            alerts.validate({"email": {"from": "mauvais"}})

    def test_save_and_load_roundtrip_and_no_secret_in_the_file(self):
        alerts.save({"enabled": True, "webhook": {"enabled": True, "format": "discord", "url": "https://secret.example/x"},
                     "email": {"enabled": True, "host": "smtp.test", "user": "moi", "password": "SECRET", "from": "a@b.fr", "to": ["c@d.fr"]}})
        with open(alerts.PATH, encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn("secret.example", raw); self.assertNotIn("SECRET", raw)             # les secrets n'entrent jamais dans ce fichier
        c = alerts.load()
        self.assertEqual((c["enabled"], c["webhook"]["format"], c["email"]["host"], c["email"]["to"]), (True, "discord", "smtp.test", ["c@d.fr"]))

    def test_corrupt_file_gives_defaults(self):
        with open(alerts.PATH, "w") as f:
            f.write("{pas du json")
        self.assertEqual(alerts.load(), alerts.DEFAULTS)
        self.assertEqual(alerts.load(os.path.join(self.tmp.name, "absent.json")), alerts.DEFAULTS)


def dev(**kw):
    d = {"ip": "192.168.1.50", "hostname": "cam", "type": "camera", "vendor": "Hikvision", "online": True, "key": "aa:00:00:00:00:50", "mac": "aa:00:00:00:00:50"}
    d.update(kw)
    return d


def finding(sev="élevé", title="Telnet activé", port=23):
    return {"id": "telnet", "severity": sev, "title": title, "detail": "", "remedy": "", "port": port}


class EventTests(Base):
    cfg = alerts.validate({"events": {"new_device": True, "new_exposure": True, "exposure_min": "élevé", "trusted_offline": True}})

    def test_first_analysis_is_silent(self):
        self.assertEqual(alerts.build_events([dev(new=True)], {"baseline": True}, {"new": []}, self.cfg), [])

    def test_new_device_and_exposure_events(self):
        ev = alerts.build_events([dev(new=True), dev(hostname="vieux", new=False, key="k2")], {"baseline": False}, {"new": [(dev(), finding())]}, self.cfg)
        self.assertEqual([e["kind"] for e in ev], ["new_device", "new_exposure"])
        self.assertIn("cam", ev[0]["title"]); self.assertIn("192.168.1.50", ev[0]["detail"])
        self.assertIn("Telnet activé (port 23)", ev[1]["detail"])

    def test_exposure_threshold_and_switches(self):
        low = {"new": [(dev(), finding("moyen", "Boa", 80)), (dev(), finding("critique", "Redis ouvert", 6379))]}
        ev = alerts.build_events([], {"baseline": False}, low, self.cfg)
        self.assertEqual([e["detail"] for e in ev], ["Redis ouvert (port 6379)"])           # « moyen » < seuil « élevé »
        off = alerts.validate({"events": {"new_device": False, "new_exposure": False}})
        self.assertEqual(alerts.build_events([dev(new=True)], {"baseline": False}, low, off), [])

    def test_offline_alert_only_for_trusted_devices_and_when_enabled(self):
        hist = [("offline", "aa:00:00:00:00:50", "cam", "absent de 2 scans"), ("offline", "k2", "autre", "absent de 2 scans")]
        devs = [dev(trusted=True), dev(key="k2", trusted=False)]
        ev = alerts.build_events(devs, {"baseline": False}, {"new": []}, self.cfg, hist)
        self.assertEqual([e["title"] for e in ev], ["Appareil de confiance hors ligne : cam"])
        quiet = alerts.validate({"events": {"trusted_offline": False}})
        self.assertEqual(alerts.build_events(devs, {"baseline": False}, {"new": []}, quiet, hist), [])

    def test_hostile_device_names_cannot_inject_lines_or_control_characters(self):
        ev = alerts.build_events([dev(hostname="x\r\nBcc: evil@x.fr\x1b[31m", new=True)], {"baseline": False}, {"new": []}, self.cfg)
        self.assertNotIn("\n", ev[0]["title"]); self.assertNotIn("\x1b", ev[0]["title"])
        self.assertEqual(alerts.clean("a\r\nb\x00c"), "a  b c")
        self.assertLessEqual(len(alerts.clean("z" * 1000)), alerts.MAX_TEXT)

    def test_compose_pluralises_and_caps_the_message(self):
        one = alerts.compose([{"title": "A", "detail": "d"}], when=0)
        self.assertEqual(one[0], "Panther : 1 événement sur le réseau")
        many = alerts.compose([{"title": f"E{i}", "detail": ""} for i in range(35)], when=0)
        self.assertEqual(many[0], "Panther : 35 événements sur le réseau")
        self.assertEqual(many[1].count("•"), alerts.MAX_LINES)
        self.assertIn("… et 15 autre(s)", many[1])


class WebhookRequestTests(Base):
    def req(self, fmt, title="Titre é", text="Corps"):
        return alerts.webhook_request("https://hooks.example/x", fmt, title, text, [{"kind": "k"}])

    def test_formats(self):
        _, h, b = self.req("discord"); self.assertEqual(json.loads(b)["content"], "**Titre é**\nCorps")
        _, h, b = self.req("slack"); self.assertEqual(json.loads(b)["text"], "*Titre é*\nCorps")
        _, h, b = self.req("generic"); d = json.loads(b)
        self.assertEqual((d["title"], d["message"], d["events"]), ("Titre é", "Corps", [{"kind": "k"}]))
        _, h, b = self.req("ntfy"); self.assertEqual((b, h["Content-Type"].split(";")[0]), (b"Corps", "text/plain"))
        self.assertEqual(h["Title"], "Titre")                                                # l'en-tête reste en ASCII

    def test_discord_message_is_capped(self):
        _, _, b = self.req("discord", text="x" * 5000)
        self.assertLessEqual(len(json.loads(b)["content"]), 1900)

    def test_only_http_and_https_urls_are_accepted(self):
        for bad in ("", None, "file:///etc/passwd", "ftp://x/y", "javascript:alert(1)", "//x/y", "http://", "pas une url"):
            with self.assertRaises(alerts.AlertError, msg=repr(bad)):
                alerts.webhook_request(bad, "generic", "t", "x")


class Capture(http.server.BaseHTTPRequestHandler):
    seen, code, location = [], 200, None

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        type(self).seen.append((self.path, dict(self.headers), body))
        self.send_response(type(self).code)
        if type(self).location:
            self.send_header("Location", type(self).location)
        self.end_headers()


def serve(code=200, location=None):
    handler = type("H", (Capture,), {"seen": [], "code": code, "location": location})
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, handler, f"http://127.0.0.1:{srv.server_address[1]}"


class SendWebhookTests(Base):
    def test_posts_json_to_the_given_url(self):
        srv, h, url = serve()
        try:
            self.assertEqual(alerts.send_webhook(url + "/hook", "generic", "Titre", "Corps", [{"kind": "a"}]), 200)
        finally:
            srv.shutdown(); srv.server_close()
        path, headers, body = h.seen[0]
        self.assertEqual((path, json.loads(body)["title"], headers["User-Agent"]), ("/hook", "Titre", "Panther"))

    def test_redirects_are_never_followed(self):
        other, h2, url2 = serve()
        srv, h1, url1 = serve(code=302, location=url2 + "/ailleurs")
        try:
            with self.assertRaises(alerts.AlertError) as cm:
                alerts.send_webhook(url1, "generic", "t", "x")
        finally:
            srv.shutdown(); srv.server_close(); other.shutdown(); other.server_close()
        self.assertIn("302", str(cm.exception))
        self.assertEqual(h2.seen, [])                                                        # le message n'est jamais parti ailleurs

    def test_http_error_and_unreachable_server_give_clear_errors(self):
        srv, h, url = serve(code=500)
        try:
            with self.assertRaises(alerts.AlertError) as cm:
                alerts.send_webhook(url, "generic", "t", "x")
        finally:
            srv.shutdown(); srv.server_close()
        self.assertIn("500", str(cm.exception))
        with self.assertRaises(alerts.AlertError):
            alerts.send_webhook("http://127.0.0.1:1/x", "generic", "t", "x", timeout=2)


class SmtpHandler(socketserver.StreamRequestHandler):
    log = []

    def handle(self):
        w = lambda s: (self.wfile.write(s.encode() + b"\r\n"), self.wfile.flush())
        w("220 test ESMTP")
        rec, data_mode, buf = {"auth": None, "from": None, "to": [], "data": ""}, False, []
        while True:
            line = self.rfile.readline()
            if not line:
                break
            text = line.decode("utf-8", "replace").rstrip("\r\n")
            if data_mode:
                if text == ".":
                    data_mode = False; rec["data"] = "\n".join(buf); w("250 queued")
                else:
                    buf.append(text)
                continue
            cmd = text.upper()
            if cmd.startswith("EHLO"):
                self.wfile.write(b"250-test\r\n250 AUTH PLAIN\r\n"); self.wfile.flush()
            elif cmd.startswith("HELO"):
                w("250 test")
            elif cmd.startswith("AUTH PLAIN"):
                rec["auth"] = text.split()[-1]; w("235 ok")
            elif cmd.startswith("MAIL FROM"):
                rec["from"] = text[10:]; w("250 ok")
            elif cmd.startswith("RCPT TO"):
                rec["to"].append(text[8:]); w("250 ok")
            elif cmd == "DATA":
                data_mode = True; w("354 go")
            elif cmd == "QUIT":
                w("221 bye"); break
            else:
                w("250 ok")
        type(self).log.append(rec)


def smtp_server():
    handler = type("S", (SmtpHandler,), {"log": []})
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, handler


class SendEmailTests(Base):
    def em(self, port, **kw):
        base = {"enabled": True, "host": "127.0.0.1", "port": port, "security": "none", "user": "", "from": "panther@x.fr", "to": ["moi@x.fr", "toi@x.fr"]}
        base.update(kw)
        return base

    def test_message_is_delivered_to_all_recipients(self):
        srv, h = smtp_server()
        try:
            alerts.send_email(self.em(srv.server_address[1]), None, "Panther : 2 événements", "• Nouvel appareil : cam")
        finally:
            srv.shutdown(); srv.server_close()
        rec = h.log[0]
        self.assertEqual((rec["from"], rec["to"]), ("<panther@x.fr>", ["<moi@x.fr>", "<toi@x.fr>"]))
        import email
        import email.policy
        msg = email.message_from_string(rec["data"], policy=email.policy.default)
        self.assertEqual(msg["Subject"], "Panther : 2 événements")                          # accents encodés puis décodés correctement
        self.assertIn("Nouvel appareil : cam", msg.get_content())

    def test_password_comes_from_the_argument_and_reaches_the_server(self):
        srv, h = smtp_server()
        try:
            alerts.send_email(self.em(srv.server_address[1], user="moi"), "S3CRET", "t", "x")
        finally:
            srv.shutdown(); srv.server_close()
        import base64
        self.assertEqual(base64.b64decode(h.log[0]["auth"]), b"\0moi\0S3CRET")

    def test_hostile_subject_cannot_inject_headers(self):
        srv, h = smtp_server()
        try:
            alerts.send_email(self.em(srv.server_address[1]), None, "Titre\r\nBcc: evil@x.fr", "corps")
        finally:
            srv.shutdown(); srv.server_close()
        data = h.log[0]["data"]
        self.assertNotIn("\nBcc:", data)
        self.assertEqual(h.log[0]["to"], ["<moi@x.fr>", "<toi@x.fr>"])                              # aucun destinataire ajouté

    def test_starttls_ssl_and_login_calls(self):
        calls = []

        class FakeSMTP:
            def __init__(self, *a, **k): calls.append(("init", type(self).__name__, a[:2]))
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def starttls(self, context=None): calls.append(("starttls", context.verify_mode == ssl.CERT_REQUIRED))
            def login(self, u, p): calls.append(("login", u, p))
            def send_message(self, m): calls.append(("send", m["To"]))
        class FakeSSL(FakeSMTP):
            pass
        with mock.patch.object(alerts.smtplib, "SMTP", FakeSMTP), mock.patch.object(alerts.smtplib, "SMTP_SSL", FakeSSL):
            alerts.send_email(self.em(587, security="starttls", user="u"), "pw", "t", "x")
            alerts.send_email(self.em(465, security="ssl", user="u"), "pw", "t", "x")
        self.assertEqual([c[0] for c in calls], ["init", "starttls", "login", "send", "init", "login", "send"])
        self.assertEqual(calls[1], ("starttls", True))                                       # certificat vérifié, jamais désactivé
        self.assertEqual(calls[4][1], "FakeSSL")
        self.assertEqual(calls[2], ("login", "u", "pw"))

    def test_incomplete_settings_and_unreachable_server(self):
        for bad in ({"host": ""}, {"to": []}, {"from": ""}):
            with self.assertRaises(alerts.AlertError):
                alerts.send_email(self.em(25, **bad), None, "t", "x")
        with self.assertRaises(alerts.AlertError):
            alerts.send_email(self.em(1), None, "t", "x", timeout=2)

    @unittest.skipUnless(shutil.which("openssl"), "openssl absent")
    def test_a_self_signed_server_certificate_is_refused_not_silently_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            key, crt = os.path.join(d, "k"), os.path.join(d, "c")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=localhost"],
                           check=True, capture_output=True)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(crt, key)
            srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), type("T", (socketserver.BaseRequestHandler,), {"handle": lambda s: None}))
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                with self.assertRaises(alerts.AlertError) as cm:
                    alerts.send_email(self.em(srv.server_address[1], security="ssl"), None, "t", "x", timeout=3)
            finally:
                srv.shutdown(); srv.server_close()
        self.assertIn("sécurisée", str(cm.exception))


class DispatchTests(Base):
    def cfg(self, **kw):
        c = alerts.validate({"enabled": True, "webhook": {"enabled": True, "format": "generic"}, "email": {"enabled": False}})
        c.update(kw)
        return c

    def test_no_events_means_no_message(self):
        self.assertEqual(alerts.dispatch(self.cfg(), []), [])

    def test_webhook_url_comes_from_the_secret_store_and_is_never_logged(self):
        srv, h, url = serve()
        secrets.set(alerts.SECRET_WEBHOOK, url + "/jeton-ultra-secret")
        try:
            with self.assertLogs("panther", level="DEBUG") as logs:
                alerts.log.warning("sentinelle")                                              # garantit qu'il y a au moins une ligne à examiner
                res = alerts.dispatch(self.cfg(), alerts.test_message())
        finally:
            srv.shutdown(); srv.server_close()
        self.assertEqual(res, [("webhook", True, "")])
        self.assertEqual(h.seen[0][0], "/jeton-ultra-secret")
        self.assertNotIn("jeton-ultra-secret", "\n".join(logs.output))

    def test_a_failing_channel_does_not_stop_the_other_one(self):
        srv, h, url = serve()
        secrets.set(alerts.SECRET_WEBHOOK, url)
        cfg = self.cfg()
        cfg["email"] = dict(cfg["email"], enabled=True, host="127.0.0.1", port=1, security="none", **{"from": "a@b.fr"}, to=["c@d.fr"])
        try:
            res = alerts.dispatch(cfg, alerts.test_message())
        finally:
            srv.shutdown(); srv.server_close()
        self.assertEqual([(c, ok) for c, ok, _ in res], [("webhook", True), ("e-mail", False)])
        self.assertTrue(res[1][2])

    def test_missing_webhook_secret_is_reported_not_raised(self):
        res = alerts.dispatch(self.cfg(), alerts.test_message())
        self.assertEqual((res[0][0], res[0][1]), ("webhook", False))

    def test_disabled_channels_are_skipped(self):
        cfg = self.cfg(); cfg["webhook"]["enabled"] = False
        self.assertEqual(alerts.dispatch(cfg, alerts.test_message()), [])


if __name__ == "__main__":
    unittest.main()
