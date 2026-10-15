import socket
import threading
import unittest

from panther import security as sec


class FakeServer(threading.Thread):
    """Serveur TCP local : lit la requête puis répond `reply` (None = ne répond pas)."""

    def __init__(self, reply):
        super().__init__(daemon=True)
        self.reply, self.got = reply, b""
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0)); self.sock.listen(4); self.sock.settimeout(3)
        self.port = self.sock.getsockname()[1]
        self.start()

    def run(self):
        try:
            conn, _ = self.sock.accept()
            conn.settimeout(1)
            try:
                self.got = conn.recv(4096)
                if self.reply is not None:
                    conn.sendall(self.reply)
            except OSError:
                pass
            conn.close()
        except OSError:
            pass

    def close(self):
        self.join(2); self.sock.close()


def dev(ports=(), typ="unknown", banners=None, ssdp=None):
    return {"ip": "192.168.1.9", "hostname": "x", "type": typ, "ports": list(ports), "banners": banners or {}, "ssdp": ssdp or {}}


def ids(findings):
    return [f["id"] for f in findings]


class ProbeTests(unittest.TestCase):
    def check(self, fn, reply, expected, sent=None):
        s = FakeServer(reply)
        try:
            self.assertEqual(fn("127.0.0.1", s.port), expected)
            s.join(2)
            if sent:
                self.assertIn(sent, s.got)
        finally:
            s.close()

    def test_redis(self):
        self.check(sec.probe_redis, b"+PONG\r\n", "open", b"PING")
        self.check(sec.probe_redis, b"-NOAUTH Authentication required.\r\n", "protected")
        self.check(sec.probe_redis, b"HTTP/1.1 400 Bad Request\r\n", None)       # autre service : on ne conclut rien
        self.check(sec.probe_redis, None, None)

    def test_memcached(self):
        self.check(sec.probe_memcached, b"VERSION 1.6.9\r\n", "open", b"version")
        self.check(sec.probe_memcached, b"ERROR\r\n", None)

    def test_elasticsearch(self):
        self.check(sec.probe_elasticsearch, b'HTTP/1.1 200 OK\r\n\r\n{"cluster_name":"x"}', "open", b"GET /")
        self.check(sec.probe_elasticsearch, b"HTTP/1.1 401 Unauthorized\r\n\r\n", "protected")

    def test_docker(self):
        self.check(sec.probe_docker, b'HTTP/1.1 200 OK\r\n\r\n{"ApiVersion":"1.41"}', "open", b"/version")
        self.check(sec.probe_docker, b"HTTP/1.1 404 Not Found\r\n\r\n", None)

    def test_rtsp(self):
        s = FakeServer(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")
        try:
            self.assertEqual(sec.probe_rtsp("127.0.0.1", s.port), "open"); s.join(2)
            self.assertTrue(s.got.startswith(b"DESCRIBE rtsp://"))               # requête de lecture, aucun identifiant
            self.assertNotIn(b"Authorization", s.got)
        finally:
            s.close()
        s = FakeServer(b"RTSP/1.0 401 Unauthorized\r\n\r\n")
        try:
            self.assertEqual(sec.probe_rtsp("127.0.0.1", s.port), "protected")
        finally:
            s.close()

    def test_unreachable_port_gives_nothing(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
        self.assertEqual(sec.probe_redis("127.0.0.1", port), None)

    def test_active_probes_only_touch_known_services_and_survive_errors(self):
        s = FakeServer(b"+PONG\r\n")
        try:
            orig = dict(sec.PROBES)
            sec.PROBES[s.port] = lambda ip: sec.probe_redis(ip, s.port)
            sec.PROBES[1] = lambda ip: 1 / 0                                      # une sonde qui plante n'arrête rien
            self.assertEqual(sec.active_probes("127.0.0.1", [s.port, 22, 1]), {s.port: "open"})
        finally:
            sec.PROBES.clear(); sec.PROBES.update(orig); s.close()


class AnalyzeTests(unittest.TestCase):
    def test_clear_text_services(self):
        f = sec.analyze(dev([21, 23, 2323]))
        self.assertEqual(ids(f), ["telnet", "ftp"])                              # 23 et 2323 : un seul constat
        self.assertEqual(f[0]["severity"], "élevé")

    def test_sorted_from_most_to_least_severe(self):
        f = sec.analyze(dev([1883, 3306, 3389, 2375]))
        self.assertEqual([x["severity"] for x in f], ["critique", "élevé", "moyen", "faible"])

    def test_open_probe_replaces_generic_rule_and_protected_downgrades_it(self):
        f = sec.analyze(dev([6379]), {6379: "open"})
        self.assertEqual((ids(f), f[0]["severity"]), (["redis-open"], "critique"))
        f = sec.analyze(dev([6379]), {6379: "protected"})
        self.assertEqual((ids(f), f[0]["severity"]), (["redis"], "faible"))
        self.assertEqual(sec.analyze(dev([6379]))[0]["severity"], "moyen")        # pas de sonde : règle de base

    def test_rtsp_open_is_high_protected_is_low(self):
        self.assertEqual(sec.analyze(dev([554], "camera"), {554: "open"})[0]["id"], "rtsp-open")
        self.assertEqual(sec.analyze(dev([554], "camera"), {554: "protected"})[0]["severity"], "faible")

    def test_smb_is_normal_on_a_pc_but_flagged_on_an_iot_device(self):
        self.assertEqual(sec.analyze(dev([445], "desktop")), [])
        self.assertEqual(ids(sec.analyze(dev([445], "printer"))), ["smb-device"])

    def test_plain_http_admin_only_for_admin_type_devices_without_https(self):
        self.assertIn("http-admin", ids(sec.analyze(dev([80], "camera"))))
        self.assertNotIn("http-admin", ids(sec.analyze(dev([80, 443], "camera"))))
        self.assertNotIn("http-admin", ids(sec.analyze(dev([80], "desktop"))))

    def test_banner_rules(self):
        f = sec.analyze(dev([21], banners={"21": "220 (vsFTPd 2.3.4)"}))
        self.assertIn("vsftpd-backdoor", ids(f)); self.assertEqual(f[0]["severity"], "critique")
        self.assertIn("ssh1", ids(sec.analyze(dev([22], banners={"22": "SSH-1.5-Foo"}))))
        self.assertNotIn("ssh1", ids(sec.analyze(dev([22], banners={"22": "SSH-1.99-OpenSSH_9.2"}))))   # compat v2 : pas un SSH1
        self.assertIn("boa", ids(sec.analyze(dev([80], banners={"80": "Boa/0.94.14rc21 | Login"}))))
        self.assertIn("apache-old", ids(sec.analyze(dev([80], banners={"80": "Apache/2.2.22 (Debian)"}))))
        self.assertNotIn("apache-old", ids(sec.analyze(dev([80], banners={"80": "Apache/2.4.57 (Debian)"}))))

    def test_openssh_version_threshold_and_honest_wording(self):
        old = sec.analyze(dev([22], banners={"22": "SSH-2.0-OpenSSH_7.2p2 Ubuntu"}))
        self.assertEqual((ids(old), old[0]["severity"]), (["openssh-old"], "faible"))
        self.assertIn("rétroportés", old[0]["detail"])                            # ne prétend pas prouver une faille
        self.assertEqual(sec.analyze(dev([22], banners={"22": "SSH-2.0-OpenSSH_9.2p1 Debian"})), [])
        self.assertEqual(sec.analyze(dev([22], banners={"22": "SSH-2.0-OpenSSH_7.4"})), [])

    def test_libupnp_boundary(self):
        mk = lambda v: dev(ssdp={"server": f"Linux/3.0 UPnP/1.0 Portable SDK for UPnP devices/{v}"})
        self.assertEqual(ids(sec.analyze(mk("1.6.17"))), ["libupnp-old"])
        self.assertEqual(sec.analyze(mk("1.6.18")), [])
        self.assertEqual(sec.analyze(mk("1.14.12")), [])

    def test_clean_or_empty_device_has_no_findings(self):
        self.assertEqual(sec.analyze({"ip": "1.1.1.1"}), [])
        self.assertEqual(sec.analyze(dev([22, 443], "server")), [])

    def test_worst_and_counts(self):
        a = dict(dev(), security=sec.analyze(dev([23, 3306])))
        b = dict(dev(), security=[])
        self.assertEqual(sec.worst(a["security"]), "élevé")
        self.assertEqual(sec.worst([]), "")
        self.assertEqual(sec.count_by_severity([a, b]), {"critique": 0, "élevé": 1, "moyen": 1, "faible": 0, "info": 0})


class TitleTests(unittest.TestCase):
    def test_every_rule_id_has_a_readable_title(self):
        for fid, _s, _title, *_ in sec.PORT_RULES.values():
            same_id = {x[2] for x in sec.PORT_RULES.values() if x[0] == fid}      # telnet : ports 23 et 2323, deux titres possibles
            self.assertIn(sec.title_of(fid), same_id)
        for f in sec.OPEN_PROBE.values():
            self.assertEqual(sec.title_of(f["id"]), f["title"])
        for _rx, fid, _s, title, *_ in sec.BANNER_RULES:
            self.assertEqual(sec.title_of(fid), title)
        for fid in ("smb-device", "http-admin", "libupnp-old", "openssh-old"):
            self.assertNotEqual(sec.title_of(fid), fid)
        self.assertEqual(sec.title_of("inconnu-xyz"), "inconnu-xyz")           # jamais d'erreur sur une règle inconnue


class ReportTests(unittest.TestCase):
    def test_markdown_report(self):
        a = dict(dev([23, 6379], "camera"), hostname="cam", security=None, online=True)
        a["security"] = sec.analyze(a, {6379: "open"})
        ok = dict(dev([22], "server"), hostname="srv", ip="192.168.1.5", security=[], online=True)
        off = dict(dev([23]), hostname="absent", security=sec.analyze(dev([23])), online=False)
        raw = dict(dev(), hostname="non-analysé", security=None, online=True)
        md = sec.report_markdown([a, ok, off, raw], networks=["192.168.1.0/24"], when=0)
        self.assertIn("### cam (192.168.1.9)", md)
        self.assertIn("**Critique** – Redis accessible sans mot de passe (port 6379)", md)
        self.assertIn("À faire :", md)
        self.assertIn("2 appareil(s) analysé(s), 1 avec au moins un constat", md)    # srv et cam ; ni l'absent ni le non-analysé
        self.assertNotIn("absent", md); self.assertNotIn("non-analysé", md); self.assertNotIn("### srv", md)
        self.assertIn("Aucun mot de passe n'a été essayé", md)

    def test_report_without_findings(self):
        self.assertIn("Aucun constat", sec.report_markdown([dict(dev([22]), security=[], online=True)], when=0))


if __name__ == "__main__":
    unittest.main()
