import json
import os
import random
import shutil
import ssl
import subprocess
import tempfile
import unittest
from unittest import mock

from panther import certs, fingerprint, rules, scanner, security, snmp
from tests.test_http_banner import Handler, serve

HAS_OPENSSL = shutil.which("openssl") is not None


def openssl(*args, cwd=None):
    subprocess.run(["openssl", *args], check=True, capture_output=True, cwd=cwd)


def make_cert(d, name, subj, san=None, ca=None, days=30, utf8=False):
    """Génère `name`.pem / `name`.key dans d ; auto-signé, ou signé par `ca` (nom d'un certificat déjà créé)."""
    key, crt = os.path.join(d, name + ".key"), os.path.join(d, name + ".pem")
    ext = ["-addext", "subjectAltName=" + ",".join("DNS:" + s for s in san)] if san else []
    if ca is None:
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-days", str(days), "-subj", subj, *(["-utf8"] if utf8 else []), *ext)
    else:
        csr, extfile = os.path.join(d, name + ".csr"), os.path.join(d, name + ".ext")
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", subj, *(["-utf8"] if utf8 else []))
        with open(extfile, "w") as f:
            f.write("subjectAltName=" + ",".join("DNS:" + s for s in (san or ["x.local"])) + "\n")
        openssl("x509", "-req", "-in", csr, "-CA", os.path.join(d, ca + ".pem"), "-CAkey", os.path.join(d, ca + ".key"), "-CAcreateserial",
                "-out", crt, "-days", str(days), "-extfile", extfile)
    with open(crt) as f:
        return key, crt, ssl.PEM_cert_to_DER_cert(f.read())


@unittest.skipUnless(HAS_OPENSSL, "openssl absent : tests de certificats ignorés")
class RealCertTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = cls.tmp.name
        _, _, cls.nas = make_cert(d, "nas", "/C=FR/O=Synology Inc./OU=NAS/CN=DiskStation", san=["diskstation.local", "localhost"])
        make_cert(d, "ca", "/O=Mon Autorité/CN=Ma CA", days=3650, utf8=True)
        _, _, cls.leaf = make_cert(d, "leaf", "/CN=cam-garage", ca="ca", san=["cam.lan"])
        _, _, cls.utf8 = make_cert(d, "u8", "/O=Café Électrique/CN=caméra du garage", utf8=True)
        _, _, cls.only_o = make_cert(d, "oo", "/O=TP-Link Technologies")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_self_signed_subject_issuer_and_alt_names(self):
        c = certs.parse_cert(self.nas)
        self.assertEqual(c["subject"], {"C": "FR", "O": "Synology Inc.", "OU": "NAS", "CN": "DiskStation"})
        self.assertTrue(c["self_signed"])
        self.assertEqual(c["san"], ["diskstation.local", "localhost"])
        self.assertFalse(c["expired"])
        self.assertRegex(c["not_after"], r"^20\d\d-\d\d-\d\d$")

    def test_expiry_is_judged_against_the_given_time(self):
        far = 4_000_000_000                                                              # an 2096
        self.assertTrue(certs.parse_cert(self.nas, now=far)["expired"])
        self.assertFalse(certs.parse_cert(self.nas, now=1_700_000_000)["expired"])

    def test_certificate_signed_by_an_authority_is_not_self_signed(self):
        c = certs.parse_cert(self.leaf)
        self.assertEqual((c["subject"]["CN"], c["issuer"]["CN"], c["issuer"]["O"]), ("cam-garage", "Ma CA", "Mon Autorité"))
        self.assertFalse(c["self_signed"])
        self.assertEqual(c["san"], ["cam.lan"])

    def test_utf8_names_are_decoded(self):
        c = certs.parse_cert(self.utf8)
        self.assertEqual((c["subject"]["O"], c["subject"]["CN"]), ("Café Électrique", "caméra du garage"))

    def test_indicators_keep_brand_and_drop_noise(self):
        info = certs.parse_cert(self.nas)
        self.assertEqual(certs.indicators(info), "Synology Inc. NAS DiskStation diskstation.local")       # « localhost » écarté
        self.assertIn("Mon Autorité", certs.indicators(certs.parse_cert(self.leaf)))                       # l'émetteur compte s'il n'est pas le sujet
        self.assertNotIn("Synology", certs.indicators(certs.parse_cert(self.leaf)))

    def test_summary_is_json_compatible(self):
        s = certs.summary(certs.parse_cert(self.nas))
        json.dumps(s)
        self.assertEqual((s["cn"], s["o"], s["self_signed"], s["expired"]), ("DiskStation", "Synology Inc.", True, False))
        self.assertEqual(certs.summary({}), {})

    def test_truncated_certificates_never_raise(self):
        for n in range(0, len(self.nas), 7):
            certs.parse_cert(self.nas[:n])

    def test_corrupted_certificates_never_raise(self):
        rnd = random.Random(1234)
        for _ in range(400):
            b = bytearray(self.nas)
            for _ in range(rnd.randint(1, 6)):
                b[rnd.randrange(len(b))] = rnd.randrange(256)
            certs.parse_cert(bytes(b))

    def test_garbage_input(self):
        for bad in (b"", b"\x30", b"\x30\x80", b"\xff" * 50, bytes(range(256)), b"pas un certificat"):
            self.assertEqual(certs.parse_cert(bad), {})


class AsnPiecesTests(unittest.TestCase):
    def name(self, *pairs):
        rdns = b"".join(snmp._tlv(0x31, snmp._tlv(0x30, snmp.enc_oid(oid) + snmp._tlv(tag, val))) for oid, tag, val in pairs)
        return snmp._tlv(0x30, rdns)

    def test_string_types(self):
        n = certs._name(self.name(("2.5.4.3", 0x1E, "Caméra".encode("utf-16-be")), ("2.5.4.10", 0x13, b"Acme"), ("2.5.4.11", 0x14, "Équipe".encode("latin-1"))))
        self.assertEqual(n, {"CN": "Caméra", "O": "Acme", "OU": "Équipe"})

    def test_unknown_string_type_and_unknown_attribute_are_ignored(self):
        self.assertEqual(certs._name(self.name(("2.5.4.3", 0x04, b"octets"), ("2.5.4.99", 0x0C, b"x"))), {})

    def test_control_characters_and_length_are_bounded(self):
        n = certs._name(self.name(("2.5.4.3", 0x0C, b"a\x00\x1b[31m" + b"z" * 500)))
        self.assertNotIn("\x1b", n["CN"]); self.assertNotIn("\x00", n["CN"])
        self.assertLessEqual(len(n["CN"]), 100)

    def test_an_empty_value_does_not_hide_a_later_valid_one(self):
        self.assertEqual(certs._name(self.name(("2.5.4.3", 0x04, b"octets"), ("2.5.4.3", 0x0C, b"valide"))), {"CN": "valide"})

    def test_first_value_of_an_attribute_wins(self):
        self.assertEqual(certs._name(self.name(("2.5.4.3", 0x0C, b"premier"), ("2.5.4.3", 0x0C, b"second")))["CN"], "premier")

    def test_times(self):
        self.assertEqual(certs._time(0x17, b"491231235959Z"), 2524607999)                        # 49 -> 2049 (veille du 1er janvier 2050)
        self.assertEqual(certs._time(0x17, b"500101000000Z"), -631152000 + 0)                      # 50 -> 1950
        self.assertEqual(certs._time(0x18, b"20301231235959Z"), 1924991999)
        for bad in (b"", b"abc", b"2030123123595Z", b"991332250000Z", b"20301231235959"):
            self.assertIsNone(certs._time(0x18 if len(bad) > 13 else 0x17, bad))

    def test_noise_filter(self):
        for noise in ("localhost", "localhost.localdomain", "192.168.1.1", "*", "123e4567-e89b-12d3-a456-426614174000", "fe80::1:2:3:4:5"):
            self.assertTrue(certs._NOISE.match(noise), noise)
        for real in ("DiskStation", "Hikvision", "cam-garage"):
            self.assertFalse(certs._NOISE.match(real), real)


@unittest.skipUnless(HAS_OPENSSL, "openssl absent : tests de certificats ignorés")
class ScannerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.key, self.crt, self.der = make_cert(self.tmp.name, "nas", "/O=Synology Inc./CN=DiskStation")
        self.srv, self.port = serve(type("H", (Handler,), {"page": b"<title>Connexion</title>"}), tls=(self.crt, self.key))
        scanner.TLS_PORTS += (self.port,)
        rules.PATH = os.path.join(self.tmp.name, "rules.json")
        rules._cache.update(path=None, mtime=None, rs=rules.RuleSet())

    def tearDown(self):
        scanner.TLS_PORTS = scanner.TLS_PORTS[:-1]
        self.srv.shutdown(); self.srv.server_close(); self.tmp.cleanup()
        rules._cache.update(path=None, mtime=None, rs=rules.RuleSet())

    def inspect(self, mac=""):
        sc = scanner.Scanner(); sc.overrides = {}
        net = {"iface": "eth0", "ip": "192.168.99.13", "cidr": "192.168.99.0/24", "gateway": "192.168.99.1"}
        patches = [mock.patch.object(scanner, "scan_ports", lambda i, p, t: [self.port]), mock.patch.object(scanner, "resolve_names", lambda i, t=1.5: ("", "", "")),
                   mock.patch.object(scanner, "ping_ttl", lambda i: 64)]
        for p in patches:
            p.start()
        try:
            return sc._inspect("127.0.0.1", net, {"127.0.0.1": mac} if mac else {}, {"mdns": {}, "ssdp": {}})
        finally:
            for p in patches:
                p.stop()

    def test_certificate_is_read_with_the_web_page_and_identifies_the_device(self):
        d = self.inspect()
        self.assertEqual((d["cert"]["cn"], d["cert"]["o"], d["cert"]["self_signed"]), ("DiskStation", "Synology Inc.", True))
        self.assertEqual(d["vendor"], "Synology")                                       # pas de MAC : la marque vient du certificat
        self.assertEqual(d["type"], "nas")
        self.assertTrue(any("nom évocateur" in r or "certificat" in r.lower() or "synology" in r.lower() for r in d["reasons"]))
        self.assertEqual(d["http_info"], "Debut/1.0 | Connexion")

    def test_cert_cache_is_consumed_not_leaked(self):
        self.inspect()
        self.assertEqual([k for k in scanner._cert_cache if k[0] == "127.0.0.1"], [])

    def test_the_oui_vendor_wins_over_the_certificate_brand(self):
        with mock.patch.object(fingerprint, "vendor_of", lambda mac: "Netgear"):
            self.assertEqual(self.inspect(mac="aa:bb:cc:00:00:01")["vendor"], "Netgear")

    def test_rules_can_match_the_certificate(self):
        d = self.inspect()
        r = rules.parse_rule({"name": "c", "type": "server", "match": {"cert": "synology"}})
        self.assertTrue(r.matches(rules._view(d)))
        self.assertFalse(rules.parse_rule({"name": "c", "type": "server", "match": {"cert": "hikvision"}}).matches(rules._view(d)))


class SecurityTests(unittest.TestCase):
    def test_expired_certificate_is_a_low_severity_finding_with_a_readable_title(self):
        d = {"ip": "1.1.1.1", "type": "nas", "ports": [443], "banners": {}, "ssdp": {}, "cert": {"expired": True, "not_after": "2021-03-04"}}
        f = security.analyze(d)
        self.assertEqual([(x["id"], x["severity"]) for x in f], [("tls-expired", "faible")])
        self.assertIn("2021-03-04", f[0]["detail"])
        self.assertEqual(security.title_of("tls-expired"), "Certificat HTTPS expiré")

    def test_valid_self_signed_or_missing_certificates_raise_nothing(self):
        base = {"ip": "1.1.1.1", "type": "nas", "ports": [443], "banners": {}, "ssdp": {}}
        self.assertEqual(security.analyze(dict(base, cert={"expired": False, "self_signed": True})), [])
        self.assertEqual(security.analyze(dict(base)), [])


if __name__ == "__main__":
    unittest.main()
