"""Certificat lu dans la première réponse d'un serveur TLS qui refuse la poignée de main (certificat client exigé)."""
import shutil
import socket
import ssl
import struct
import tempfile
import threading
import unittest

from panther import scanner
from tests import test_certs


def record(rtype, payload):
    return bytes([rtype]) + b"\x03\x03" + struct.pack(">H", len(payload)) + payload


def handshake(mtype, body):
    return bytes([mtype]) + len(body).to_bytes(3, "big") + body


def certificate_message(der):
    chain = len(der).to_bytes(3, "big") + der
    return handshake(11, len(chain).to_bytes(3, "big") + chain)


class StreamParsingTests(unittest.TestCase):
    DER = b"\x30\x82\x01\x00" + b"\xAA" * 256

    def test_extracts_the_first_certificate_among_other_messages(self):
        flight = record(22, handshake(2, b"\x03\x03" + b"\x00" * 40)) + record(22, certificate_message(self.DER) + handshake(14, b""))
        self.assertEqual(scanner.tls_certificate_in(flight), self.DER)

    def test_certificate_split_over_two_records_and_incomplete_streams(self):
        msg = certificate_message(self.DER)
        two = record(22, msg[:100]) + record(22, msg[100:])
        self.assertEqual(scanner.tls_certificate_in(two), self.DER)
        self.assertIsNone(scanner.tls_certificate_in(record(22, msg[:100])))                 # pas encore tout reçu
        self.assertIsNone(scanner.tls_certificate_in(two[:-1]))
        self.assertIsNone(scanner.tls_certificate_in(b""))

    def test_hostile_lengths_never_crash(self):
        bad = [record(22, handshake(11, b"\x00\x00\x00")), record(22, handshake(11, b"\x00\xff\xff\xff\xff\xff" + b"x")),
               record(22, handshake(11, b"\x00\x00\x00\x00\x00\x00")), record(23, b"\x00" * 10), b"\x16\x03\x03\xff\xff" + b"\x00" * 20,
               record(22, b"\x0b\xff\xff\xff")]
        for stream in bad:
            self.assertIsNone(scanner.tls_certificate_in(stream), stream[:12])


@unittest.skipUnless(shutil.which("openssl"), "openssl absent")
class ClientCertRequiredTests(unittest.TestCase):
    """Un serveur qui exige un certificat client : la poignée de main normale échoue, le certificat du serveur reste lisible."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        key, crt, _der = test_certs.make_cert(self.tmp.name, "stb", "/C=FR/O=Orange/CN=AABBCC-stbste-1", days=30)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(crt)
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        self.srv = socket.socket(); self.srv.bind(("127.0.0.1", 0)); self.srv.listen(5)
        self.port = self.srv.getsockname()[1]
        self.stop = False

        def serve():
            self.srv.settimeout(0.2)
            while not self.stop:
                try:
                    c, _ = self.srv.accept()
                except OSError:
                    continue
                try:
                    ctx.wrap_socket(c, server_side=True)       # échoue : pas de certificat client
                except (OSError, ssl.SSLError):
                    pass
                finally:
                    c.close()
        self.th = threading.Thread(target=serve, daemon=True); self.th.start()

    def tearDown(self):
        self.stop = True; self.th.join(2); self.srv.close(); self.tmp.cleanup()

    def test_certificate_is_still_read_and_summarised(self):
        scanner._cert_cache.clear()
        self.assertEqual(scanner.grab_banner("127.0.0.1", self.port, timeout=3), "")
        # le port d'essai n'est pas un port TLS connu : on appelle directement la lecture
        der = scanner.peek_certificate("127.0.0.1", self.port, timeout=3)
        self.assertIsNotNone(der)
        info = scanner.certs.summary(scanner.certs.parse_cert(der))
        self.assertEqual((info["cn"], info["o"]), ("AABBCC-stbste-1", "Orange"))

    def test_grab_banner_on_a_tls_port_uses_the_fallback(self):
        scanner._cert_cache.clear()
        old = scanner.TLS_PORTS
        scanner.TLS_PORTS = old + (self.port,)
        try:
            self.assertEqual(scanner.grab_banner("127.0.0.1", self.port, timeout=3), "")
        finally:
            scanner.TLS_PORTS = old
        self.assertEqual(scanner._cert_cache[("127.0.0.1", self.port)]["cn"], "AABBCC-stbste-1")

    def test_closed_port_and_silent_server_return_none(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); free = s.getsockname()[1]; s.close()
        self.assertIsNone(scanner.peek_certificate("127.0.0.1", free, timeout=0.5))
        mute = socket.socket(); mute.bind(("127.0.0.1", 0)); mute.listen(1)
        try:
            self.assertIsNone(scanner.peek_certificate("127.0.0.1", mute.getsockname()[1], timeout=0.5))
        finally:
            mute.close()


class SetTopBoxClassificationTests(unittest.TestCase):
    def test_operator_set_top_box_certificate_means_tv(self):
        from panther import fingerprint
        dev = {"ip": "192.168.1.12", "ports": [8080, 8443], "vendor": "Sagemcom", "hostname": "", "mdns_services": [], "banners": {}, "os": "",
               "cert": {"cn": "AABBCC-stbste-12345678", "o": "Orange", "indicators": "Orange AABBCC-stbste-12345678"}}
        kind, conf, why = fingerprint.classify_detail(dev)
        self.assertEqual(kind, "tv")
        self.assertTrue(any("stb" in r for r in why))


if __name__ == "__main__":
    unittest.main()
