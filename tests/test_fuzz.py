"""Fuzz déterministe des analyseurs de données non fiables (réseau) : octets aléatoires et mutations d'exemples valides.

Un analyseur peut refuser une entrée (valeur vide, exception documentée), jamais planter autrement ni boucler : chaque appel doit
rendre la main vite. La graine est fixe, donc un échec se rejoue à l'identique.
"""
import random
import shutil
import struct
import tempfile
import time
import unittest

from panther import certs, dhcp, discovery, scanner, snmp, snmpv3, topology
from tests import test_certs, test_sources, test_topology

ONVIF, nbstat = test_sources.ONVIF, test_sources.nbstat
SRC, lldp_tlv = test_topology.SRC, test_topology.lldp_tlv
make_cert = test_certs.make_cert

SEED, ROUNDS, BUDGET = 20261015, 400, 0.5


def mutations(rng, sample, rounds=ROUNDS):
    """Exemples dérivés : tronqués, octets changés, insérés, supprimés, longueurs extrêmes, bruit pur."""
    yield b""
    yield sample
    for i in range(len(sample)):
        yield sample[:i]                                                    # toutes les troncatures
    for _ in range(rounds):
        b = bytearray(sample)
        for _ in range(rng.randint(1, 6)):
            op = rng.choice(("flip", "set", "ins", "del", "ff", "zero"))
            if not b:
                break
            i = rng.randrange(len(b))
            if op == "flip":
                b[i] ^= 1 << rng.randrange(8)
            elif op == "set":
                b[i] = rng.randrange(256)
            elif op == "ins":
                b.insert(i, rng.randrange(256))
            elif op == "del":
                del b[i]
            elif op == "ff":
                b[i] = 0xFF                                                   # longueur « énorme »
            else:
                b[i] = 0
        yield bytes(b)
    for _ in range(rounds // 4):
        yield rng.randbytes(rng.randint(0, 400))


def dns_sample():
    def name(*labels):
        return b"".join(bytes([len(x)]) + x.encode() for x in labels) + b"\x00"
    q = struct.pack(">HHHHHH", 0, 0x8400, 0, 3, 0, 0)
    ptr = name("_ipp", "_tcp", "local") + struct.pack(">HHIH", 12, 1, 120, len(name("imprimante", "_ipp", "_tcp", "local"))) + name("imprimante", "_ipp", "_tcp", "local")
    txt_data = bytes([9]) + b"ty=HP-123" + bytes([7]) + b"rp=ipp/"
    txt = name("imprimante", "local") + struct.pack(">HHIH", 16, 1, 120, len(txt_data)) + txt_data
    srv_data = struct.pack(">HHH", 0, 0, 631) + name("imprimante", "local")
    srv = name("imprimante", "_ipp", "_tcp", "local") + struct.pack(">HHIH", 33, 1, 120, len(srv_data)) + srv_data
    return q + ptr + txt + srv


class FuzzTests(unittest.TestCase):
    def run_all(self, fn, sample, allowed=(), name=""):
        rng = random.Random(SEED)
        n = 0
        for data in mutations(rng, sample):
            t0 = time.perf_counter()
            try:
                fn(data)
            except allowed:
                pass
            except Exception as e:
                self.fail(f"{name} a levé {type(e).__name__}: {e} sur {data[:60].hex()}…")
            self.assertLess(time.perf_counter() - t0, BUDGET, f"{name} trop lent sur {data[:40].hex()}…")
            n += 1
        self.assertGreater(n, 400)

    def test_snmp_message_parser(self):
        sample = snmp.build_request(0xA2, "public", 7, ["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.4.22.1.2.1.192.168.1.1"])
        self.run_all(snmp.parse_message, sample, (snmp.SnmpError,), "snmp.parse_message")

    def test_snmp_tlv_walker(self):
        self.run_all(lambda d: snmp.parse_tlv(d, 0), snmp.build_request(0xA0, "c", 1, ["1.3.6.1.2.1.1.1.0"]), (snmp.SnmpError,), "snmp.parse_tlv")

    def test_snmp_v3_message_parser(self):
        key = snmpv3.localize(snmpv3.password_to_key("motdepasse-long", "sha1"), b"\x80\x00\x1f\x88\x01", "sha1")
        user = snmpv3.V3User("lecteur", "motdepasse-long", "sha1")
        sample = snmpv3.build_request(user, key, (b"\x80\x00\x1f\x88\x01", 3, 1000), 5, snmp.GET, 6, ["1.3.6.1.2.1.1.5.0"])
        self.run_all(snmpv3.parse_message, sample, (snmp.SnmpError,), "snmpv3.parse_message")
        self.run_all(snmpv3.parse_message, snmpv3.build_discovery(1, 2), (snmp.SnmpError,), "snmpv3.parse_message (découverte)")

    def test_tls_certificate_extraction(self):
        flight = b"\x16\x03\x03\x00\x0e" + b"\x0b\x00\x00\x0a\x00\x00\x07\x00\x00\x04\x30\x02\x05\x00"
        self.run_all(scanner.tls_certificate_in, flight, (), "scanner.tls_certificate_in")

    def test_lldp_and_cdp_frames(self):
        frame = test_topology.LldpTests().frame()
        self.run_all(topology.parse_frame, frame, (), "topology.parse_frame (LLDP)")
        cdp = bytes([2, 180, 0, 0]) + struct.pack(">HH", 1, 4 + 7) + b"core-sw" + struct.pack(">HH", 3, 4 + 6) + b"Gi1/0/3"
        cdp_frame = topology.CDP_DST + SRC + struct.pack(">H", len(cdp)) + cdp
        self.run_all(topology.parse_frame, cdp_frame, (), "topology.parse_frame (CDP)")
        self.run_all(topology.parse_lldp, lldp_tlv(5, b"core-sw") + lldp_tlv(0, b""), (), "topology.parse_lldp")

    def test_dns_wire_format(self):
        self.run_all(discovery.parse_dns, dns_sample(), (), "discovery.parse_dns")

    def test_ssdp_headers_and_wsd_xml(self):
        self.run_all(discovery._parse_ssdp, b"HTTP/1.1 200 OK\r\nSERVER: Linux UPnP/1.0\r\nLOCATION: http://10.0.0.2:80/d.xml\r\nST: upnp:rootdevice\r\n\r\n",
                     (), "discovery._parse_ssdp")
        self.run_all(discovery.parse_wsd, ONVIF if isinstance(ONVIF, bytes) else ONVIF.encode(), (), "discovery.parse_wsd")

    def test_netbios_node_status(self):
        self.run_all(scanner.parse_nbstat, nbstat([("SALON", 0x00, False), ("WORKGROUP", 0x00, True), ("SALON", 0x20, False)]), (), "scanner.parse_nbstat")

    def test_http_summary_on_hostile_text(self):
        rng = random.Random(SEED)
        head = "HTTP/1.1 401 Unauthorized\r\nServer: Boa/0.94\r\nWWW-Authenticate: Basic realm=\"DS-2CD2043\"\r\n\r\n"
        body = "<html><head><title>Login</title></head></html>"
        for _ in range(300):
            h = "".join(rng.choice(head + "\x00<>\"' \r\n") for _ in range(rng.randint(0, 300)))
            b = "".join(rng.choice(body + "\x00\r\n") for _ in range(rng.randint(0, 300)))
            t0 = time.perf_counter()
            self.assertIsInstance(scanner.http_summary(h, b), str)
            self.assertLess(time.perf_counter() - t0, BUDGET)
        t0 = time.perf_counter()                                              # motifs à backtracking : entrées longues et répétitives
        scanner.http_summary("Server:" + " " * 50000 + "\r\n" + "WWW-Authenticate: realm=" + '"' * 20000, "<title" + ">" * 20000 + "</title" * 5000)
        self.assertLess(time.perf_counter() - t0, 2.0)

    def test_dhcp_lease_files(self):
        leases = "1700000000 aa:bb:cc:00:00:01 192.168.1.20 salon *\n1700000001 aa:bb:cc:00:00:02 192.168.1.21 * *\n"
        isc = 'lease 192.168.1.5 {\n  hardware ethernet aa:bb:cc:00:00:03;\n  client-hostname "tv";\n}\n'
        self.run_all(lambda d: dhcp.parse_dnsmasq(d.decode("latin-1")), leases.encode(), (), "dhcp.parse_dnsmasq")
        self.run_all(lambda d: dhcp.parse_isc(d.decode("latin-1")), isc.encode(), (), "dhcp.parse_isc")

    @unittest.skipUnless(shutil.which("openssl"), "openssl absent")
    def test_certificate_der(self):
        with tempfile.TemporaryDirectory() as d:
            _key, _crt, der = make_cert(d, "x", "/CN=camera.lan/O=Hikvision", san="DNS:camera.lan")
        self.run_all(certs.parse_cert, der, (), "certs.parse_cert")


if __name__ == "__main__":
    unittest.main()
