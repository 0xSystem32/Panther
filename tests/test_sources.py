import socket
import threading
import unittest
from unittest import mock

from panther import dhcp, discovery, fingerprint, scanner

ONVIF = (b'<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><d:ProbeMatches><d:ProbeMatch>'
         b'<d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types>'
         b'<d:Scopes>onvif://www.onvif.org/name/Hikvision onvif://www.onvif.org/hardware/DS-2CD2043G0-I onvif://www.onvif.org/location/country/fr</d:Scopes>'
         b'<d:XAddrs>http://192.168.20.10/onvif/device_service</d:XAddrs></d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>')
WINDOWS = b"<Envelope><Body><ProbeMatches><ProbeMatch><wsd:Types>wsdp:Device pub:Computer</wsd:Types><wsd:XAddrs>http://10.0.0.5:5357/uuid</wsd:XAddrs></ProbeMatch></ProbeMatches></Body></Envelope>"
PRINTER = b"<e><d:Types>wsdp:Device wprt:PrintDeviceType</d:Types><d:XAddrs>http://192.168.1.40:80/WSD</d:XAddrs></e>"


def nbstat(names):
    """Paquet de réponse NBSTAT : 56 octets d'en-tête, nombre de noms, puis (nom 15 + suffixe + 2 octets de drapeaux)."""
    out = b"\x00" * 56 + bytes([len(names)])
    for name, suffix, group in names:
        out += name.ljust(15).encode() + bytes([suffix, 0x80 if group else 0x04, 0x00])
    return out


class WsdParsingTests(unittest.TestCase):
    def test_onvif_camera_gives_type_name_and_model(self):
        w = discovery.parse_wsd(ONVIF)
        self.assertEqual(w["types"], ["NetworkVideoTransmitter", "Device"])
        self.assertEqual((w["name"], w["hardware"]), ("Hikvision", "DS-2CD2043G0-I"))
        self.assertEqual(w["xaddrs"], ["http://192.168.20.10/onvif/device_service"])

    def test_windows_computer_and_printer(self):
        self.assertEqual(discovery.parse_wsd(WINDOWS)["types"], ["Device", "Computer"])
        self.assertEqual(discovery.parse_wsd(PRINTER)["types"], ["Device", "PrintDeviceType"])

    def test_garbage_empty_and_oversized_input(self):
        for bad in (b"", b"\xff\xfe\x00", b"<html>rien</html>", b"<Types></Types>"):
            self.assertEqual(discovery.parse_wsd(bad), {})
        big = b"<Types>" + b" ".join(b"t%d" % i for i in range(500)) + b"</Types>"
        self.assertEqual(len(discovery.parse_wsd(big)["types"]), 20)                 # bornes : un appareil ne peut pas gonfler la mémoire

    def test_percent_encoded_scope_is_decoded(self):
        w = discovery.parse_wsd(b"<Types>x</Types><Scopes>onvif://www.onvif.org/name/Ma%20Cam</Scopes>")
        self.assertEqual(w["name"], "Ma Cam")


class WsdScanTests(unittest.TestCase):
    def test_full_exchange_over_udp(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); srv.bind(("127.0.0.1", 0)); srv.settimeout(3)
        got = []
        def answer():
            data, addr = srv.recvfrom(65535)
            got.append(data); srv.sendto(ONVIF, addr)
        threading.Thread(target=answer, daemon=True).start()
        with mock.patch.object(discovery, "WSD_ADDR", srv.getsockname()):
            res = discovery.wsd_scan(timeout=1.0)
        srv.close()
        self.assertIn(b"Probe", got[0]); self.assertIn(b"urn:uuid:", got[0])
        self.assertEqual(res["127.0.0.1"]["hardware"], "DS-2CD2043G0-I")

    def test_scan_all_returns_ssdp_mdns_and_wsd(self):
        with mock.patch.object(discovery, "ssdp_scan", lambda *a: {"a": 1}), mock.patch.object(discovery, "mdns_scan", lambda *a: {"b": 2}), \
                mock.patch.object(discovery, "wsd_scan", lambda *a: {"c": 3}):
            self.assertEqual(discovery.scan_all("1.1.1.1", 1, 1), ({"a": 1}, {"b": 2}, {"c": 3}))


class NetbiosTests(unittest.TestCase):
    def test_windows_pc_with_workgroup_and_file_sharing(self):
        info = scanner.parse_nbstat(nbstat([("PC-SALON", 0x00, False), ("WORKGROUP", 0x00, True), ("PC-SALON", 0x20, False)]))
        self.assertEqual(info, {"name": "PC-SALON", "workgroup": "WORKGROUP", "file_server": True})

    def test_device_without_file_sharing(self):
        info = scanner.parse_nbstat(nbstat([("TELE", 0x00, False)]))
        self.assertEqual((info["name"], info["workgroup"], info["file_server"]), ("TELE", "", False))

    def test_truncated_or_absurd_packets_never_crash(self):
        self.assertEqual(scanner.parse_nbstat(b""), {})
        self.assertEqual(scanner.parse_nbstat(b"\x00" * 56), {})
        pkt = b"\x00" * 56 + bytes([200]) + b"AB" * 10                              # annonce 200 noms, n'en contient pas
        self.assertEqual(scanner.parse_nbstat(pkt)["name"], "")
        scanner.parse_nbstat(bytes(range(256)) * 3)


class DhcpTests(unittest.TestCase):
    def test_dnsmasq_leases(self):
        text = ("1760000000 aa:bb:cc:00:00:01 192.168.1.50 salon-tv 01:aa:bb:cc:00:00:01\n"
                "1760000001 aa:bb:cc:00:00:02 192.168.1.51 * *\n"                          # pas de nom
                "1760000002 AA:BB:CC:00:00:03 192.168.1.52 ipad-de-marie *\n"
                "ligne cassée\n1760000003 zz:zz 192.168.1.53 x *\n"
                "1760000004 aa:bb:cc:00:00:04 192.168.1.54 <script>alert(1)</script> *\n")
        self.assertEqual(dhcp.parse_dnsmasq(text), {"aa:bb:cc:00:00:01": "salon-tv", "aa:bb:cc:00:00:03": "ipad-de-marie"})

    def test_isc_leases_last_one_wins(self):
        text = ('lease 192.168.1.60 {\n  hardware ethernet aa:bb:cc:00:00:09;\n  client-hostname "ancien";\n}\n'
                'lease 192.168.1.61 {\n  hardware ethernet aa:bb:cc:00:00:09;\n  client-hostname "recent";\n}\n'
                'lease 192.168.1.62 {\n  hardware ethernet aa:bb:cc:00:00:0a;\n}\n')
        self.assertEqual(dhcp.parse_isc(text), {"aa:bb:cc:00:00:09": "recent"})

    def test_read_leases_ignores_missing_files_and_picks_the_right_format(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            a, b = os.path.join(d, "dnsmasq.leases"), os.path.join(d, "dhcpd.leases")
            with open(a, "w") as f:
                f.write("1 aa:bb:cc:00:00:01 1.1.1.1 un *\n")
            with open(b, "w") as f:
                f.write('lease 1.1.1.2 {\n hardware ethernet aa:bb:cc:00:00:02;\n client-hostname "deux";\n}\n')
            self.assertEqual(dhcp.read_leases((os.path.join(d, "absent"), a, b)), {"aa:bb:cc:00:00:01": "un", "aa:bb:cc:00:00:02": "deux"})
        self.assertEqual(dhcp.read_leases(("/nonexistent/x",)), {})


def dev(**kw):
    d = {"ip": "1.1.1.1", "mac": "", "hostname": "x", "vendor": "", "os": "", "ports": [], "banners": {}, "ssdp": {}, "mdns_services": [],
         "mdns_txt": {}, "mdns_names": [], "is_gateway": False, "is_self": False, "random_mac": False}
    d.update(kw)
    return d


class EvidenceTests(unittest.TestCase):
    def test_onvif_camera_is_identified_and_its_model_feeds_the_text(self):
        d = dev(wsd=discovery.parse_wsd(ONVIF))
        kind, conf, why = fingerprint.classify_detail(d)
        self.assertEqual(kind, "camera")
        self.assertIn("WS-Discovery : caméra ONVIF", why)
        self.assertIn("ds-2cd2043g0-i", fingerprint._model_text(d))

    def test_wsd_printer_and_computer(self):
        self.assertEqual(fingerprint.classify_detail(dev(wsd=discovery.parse_wsd(PRINTER)))[0], "printer")
        self.assertEqual(fingerprint.classify_detail(dev(wsd=discovery.parse_wsd(WINDOWS)))[0], "desktop")

    def test_netbios_workgroup_is_a_weak_desktop_hint_not_a_verdict(self):
        k, conf, _ = fingerprint.classify_detail(dev(netbios={"workgroup": "WORKGROUP", "file_server": True}))
        self.assertEqual((k, conf), ("desktop", 20))
        self.assertEqual(fingerprint.classify_detail(dev(ports=[9100], netbios={"workgroup": "W"}))[0], "printer")   # un indice fort l'emporte

    def test_http_title_helps_but_weighs_like_a_name(self):
        k, conf, _ = fingerprint.classify_detail(dev(http_info="Synology DiskStation | Connexion"))
        self.assertEqual(k, "nas")
        self.assertLess(conf, 50)


class InspectIntegrationTests(unittest.TestCase):
    def inspect(self, extra, mac="aa:bb:cc:00:00:01", names=("", "", "")):
        sc = scanner.Scanner(); sc.overrides = {}
        net = {"iface": "eth0", "ip": "192.168.1.13", "cidr": "192.168.1.0/24", "gateway": "192.168.1.1"}
        patches = [mock.patch.object(scanner, "scan_ports", lambda i, p, t: [80]), mock.patch.object(scanner, "grab_banner", lambda i, p: "Boa/0.94 | Login"),
                   mock.patch.object(scanner, "resolve_names", lambda i, t=1.5: names), mock.patch.object(scanner, "ping_ttl", lambda i: 64)]
        for p in patches:
            p.start()
        try:
            return sc._inspect("192.168.1.50", net, {"192.168.1.50": mac}, {"mdns": {}, "ssdp": {}, **extra})
        finally:
            for p in patches:
                p.stop()

    def test_wsd_model_vendor_and_type_reach_the_device(self):
        d = self.inspect({"wsd": {"192.168.1.50": discovery.parse_wsd(ONVIF)}})
        self.assertEqual((d["type"], d["model"], d["vendor"]), ("camera", "DS-2CD2043G0-I", "Hikvision"))
        self.assertIn("Boa", d["http_info"])

    def test_dhcp_lease_is_the_last_resort_name(self):
        d = self.inspect({"leases": {"aa:bb:cc:00:00:01": "salon-tv"}})
        self.assertEqual(d["hostname"], "salon-tv")

    def test_a_real_name_wins_over_the_lease(self):
        d = self.inspect({"leases": {"aa:bb:cc:00:00:01": "salon-tv"}}, names=("vrai-nom", "", ""))
        self.assertEqual(d["hostname"], "vrai-nom")

    def test_netbios_info_is_attached_and_consumed(self):
        scanner._nb_info["192.168.1.50"] = {"name": "PC", "workgroup": "WORKGROUP", "file_server": True}
        d = self.inspect({})
        self.assertEqual(d["netbios"]["workgroup"], "WORKGROUP")
        self.assertNotIn("192.168.1.50", scanner._nb_info)                              # pas de fuite mémoire d'un scan à l'autre


if __name__ == "__main__":
    unittest.main()
