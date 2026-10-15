import struct
import unittest

from panther import discovery, fingerprint


def dev(**kw):
    base = dict(ip="192.168.1.50", ports=[], vendor="", hostname="", os="Inconnu", is_gateway=False,
                is_self=False, random_mac=False, mdns_services=[], mdns_names=[], mdns_txt={}, ssdp={})
    base.update(kw)
    return base


class ClassifyTests(unittest.TestCase):
    def kind(self, **kw):
        return fingerprint.classify_detail(dev(**kw))[0]

    def test_printer_from_mdns_and_port(self):
        self.assertEqual(self.kind(ports=[9100], mdns_services=["_ipp._tcp"], vendor="HP"), "printer")

    def test_printer_from_hostname_only(self):
        self.assertEqual(self.kind(hostname="MFC-L2710DW"), "printer")

    def test_iphone_from_model(self):
        self.assertEqual(self.kind(mdns_txt={"model": "iPhone14,2"}, random_mac=True), "phone")

    def test_ipad_is_tablet(self):
        self.assertEqual(self.kind(hostname="ipad-de-marie", random_mac=True), "tablet")

    def test_chromecast_tv(self):
        self.assertEqual(self.kind(ports=[8009], mdns_services=["_googlecast._tcp"]), "tv")

    def test_tv_from_hostname_suffix_and_vewd(self):
        self.assertEqual(self.kind(hostname="salontv", ssdp={"model": "Vewd"}), "tv")

    def test_vestel_vendor_name_with_suffix(self):
        self.assertEqual(self.kind(vendor="Vestel Elektronik San ve Tic. A.S", hostname="x"), "tv")

    def test_switch_from_snmp_or_lldp_hint_but_not_the_gateway(self):
        self.assertEqual(self.kind(is_switch=True, vendor="Cisco"), "switch")
        self.assertEqual(self.kind(is_switch=True, is_gateway=True), "router")

    def test_switch_by_name_but_nintendo_switch_is_a_console(self):
        self.assertEqual(self.kind(hostname="sw-salon"), "switch")
        self.assertEqual(self.kind(hostname="Nintendo-Switch"), "console")

    def test_roku_tv(self):
        self.assertEqual(self.kind(ports=[8060], vendor="Roku"), "tv")

    def test_gateway_is_router(self):
        self.assertEqual(self.kind(is_gateway=True, ports=[80, 443]), "router")

    def test_camera_rtsp(self):
        self.assertEqual(self.kind(ports=[554], vendor="Hikvision"), "camera")

    def test_console(self):
        self.assertEqual(self.kind(hostname="PS5-4821"), "console")

    def test_nas(self):
        self.assertEqual(self.kind(vendor="Synology", ports=[5000, 445]), "nas")

    def test_unknown_when_no_evidence(self):
        kind, conf, _ = fingerprint.classify_detail(dev())
        self.assertEqual((kind, conf), ("unknown", 0))

    def test_reasons_explain_choice(self):
        _, conf, why = fingerprint.classify_detail(dev(ports=[9100], mdns_services=["_ipp._tcp"]))
        self.assertGreaterEqual(conf, 70)
        self.assertTrue(any("_ipp" in r for r in why))

    def test_self_uses_self_kind(self):
        self.assertEqual(self.kind(is_self=True, self_kind="laptop"), "laptop")


def _name(n):
    return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\x00"


def _rr(name, rtype, rdata):
    return _name(name) + struct.pack(">HHIH", rtype, 1, 120, len(rdata)) + rdata


class MdnsParserTests(unittest.TestCase):
    def test_parse_ptr_srv_txt(self):
        txt = b"".join(bytes([len(x)]) + x for x in (b"ty=HP OfficeJet 3830", b"model=OfficeJet"))
        pkt = struct.pack(">HHHHHH", 0, 0x8400, 0, 3, 0, 0)
        pkt += _rr("_ipp._tcp.local", 12, _name("Bureau._ipp._tcp.local"))
        pkt += _rr("Bureau._ipp._tcp.local", 33, struct.pack(">HHH", 0, 0, 631) + _name("hp-printer.local"))
        pkt += _rr("Bureau._ipp._tcp.local", 16, txt)
        info = discovery.collect_mdns([("192.168.1.40", pkt)])["192.168.1.40"]
        self.assertIn("_ipp._tcp", info["services"])
        self.assertIn("Bureau", info["names"])
        self.assertEqual(info["host"], "hp-printer")
        self.assertEqual(info["txt"]["ty"], "HP OfficeJet 3830")

    def test_garbage_does_not_crash(self):
        self.assertEqual(discovery.parse_dns(b"\xff" * 40), [])
        self.assertEqual(discovery.parse_dns(b""), [])

    def test_compression_loop_is_rejected(self):
        pkt = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + b"\xc0\x0c" + b"\x00\x0c\x00\x01"
        self.assertEqual(discovery.parse_dns(pkt), [])


if __name__ == "__main__":
    unittest.main()


class VendorTests(unittest.TestCase):
    def test_canonical_names(self):
        c = fingerprint.canonical_vendor
        self.assertEqual(c("Apple, Inc."), "Apple")
        self.assertEqual(c("HP Inc."), "HP")
        self.assertEqual(c("Hewlett Packard"), "HP")
        self.assertEqual(c("Brother Industries, LTD."), "Brother")
        self.assertEqual(c("Sony Interactive Entertainment Inc."), "Sony (PlayStation)")
        self.assertEqual(c("TP-LINK TECHNOLOGIES CO.,LTD."), "TP-Link")
        self.assertEqual(c("Some Obscure Company Ltd"), "Some Obscure")

    def test_shorten_vendor(self):
        s = fingerprint.shorten_vendor
        self.assertEqual(s("Vestel Elektronik San ve Tic. A.S"), "Vestel")
        self.assertEqual(s("Sagemcom Broadband SAS"), "Sagemcom")
        self.assertEqual(s("AzureWave Technology"), "AzureWave")
        self.assertEqual(s("Arcadyan"), "Arcadyan")
        self.assertEqual(s("Technology"), "Technology")  # jamais de nom vide
        self.assertEqual(s(""), "")

    def test_conversion_from_ieee_csv(self):
        import importlib.util
        import os
        spec = importlib.util.spec_from_file_location("upd", os.path.join(os.path.dirname(__file__), "..", "tools", "update_oui.py"))
        upd = importlib.util.module_from_spec(spec); spec.loader.exec_module(upd)
        text = ("Registry,Assignment,Organization Name,Organization Address\n"
                "MA-L,001BA9,Brother industries, LTD.,Nagoya\n".replace("Brother industries, LTD.", '"Brother industries, LTD."')
                + "MA-L,BADROW,Nope,x\nMA-L,3C0754,\"Apple, Inc.\",Cupertino\n")
        self.assertEqual(upd.convert(text), {"001BA9": "Brother", "3C0754": "Apple"})
