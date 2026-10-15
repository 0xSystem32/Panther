import csv
import io
import json
import time
import unittest

from panther import exporter, security


def dev(**kw):
    d = {"ip": "192.168.1.10", "hostname": "salon-tv", "type": "tv", "mac": "aa:bb:cc:00:00:01", "vendor": "Samsung", "os": "Android", "model_name": "Samsung TV",
         "model": "UE55", "network": "192.168.1.0/24", "vlan": None, "online": True, "trusted": True, "group": "Salon", "tags": ["enfants", "domotique"],
         "note": "Sur le meuble", "first_seen": 1_700_000_000, "ports": [8009, 8060], "services": ["Cast", "Roku"], "confidence": 85,
         "reasons": ["annonce mDNS", "fabricant"], "security": None, "cert": {}}
    d.update(kw)
    return d


class RowTests(unittest.TestCase):
    def test_every_documented_column_is_filled(self):
        r = exporter.row(dev())
        self.assertEqual([k for k, _ in exporter.COLUMNS], list(r))
        self.assertEqual((r["name"], r["type"], r["model"], r["group"], r["tags"], r["note"]), ("salon-tv", "TV / multimédia", "Samsung TV", "Salon", "enfants, domotique", "Sur le meuble"))
        self.assertEqual((r["ports"], r["services"], r["status"], r["last_seen"]), ("8009 8060", "Cast, Roku", "En ligne", "en ligne"))
        self.assertRegex(r["first_seen"], r"^\d{4}-\d\d-\d\d \d\d:\d\d$")

    def test_status_and_last_seen(self):
        self.assertEqual(exporter.row(dev(new=True))["status"], "Nouveau")
        off = exporter.row(dev(online=False, last_seen=1_700_000_000))
        self.assertEqual(off["status"], "Hors ligne")
        self.assertRegex(off["last_seen"], r"^\d{4}-")

    def test_exposure_distinguishes_not_analysed_from_clean_from_findings(self):
        self.assertEqual(exporter.row(dev(security=None))["exposure"], "")
        self.assertEqual(exporter.row(dev(security=[]))["exposure"], "aucun")
        f = security.analyze({"ip": "1.1.1.1", "type": "camera", "ports": [23, 554], "banners": {}, "ssdp": {}}, {554: "open"})
        r = exporter.row(dev(security=f))
        self.assertEqual(r["exposure"], "Élevé")
        self.assertIn("Telnet activé", r["findings"])

    def test_certificate_summary(self):
        r = exporter.row(dev(cert={"cn": "DiskStation", "o": "Synology", "self_signed": True, "not_after": "2039-12-19", "expired": False}))
        self.assertEqual(r["cert"], "DiskStation · auto-signé · expire le 2039-12-19")
        self.assertIn("expiré", exporter.row(dev(cert={"cn": "x", "issuer": "Ma CA", "expired": True, "not_after": "2020-01-01"}))["cert"])
        self.assertEqual(exporter.row(dev(cert={}))["cert"], "")

    def test_missing_optional_fields_do_not_crash(self):
        exporter.row({"ip": "1.1.1.1"})
        exporter.row({})

    def test_rows_are_sorted_by_ip_numerically_and_skip_virtual_nodes(self):
        r = exporter.rows([dev(ip="192.168.1.100"), dev(ip="192.168.1.9"), {"ip": "", "hostname": "Internet", "type": "internet", "virtual": True}])
        self.assertEqual([x["ip"] for x in r], ["192.168.1.9", "192.168.1.100"])


class CsvTests(unittest.TestCase):
    def parse(self, text):
        return list(csv.reader(io.StringIO(text, newline="")))

    def test_header_and_values_roundtrip(self):
        rows = self.parse(exporter.to_csv([dev()]))
        self.assertEqual(rows[0][:3], ["Adresse IP", "Nom", "Type"])
        self.assertEqual(rows[1][0], "192.168.1.10")
        self.assertEqual(len(rows[1]), len(exporter.COLUMNS))
        self.assertEqual(rows[1][exporter.COLUMNS.index(("trusted", "De confiance"))], "oui")

    def test_formula_injection_from_a_hostile_device_name_is_neutralised(self):
        for evil in ("=HYPERLINK(\"http://x\",\"c\")", "+1+1", "-2+3", "@SUM(A1)", "\t=1", "\r=1"):
            cell = self.parse(exporter.to_csv([dev(hostname=evil)]))[1][1]
            self.assertTrue(cell.startswith("'"), repr(evil))                      # un tableur l'affichera comme du texte
        self.assertEqual(self.parse(exporter.to_csv([dev(hostname="tv-salon")]))[1][1], "tv-salon")

    def test_commas_quotes_and_newlines_stay_in_their_cell(self):
        rows = self.parse(exporter.to_csv([dev(note='a, "b"\nc', hostname="x,y")]))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1][1], "x,y")
        self.assertEqual(rows[1][exporter.COLUMNS.index(("note", "Notes"))], 'a, "b"\nc')

    def test_empty_list_gives_only_the_header(self):
        self.assertEqual(len(self.parse(exporter.to_csv([]))), 1)

    def test_csv_safe(self):
        self.assertEqual((exporter.csv_safe(True), exporter.csv_safe(False), exporter.csv_safe(None), exporter.csv_safe(42)), ("oui", "non", "", "42"))
        self.assertEqual(exporter.csv_safe("normal"), "normal")


class JsonTests(unittest.TestCase):
    def test_structure_and_unicode(self):
        data = json.loads(exporter.to_json([dev(hostname="Télé de Marie")], ["192.168.1.0/24"]))
        self.assertEqual(data["networks"], ["192.168.1.0/24"])
        self.assertEqual(data["devices"][0]["name"], "Télé de Marie")
        self.assertIn("T", data["generated"])
        self.assertIs(data["devices"][0]["trusted"], True)

    def test_internal_fields_are_not_leaked(self):
        d = json.loads(exporter.to_json([dev(banners={"80": "x"}, mdns_txt={"k": "v"}, ssdp={"server": "s"}, key="aa:bb")]))["devices"][0]
        for internal in ("banners", "mdns_txt", "ssdp", "key", "random_mac"):
            self.assertNotIn(internal, d)


if __name__ == "__main__":
    unittest.main()
