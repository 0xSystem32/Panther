import importlib.util
import os
import tempfile
import unittest

from panther import reportpdf

HAS_QT = importlib.util.find_spec("PyQt6") is not None


def dev(ip, name, **kw):
    d = {"ip": ip, "mac": "aa:bb:cc:dd:ee:ff", "hostname": name, "vendor": "V", "type": "tv", "os": "Linux", "online": True, "ports": [],
         "network": "192.168.1.0/24"}
    d.update(kw)
    return d


class HtmlTests(unittest.TestCase):
    def test_everything_from_the_network_is_escaped(self):
        evil = '<script>alert(1)</script>'
        h = reportpdf.build_html([dev("192.168.1.2", evil, vendor='"><img src=x>', os="a&b")], networks=["<x>"], warnings=[evil])
        self.assertNotIn("<script>", h)
        self.assertNotIn("<img src=x>", h)
        self.assertIn("&lt;script&gt;", h)
        self.assertIn("a&amp;b", h)

    def test_summary_counts_and_sections(self):
        devs = [dev("192.168.1.2", "tv", trusted=True), dev("192.168.1.3", "pc", type="desktop", new=True),
                dev("192.168.1.4", "vieux", online=False), {"ip": "", "hostname": "Internet", "type": "internet", "virtual": True}]
        h = reportpdf.build_html(devs, ["192.168.1.0/24"], when=0)
        self.assertIn("<b>2</b> appareil(s) en ligne · <b>1</b> hors ligne · <b>1</b> de confiance · <b>1</b> nouveau(x)", h)
        self.assertNotIn("Internet", h)                                          # les nœuds virtuels de la carte n'y figurent pas
        self.assertIn("Hors ligne", h)
        self.assertIn("Appareils", h)
        self.assertNotIn("Exposition", h)                                         # sécurité désactivée : aucune section
        self.assertNotIn("<img", h)

    def test_devices_are_sorted_by_ip_numerically(self):
        h = reportpdf.build_html([dev("192.168.1.100", "z"), dev("192.168.1.9", "a")])
        self.assertLess(h.index("192.168.1.9<"), h.index("192.168.1.100<"))

    def test_map_image_is_referenced_when_given(self):
        self.assertIn('<img src="map" width="680">', reportpdf.build_html([dev("192.168.1.2", "x")], image_name="map"))

    def test_security_section_only_when_enabled_and_analysed(self):
        f = {"id": "telnet", "severity": "élevé", "title": "Telnet activé", "detail": "", "remedy": "Désactiver Telnet", "port": 23}
        d = dev("192.168.1.2", "cam", security=[f])
        self.assertIn("Telnet activé (port 23)", reportpdf.build_html([d], security_on=True))
        self.assertNotIn("Telnet activé", reportpdf.build_html([d], security_on=False))
        self.assertNotIn("Exposition", reportpdf.build_html([dict(d, security=None)], security_on=True))

    def test_changes_section(self):
        ch = {"new": [{"name": "nouveau", "ip": "192.168.1.9"}], "gone": [{"name": "parti", "ip": "192.168.1.8"}],
              "changed": [{"rec": {"name": "tv", "ip": "192.168.1.2"}, "changes": [("Adresse IP", "192.168.1.2", "192.168.1.3")]}], "same": 4}
        h = reportpdf.build_html([dev("192.168.1.2", "tv")], changes=ch)
        for s in ("Changements depuis le scan précédent", "Nouveau</b> : nouveau", "Disparu</b> : parti", "Adresse IP : 192.168.1.2 → 192.168.1.3", "4 inchangé"):
            self.assertIn(s, h)

    def test_empty_report_does_not_crash(self):
        self.assertIn("<b>0</b> appareil(s) en ligne", reportpdf.build_html([]))


@unittest.skipUnless(HAS_QT, "PyQt6 absent : test du PDF ignoré (lancer avec le Python du .venv)")
class PdfTests(unittest.TestCase):
    def test_a_real_pdf_is_written_with_text_and_image(self):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PyQt6.QtGui import QColor, QGuiApplication, QImage
        QGuiApplication.instance() or QGuiApplication([])
        img = QImage(400, 200, QImage.Format.Format_ARGB32); img.fill(QColor("#3366cc"))
        devs = [dev("192.168.1.%d" % i, "appareil-%d" % i) for i in range(2, 70)]          # assez long pour plusieurs pages
        html_text = reportpdf.build_html(devs, ["192.168.1.0/24"], image_name="map", warnings=["Réseau injoignable"])
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.pdf")
            reportpdf.write_pdf(path, html_text, img)
            with open(path, "rb") as f:
                data = f.read()
        self.assertTrue(data.startswith(b"%PDF"))
        self.assertGreater(len(data), 8000)
        self.assertGreaterEqual(data.count(b"/Type /Page\n") + data.count(b"/Type /Page\r"), 2)   # plusieurs pages


if __name__ == "__main__":
    unittest.main()
