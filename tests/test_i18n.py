import ast
import os
import sys
import unittest

from panther import i18n
from panther.lang_en import EN

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import i18n_check  # noqa: E402


class CatalogueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys, cls.dynamic = i18n_check.collect()

    def test_every_marked_text_has_an_english_translation(self):
        missing = [k for k in self.keys if k not in EN]
        self.assertEqual(missing, [], f"{len(missing)} textes sans traduction (python3 tools/i18n_check.py)")

    def test_no_stale_translation(self):
        self.assertEqual([k for k in EN if k not in self.keys], [])

    def test_no_f_string_passed_to_tr(self):
        self.assertEqual(self.dynamic, [], "tr() reçoit un texte construit : la traduction ne peut pas le retrouver")

    def test_placeholders_are_identical_in_both_languages(self):
        for fr, en in EN.items():
            self.assertEqual(i18n_check.fields(fr), i18n_check.fields(en), fr)

    def test_translation_is_not_empty_and_keeps_edge_whitespace(self):
        for fr, en in EN.items():
            self.assertTrue(en.strip() or not fr.strip(), fr)
            self.assertEqual(fr[:1].isspace(), en[:1].isspace(), repr(fr))      # « " (port {port})" » : l'espace initial sert à la mise en forme
            self.assertEqual(fr[-1:].isspace(), en[-1:].isspace(), repr(fr))

    def test_english_text_does_not_contain_french_leftovers(self):
        accents = set("àâçéèêëîïôùûüœ")
        for fr, en in EN.items():
            if fr.startswith(("Panther → ", "https://")):
                continue
            self.assertFalse(accents & set(en.lower()), f"{fr!r} -> {en!r}")


class RuntimeTests(unittest.TestCase):
    def tearDown(self):
        i18n.set_language("fr")

    def test_french_is_the_identity(self):
        i18n.set_language("fr")
        self.assertEqual(i18n.tr("Enregistrer"), "Enregistrer")
        self.assertEqual(i18n.tr("{n} appareils", n=3), "3 appareils")

    def test_english_translates_and_formats_values(self):
        i18n.set_language("en")
        self.assertEqual(i18n.tr("Enregistrer"), "Save")
        self.assertEqual(i18n.tr("Rapport enregistré : {path}", path="/tmp/x"), "Report saved: /tmp/x")

    def test_unknown_text_falls_back_to_itself(self):
        i18n.set_language("en")
        self.assertEqual(i18n.tr("Texte inconnu {x}", x=1), "Texte inconnu 1")

    def test_unknown_language_is_french(self):
        self.assertEqual(i18n.set_language("de"), "fr")
        self.assertEqual(i18n.language(), "fr")

    def test_a_field_named_text_is_possible(self):
        i18n.set_language("en")
        self.assertEqual(i18n.tr("« {text} » n'est pas une plage valide (exemple : 192.168.20.0/24).", text="x"),
                         "“x” is not a valid range (example: 192.168.20.0/24).")

    def test_plural_rules_differ_by_language(self):
        i18n.set_language("fr")
        self.assertEqual([i18n.plural(n, "événement", "événements") for n in (0, 1, 2)], ["0 événement", "1 événement", "2 événements"])
        i18n.set_language("en")
        self.assertEqual([i18n.plural(n, "événement", "événements") for n in (0, 1, 2)], ["0 events", "1 event", "2 events"])

    def test_translated_table_reads_through_the_active_language(self):
        table = i18n.TrDict({"a": i18n.N_("Enregistrer"), "b": i18n.N_("Annuler")})
        i18n.set_language("en")
        self.assertEqual((table["a"], table.get("b"), table.get("zzz", "?"), sorted(table.values()), dict(table.items())["a"]),
                         ("Save", "Cancel", "?", ["Cancel", "Save"], "Save"))
        i18n.set_language("fr")
        self.assertEqual(table["a"], "Enregistrer")

    def test_detect_system_language(self):
        self.assertEqual(i18n.detect({"LANG": "fr_FR.UTF-8"}), "fr")
        self.assertEqual(i18n.detect({"LANG": "en_US.UTF-8"}), "en")
        self.assertEqual(i18n.detect({"LC_ALL": "de_DE.UTF-8", "LANG": "fr_FR.UTF-8"}), "en")   # LC_ALL prime ; langue inconnue -> anglais
        self.assertEqual(i18n.detect({"LANG": "C"}), "en")
        self.assertEqual(i18n.detect({}), "en")
        self.assertEqual(i18n.detect({"LANGUAGE": "fr", "LANG": ""}), "fr")


class EnglishOutputTests(unittest.TestCase):
    """Les modules du moteur produisent de l'anglais sans mélange avec le français."""

    def setUp(self):
        i18n.set_language("en")

    def tearDown(self):
        i18n.set_language("fr")

    def test_security_findings_and_report(self):
        from panther import security
        dev = {"ip": "10.0.0.5", "type": "camera", "ports": [23, 554], "banners": {}, "hostname": "cam"}
        f = security.analyze(dev, {554: "open"})
        titles = [x["title"] for x in f]
        self.assertIn("Telnet enabled", titles)
        self.assertIn("Camera stream reachable without a password", titles)
        self.assertEqual(security.LABELS["élevé"], "High")
        md = security.report_markdown([dict(dev, security=f)], ["10.0.0.0/24"], when=0)
        self.assertIn("## Findings by device", md)
        self.assertNotIn("Constats", md)

    def test_fingerprint_reasons_and_models(self):
        from panther import fingerprint, models
        kind, conf, why = fingerprint.classify_detail({"ip": "1.1.1.1", "ports": [9100], "vendor": "HP", "hostname": "", "mdns_services": []})
        self.assertEqual(kind, "printer")
        self.assertIn("printing port 9100", why)
        self.assertEqual(models.friendly("iPad7,5")["name"], "iPad (6th generation)")
        self.assertEqual(fingerprint.confidence_label(80), "high")

    def test_exporter_headers_and_labels(self):
        from panther import exporter
        csv_text = exporter.to_csv([{"ip": "10.0.0.5", "hostname": "x", "type": "tv", "online": True, "mac": "", "ports": [], "services": []}])
        self.assertTrue(csv_text.splitlines()[0].startswith("IP address,Name,Type,MAC address"))
        self.assertIn("TV / media", csv_text)

    def test_compare_labels(self):
        from panther import compare
        self.assertEqual(compare.format_change("Ports ouverts", "−80", "+443"), "Open ports : −80  /  +443")
        self.assertEqual(compare.format_change("Nom", "a", "b"), "Name : a → b")

    def test_pdf_report_html(self):
        from panther import reportpdf
        html = reportpdf.build_html([{"ip": "10.0.0.5", "hostname": "x", "type": "nas", "online": True, "mac": "", "vendor": "", "os": ""}], ["10.0.0.0/24"], 0)
        self.assertIn("Network scan report", html)
        self.assertIn("NAS", html)
        self.assertNotIn("Résumé", html)


if __name__ == "__main__":
    unittest.main()
