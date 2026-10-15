import json
import os
import tempfile
import unittest

from panther import fingerprint, models, rules


class ModelNameTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        rules.PATH = os.path.join(self.tmp.name, "rules.json")
        rules._cache.update(path=None, mtime=None, rs=rules.RuleSet())

    def tearDown(self):
        self.tmp.cleanup()
        rules._cache.update(path=None, mtime=None, rs=rules.RuleSet())

    def test_known_apple_identifiers_give_the_right_name_and_type(self):
        # 14,2 est un iPhone 13 **Pro** (le 13 « tout court » est 14,5) : ce piège est vérifié explicitement
        self.assertEqual(models.friendly("iPhone14,2")["name"], "iPhone 13 Pro")
        self.assertEqual(models.friendly("iPhone14,5")["name"], "iPhone 13")
        self.assertEqual(models.friendly("iPhone12,1")["name"], "iPhone 11")
        self.assertEqual(models.friendly("iPhone15,4"), {"name": "iPhone 15", "type": "phone", "source": "table"})
        self.assertEqual(models.friendly("iPad13,18")["type"], "tablet")
        self.assertEqual(models.friendly("iPad8,2")["name"], "iPad Pro 11 pouces (1re génération)")
        self.assertEqual(models.friendly("iPad13,5")["name"], "iPad Pro 11 pouces (3e génération)")
        self.assertEqual(models.friendly("iPad13,9")["name"], "iPad Pro 12,9 pouces (5e génération)")
        self.assertEqual(models.friendly("AppleTV11,1")["type"], "tv")
        self.assertEqual(models.friendly("AudioAccessory5,1")["name"], "HomePod mini")
        self.assertEqual(models.friendly("Mac14,2")["name"], "MacBook Air (M2, 2022)")

    def test_both_identifiers_of_the_same_model_agree(self):
        for a, b in (("iPhone10,1", "iPhone10,4"), ("iPad7,5", "iPad7,6"), ("iPad11,3", "iPad11,4"), ("AudioAccessory1,1", "AudioAccessory1,2")):
            self.assertEqual(models.friendly(a)["name"], models.friendly(b)["name"])

    def test_every_table_entry_has_a_plausible_family_type(self):
        for ident, name in models.EXACT.items():
            f = models.friendly(ident)
            self.assertEqual(f["source"], "table")
            if ident.startswith("iPhone"):
                self.assertTrue(name.startswith("iPhone") and f["type"] == "phone", ident)
            if ident.startswith("iPad"):
                self.assertTrue(name.startswith("iPad") and f["type"] == "tablet", ident)

    def test_unknown_identifiers_fall_back_to_their_family_never_to_a_guess(self):
        self.assertEqual(models.friendly("iPhone99,9"), {"name": "iPhone", "type": "phone", "source": "famille"})
        self.assertEqual(models.friendly("iPad99,1")["name"], "iPad")
        self.assertEqual(models.friendly("MacBookPro99,1")["type"], "laptop")
        self.assertIsNone(models.friendly("Mac99,1")["type"])                       # portable ou fixe : on ne devine pas
        self.assertEqual(models.friendly("SM-T510")["type"], "tablet")
        self.assertEqual(models.friendly("SM-G991B")["type"], "phone")
        self.assertEqual(models.friendly("UE55AU7175")["type"], "tv")

    def test_unrecognised_or_empty_identifiers_give_nothing(self):
        for x in ("Pixel7", "", None, "  ", "ModèleInconnu 3000"):
            self.assertIsNone(models.friendly(x))

    def test_describe_formats(self):
        self.assertEqual(models.describe("iPhone14,2"), "iPhone 13 Pro (iPhone14,2)")
        self.assertEqual(models.describe("iPhone99,9"), "iPhone (iPhone99,9)")
        self.assertEqual(models.describe("SM-G991B"), "Samsung Galaxy (SM-G991B)")            # l'identifiant n'est pas répété
        self.assertEqual(models.describe("Pixel7"), "Pixel7")
        self.assertEqual(models.describe(""), "")
        self.assertEqual(models.describe(None), "")

    def test_user_models_take_precedence_and_can_add_a_type(self):
        os.makedirs(os.path.dirname(rules.PATH), exist_ok=True)
        with open(rules.PATH, "w") as f:
            json.dump({"models": [{"pattern": "^iPhone14,2$", "name": "Le téléphone de Marie", "type": "phone"},
                                  {"pattern": "^MaCam-", "name": "Ma caméra", "type": "camera"}]}, f)
        self.assertEqual(models.friendly("iPhone14,2"), {"name": "Le téléphone de Marie", "type": "phone", "source": "utilisateur"})
        self.assertEqual(models.friendly("MaCam-X1")["type"], "camera")
        self.assertEqual(models.friendly("iPhone14,5")["name"], "iPhone 13")                  # le reste de la table est intact

    def test_a_user_model_with_a_type_is_evidence_for_the_classification(self):
        os.makedirs(os.path.dirname(rules.PATH), exist_ok=True)
        with open(rules.PATH, "w") as f:
            json.dump({"models": [{"pattern": "^MaCam-", "name": "Ma caméra", "type": "camera"}]}, f)
        d = {"ip": "1.1.1.1", "mac": "", "hostname": "x", "vendor": "", "os": "", "ports": [], "banners": {}, "ssdp": {}, "mdns_services": [],
             "mdns_txt": {}, "mdns_names": [], "is_gateway": False, "is_self": False, "random_mac": False, "model": "MaCam-X1"}
        kind, conf, why = fingerprint.classify_detail(d)
        self.assertEqual((kind, conf), ("camera", 70))
        self.assertTrue(any("Ma caméra" in r for r in why))

    def test_apple_companion_link_model_key_is_read(self):
        d = {"ip": "1.1.1.1", "mdns_txt": {"rpmd": "iPad13,18"}, "ssdp": {}}
        self.assertIn("ipad13,18", fingerprint._model_text(d))
        self.assertEqual(fingerprint.classify_detail(dict(d, mac="", hostname="x", vendor="", os="", ports=[], banners={}, mdns_services=[],
                                                          mdns_names=[], is_gateway=False, is_self=False, random_mac=False))[0], "tablet")


if __name__ == "__main__":
    unittest.main()


class IPhone16Tests(unittest.TestCase):
    def test_iphone_16_family(self):
        expected = {"iPhone17,1": "iPhone 16 Pro", "iPhone17,2": "iPhone 16 Pro Max", "iPhone17,3": "iPhone 16", "iPhone17,4": "iPhone 16 Plus",
                    "iPhone17,5": "iPhone 16e"}
        for ident, name in expected.items():
            f = models.friendly(ident)
            self.assertEqual((f["name"], f["type"], f["source"]), (name, "phone", "table"), ident)
        self.assertEqual(models.friendly("iPhone17,9")["source"], "famille")           # un identifiant futur retombe sur la famille, jamais un nom deviné
