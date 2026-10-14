import json
import os
import tempfile
import time
import unittest

from panther import fingerprint, rules


def dev(**kw):
    d = {"ip": "192.168.20.5", "mac": "00:1b:a9:11:22:33", "hostname": "hp-bureau", "vendor": "Brother", "os": "Linux", "ports": [9100, 80],
         "banners": {}, "ssdp": {}, "mdns_services": ["_ipp._tcp"], "mdns_txt": {}, "mdns_names": [], "is_gateway": False,
         "is_self": False, "random_mac": False}
    d.update(kw)
    return d


def rule(match, kind="printer", **kw):
    return {"name": "r", "type": kind, "match": match, **kw}


class RuleBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "Panther", "rules.json")
        rules.PATH = self.path
        rules._cache.update(path=None, mtime=None, rs=rules.RuleSet())

    def tearDown(self):
        self.tmp.cleanup()
        rules._cache.update(path=None, mtime=None, rs=rules.RuleSet())

    def write(self, data):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.utime(self.path, (time.time() + len(str(data)), time.time() + len(str(data))))  # force un mtime différent

    def matches(self, match, **devkw):
        r = rules.parse_rule(rule(match))
        return r.matches(rules._view(dev(**devkw)))


class ConditionTests(RuleBase):
    def test_each_condition(self):
        self.assertTrue(self.matches({"hostname": "^hp-"}))
        self.assertFalse(self.matches({"hostname": "^brother"}))
        self.assertTrue(self.matches({"vendor": "bro"}))
        self.assertTrue(self.matches({"os": "linux"}))
        self.assertTrue(self.matches({"ports_any": [22, 9100]}))
        self.assertFalse(self.matches({"ports_any": [22]}))
        self.assertTrue(self.matches({"ports_all": [80, 9100]}))
        self.assertFalse(self.matches({"ports_all": [80, 22]}))
        self.assertTrue(self.matches({"mdns_service": "_ipp"}))
        self.assertTrue(self.matches({"mac_prefix": "00:1B:A9"}))
        self.assertTrue(self.matches({"mac_prefix": ["aa:bb", "001ba9"]}))
        self.assertFalse(self.matches({"mac_prefix": "00:11:22"}))
        self.assertTrue(self.matches({"in_network": "192.168.20.0/24"}))
        self.assertFalse(self.matches({"in_network": "10.0.0.0/8"}))
        self.assertTrue(self.matches({"gateway": False}))
        self.assertFalse(self.matches({"gateway": True}))

    def test_list_of_patterns_means_any_and_conditions_mean_all(self):
        self.assertTrue(self.matches({"hostname": ["^nope", "^hp-"]}))
        self.assertFalse(self.matches({"hostname": "^hp-", "ports_any": [22]}))          # une condition fausse suffit à écarter la règle
        self.assertTrue(self.matches({"hostname": "^hp-", "ports_any": [80], "vendor": "brother"}))

    def test_model_banner_and_ssdp_fields(self):
        self.assertTrue(self.matches({"model": "officejet"}, mdns_txt={"ty": "HP OfficeJet 3830"}))
        self.assertTrue(self.matches({"banner": "boa"}, banners={"80": "Boa/0.94 | Login"}))
        self.assertTrue(self.matches({"ssdp": "vewd"}, ssdp={"model": "Vewd"}))

    def test_rules_match_the_automatic_name_not_a_manual_rename(self):
        self.assertTrue(self.matches({"hostname": "^hp-"}, hostname="Mon imprimante", auto_hostname="hp-bureau"))

    def test_matching_is_case_insensitive_and_text_is_truncated(self):
        self.assertTrue(self.matches({"hostname": "HP-BUREAU"}))
        self.assertFalse(self.matches({"hostname": "fin$"}, hostname="x" * 1000 + "fin"))   # texte limité : la fin n'est pas lue


class ValidationTests(RuleBase):
    def bad(self, raw, message):
        with self.assertRaises(rules.RuleError) as cm:
            rules.parse_rule(raw)
        self.assertIn(message, str(cm.exception))

    def test_invalid_rules_are_refused_with_a_clear_message(self):
        self.bad({"type": "printer", "match": {"hostname": "x"}}, "nom manquant")
        self.bad({"name": "a", "type": "frigo", "match": {"hostname": "x"}}, "inconnu")
        self.bad({"name": "a", "type": "printer"}, "au moins une condition")
        self.bad({"name": "a", "type": "printer", "match": {}}, "au moins une condition")        # sinon : s'appliquerait à tout
        self.bad(rule({"couleur": "rouge"}), "inconnue")
        self.bad(rule({"hostname": "("}), "invalide")
        self.bad(rule({"hostname": ""}), "vide")
        self.bad(rule({"ports_any": ["80"]}), "ports")
        self.bad(rule({"ports_any": [70000]}), "ports")
        self.bad(rule({"ports_any": []}), "ports")
        self.bad(rule({"in_network": "pas-une-plage"}), "plage invalide")
        self.bad(rule({"mac_prefix": "zz"}), "préfixe")
        self.bad(rule({"hostname": "x"}, points=0), "points")
        self.bad(rule({"hostname": "x"}, points=101), "points")
        self.bad(rule({"hostname": "x"}, points=True), "points")
        self.bad("pas un objet", "objet")

    def test_regexes_that_could_freeze_the_scan_are_refused(self):
        for p in ("(a+)+$", "(.*)*x", "(x*)+", "([a-z]+)*", "(a|b+)+"):
            self.bad(rule({"hostname": p}), "refusé")
        self.bad(rule({"hostname": "a" * 201}), "trop long")
        rules.parse_rule(rule({"hostname": "^(hp|brother)-[0-9]+$"}))                            # un motif ordinaire reste accepté

    def test_a_rule_with_a_hostile_text_does_not_hang(self):
        r = rules.parse_rule(rule({"hostname": "^(a|aa)+$"}))                                   # accepté ? alors le texte tronqué borne le coût
        t = time.time()
        r.matches(rules._view(dev(hostname="a" * 5000 + "b")))
        self.assertLess(time.time() - t, 1.0)

    def test_invalid_rules_are_skipped_but_valid_ones_kept(self):
        rs = rules.parse({"rules": [rule({"hostname": "ok"}), {"name": "mauvaise", "type": "x", "match": {"a": 1}}, rule({"hostname": "("})]})
        self.assertEqual(len(rs.rules), 1)
        self.assertEqual(len(rs.warnings), 2)
        self.assertIn("mauvaise", rs.warnings[0])

    def test_models_validation(self):
        rs = rules.parse({"models": [{"pattern": "^Cam-", "name": "Caméra", "type": "camera"}, {"pattern": "(", "name": "x"},
                                      {"pattern": "a", "name": ""}, {"pattern": "b", "name": "B", "type": "frigo"}, "n'importe quoi"]})
        self.assertEqual(len(rs.models), 1)
        self.assertEqual(len(rs.warnings), 4)
        self.assertEqual(rules.user_model("Cam-12", rs), ("Caméra", "camera"))
        self.assertIsNone(rules.user_model("Autre", rs))
        self.assertIsNone(rules.user_model("", rs))

    def test_too_many_rules_are_capped(self):
        rs = rules.parse({"rules": [dict(rule({"hostname": "x"}), name=f"r{i}") for i in range(rules.MAX_RULES + 10)]})
        self.assertEqual(len(rs.rules), rules.MAX_RULES)
        self.assertTrue(any("seules" in w for w in rs.warnings))


class FileTests(RuleBase):
    def test_missing_file_is_empty_not_an_error(self):
        self.assertEqual((rules.current().rules, rules.current().warnings), ([], []))

    def test_corrupt_or_huge_file_never_breaks_detection(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w") as f:
            f.write("{pas du json")
        rs = rules.current()
        self.assertEqual(rs.rules, [])
        self.assertTrue(rs.warnings and "illisible" in rs.warnings[0])
        self.assertEqual(rules.evaluate(dev()), [])
        with open(self.path, "w") as f:
            f.write(" " * (rules.MAX_BYTES + 1))
        rules._cache.update(path=None, mtime=None)
        self.assertIn("trop gros", rules.current().warnings[0])

    def test_file_is_reloaded_when_it_changes_and_cached_otherwise(self):
        self.write({"rules": [rule({"hostname": "^hp-"})]})
        a = rules.current()
        self.assertIs(rules.current(), a)                                           # pas de relecture inutile
        self.write({"rules": [rule({"hostname": "^hp-"}), dict(rule({"os": "x"}), name="r2")]})
        self.assertEqual(len(rules.current().rules), 2)

    def test_the_example_file_is_valid_and_not_overwritten(self):
        self.assertTrue(rules.create_example())
        rs = rules.current()
        self.assertEqual((len(rs.rules), rs.warnings, len(rs.models)), (2, [], 1))
        self.assertFalse(rules.create_example())

    def test_many_rules_evaluate_quickly(self):
        self.write({"rules": [dict(rule({"hostname": f"^zz{i}", "ports_any": [i % 60000 + 1]}), name=f"r{i}") for i in range(500)]})
        rs = rules.current()
        t = time.time()
        for _ in range(100):
            rules.evaluate(dev(), rs)
        self.assertLess(time.time() - t, 2.0)


class ClassificationTests(RuleBase):
    def kind(self, **kw):
        return fingerprint.classify_detail(dev(**kw))

    def test_without_rules_nothing_changes(self):
        self.assertEqual(self.kind(hostname="x", ports=[], mdns_services=[], vendor="")[0], "unknown")

    def test_a_user_rule_identifies_an_otherwise_unknown_device_and_explains_why(self):
        self.write({"rules": [{"name": "Caméra du garage", "type": "camera", "points": 60, "match": {"hostname": "^garage-"}}]})
        kind, conf, why = self.kind(hostname="garage-1", ports=[], mdns_services=[], vendor="")
        self.assertEqual((kind, conf), ("camera", 60))
        self.assertIn("règle « Caméra du garage »", why)

    def test_points_add_up_with_the_builtin_evidence(self):
        base = self.kind(hostname="x", ports=[554], mdns_services=[], vendor="")                     # RTSP : caméra, points intégrés
        self.write({"rules": [rule({"ports_any": [554]}, kind="camera", points=40)]})
        boosted = self.kind(hostname="x", ports=[554], mdns_services=[], vendor="")
        self.assertEqual(boosted[0], "camera")
        self.assertGreater(boosted[1], base[1])

    def test_a_strong_rule_can_outweigh_the_builtin_guess(self):
        weak = dict(ports=[9100], mdns_services=[], vendor="")                                          # seul indice intégré : port d'impression (40)
        self.assertEqual(self.kind(**weak)[0], "printer")
        self.write({"rules": [rule({"hostname": "^hp-"}, kind="nas", points=100)]})
        self.assertEqual(self.kind(**weak)[0], "nas")
        self.assertEqual(self.kind()[0], "printer")                                                   # des indices intégrés plus nombreux (115) l'emportent encore : `force` existe pour imposer

    def test_force_imposes_the_type_with_full_confidence(self):
        self.write({"rules": [rule({"hostname": "^hp-"}, kind="server", points=1, force=True, reason="forcé par une règle")]})
        kind, conf, why = self.kind()
        self.assertEqual((kind, conf, why[0]), ("server", 100, "forcé par une règle"))

    def test_this_machine_is_never_reclassified_by_a_rule(self):
        self.write({"rules": [rule({"hostname": "hp"}, kind="nas", force=True)]})
        self.assertEqual(self.kind(is_self=True, self_kind="laptop")[0], "laptop")

    def test_a_crashing_rule_is_ignored(self):
        self.write({"rules": [rule({"hostname": "hp"}, kind="nas", points=100)]})
        rs = rules.current()
        rs.rules[0].cond["ports_any"] = None                                                         # état corrompu
        self.assertEqual(rules.evaluate(dev(), rs), [])


class EditingTests(RuleBase):
    def test_make_rule_from_a_device_uses_only_the_chosen_criteria(self):
        r = rules.make_rule(dev(), "printer", {"hostname", "vendor", "ports", "mdns", "mac"}, "Mon imprimante")
        self.assertEqual(r["match"]["hostname"], "^hp\\-bureau$")
        self.assertEqual(r["match"]["ports_all"], [80, 9100])
        self.assertEqual(r["match"]["mac_prefix"], "00:1b:a9")
        self.assertTrue(rules.parse_rule(r).matches(rules._view(dev())))                            # la règle générée reconnaît son appareil
        self.assertFalse(rules.parse_rule(r).matches(rules._view(dev(hostname="autre"))))
        self.assertEqual(list(rules.make_rule(dev(), "printer", {"vendor"})["match"]), ["vendor"])

    def test_make_rule_skips_useless_criteria_and_refuses_an_empty_result(self):
        d = dev(hostname="192.168.20.5", vendor="MAC aléatoire", ports=[], mdns_services=[], mac="7a:00:00:00:00:01")
        with self.assertRaises(rules.RuleError):
            rules.make_rule(d, "phone", {"hostname", "vendor", "ports", "mdns", "mac"})            # nom = IP, MAC aléatoire, rien d'autre
        with self.assertRaises(rules.RuleError):
            rules.make_rule(dev(), "frigo", {"hostname"})

    def test_add_rule_validates_writes_and_replaces_by_name(self):
        rules.add_rule(rule({"hostname": "a"}, kind="tv"))
        rules.add_rule(dict(rule({"hostname": "b"}, kind="nas"), name="r"))                          # même nom : remplacée
        data = rules.read_data()
        self.assertEqual([(x["name"], x["type"]) for x in data["rules"]], [("r", "nas")])
        with self.assertRaises(rules.RuleError):
            rules.add_rule({"name": "mauvaise", "type": "tv", "match": {}})
        self.assertEqual(len(rules.read_data()["rules"]), 1)                                         # rien n'a été écrit

    def test_export_and_import_merge_and_report_invalid_rules(self):
        rules.add_rule(dict(rule({"hostname": "a"}, kind="tv"), name="mienne"))
        dest = os.path.join(self.tmp.name, "export.json")
        rules.export_to(dest)
        self.assertEqual(rules.read_data(dest)["rules"][0]["name"], "mienne")
        incoming = os.path.join(self.tmp.name, "autre.json")
        with open(incoming, "w") as f:
            json.dump({"rules": [dict(rule({"hostname": "b"}, kind="nas"), name="amie"), {"name": "piégée", "type": "tv", "match": {"hostname": "(a+)+$"}},
                                 dict(rule({"hostname": "c"}, kind="tv"), name="mienne")],
                       "models": [{"pattern": "^X-", "name": "X", "type": "iot"}, {"pattern": "(", "name": "casse"}]}, f)
        added, warnings = rules.import_from(incoming)
        self.assertEqual(added, 2)
        self.assertEqual(len(warnings), 2)                                                           # la règle piégée et le modèle invalide
        names = {r["name"] for r in rules.read_data()["rules"]}
        self.assertEqual(names, {"mienne", "amie"})
        self.assertEqual(next(r for r in rules.read_data()["rules"] if r["name"] == "mienne")["match"], {"hostname": "c"})   # remplacée
        self.assertEqual([m["pattern"] for m in rules.read_data()["models"]], ["^X-"])

    def test_export_without_a_rules_file_gives_the_example(self):
        dest = os.path.join(self.tmp.name, "ex.json")
        rules.export_to(dest)
        self.assertEqual(len(rules.parse(rules.read_data(dest)).rules), 2)

    def test_import_of_garbage_is_refused_without_touching_the_current_file(self):
        rules.add_rule(rule({"hostname": "a"}))
        bad = os.path.join(self.tmp.name, "bad.json")
        with open(bad, "w") as f:
            f.write("pas du json")
        with self.assertRaises(rules.RuleError):
            rules.import_from(bad)
        self.assertEqual(len(rules.read_data()["rules"]), 1)


if __name__ == "__main__":
    unittest.main()
