import unittest

from panther import profiles


class ProfileTests(unittest.TestCase):
    def test_make_cleans_and_bounds_everything(self):
        p = profiles.make("  Bureau   VLAN 20  ", ["192.168.20.0/24", "192.168.20.0/24", "8.8.8.0/24", "pas une plage", "10.0.0.0/8x"],
                          "dangereux", "eth0; rm -rf /", ["192.168.1.2", "8.8.8.8", "x", "192.168.1.2"], True, True)
        self.assertEqual(p, {"name": "Bureau VLAN 20", "targets": ["192.168.20.0/24"], "depth": "normal", "iface": "", "snmp": ["192.168.1.2"],
                             "security": False, "passive": True})                                      # écoute seule : jamais d'analyse active

    def test_empty_name_is_refused_and_long_name_cut(self):
        for bad in ("", "   ", None):
            with self.assertRaises(ValueError):
                profiles.make(bad)
        self.assertEqual(len(profiles.make("x" * 500)["name"]), profiles.MAX_NAME)

    def test_clean_treats_the_stored_json_as_untrusted(self):
        raw = [{"name": "A", "targets": ["10.1.0.0/24"], "depth": "rapide", "iface": "wlan0", "snmp": ["10.1.0.1"], "security": 1},
               {"name": "a", "depth": "approfondi"},                                                   # même nom (casse) : ignoré
               {"name": ""}, {"nom": "x"}, "texte", 42, None, {"name": "B", "targets": "pas une liste", "snmp": {"x": 1}, "depth": ["zz"]}]
        out = profiles.clean(raw)
        self.assertEqual([p["name"] for p in out], ["A", "B"])
        self.assertEqual((out[0]["depth"], out[0]["iface"], out[0]["security"]), ("rapide", "wlan0", True))
        self.assertEqual((out[1]["targets"], out[1]["snmp"], out[1]["depth"]), ([], [], "normal"))
        for junk in (None, "x", 3, {"a": 1}):
            self.assertEqual(profiles.clean(junk), [])

    def test_clean_caps_the_number_of_profiles(self):
        raw = [{"name": f"p{i}"} for i in range(100)]
        self.assertEqual(len(profiles.clean(raw)), profiles.MAX_PROFILES)

    def test_upsert_replaces_by_name_and_remove_ignores_case(self):
        a, b = profiles.make("Maison", depth="rapide"), profiles.make("Bureau")
        lst = profiles.upsert(profiles.upsert([], a), b)
        lst = profiles.upsert(lst, profiles.make("maison", depth="approfondi"))
        self.assertEqual([(p["name"], p["depth"]) for p in lst], [("Bureau", "normal"), ("maison", "approfondi")])
        self.assertEqual([p["name"] for p in profiles.remove(lst, " BUREAU ")], ["maison"])
        full = [profiles.make(f"p{i}") for i in range(profiles.MAX_PROFILES)]
        with self.assertRaises(ValueError):
            profiles.upsert(full, profiles.make("nouveau"))
        self.assertEqual(len(profiles.upsert(full, profiles.make("p3", depth="rapide"))), profiles.MAX_PROFILES)   # remplacer reste permis


if __name__ == "__main__":
    unittest.main()
