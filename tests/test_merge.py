import os
import sqlite3
import tempfile
import unittest

from panther import compare, history, identity, scanner, store

NET = "192.168.1.0/24"
OLD, NEW = "02:11:22:33:44:01", "06:11:22:33:44:02"          # deux MAC « privées » d'un même iPhone


def dev(ip, mac, name="iphone", typ="phone", **kw):
    d = {"ip": ip, "mac": mac, "hostname": name, "type": typ, "vendor": "MAC aléatoire", "network": NET, "online": True, "os": "iOS", "ports": []}
    d.update(kw)
    return d


class MergeBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        history.PATH = os.path.join(self.tmp.name, "p.db")
        store.PATH = os.path.join(self.tmp.name, "devices.json")

    def tearDown(self):
        self.tmp.cleanup()

    def rows(self, table):
        con = sqlite3.connect(history.PATH)
        try:
            return con.execute(f"SELECT * FROM {table}").fetchall()
        finally:
            con.close()


class MergeTests(MergeBase):
    def two_identities(self):
        history.record_scan([dev("192.168.1.27", OLD)], now=1000, networks=[NET])
        history.set_trusted([dev("192.168.1.27", OLD)], True, now=1100)
        history.save_position("etoile", OLD, 5, 6)
        history.record_scan([dev("192.168.1.27", OLD, security=[{"id": "telnet", "severity": "élevé", "title": "Telnet"}])], now=1200, networks=[NET])
        history.record_findings([dev("192.168.1.27", OLD, security=[{"id": "telnet", "severity": "élevé", "title": "Telnet"}])], now=1200)
        history.record_scan([dev("192.168.1.14", NEW)], now=5000, networks=[NET])      # même téléphone, nouvelle MAC : doublon
        self.assertEqual(len(self.rows("devices")), 2)

    def test_merge_regroups_history_trust_findings_positions_and_logs_it(self):
        self.two_identities()
        history.merge_devices(NEW, OLD, now=6000)
        devs = self.rows("devices")
        self.assertEqual(len(devs), 1)
        con = sqlite3.connect(history.PATH); con.row_factory = sqlite3.Row
        try:
            row = con.execute("SELECT * FROM devices").fetchone()
            self.assertEqual((row["key"], row["first_seen"], row["trusted"]), (NEW, 1000, 1))        # plus ancienne apparition, confiance gardée
            self.assertEqual({r["key"] for r in con.execute("SELECT key FROM seen")}, {NEW})
            self.assertEqual({r["key"] for r in con.execute("SELECT key FROM findings")}, {NEW})
            self.assertEqual({r["key"] for r in con.execute("SELECT key FROM positions")}, {NEW})
            self.assertEqual(con.execute("SELECT kind FROM events ORDER BY id DESC LIMIT 1").fetchone()[0], "merged")
        finally:
            con.close()
        self.assertEqual(history.alias_map(), {OLD: NEW})

    def test_the_old_mac_seen_later_is_attached_to_the_merged_device_without_duplicate(self):
        self.two_identities()
        history.merge_devices(NEW, OLD, now=6000)
        d = dev("192.168.1.99", OLD)                                                   # l'ancienne MAC réapparaît
        r = history.record_scan([d], now=7000, networks=[NET])
        self.assertEqual((d["key"], r["new"], len(self.rows("devices"))), (NEW, [], 1))
        history.annotate([d])
        self.assertTrue(d["trusted"])

    def test_both_macs_present_in_the_same_scan_never_crash_nor_collapse_into_one_key(self):
        self.two_identities()
        history.merge_devices(NEW, OLD, now=6000)
        a, b = dev("192.168.1.14", NEW), dev("192.168.1.27", OLD)
        history.record_scan([a, b], now=7000, networks=[NET])
        self.assertNotEqual(a["key"], b["key"])                                         # deux appareils présents en même temps restent distincts

    def test_old_snapshots_are_read_with_the_current_key_so_compare_shows_no_fake_change(self):
        history.record_scan([dev("192.168.1.27", OLD, ports=[62078])], now=1000, networks=[NET])
        history.record_scan([dev("192.168.1.14", NEW, ports=[62078])], now=2000, networks=[NET])
        before = compare.compare(*[history.load_snapshot(s["id"]) for s in reversed(history.list_scans())])
        self.assertEqual((len(before["new"]), len(before["gone"])), (1, 1))             # avant fusion : « disparu » + « nouveau »
        history.merge_devices(NEW, OLD, now=3000)
        after = compare.compare(*[history.load_snapshot(s["id"]) for s in reversed(history.list_scans())])
        self.assertEqual((after["new"], after["gone"]), ([], []))
        self.assertEqual(after["changed"][0]["changes"], [("Adresse IP", "192.168.1.27", "192.168.1.14")])
        self.assertEqual(list(history.last_snapshot_map()), [NEW])

    def test_errors(self):
        self.two_identities()
        with self.assertRaises(ValueError):
            history.merge_devices(NEW, NEW)
        with self.assertRaises(ValueError):
            history.merge_devices(NEW, "inconnu")

    def test_forgetting_removes_the_alias(self):
        self.two_identities()
        history.merge_devices(NEW, OLD, now=6000)
        history.forget(dev("192.168.1.14", NEW))
        self.assertEqual(history.alias_map(), {})

    def test_chained_merges_keep_pointing_to_the_final_device(self):
        history.record_scan([dev("192.168.1.2", "aa:00:00:00:00:01")], now=1000, networks=[NET])
        history.record_scan([dev("192.168.1.3", "aa:00:00:00:00:02")], now=2000, networks=[NET])
        history.record_scan([dev("192.168.1.4", "aa:00:00:00:00:03")], now=3000, networks=[NET])
        history.merge_devices("aa:00:00:00:00:02", "aa:00:00:00:00:01", now=4000)
        history.merge_devices("aa:00:00:00:00:03", "aa:00:00:00:00:02", now=5000)
        self.assertEqual(history.alias_map(), {"aa:00:00:00:00:01": "aa:00:00:00:00:03", "aa:00:00:00:00:02": "aa:00:00:00:00:03"})


class OverrideTests(MergeBase):
    def test_manual_name_follows_the_merge_and_applies_to_an_aliased_mac(self):
        history.record_scan([dev("192.168.1.27", OLD)], now=1000, networks=[NET])
        history.record_scan([dev("192.168.1.14", NEW)], now=2000, networks=[NET])
        store.set_override(dev("192.168.1.27", OLD), "iPhone de Marie", "phone")
        history.merge_devices(NEW, OLD, now=3000)
        self.assertEqual(store.load(), {NEW: {"name": "iPhone de Marie", "type": "phone"}})
        d = dev("192.168.1.99", OLD)                                                    # le scanner voit l'ancienne MAC
        store.apply(d, store.load(), history.alias_map())
        self.assertEqual((d["hostname"], d["custom"]), ("iPhone de Marie", True))

    def test_a_device_that_gains_a_mac_keeps_its_manual_name(self):
        d = dev("10.0.0.5", "", "cam", "camera", network="10.0.0.0/24")
        history.record_scan([d], now=1000, networks=["10.0.0.0/24"])
        store.set_override(d, "Caméra garage")
        history.record_scan([dev("10.0.0.5", "bb:00:00:00:00:05", "cam", "camera", network="10.0.0.0/24")], now=2000, networks=["10.0.0.0/24"])
        self.assertEqual(store.load(), {"bb:00:00:00:00:05": {"name": "Caméra garage"}})

    def test_set_override_uses_the_resolved_identity(self):
        d = dev("192.168.1.99", OLD, key=NEW)
        store.set_override(d, "Nom")
        self.assertEqual(list(store.load()), [NEW])

    def test_move_override_never_overwrites_an_existing_setting(self):
        store.set_override(dev("1.1.1.1", "aa:00:00:00:00:01"), "A"); store.set_override(dev("1.1.1.2", "aa:00:00:00:00:02"), "B")
        store.move_override("aa:00:00:00:00:01", "aa:00:00:00:00:02")
        self.assertEqual(store.load()["aa:00:00:00:00:02"]["name"], "B")


class ScannerAliasTests(unittest.TestCase):
    def test_light_scan_finds_a_known_device_through_its_alias_and_applies_its_manual_name(self):
        sc = scanner.Scanner(); sc.profile = scanner.PROFILES["presence"]
        sc.known = {NEW: {"key": NEW, "name": "iphone", "type": "phone", "vendor": "V", "os": "iOS", "ports": []}}
        sc.aliases = {OLD: NEW}
        sc.overrides = {NEW: {"name": "iPhone de Marie"}}
        net = {"iface": "eth0", "ip": "192.168.1.13", "cidr": NET, "gateway": "192.168.1.1"}
        d = sc._inspect("192.168.1.99", net, {"192.168.1.99": OLD}, {"mdns": {}, "ssdp": {}})
        self.assertEqual((d["light"], d["hostname"]), (True, "iPhone de Marie"))


class SuggestionTests(unittest.TestCase):
    def pair(self, **new_kw):
        new = dev("192.168.1.14", NEW, new=True, **new_kw)
        old = dev("192.168.1.27", OLD, online=False)
        return new, old

    def test_same_name_type_and_random_mac_is_suggested_with_reasons(self):
        new, old = self.pair()
        (n, o, reasons), = identity.suggest_duplicates([new, old])
        self.assertEqual((n["mac"], o["mac"]), (NEW, OLD))
        self.assertIn("même nom « iphone »", reasons)
        self.assertTrue(any("aléatoire" in r for r in reasons))

    def test_no_suggestion_when_names_networks_or_types_differ(self):
        new, old = self.pair(hostname="ipad")
        self.assertEqual(identity.suggest_duplicates([new, old]), [])
        new, old = self.pair(network="10.0.0.0/24")
        self.assertEqual(identity.suggest_duplicates([new, old]), [])
        new, old = self.pair(type="printer")
        self.assertEqual(identity.suggest_duplicates([new, old]), [])

    def test_unknown_type_is_compatible_with_any_type(self):
        new, old = self.pair(type="unknown")
        self.assertEqual(len(identity.suggest_duplicates([new, old])), 1)

    def test_two_online_devices_or_this_machine_are_never_suggested(self):
        a, b = dev("192.168.1.14", NEW), dev("192.168.1.27", OLD)
        self.assertEqual(identity.suggest_duplicates([a, b]), [])
        me = dev("192.168.1.13", NEW, is_self=True)
        self.assertEqual(identity.suggest_duplicates([me, dev("192.168.1.27", OLD, online=False)]), [])

    def test_name_equal_to_the_ip_is_not_a_reason(self):
        new, old = self.pair(hostname="192.168.1.14")
        old["hostname"] = "192.168.1.14"
        self.assertEqual(identity.suggest_duplicates([new, old]), [])

    def test_an_offline_device_is_proposed_once_and_without_random_mac_only_for_new_devices(self):
        a, b = dev("192.168.1.14", NEW, new=True), dev("192.168.1.15", "c2:00:00:00:00:99", new=True)
        old = dev("192.168.1.27", OLD, online=False)
        self.assertEqual(len(identity.suggest_duplicates([a, b, old])), 1)
        plain_new = dev("192.168.1.14", "00:11:22:33:44:55", new=True)
        plain_old = dev("192.168.1.27", "00:11:22:33:44:66", online=False)
        self.assertEqual(len(identity.suggest_duplicates([plain_new, plain_old])), 1)      # nouveau + même nom : suggéré
        plain_new["new"] = False
        self.assertEqual(identity.suggest_duplicates([plain_new, plain_old]), [])           # ni nouveau ni MAC aléatoire : non


if __name__ == "__main__":
    unittest.main()
