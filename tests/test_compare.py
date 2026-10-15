import os
import tempfile
import unittest

from panther import compare, history

NET = "192.168.1.0/24"


def rec(key, ip, name="n", typ="unknown", ports=(), sec=None, os_="Linux", vendor="V"):
    return {"key": key, "ip": ip, "mac": key, "name": name, "type": typ, "vendor": vendor, "os": os_, "network": NET,
            "ports": sorted(ports), "sec": sec}


class CompareTests(unittest.TestCase):
    def test_new_gone_changed_and_same(self):
        a = [rec("a", "192.168.1.2"), rec("b", "192.168.1.3"), rec("c", "192.168.1.4")]
        b = [rec("a", "192.168.1.2"), rec("c", "192.168.1.44"), rec("d", "192.168.1.9")]
        r = compare.compare(a, b)
        self.assertEqual([x["key"] for x in r["new"]], ["d"])
        self.assertEqual([x["key"] for x in r["gone"]], ["b"])
        self.assertEqual(r["same"], 1)
        self.assertEqual(r["changed"][0]["changes"], [("Adresse IP", "192.168.1.4", "192.168.1.44")])

    def test_each_field_and_port_diffs(self):
        r = compare.compare([rec("a", "1.1.1.1", "tv", "unknown", [80, 8009], os_="Linux")],
                            [rec("a", "1.1.1.1", "salon", "tv", [80, 443], os_="Android")])
        ch = dict((c[0], c[1:]) for c in r["changed"][0]["changes"])
        self.assertEqual(ch["Nom"], ("tv", "salon"))
        self.assertEqual(ch["Type"], ("unknown", "tv"))
        self.assertEqual(ch["Système"], ("Linux", "Android"))
        self.assertEqual(ch["Ports ouverts"], ("−8009", "+443"))

    def test_only_added_or_only_removed_ports(self):
        r = compare.compare([rec("a", "1.1.1.1", ports=[80])], [rec("a", "1.1.1.1", ports=[80, 22])])
        self.assertEqual(r["changed"][0]["changes"], [("Ports ouverts", "—", "+22")])
        r = compare.compare([rec("a", "1.1.1.1", ports=[80, 22])], [rec("a", "1.1.1.1", ports=[80])])
        self.assertEqual(r["changed"][0]["changes"], [("Ports ouverts", "−22", "—")])

    def test_security_compared_only_when_both_scans_analysed(self):
        r = compare.compare([rec("a", "1.1.1.1", sec=["telnet"])], [rec("a", "1.1.1.1", sec=["telnet", "redis-open"])])
        self.assertEqual(r["changed"][0]["changes"], [("Constats de sécurité", "—", "+redis-open")])
        r = compare.compare([rec("a", "1.1.1.1", sec=None)], [rec("a", "1.1.1.1", sec=["telnet"])])
        self.assertEqual((r["changed"], r["same"]), ([], 1))                    # ancien scan sans analyse : pas de faux « nouveau constat »

    def test_manual_rename_is_not_a_device_change(self):
        d = {"ip": "1.1.1.1", "mac": "m", "hostname": "Mon salon", "auto_hostname": "device-7", "type": "tv", "auto_type": "unknown",
             "vendor": "V", "os": "L", "ports": [], "online": True, "key": "m"}
        r = compare.snapshot_record(d)
        self.assertEqual((r["name"], r["type"]), ("device-7", "unknown"))     # valeurs automatiques

    def test_snapshot_skips_offline_and_virtual_devices(self):
        devs = [{"ip": "1.1.1.1", "mac": "a", "hostname": "x", "type": "t", "ports": [], "online": True, "key": "a"},
                {"ip": "1.1.1.2", "mac": "b", "hostname": "y", "type": "t", "ports": [], "online": False, "key": "b"},
                {"ip": "", "hostname": "Internet", "type": "internet", "virtual": True, "key": "virt:internet", "ports": []}]
        self.assertEqual([r["key"] for r in compare.snapshot_of(devs)], ["a"])

    def test_results_sorted_by_ip_numerically_and_empty_inputs(self):
        r = compare.compare([], [rec("x", "192.168.1.100"), rec("y", "192.168.1.9")])
        self.assertEqual([x["ip"] for x in r["new"]], ["192.168.1.9", "192.168.1.100"])
        self.assertEqual(compare.compare([], []), {"new": [], "gone": [], "changed": [], "same": 0})


class FormatTests(unittest.TestCase):
    def test_plain_fields_show_before_and_after(self):
        self.assertEqual(compare.format_change("Adresse IP", "1.1.1.1", "1.1.1.2"), "Adresse IP : 1.1.1.1 → 1.1.1.2")

    def test_ports_only_added_or_removed_or_both(self):
        self.assertEqual(compare.format_change("Ports ouverts", "—", "+443"), "Ports ouverts : +443")
        self.assertEqual(compare.format_change("Ports ouverts", "−22", "—"), "Ports ouverts : −22")
        self.assertEqual(compare.format_change("Ports ouverts", "−8009", "+443"), "Ports ouverts : −8009  /  +443")

    def test_security_ids_become_readable_titles(self):
        self.assertEqual(compare.format_change("Constats de sécurité", "—", "+rtsp-open, telnet"),
                         "Constats de sécurité : +Flux caméra accessible sans mot de passe, Telnet activé")
        self.assertEqual(compare.format_change("Constats de sécurité", "−redis-open", "—"),
                         "Constats de sécurité : −Redis accessible sans mot de passe")


def dev(ip, mac, name="x", ports=()):
    return {"ip": ip, "mac": mac, "hostname": name, "type": "unknown", "vendor": "V", "network": NET, "online": True,
            "os": "Linux", "ports": list(ports)}


class SnapshotHistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        history.PATH = os.path.join(self.tmp.name, "Panther", "panther.db")

    def tearDown(self):
        self.tmp.cleanup()

    def n_snapshots(self):
        import sqlite3
        con = sqlite3.connect(history.PATH)
        try:
            return con.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
        finally:
            con.close()

    def test_identical_scans_share_one_snapshot_but_all_stay_listed(self):
        for i in range(4):
            history.record_scan([dev("192.168.1.2", "aa:00:00:00:00:02")], now=1000 + i, networks=[NET])
        self.assertEqual(self.n_snapshots(), 1)
        scans = history.list_scans()
        self.assertEqual((len(scans), scans[0]["count"]), (4, 1))
        self.assertGreater(scans[0]["id"], scans[-1]["id"])                      # le plus récent d'abord

    def test_a_change_creates_a_new_snapshot_and_compare_sees_it(self):
        history.record_scan([dev("192.168.1.2", "aa:00:00:00:00:02", ports=[80])], now=1000, networks=[NET])
        history.record_scan([dev("192.168.1.2", "aa:00:00:00:00:02", ports=[80, 22]), dev("192.168.1.9", "aa:00:00:00:00:09")], now=2000, networks=[NET])
        self.assertEqual(self.n_snapshots(), 2)
        new, old = history.list_scans()
        r = compare.compare(history.load_snapshot(old["id"]), history.load_snapshot(new["id"]))
        self.assertEqual(([x["ip"] for x in r["new"]], r["changed"][0]["changes"]), (["192.168.1.9"], [("Ports ouverts", "—", "+22")]))

    def test_offline_devices_are_not_in_the_snapshot(self):
        d = dev("192.168.1.2", "aa:00:00:00:00:02"); gone = dict(dev("192.168.1.3", "aa:00:00:00:00:03"), online=False)
        history.record_scan([d, gone], now=1000, networks=[NET])
        self.assertEqual([r["key"] for r in history.load_snapshot(history.list_scans()[0]["id"])], ["aa:00:00:00:00:02"])

    def test_old_scans_and_orphan_snapshots_are_pruned(self):
        history.record_scan([dev("192.168.1.2", "aa:00:00:00:00:02", ports=[1])], now=1000, networks=[NET])
        history.record_scan([dev("192.168.1.2", "aa:00:00:00:00:02", ports=[2])], now=1000 + 91 * 86400, networks=[NET])
        self.assertEqual((len(history.list_scans()), self.n_snapshots()), (1, 1))

    def test_unknown_scan_has_no_snapshot(self):
        self.assertIsNone(history.load_snapshot(999))

    def test_v3_database_is_upgraded_and_old_scans_are_simply_not_listed(self):
        import sqlite3
        history.record_scan([dev("192.168.1.2", "aa:00:00:00:00:02")], now=1000, networks=[NET])
        con = sqlite3.connect(history.PATH)
        con.execute("DROP TABLE snapshots"); con.execute("UPDATE scans SET snapshot_id=NULL"); con.execute("PRAGMA user_version=3"); con.commit(); con.close()
        self.assertEqual(history.list_scans(), [])                              # recrée la table sans erreur
        history.record_scan([dev("192.168.1.2", "aa:00:00:00:00:02")], now=2000, networks=[NET])
        self.assertEqual(len(history.list_scans()), 1)


if __name__ == "__main__":
    unittest.main()
