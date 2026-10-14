import os
import tempfile
import unittest

from panther import history

DAY = 86400


def dev(ip, mac, name="x", typ="unknown", net="192.168.1.0/24"):
    return {"ip": ip, "mac": mac, "hostname": name, "type": typ, "vendor": "V", "network": net, "online": True}


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        history.PATH = os.path.join(self.tmp.name, "Panther", "panther.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_first_scan_is_baseline_nothing_is_new(self):
        r = history.record_scan([dev("192.168.1.2", "aa:00:00:00:00:02")], now=1000)
        self.assertEqual((r["baseline"], r["new"]), (True, []))

    def test_later_scan_reports_only_really_new_devices(self):
        history.record_scan([dev("192.168.1.2", "aa:00:00:00:00:02")], now=1000)
        r = history.record_scan([dev("192.168.1.2", "aa:00:00:00:00:02"), dev("192.168.1.9", "aa:00:00:00:00:09")], now=2000)
        self.assertEqual((r["baseline"], r["new"]), (False, ["aa:00:00:00:00:09"]))
        self.assertEqual(history.record_scan([dev("192.168.1.9", "aa:00:00:00:00:09")], now=3000)["new"], [])

    def test_ip_change_is_not_a_new_device(self):
        history.record_scan([dev("192.168.1.2", "aa:00:00:00:00:02")], now=1000)
        r = history.record_scan([dev("192.168.1.77", "aa:00:00:00:00:02")], now=2000)
        self.assertEqual(r["new"], [])

    def test_offline_devices_are_the_known_ones_missing_now(self):
        history.record_scan([dev("192.168.1.2", "aa:00:00:00:00:02", "tv", "tv"), dev("192.168.1.3", "aa:00:00:00:00:03", "pc")], now=1000)
        off = history.known_offline(["aa:00:00:00:00:03"], ["192.168.1.0/24"], now=1000 + DAY)
        self.assertEqual([(d["hostname"], d["type"], d["online"]) for d in off], [("tv", "tv", False)])
        self.assertEqual(off[0]["last_seen"], 1000)

    def test_old_devices_and_other_networks_are_not_shown(self):
        history.record_scan([dev("192.168.1.2", "aa:00:00:00:00:02"), dev("10.0.0.5", "", net="10.0.0.0/24")], now=1000)
        self.assertEqual(history.known_offline([], ["192.168.1.0/24"], now=1000 + 15 * DAY), [])   # trop ancien
        self.assertEqual(len(history.known_offline([], ["192.168.1.0/24"], now=1000 + DAY)), 1)    # pas le 10.0.0.0/24
        self.assertEqual(history.known_offline([], [], now=1000), [])

    def test_ip_key_for_devices_without_mac(self):
        history.record_scan([dev("10.0.0.5", "", net="10.0.0.0/24")], now=1000)
        r = history.record_scan([dev("10.0.0.5", "", net="10.0.0.0/24"), dev("10.0.0.6", "", net="10.0.0.0/24")], now=2000)
        self.assertEqual(r["new"], ["ip:10.0.0.6"])

    def test_manual_name_does_not_overwrite_automatic_one(self):
        d = dev("192.168.1.2", "aa:00:00:00:00:02", "Salon", "tv")
        d.update(auto_hostname="device-7", auto_type="unknown")
        history.record_scan([d], now=1000)
        self.assertEqual(history.known_offline([], ["192.168.1.0/24"], now=1000)[0]["hostname"], "device-7")

    def test_offline_stub_has_every_field_the_ui_reads(self):
        history.record_scan([dev("192.168.1.2", "aa:00:00:00:00:02")], now=1000)
        stub = history.known_offline([], ["192.168.1.0/24"], now=1000)[0]
        for k in ("ports", "services", "banners", "is_gateway", "is_self", "os", "confidence", "reasons", "mdns_services", "path"):
            self.assertIn(k, stub)


NET = "192.168.1.0/24"
H = 3600


class PresenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        history.PATH = os.path.join(self.tmp.name, "Panther", "panther.db")
        self.a = dev("192.168.1.2", "aa:00:00:00:00:02", "tv", "tv")
        self.b = dev("192.168.1.3", "aa:00:00:00:00:03", "pc")

    def tearDown(self):
        self.tmp.cleanup()

    def kinds(self, key=None):
        return [e["kind"] for e in history.recent_events(50, key)][::-1]  # ordre chronologique

    def test_migration_from_phase3_database(self):
        import sqlite3
        os.makedirs(os.path.dirname(history.PATH))
        con = sqlite3.connect(history.PATH)
        con.execute("CREATE TABLE devices(key TEXT PRIMARY KEY, mac TEXT, ip TEXT, name TEXT, type TEXT, vendor TEXT, "
                    "network TEXT, first_seen REAL NOT NULL, last_seen REAL NOT NULL)")
        con.execute("INSERT INTO devices VALUES('aa:00:00:00:00:02','aa:00:00:00:00:02','192.168.1.2','tv','tv','V',?,5,9)", (NET,))
        con.commit(); con.close()
        d = dev("192.168.1.2", "aa:00:00:00:00:02"); history.annotate([d])
        self.assertFalse(d["trusted"]); self.assertEqual(d["first_seen"], 5)       # ancienne ligne conservée
        r = history.record_scan([d], now=1000, networks=[NET])
        self.assertEqual(r["baseline"], False)
        con = sqlite3.connect(history.PATH)
        try:
            self.assertEqual(con.execute("PRAGMA user_version").fetchone()[0], history.VERSION)
        finally:
            con.close()

    def test_ip_change_is_logged_with_old_and_new_address(self):
        history.record_scan([self.a], now=1000, networks=[NET])
        history.record_scan([dev("192.168.1.77", "aa:00:00:00:00:02", "tv", "tv")], now=2000, networks=[NET])
        ev = [e for e in history.recent_events() if e["kind"] == "ip_changed"]
        self.assertEqual([e["detail"] for e in ev], ["192.168.1.2 → 192.168.1.77"])

    def test_offline_needs_two_missed_scans_then_online_when_back(self):
        history.record_scan([self.a, self.b], now=1 * H, networks=[NET])
        history.record_scan([self.b], now=2 * H, networks=[NET])                 # 1er scan manqué : on attend
        self.assertNotIn("offline", self.kinds())
        history.record_scan([self.b], now=3 * H, networks=[NET])                 # 2e : hors ligne
        self.assertEqual(self.kinds("aa:00:00:00:00:02"), ["first_seen", "offline"])
        history.record_scan([self.b], now=4 * H, networks=[NET])                 # pas de doublon
        self.assertEqual(self.kinds("aa:00:00:00:00:02").count("offline"), 1)
        history.record_scan([self.a, self.b], now=5 * H, networks=[NET])
        self.assertEqual(self.kinds("aa:00:00:00:00:02"), ["first_seen", "offline", "online"])

    def test_one_missed_scan_then_seen_again_is_no_flapping(self):
        history.record_scan([self.a], now=1 * H, networks=[NET])
        history.record_scan([], now=2 * H, networks=[NET])
        history.record_scan([self.a], now=3 * H, networks=[NET])
        history.record_scan([], now=4 * H, networks=[NET])
        self.assertEqual(self.kinds("aa:00:00:00:00:02"), ["first_seen"])         # les ratés ne s'accumulent pas

    def test_absence_only_counts_for_scanned_networks(self):
        other = dev("10.0.0.5", "", "x", net="10.0.0.0/24")
        history.record_scan([self.a, other], now=1 * H, networks=[NET, "10.0.0.0/24"])
        for i in (2, 3, 4):
            history.record_scan([self.a], now=i * H, networks=[NET])             # 10.0.0.0/24 n'est pas scanné
        self.assertNotIn("offline", self.kinds("ip:10.0.0.5"))

    def test_presence_bar_and_uptime(self):
        history.record_scan([self.a], now=1 * H, networks=[NET])
        history.record_scan([self.a], now=2 * H, networks=[NET])
        history.record_scan([], now=3 * H, networks=[NET])
        history.record_scan([self.a], now=4 * H, networks=["10.0.0.0/24"])       # scan d'un autre réseau : ignoré
        s = history.device_summary(self.a, now=5 * H)
        self.assertEqual(s["presence"], [True, True, False])
        self.assertEqual((s["uptime7"], s["scans"]), (67, 3))
        self.assertIsNone(history.device_summary(dev("1.1.1.1", "ff:ff:ff:ff:ff:ff")))

    def test_trust_is_persisted_logged_and_reaches_offline_stubs(self):
        history.record_scan([self.a], now=1000, networks=[NET])
        history.set_trusted([self.a], True, now=1500)
        history.set_trusted([self.a], True, now=1600)                             # inchangé : pas de 2e événement
        d = dev("192.168.1.2", "aa:00:00:00:00:02"); history.annotate([d])
        self.assertTrue(d["trusted"])
        self.assertEqual(self.kinds().count("trusted"), 1)
        self.assertTrue(history.known_offline([], [NET], now=2000)[0]["trusted"])
        history.set_trusted([self.a], False, now=1700)
        self.assertEqual(self.kinds()[-1], "untrusted")

    def test_forget_removes_device_and_presence(self):
        history.record_scan([self.a, self.b], now=1000, networks=[NET])
        history.forget(self.a)
        self.assertEqual([d["hostname"] for d in history.known_offline([], [NET], now=1000)], ["pc"])
        self.assertIsNone(history.device_summary(self.a, now=1000))

    def test_old_presence_is_pruned(self):
        history.record_scan([self.a], now=1000, networks=[NET])
        history.record_scan([self.a], now=1000 + 91 * 86400, networks=[NET])
        s = history.device_summary(self.a, now=1000 + 91 * 86400)
        self.assertEqual(s["scans"], 1)

    def test_baseline_is_logged_as_reference(self):
        history.record_scan([self.a], now=1000, networks=[NET])
        self.assertEqual(history.recent_events()[0]["detail"], "première analyse")


class IdentityTests(unittest.TestCase):
    """L'identité passe par la MAC d'abord : l'IP seule ne doit jamais créer de doublon."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        history.PATH = os.path.join(self.tmp.name, "Panther", "panther.db")

    def tearDown(self):
        self.tmp.cleanup()

    def count(self):
        import sqlite3
        con = sqlite3.connect(history.PATH)
        try:
            return con.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        finally:
            con.close()

    def test_ip_change_keeps_one_record_and_trust(self):
        a = dev("192.168.1.2", "aa:00:00:00:00:02", "tv", "tv")
        history.record_scan([a], now=1000, networks=[NET]); history.set_trusted([a], True, now=1100)
        b = dev("192.168.1.99", "aa:00:00:00:00:02", "tv", "tv")
        history.record_scan([b], now=2000, networks=[NET]); history.annotate([b])
        self.assertEqual(self.count(), 1)
        self.assertTrue(b["trusted"])                      # la confiance suit l'appareil, pas l'adresse
        self.assertEqual(b["key"], "aa:00:00:00:00:02")

    def test_device_that_gains_a_mac_is_merged_not_duplicated(self):
        history.record_scan([dev("10.0.0.5", "", "cam", "camera", net="10.0.0.0/24")], now=1000, networks=["10.0.0.0/24"])
        history.set_trusted([dev("10.0.0.5", "", "cam", "camera", net="10.0.0.0/24")], True, now=1100)
        d = dev("10.0.0.5", "bb:00:00:00:00:05", "cam", "camera", net="10.0.0.0/24")      # SNMP vient de révéler sa MAC
        history.record_scan([d], now=2000, networks=["10.0.0.0/24"]); history.annotate([d])
        self.assertEqual(self.count(), 1)
        self.assertTrue(d["trusted"])
        s = history.device_summary(d, now=3000)
        self.assertEqual(s["first_seen"], 1000)             # historique conservé
        self.assertEqual(s["scans"], 2)
        self.assertEqual(len([e for e in history.recent_events() if e["kind"] == "first_seen"]), 1)

    def test_device_that_temporarily_loses_its_mac_is_still_the_same(self):
        history.record_scan([dev("192.168.1.2", "aa:00:00:00:00:02", "tv")], now=1000, networks=[NET])
        d = dev("192.168.1.2", "", "tv")
        r = history.record_scan([d], now=2000, networks=[NET])
        self.assertEqual((self.count(), r["new"], d["key"]), (1, [], "aa:00:00:00:00:02"))

    def test_ambiguous_ip_is_not_merged_by_guesswork(self):
        history.record_scan([dev("192.168.1.2", "aa:00:00:00:00:02", "tv")], now=1000, networks=[NET])
        history.record_scan([dev("192.168.1.2", "aa:00:00:00:00:99", "autre")], now=1500, networks=[NET])  # même IP, autre MAC
        d = dev("192.168.1.2", "", "?")
        history.record_scan([d], now=2000, networks=[NET])
        self.assertEqual(d["key"], "ip:192.168.1.2")        # ambigu : on ne fusionne pas à tort, entrée séparée
        self.assertEqual(self.count(), 3)

    def test_reassigned_ip_creates_a_new_device_not_a_merge(self):
        history.record_scan([dev("192.168.1.20", "aa:00:00:00:00:02", "ancien")], now=1000, networks=[NET])
        r = history.record_scan([dev("192.168.1.20", "cc:00:00:00:00:07", "nouveau")], now=2000, networks=[NET])
        self.assertEqual((self.count(), r["new"]), (2, ["cc:00:00:00:00:07"]))

    def test_offline_stub_carries_its_key(self):
        history.record_scan([dev("192.168.1.2", "aa:00:00:00:00:02")], now=1000, networks=[NET])
        self.assertEqual(history.known_offline([], [NET], now=1000)[0]["key"], "aa:00:00:00:00:02")


class PositionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        history.PATH = os.path.join(self.tmp.name, "Panther", "panther.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_positions_are_saved_per_layout_and_overwritten(self):
        history.save_position("hierarchique", "k1", 10, 20)
        history.save_position("hierarchique", "k1", 30, 40)
        history.save_position("etoile", "k1", 1, 2)
        self.assertEqual(history.load_positions("hierarchique"), {"k1": (30.0, 40.0)})
        self.assertEqual(history.load_positions("etoile"), {"k1": (1.0, 2.0)})

    def test_clear_only_resets_the_given_layout(self):
        history.save_position("hierarchique", "k1", 1, 1); history.save_position("etoile", "k1", 2, 2)
        history.clear_positions("hierarchique")
        self.assertEqual((history.load_positions("hierarchique"), history.load_positions("etoile")), ({}, {"k1": (2.0, 2.0)}))

    def test_forgetting_a_device_forgets_its_positions(self):
        d = dev("192.168.1.2", "aa:00:00:00:00:02")
        history.record_scan([d], now=1000, networks=[NET]); history.save_position("etoile", d["key"], 5, 5)
        history.forget(d)
        self.assertEqual(history.load_positions("etoile"), {})

    def test_v1_database_gets_the_positions_table(self):
        import sqlite3
        history.record_scan([dev("192.168.1.2", "aa:00:00:00:00:02")], now=1000, networks=[NET])
        con = sqlite3.connect(history.PATH); con.execute("DROP TABLE positions"); con.execute("PRAGMA user_version=1"); con.commit(); con.close()
        self.assertEqual(history.load_positions("etoile"), {})                  # recréée à l'ouverture


def finding(fid, sev="moyen", title=None):
    return {"id": fid, "severity": sev, "title": title or fid, "detail": "", "remedy": "", "port": None}


class FindingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        history.PATH = os.path.join(self.tmp.name, "Panther", "panther.db")
        self.d = dev("192.168.1.2", "aa:00:00:00:00:02", "cam", "camera")
        history.record_scan([self.d], now=1000, networks=[NET])

    def tearDown(self):
        self.tmp.cleanup()

    def kinds(self):
        return [e["kind"] for e in history.recent_events(50)][::-1]

    def test_first_security_scan_is_a_silent_baseline(self):
        self.d["security"] = [finding("telnet", "élevé")]
        r = history.record_findings([self.d], now=2000)
        self.assertEqual((r["baseline"], r["new"], r["fixed"]), (True, [], []))
        self.assertNotIn("exposure", self.kinds())

    def test_new_exposure_then_fixed_exposure_are_logged(self):
        self.d["security"] = [finding("telnet", "élevé")]; history.record_findings([self.d], now=2000)
        self.d["security"] = [finding("telnet", "élevé"), finding("redis-open", "critique", "Redis sans mot de passe")]
        r = history.record_findings([self.d], now=3000)
        self.assertEqual([f["id"] for _, f in r["new"]], ["redis-open"])           # telnet n'est pas « nouveau »
        self.d["security"] = [finding("redis-open", "critique", "Redis sans mot de passe")]
        r = history.record_findings([self.d], now=4000)
        self.assertEqual([t for _, t in r["fixed"]], ["telnet"])
        ev = history.recent_events(10)
        self.assertEqual([(e["kind"], e["detail"]) for e in ev][:2], [("exposure_fixed", "telnet"), ("exposure", "Redis sans mot de passe (critique)")])

    def test_devices_not_analysed_or_offline_are_ignored(self):
        self.d["security"] = None
        history.record_findings([self.d], now=2000)                                 # pas analysé : ne compte même pas comme référence...
        self.d["security"] = [finding("telnet", "élevé")]
        self.assertTrue(history.record_findings([dict(self.d, online=False)], now=3000)["baseline"])

    def test_empty_findings_list_means_analysed_and_clean(self):
        self.d["security"] = []
        r = history.record_findings([self.d], now=2000)
        self.assertEqual((r["new"], r["fixed"]), ([], []))
        self.d["security"] = [finding("ftp")]
        self.assertEqual(len(history.record_findings([self.d], now=3000)["new"]), 1)    # la référence existait déjà

    def test_forgetting_a_device_forgets_its_findings(self):
        import sqlite3
        self.d["security"] = [finding("telnet")]; history.record_findings([self.d], now=2000)
        history.forget(self.d)
        con = sqlite3.connect(history.PATH)
        try:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM findings").fetchone()[0], 0)
        finally:
            con.close()

    def test_v2_database_is_upgraded(self):
        import sqlite3
        con = sqlite3.connect(history.PATH); con.execute("DROP TABLE findings"); con.execute("DROP TABLE meta"); con.execute("PRAGMA user_version=2"); con.commit(); con.close()
        self.d["security"] = []
        history.record_findings([self.d], now=2000)                                  # recrée les tables sans erreur


class DbSizeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        history.PATH = os.path.join(self.tmp.name, "p.db")

    def tearDown(self):
        self.tmp.cleanup()

    def fill(self, n=30):
        for i in range(n):  # un scan par jour, avec un appareil qui change
            d = dev("192.168.1.2", "aa:00:00:00:00:02"); d["ports"] = [i]
            history.record_scan([d], now=1000 + i * 86400, networks=[NET])

    def test_stats_describe_the_content_and_size(self):
        self.fill(5)
        st = history.db_stats()
        self.assertEqual((st["devices"], st["scans"], st["snapshots"]), (1, 5, 5))
        self.assertGreater(st["events"], 0)
        self.assertGreater(st["size"], 4096)
        self.assertEqual(st["oldest_scan"], 1000)

    def test_stats_on_an_empty_history_do_not_crash(self):
        st = history.db_stats()
        self.assertEqual((st["devices"], st["scans"], st["oldest_scan"]), (0, 0, None))

    def test_purge_removes_old_scans_snapshots_and_events_but_keeps_known_devices(self):
        self.fill(30)
        before = history.db_stats()
        r = history.purge(10, now=1000 + 29 * 86400)
        after = history.db_stats()
        self.assertEqual(r["scans"], 19)                                             # il reste les scans des 10 derniers jours
        self.assertEqual((after["scans"], after["snapshots"], after["devices"]), (11, 11, 1))
        self.assertLessEqual(after["size"], before["size"])
        self.assertEqual(len(history.list_scans()), 11)

    def test_purge_can_keep_the_journal_longer_than_the_presence_data(self):
        self.fill(30)
        history.record_scan([dev("192.168.1.9", "aa:00:00:00:00:09")], now=1000 + 30 * 86400, networks=[NET])   # événement récent
        history.purge(5, events_days=100, now=1000 + 30 * 86400)
        self.assertGreaterEqual(len(history.recent_events(50)), 2)                    # le journal est conservé
        self.assertEqual(history.db_stats()["scans"], 6)

    def test_purge_with_nothing_old_changes_nothing(self):
        self.fill(3)
        self.assertEqual(history.purge(365, now=1000 + 3 * 86400), {"scans": 0, "events": 0})
        self.assertEqual(history.db_stats()["scans"], 3)


if __name__ == "__main__":
    unittest.main()
