import os
import sqlite3
import tempfile
import unittest

from panther import history

NET = "192.168.1.0/24"


def dev(ip="192.168.1.2", mac="aa:00:00:00:00:02", name="tv", **kw):
    d = {"ip": ip, "mac": mac, "hostname": name, "type": "tv", "vendor": "V", "network": NET, "online": True, "os": "L", "ports": []}
    d.update(kw)
    return d


class MetaBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        history.PATH = os.path.join(self.tmp.name, "p.db")

    def tearDown(self):
        self.tmp.cleanup()

    def scanned(self, d=None):
        d = d or dev()
        history.record_scan([d], now=1000, networks=[NET])
        return d


class CleanTagsTests(unittest.TestCase):
    def test_text_is_split_on_commas_trimmed_and_deduplicated_ignoring_case(self):
        self.assertEqual(history.clean_tags("enfants,  Domotique , enfants,ENFANTS ,"), ["enfants", "Domotique"])

    def test_lists_are_accepted_and_newlines_commas_are_neutralised(self):
        self.assertEqual(history.clean_tags(["a\nb", "c,d", "  "]), ["a b", "c d"])

    def test_limits(self):
        self.assertEqual(len(history.clean_tags([f"t{i}" for i in range(50)])), history.MAX_TAGS)
        self.assertEqual(len(history.clean_tags(["x" * 500])[0]), history.MAX_TAG_LEN)
        self.assertEqual(history.clean_tags(None), [])
        self.assertEqual(history.clean_tags(""), [])


class MetaTests(MetaBase):
    def test_set_and_read_back_through_annotate(self):
        d = self.scanned()
        history.set_meta(d, note="Salon, étagère de gauche", tags="enfants, domotique", group="Salon")
        fresh = dev()
        history.annotate([fresh])
        self.assertEqual((fresh["note"], fresh["tags"], fresh["group"]), ("Salon, étagère de gauche", ["enfants", "domotique"], "Salon"))

    def test_devices_without_metadata_get_empty_defaults(self):
        d = self.scanned()
        history.annotate([d])
        self.assertEqual((d["note"], d["tags"], d["group"]), ("", [], ""))

    def test_omitted_fields_are_left_unchanged_and_all_empty_deletes_the_row(self):
        d = self.scanned()
        history.set_meta(d, note="n", tags="a", group="g")
        history.set_meta(d, tags="b")
        self.assertEqual((d["note"], d["tags"], d["group"]), ("n", ["b"], "g"))
        history.set_meta(d, note="", tags="", group="")
        con = sqlite3.connect(history.PATH)
        try:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM device_meta").fetchone()[0], 0)
        finally:
            con.close()

    def test_values_are_bounded(self):
        d = self.scanned()
        history.set_meta(d, note="x" * 10000, group="g" * 500)
        self.assertEqual((len(d["note"]), len(d["group"])), (history.MAX_NOTE, history.MAX_GROUP))

    def test_metadata_is_stored_as_data_never_interpreted(self):
        d = self.scanned()
        evil = "'); DROP TABLE devices; --"
        history.set_meta(d, note=evil, tags=evil, group=evil)
        again = dev(); history.annotate([again])
        self.assertEqual(again["note"], evil)
        self.assertEqual(len(history.known_offline([], [NET], now=1000)), 1)                    # la table existe toujours

    def test_offline_devices_keep_their_metadata(self):
        d = self.scanned()
        history.set_meta(d, tags="à surveiller", group="Bureau")
        off = history.known_offline([], [NET], now=1000)[0]
        self.assertEqual((off["tags"], off["group"]), (["à surveiller"], "Bureau"))

    def test_groups_are_listed_sorted_without_duplicates(self):
        for i, g in enumerate(["salon", "Bureau", "salon", ""]):
            d = dev(ip=f"192.168.1.{10 + i}", mac=f"aa:00:00:00:00:{10 + i:02x}")
            history.record_scan([d], now=1000 + i, networks=[NET])
            history.set_meta(d, group=g, note="x" if not g else None)
        self.assertEqual(history.meta_groups(), ["Bureau", "salon"])

    def test_metadata_is_per_device_and_survives_an_ip_change(self):
        a = self.scanned()
        history.set_meta(a, group="Salon")
        moved = dev(ip="192.168.1.99")
        history.record_scan([moved], now=2000, networks=[NET])
        history.annotate([moved])
        self.assertEqual(moved["group"], "Salon")                                                # la clé est la MAC

    def test_forgetting_a_device_forgets_its_metadata(self):
        d = self.scanned()
        history.set_meta(d, note="x")
        history.forget(d)
        con = sqlite3.connect(history.PATH)
        try:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM device_meta").fetchone()[0], 0)
        finally:
            con.close()

    def test_v5_database_is_upgraded(self):
        d = self.scanned()
        con = sqlite3.connect(history.PATH)
        con.execute("DROP TABLE device_meta"); con.execute("PRAGMA user_version=5"); con.commit(); con.close()
        history.set_meta(d, note="après migration")                                                # recrée la table sans erreur
        self.assertEqual(d["note"], "après migration")


class MergeMetaTests(MetaBase):
    OLD, NEW = "7a:00:00:00:00:01", "06:00:00:00:00:02"

    def two(self):
        a, b = dev(mac=self.OLD, ip="192.168.1.27"), dev(mac=self.NEW, ip="192.168.1.14")
        history.record_scan([a], now=1000, networks=[NET])
        history.record_scan([b], now=2000, networks=[NET])
        return a, b

    def test_tags_are_united_notes_joined_and_the_kept_group_wins(self):
        a, b = self.two()
        history.set_meta(a, tags="enfants, ipad", note="ancien", group="Chambre")
        history.set_meta(b, tags="Enfants, domotique", note="récent", group="Salon")
        history.merge_devices(self.NEW, self.OLD, now=3000)
        d = dev(mac=self.NEW); history.annotate([d])
        self.assertEqual(d["tags"], ["Enfants", "domotique", "ipad"])
        self.assertEqual((d["note"], d["group"]), ("récent | ancien", "Salon"))

    def test_metadata_of_the_merged_away_device_moves_when_the_kept_one_has_none(self):
        a, b = self.two()
        history.set_meta(a, tags="tablette", group="Chambre")
        history.merge_devices(self.NEW, self.OLD, now=3000)
        d = dev(mac=self.NEW); history.annotate([d])
        self.assertEqual((d["tags"], d["group"]), (["tablette"], "Chambre"))
        con = sqlite3.connect(history.PATH)
        try:
            self.assertEqual([r[0] for r in con.execute("SELECT key FROM device_meta")], [self.NEW])
        finally:
            con.close()


if __name__ == "__main__":
    unittest.main()
