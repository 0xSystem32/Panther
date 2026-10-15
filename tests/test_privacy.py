import logging
import os
import tempfile
import unittest

from panther import history, log, privacy, store


class PrivacyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = os.path.join(self.tmp.name, "Panther")
        os.makedirs(self.d, mode=0o755)
        history.PATH = os.path.join(self.d, "panther.db")
        store.PATH = os.path.join(self.d, "devices.json")

    def tearDown(self):
        self.tmp.cleanup()

    def dev(self, ip, mac):
        return {"ip": ip, "mac": mac, "hostname": "h", "type": "tv", "vendor": "V", "network": "192.168.1.0/24", "online": True, "os": "L", "ports": []}

    def test_database_and_folder_are_private(self):
        history.record_scan([self.dev("192.168.1.2", "aa:00:00:00:00:02")], now=1000, networks=["192.168.1.0/24"])
        self.assertEqual(privacy.mode_of(history.PATH), 0o600)
        self.assertEqual(privacy.mode_of(self.d), 0o700)

    def test_harden_ignores_missing_files_and_never_follows_symlinks(self):
        privacy.harden(os.path.join(self.d, "absent.db"))                                # pas d'exception
        target = os.path.join(self.tmp.name, "autre.txt"); open(target, "w").close(); os.chmod(target, 0o644)
        os.symlink(target, os.path.join(self.d, "x.db"))
        privacy.harden(os.path.join(self.d, "x.db"))
        self.assertEqual(privacy.mode_of(target), 0o644)

    def test_erase_all_empties_every_table_and_keeps_the_database_usable(self):
        a = self.dev("192.168.1.2", "aa:00:00:00:00:02")
        history.record_scan([a, self.dev("192.168.1.3", "aa:00:00:00:00:03")], now=1000, networks=["192.168.1.0/24"])
        history.set_meta(a, note="secret perso", tags=["enfants"], group="maison")
        removed = history.erase_all()
        self.assertGreater(removed, 0)
        st = history.db_stats()
        self.assertEqual((st["devices"], st["scans"], st["events"], st["snapshots"]), (0, 0, 0, 0))
        with open(history.PATH, "rb") as f:
            raw = f.read()
        for needle in (b"aa:00:00:00:00:02", b"192.168.1.3", b"secret perso"):
            self.assertNotIn(needle, raw)                                                # écrasé, pas seulement marqué libre
        res = history.record_scan([self.dev("192.168.1.9", "aa:00:00:00:00:09")], now=2000, networks=["192.168.1.0/24"])
        self.assertTrue(res["baseline"])                                                  # repart d'une nouvelle référence

    def test_erase_all_on_a_missing_database_is_harmless(self):
        self.assertEqual(history.erase_all(), 0)

    def test_store_erase_clears_manual_names(self):
        d = self.dev("192.168.1.2", "aa:00:00:00:00:02")
        store.set_override(d, name="Télé du salon")
        self.assertEqual(store.erase(), 1)
        self.assertEqual(store.load(), {})
        self.assertEqual(store.erase(), 0)

    def test_erase_file_truncates_log_removes_rotations_and_skips_symlinks(self):
        path = os.path.join(self.d, "panther.log")
        for suffix, text in (("", "a" * 50), (".1", "b" * 20), (".2", "c" * 10)):
            with open(path + suffix, "w") as f:
                f.write(text)
        outside = os.path.join(self.tmp.name, "important")
        with open(outside, "w") as f:
            f.write("garde-moi")
        os.symlink(outside, os.path.join(self.d, "liens.log"))
        freed = privacy.erase_file(path, backups=2)
        self.assertEqual((freed, os.path.getsize(path), os.path.exists(path + ".1"), os.path.exists(path + ".2")), (80, 0, False, False))
        self.assertEqual(privacy.erase_file(os.path.join(self.d, "liens.log")), 0)
        with open(outside) as f:
            self.assertEqual(f.read(), "garde-moi")

    def test_log_file_is_private_and_still_writes_after_being_erased(self):
        path = os.path.join(self.d, "panther.log")
        log.setup(path=path)
        try:
            logging.getLogger("panther.test").warning("avant")
            self.assertEqual(privacy.mode_of(path), 0o600)
            privacy.erase_file(path, backups=2)
            logging.getLogger("panther.test").warning("après")
            with open(path, encoding="utf-8") as f:
                content = f.read()
            self.assertIn("après", content); self.assertNotIn("avant", content)
            self.assertNotIn("\x00", content)                                            # pas de trou nul si l'écriture reprend au mauvais offset
        finally:
            log.setup(path=os.path.join(self.tmp.name, "autre.log"))


if __name__ == "__main__":
    unittest.main()
