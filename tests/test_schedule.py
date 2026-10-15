import os
import tempfile
import time
import unittest

from panther import schedule

H = 3600


class DueTests(unittest.TestCase):
    def test_never_run_is_due(self):
        for f in ("daily", "weekly"):
            self.assertTrue(schedule.is_due(None, 1000, f))
            self.assertTrue(schedule.is_due(0, 1000, f))

    def test_boundaries(self):
        now = 10 * 24 * H
        self.assertFalse(schedule.is_due(now - 24 * H + 1, now, "daily"))
        self.assertTrue(schedule.is_due(now - 24 * H, now, "daily"))
        self.assertFalse(schedule.is_due(now - 7 * 24 * H + 1, now, "weekly"))
        self.assertTrue(schedule.is_due(now - 7 * 24 * H, now, "weekly"))

    def test_unknown_frequency_is_never_due(self):
        self.assertFalse(schedule.is_due(None, 1000, "hourly"))
        self.assertFalse(schedule.is_due(None, 1000, None))

    def test_a_last_date_in_the_far_future_does_not_block_forever(self):
        self.assertTrue(schedule.is_due(5000 + 3 * 24 * H, 5000, "daily"))               # horloge remise en arrière : on reprend
        self.assertFalse(schedule.is_due(5000 + 60, 5000, "daily"))                        # quelques secondes d'écart : pas de rapport en double

    def test_filename_format_matches_the_prune_pattern(self):
        n = schedule.filename(1_700_000_000)
        self.assertRegex(n, r"^rapport-panther-\d{4}-\d{2}-\d{2}_\d{4}\.pdf$")
        self.assertTrue(schedule._NAME.match(n))


class PruneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def touch(self, name):
        with open(os.path.join(self.d, name), "w") as f:
            f.write("x")

    def names(self):
        return sorted(os.listdir(self.d))

    def test_keeps_the_newest_and_deletes_the_oldest(self):
        for day in range(1, 6):
            self.touch(f"rapport-panther-2026-10-0{day}_0800.pdf")
        removed = schedule.prune(self.d, 2)
        self.assertEqual(len(removed), 3)
        self.assertEqual(self.names(), ["rapport-panther-2026-10-04_0800.pdf", "rapport-panther-2026-10-05_0800.pdf"])

    def test_never_touches_other_files_directories_or_symlinks(self):
        self.touch("rapport-panther-2026-10-01_0800.pdf"); self.touch("rapport-panther-2026-10-02_0800.pdf")
        self.touch("mes-notes.pdf"); self.touch("rapport-panther-2026-10-01_0800.pdf.bak"); self.touch("rapport-panther-xx.pdf")
        self.touch("rapport-panther-2026-10-01_0800.PDF")
        os.mkdir(os.path.join(self.d, "rapport-panther-2026-09-01_0800.pdf"))             # un DOSSIER portant un nom de rapport
        target = os.path.join(self.tmp.name, "important.txt"); open(target, "w").write("précieux")
        os.symlink(target, os.path.join(self.d, "rapport-panther-2026-08-01_0800.pdf"))   # un LIEN portant un nom de rapport
        before = set(self.names())
        schedule.prune(self.d, 1)
        after = set(self.names())
        self.assertEqual(before - after, {"rapport-panther-2026-10-01_0800.pdf"})            # seul le plus ancien vrai rapport a disparu
        self.assertTrue(os.path.exists(target))

    def test_keep_is_clamped_to_at_least_one(self):
        self.touch("rapport-panther-2026-10-01_0800.pdf"); self.touch("rapport-panther-2026-10-02_0800.pdf")
        for bad in (0, -5):
            schedule.prune(self.d, bad)
            self.assertEqual(len(self.names()), 1)

    def test_missing_folder_and_nothing_to_remove(self):
        self.assertEqual(schedule.prune(os.path.join(self.d, "absent"), 3), [])
        self.touch("rapport-panther-2026-10-01_0800.pdf")
        self.assertEqual(schedule.prune(self.d, 5), [])

    def test_ensure_folder(self):
        sub = os.path.join(self.d, "a", "b")
        self.assertEqual(schedule.ensure_folder(sub), sub)
        self.assertTrue(os.path.isdir(sub))
        for bad in ("", None, "relatif/dossier"):
            with self.assertRaises(OSError, msg=repr(bad)):
                schedule.ensure_folder(bad)


if __name__ == "__main__":
    unittest.main()
