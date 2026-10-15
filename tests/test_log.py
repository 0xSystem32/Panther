import logging
import os
import sys
import tempfile
import threading
import unittest

from panther import log, scanner


class LogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "sub", "panther.log")
        self._hooks = (sys.excepthook, threading.excepthook)

    def tearDown(self):
        root = logging.getLogger("panther")
        for h in list(root.handlers):
            root.removeHandler(h); h.close()
        sys.excepthook, threading.excepthook = self._hooks
        self.tmp.cleanup()

    def read(self):
        for h in logging.getLogger("panther").handlers:
            h.flush()
        with open(self.path, encoding="utf-8") as f:
            return f.read()

    def test_file_is_created_and_levels_are_filtered(self):
        log.setup(path=self.path)
        log.get("scanner").warning("appareil %s muet", "192.168.1.9")
        log.get("scanner").debug("détail inutile")
        text = self.read()
        self.assertIn("WARNING panther.scanner: appareil 192.168.1.9 muet", text)
        self.assertNotIn("détail inutile", text)                                   # DEBUG ignoré hors mode verbeux

    def test_verbose_keeps_debug_and_adds_the_console(self):
        root = log.setup(path=self.path, verbose=True)
        log.get("x").debug("précis")
        self.assertIn("précis", self.read())
        self.assertTrue(any(isinstance(h, logging.StreamHandler) and not hasattr(h, "baseFilename") for h in root.handlers))

    def test_setup_twice_does_not_duplicate_lines(self):
        log.setup(path=self.path); log.setup(path=self.path)
        log.get("x").warning("une seule fois")
        self.assertEqual(self.read().count("une seule fois"), 1)

    def test_uncaught_exception_is_logged_with_its_traceback(self):
        log.setup(path=self.path)
        import contextlib
        import io
        try:
            raise ValueError("boum")
        except ValueError:
            with contextlib.redirect_stderr(io.StringIO()):                             # le crochet d'origine affiche aussi la trace
                sys.excepthook(*sys.exc_info())
        text = self.read()
        self.assertIn("CRITICAL", text); self.assertIn("ValueError: boum", text); self.assertIn("Traceback", text)

    def test_exception_in_a_thread_is_logged(self):
        log.setup(path=self.path)
        t = threading.Thread(target=lambda: 1 / 0, name="scan-test"); t.start(); t.join()
        text = self.read()
        self.assertIn("thread scan-test", text); self.assertIn("ZeroDivisionError", text)

    def test_unwritable_location_falls_back_to_the_console_without_crashing(self):
        blocker = os.path.join(self.tmp.name, "fichier")
        open(blocker, "w").close()
        root = log.setup(path=os.path.join(blocker, "impossible", "p.log"))        # « fichier » n'est pas un dossier
        self.assertTrue(root.handlers)
        log.get("x").warning("ne plante pas")

    def test_log_never_contains_the_snmp_community(self):
        log.setup(path=self.path)
        sc = scanner.Scanner()
        found = set()
        orig = scanner.snmp.read_tables
        scanner.snmp.read_tables = lambda host, comm, port=161: (_ for _ in ()).throw(scanner.snmp.SnmpError("pas de réponse"))
        try:
            sc._read_snmp([{"host": "192.168.1.254", "community": "SECRET-COMM"}], [], found)
        finally:
            scanner.snmp.read_tables = orig
        text = self.read()
        self.assertIn("SNMP 192.168.1.254", text)
        self.assertNotIn("SECRET-COMM", text)

    def test_scanner_logs_a_device_that_cannot_be_analysed(self):
        with self.assertLogs("panther.scanner", level="WARNING") as cm:
            scanner.log.warning("Analyse de %s impossible", "192.168.1.9", exc_info=False)
        self.assertIn("192.168.1.9", cm.output[0])


if __name__ == "__main__":
    unittest.main()
