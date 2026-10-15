import importlib.util
import os
import tempfile
import unittest
from unittest import mock

from panther import history, scanner

HAS_QT = importlib.util.find_spec("PyQt6") is not None
NET = "192.168.1.0/24"


def dev(ip="192.168.1.5", mac="aa:00:00:00:00:05", **kw):
    d = {"ip": ip, "mac": mac, "hostname": "tv", "type": "tv", "vendor": "V", "network": NET, "online": True, "os": "L", "ports": []}
    d.update(kw)
    return d


class PingTests(unittest.TestCase):
    def run_ping(self, out):
        scanner._rtt_cache.clear()
        with mock.patch.object(scanner.subprocess, "run", lambda *a, **k: mock.Mock(stdout=out)):
            return scanner.ping_ttl("192.168.1.5")

    def test_ttl_and_latency_come_from_the_same_ping(self):
        ttl = self.run_ping("64 bytes from 192.168.1.5: icmp_seq=1 ttl=64 time=3.42 ms\n")
        self.assertEqual((ttl, scanner._rtt_cache["192.168.1.5"]), (64, 3.42))

    def test_sub_millisecond_and_missing_values(self):
        self.run_ping("64 bytes from x: icmp_seq=1 ttl=64 time<1 ms\n")
        self.assertEqual(scanner._rtt_cache["192.168.1.5"], 1.0)
        self.assertIsNone(self.run_ping("no answer"))
        self.assertNotIn("192.168.1.5", scanner._rtt_cache)

    def test_ping_failure_is_silent(self):
        scanner._rtt_cache.clear()
        with mock.patch.object(scanner.subprocess, "run", side_effect=OSError("pas de ping")):
            self.assertIsNone(scanner.ping_ttl("192.168.1.5"))


class HistoryLatencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        history.PATH = os.path.join(self.tmp.name, "p.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_series_keeps_measures_absences_and_unmeasured_presences(self):
        d = dev()
        history.record_scan([dict(d, rtt=2.5)], now=1000, networks=[NET])
        history.record_scan([dev("192.168.1.9", "aa:00:00:00:00:09")], now=2000, networks=[NET])          # d est absent
        history.record_scan([d], now=3000, networks=[NET])                                                 # présent, sans mesure (présence)
        history.record_scan([dict(d, rtt=4.5)], now=4000, networks=[NET])
        self.assertEqual(history.latency_series(d), [(1000, 2.5, True), (2000, None, False), (3000, None, True), (4000, 4.5, True)])
        s = history.latency_summary(history.latency_series(d))
        self.assertEqual((s["n"], s["min"], s["max"], s["last"], s["missed"]), (2, 2.5, 4.5, 4.5, 1))
        self.assertAlmostEqual(s["avg"], 3.5)

    def test_summary_without_any_measure_and_bad_values_are_ignored(self):
        self.assertIsNone(history.latency_summary([]))
        d = dev()
        for i, bad in enumerate((-5, 10 ** 9, "vite", None, float("nan"))):
            history.record_scan([dict(d, rtt=bad)], now=1000 + i, networks=[NET])
        self.assertTrue(all(ms is None for _t, ms, _p in history.latency_series(d)))

    def test_limit_and_network_filter(self):
        d = dev()
        for i in range(10):
            history.record_scan([dict(d, rtt=float(i))], now=1000 + i, networks=[NET])
        history.record_scan([dev("10.9.9.9", "aa:00:00:00:00:99", network="10.9.9.0/24")], now=2000, networks=["10.9.9.0/24"])
        s = history.latency_series(d, last=4)
        self.assertEqual([ms for _t, ms, _p in s], [6.0, 7.0, 8.0, 9.0])                                   # les 4 derniers scans de CE réseau

    def test_existing_database_is_migrated_without_losing_presence(self):
        import sqlite3
        con = sqlite3.connect(history.PATH)
        con.executescript("CREATE TABLE devices(key TEXT PRIMARY KEY, mac TEXT, ip TEXT, name TEXT, type TEXT, vendor TEXT, network TEXT, first_seen REAL, last_seen REAL);"
                          "CREATE TABLE scans(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, depth TEXT, networks TEXT);"
                          "CREATE TABLE seen(scan_id INTEGER NOT NULL, key TEXT NOT NULL, ip TEXT);"
                          "INSERT INTO seen VALUES(1,'aa:00:00:00:00:05','192.168.1.5'); PRAGMA user_version=0;")
        con.commit(); con.close()
        history.record_scan([dict(dev(), rtt=1.5)], now=5000, networks=[NET])
        con = sqlite3.connect(history.PATH)
        self.assertIn("rtt", [r[1] for r in con.execute("PRAGMA table_info(seen)")])
        self.assertEqual(con.execute("PRAGMA user_version").fetchone()[0], history.VERSION)
        con.close()


@unittest.skipUnless(HAS_QT, "PyQt6 absent")
class ChartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PyQt6.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication([])

    def test_points_mark_gaps_and_scale_to_the_maximum(self):
        from panther.ui.widgets import LatencyChart
        c = LatencyChart([(1, 2.0, True), (2, None, False), (3, None, True), (4, 4.0, True)])
        pts = c.points(200, 54)
        self.assertEqual([p[2] for p in pts], ["ms", "absent", "sans mesure", "ms"])
        self.assertLess(pts[3][1], pts[0][1])                                                              # 4 ms est plus haut que 2 ms
        self.assertAlmostEqual(pts[0][0], 6); self.assertAlmostEqual(pts[3][0], 194)                       # première et dernière colonnes aux bords
        self.assertIn("4.0", c.toolTip())

    def test_single_point_and_painting_do_not_fail(self):
        from PyQt6.QtGui import QImage, QPainter

        from panther.ui.widgets import LatencyChart
        for series in ([(1, 3.0, True)], [(1, None, False)], [(i, float(i % 7), True) for i in range(60)]):
            c = LatencyChart(series); c.resize(220, 54)
            img = QImage(220, 54, QImage.Format.Format_ARGB32); img.fill(0)
            p = QPainter(img); c.render(p); p.end()


if __name__ == "__main__":
    unittest.main()
