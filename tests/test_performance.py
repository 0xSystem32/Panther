"""Garde-fous de performance : un réseau de 250 appareils doit rester fluide. Les seuils sont larges (≈ 5 à 10 fois les mesures
habituelles) pour ne pas échouer sur une machine d'intégration lente, mais ils attrapent une régression quadratique."""
import importlib.util
import os
import tempfile
import time
import unittest

from panther import compare, exporter, history, layout, reportpdf, security, store

HAS_QT = importlib.util.find_spec("PyQt6") is not None
N = 250
NET = "10.0.0.0/22"


def devices(n=N):
    kinds = ["phone", "tv", "camera", "printer", "nas", "iot", "desktop", "laptop", "tablet", "speaker"]
    out = []
    for i in range(n):
        ip = f"10.0.{i // 250}.{i % 250 + 1}"
        out.append({"ip": ip, "mac": "aa:00:00:%02x:%02x:%02x" % (i // 65536, i // 256 % 256, i % 256), "hostname": f"appareil-{i}", "type": kinds[i % 10],
                    "vendor": "V", "os": "Linux", "ports": [80, 443] if i % 3 == 0 else [], "services": [], "banners": {}, "ttl": 64, "is_gateway": i == 0,
                    "is_self": i == 1, "random_mac": False, "online": True, "confidence": 80, "reasons": [], "model": "", "network": NET, "vlan": None,
                    "mdns_services": [], "mdns_names": [], "mdns_txt": {}, "ssdp": {}, "path": [], "security": None})
    return out


class Timer:
    def __init__(self, limit, what):
        self.limit, self.what = limit, what

    def __enter__(self):
        self.t0 = time.perf_counter()

    def __exit__(self, *exc):
        took = time.perf_counter() - self.t0
        if not exc[0]:
            assert took < self.limit, f"{self.what} : {took:.2f} s (limite {self.limit} s)"


class EngineSpeedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        history.PATH = os.path.join(self.tmp.name, "p.db")
        store.PATH = os.path.join(self.tmp.name, "d.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_recording_250_devices_over_many_scans(self):
        ds = devices()
        with Timer(15, "10 scans de 250 appareils enregistrés"):
            for k in range(10):
                history.record_scan(ds, now=1_700_000_000 + k * 3600, networks=[NET])
        self.assertEqual(history.db_stats()["devices"], N)

    def test_snapshot_comparison_and_purge(self):
        ds = devices()
        history.record_scan(ds, now=1_700_000_000, networks=[NET])
        history.record_scan(ds[:-20], now=1_700_003_600, networks=[NET])
        scans = history.list_scans()
        with Timer(2, "comparaison de deux scans de 250 appareils"):
            res = compare.compare(history.load_snapshot(scans[1]["id"]), history.load_snapshot(scans[0]["id"]))
        self.assertEqual((len(res["gone"]), len(res["new"])), (20, 0))
        with Timer(5, "purge + compactage"):
            history.purge(1, now=1_800_000_000)

    def test_layouts_of_250_devices(self):
        ds = devices()
        with Timer(1, "disposition par type"):
            pos, _ = layout.type_clusters(ds)
        self.assertEqual(len(pos), N)
        with Timer(2, "arbre hiérarchique"):
            tree = layout.build_tree(ds, NET, [{"cidr": NET, "kind": "local", "vlan": None}])
            layout.hierarchical_positions(tree)

    def test_exports_and_security_analysis(self):
        ds = devices()
        with Timer(2, "analyse d'exposition de 250 appareils"):
            for d in ds:
                d["security"] = security.analyze(d)
        with Timer(2, "CSV + JSON + rapport Markdown"):
            exporter.to_csv(ds)
            exporter.to_json(ds, [NET])
            security.report_markdown(ds, [NET])
        with Timer(2, "HTML du rapport PDF"):
            reportpdf.build_html(ds, [NET], 0, None, True)


@unittest.skipUnless(HAS_QT, "PyQt6 absent")
class UiSpeedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PyQt6.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        from PyQt6.QtCore import QSettings

        from panther import ui  # noqa: F401
        from panther.ui import theme, window
        self.tmp = tempfile.TemporaryDirectory()
        history.PATH = os.path.join(self.tmp.name, "p.db")
        store.PATH = os.path.join(self.tmp.name, "d.json")
        QSettings.setPath(QSettings.Format.NativeFormat, QSettings.Scope.UserScope, self.tmp.name)
        theme.T.update(theme.THEMES["dark"])
        from panther import networks
        self._auto, networks.auto_targets = networks.auto_targets, (lambda *a, **k: [])
        self.w = window.Main()
        self.w.notify = lambda *a: None
        self.w.network = {"iface": "eth0", "cidr": NET, "gateway": "10.0.0.1", "vlan": None, "kind": "ethernet"}
        self.w.networks_info = [{"cidr": NET, "kind": "local", "vlan": None}]
        self.w.show()

    def tearDown(self):
        from panther import networks
        networks.auto_targets = self._auto
        self.w.close()
        self.tmp.cleanup()

    def test_map_table_and_layout_switch_with_250_devices(self):
        self.w.devices = devices()
        with Timer(8, "carte étoile de 250 nœuds"):
            self.w.rebuild()
        self.assertEqual(len(self.w.nodes), N)
        for mode in ("hierarchique", "types", "etoile"):
            with Timer(8, f"disposition {mode}"):
                self.w.set_layout(mode)
        with Timer(3, "filtre de la liste"):
            self.w.search.setText("appareil-12")
            self.app.processEvents()
        with Timer(5, "image de la carte pour l'export"):
            img = self.w.render_map_image()
        self.assertFalse(img.isNull())

    def test_incremental_scan_updates_stay_cheap(self):
        ds = devices()
        self.w.devices = ds[:20]
        self.w.rebuild()
        with Timer(10, "200 mises à jour incrémentales pendant un scan"):
            for i in range(21, N, 1):
                self.w.live_update(ds[:i])
        self.assertGreaterEqual(len(self.w.nodes), 20)

    def test_selecting_everything_and_painting_the_minimap(self):
        self.w.devices = devices()
        self.w.rebuild()
        with Timer(5, "sélection de 250 appareils et panneau de synthèse"):
            self.w.select_all_nodes()
            self.app.processEvents()
        self.assertEqual(len(self.w.selected_keys), N)
        self.w.view.scale(3, 3)
        with Timer(2, "dessin de la mini-carte"):
            from PyQt6.QtGui import QImage, QPainter
            img = QImage(self.w.view.viewport().size(), QImage.Format.Format_ARGB32)
            p = QPainter(img)
            self.w.view.paint_minimap(p)
            p.end()


if __name__ == "__main__":
    unittest.main()
