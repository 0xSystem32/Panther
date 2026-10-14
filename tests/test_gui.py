"""Tests d'interface, hors écran (ignorés si PyQt6 n'est pas installé)."""
import importlib.util
import os
import tempfile
import time
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
HAS_QT = importlib.util.find_spec("PyQt6") is not None

if HAS_QT:
    from PyQt6.QtCore import QSettings, Qt
    from PyQt6.QtWidgets import QApplication

    from panther import compare, gui, history, reportpdf, security, store

NET = "192.168.1.0/24"


def dev(ip, name, typ="unknown", ports=(), net=NET, **kw):
    d = {"ip": ip, "mac": "aa:00:00:00:00:%02x" % int(ip.split(".")[-1]), "hostname": name, "type": typ, "vendor": "V", "os": "Linux",
         "ports": list(ports), "services": [], "banners": {}, "ttl": 64, "is_gateway": False, "is_self": False, "random_mac": False,
         "online": True, "confidence": 80, "reasons": ["test"], "model": "", "network": net, "vlan": None, "mdns_services": [],
         "mdns_names": [], "mdns_txt": {}, "ssdp": {}, "path": [], "security": None}
    d.update(kw)
    return d


def network():
    return [dev("192.168.1.13", "debian", "desktop", is_self=True), dev("192.168.1.1", "box", "router", [80, 443], is_gateway=True),
            dev("192.168.1.10", "salon-tv", "tv", [8009]), dev("192.168.1.40", "imprimante", "printer", [9100])]


@unittest.skipUnless(HAS_QT, "PyQt6 absent : tests d'interface ignorés (utiliser le Python du .venv)")
class GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setStyle("Fusion")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        history.PATH = os.path.join(self.tmp.name, "panther.db")
        store.PATH = os.path.join(self.tmp.name, "devices.json")
        QSettings.setPath(QSettings.Format.NativeFormat, QSettings.Scope.UserScope, self.tmp.name)
        gui.T.update(gui.THEMES["dark"]); self.app.setStyleSheet(gui.make_style())
        self.boxes = []                                                          # boîtes de dialogue neutralisées (elles bloqueraient hors écran)
        for name in ("information", "warning", "critical"):
            setattr(gui.QMessageBox, name, staticmethod(lambda *a, _n=name, **k: self.boxes.append((_n, a[1:3])) or 0))
        gui.QMessageBox.question = staticmethod(lambda *a, **k: self.boxes.append(("question", a[1:3])) or gui.QMessageBox.StandardButton.Yes)
        self.w = gui.Main()
        self.w.notify = lambda *a: None
        self.w.network = {"iface": "eth0", "cidr": NET, "gateway": "192.168.1.1", "vlan": None, "kind": "ethernet"}
        self.w.networks_info = [{"cidr": NET, "kind": "local", "vlan": None}]
        self.w.show()

    def tearDown(self):
        self.w.close()
        self.tmp.cleanup()

    def scan(self, devices, depth="normal"):
        for d in devices:
            store.apply(d)  # comme le scanner : il applique les réglages manuels enregistrés à chaque appareil
        self.w.finish_scan({"devices": devices, "networks": self.w.networks_info, "depth": depth}, 5)
        self.app.processEvents()
        time.sleep(0.01)

    # --- fenêtre
    def test_window_builds_with_expected_menus_tabs_and_safe_defaults(self):
        w = self.w
        self.assertEqual([a.text() for a in w.menuBar().actions()], ["Fichier", "Scan", "Affichage", "Sécurité", "Aide"])
        self.assertEqual([w.tabs.tabText(i) for i in range(w.tabs.count())], ["Carte réseau", "Appareils", "Journal", "Sécurité"])
        self.assertFalse(w.security_on)                                          # l'analyse de sécurité est désactivée par défaut
        self.assertEqual(w.depth.currentData(), "normal")
        self.assertEqual(w.iface_combo.itemData(0), "")                          # « Automatique »

    def test_finish_scan_fills_map_table_journal_and_legend(self):
        self.scan(network())
        w = self.w
        self.assertEqual(len(w.nodes), 4)
        self.assertEqual(w.table.rowCount(), 4)
        self.assertGreaterEqual(w.journal.rowCount(), 4)                          # « Nouvel appareil » (référence) par appareil
        self.assertEqual({k for k, _ in w.view.legend}, {"desktop", "router", "tv", "printer"})
        self.assertIn("première analyse", w.status.text())

    def test_selection_is_synchronised_between_map_and_table(self):
        self.scan(network())
        w = self.w
        key = gui.dkey(w.devices[2])
        w.nodes[key].setSelected(True); self.app.processEvents()
        self.assertEqual(w.current_device()["hostname"], w.devices[2]["hostname"])
        self.assertEqual([w.table.item(r.row(), 0).data(gui.KEY_ROLE) for r in w.table.selectionModel().selectedRows()], [key])
        w.scene.clearSelection(); w.table.selectRow(0); self.app.processEvents()
        self.assertEqual(w.table.item(0, 0).data(gui.KEY_ROLE), gui.dkey(w.current_device()))

    def test_two_devices_with_the_same_ip_stay_distinct(self):
        old = dev("192.168.1.20", "ancien-pc", "desktop", mac="aa:00:00:00:00:20")
        new = dev("192.168.1.20", "nouveau-tel", "phone", mac="cc:00:00:00:00:21")
        self.scan([*network()[:2], old])
        for _ in range(3):
            self.scan([*network()[:2], new])                                    # l'ancien est absent, hors ligne
        w = self.w
        same_ip = [d for d in w.devices if d["ip"] == "192.168.1.20"]
        self.assertEqual(sorted(d["hostname"] for d in same_ip), ["ancien-pc", "nouveau-tel"])
        self.assertEqual(len({gui.dkey(d) for d in w.devices}), len(w.devices))
        self.assertEqual(len(w.nodes), len(w.devices))

    def test_filter_dims_non_matching_nodes(self):
        self.scan(network())
        w = self.w
        w.search.setText("imprimante"); self.app.processEvents()
        op = {d["hostname"]: w.nodes[gui.dkey(d)].opacity() for d in w.devices}
        self.assertEqual(op["imprimante"], 1.0)
        self.assertLess(op["salon-tv"], 0.5)
        self.assertEqual(sum(not w.table.isRowHidden(r) for r in range(w.table.rowCount())), 1)

    # --- édition, confiance
    def test_manual_name_type_and_trust_survive_a_new_scan(self):
        self.scan(network())
        w = self.w
        tv = next(d for d in w.devices if d["hostname"] == "salon-tv")
        w.commit_override(tv, "Télé du salon", "console")
        self.assertEqual((tv["hostname"], tv["type"], tv["custom"]), ("Télé du salon", "console", True))
        w.toggle_trust(tv)
        self.assertTrue(tv["trusted"])
        self.scan(network())                                                     # nouveau scan : réglages repris depuis le disque
        tv2 = next(d for d in w.devices if d["ip"] == "192.168.1.10")
        self.assertEqual((tv2["hostname"], tv2["type"], tv2["trusted"]), ("Télé du salon", "console", True))
        w.reset_device(tv2)
        self.assertEqual(tv2["type"], "tv")

    # --- dispositions
    def test_hierarchical_layout_has_virtual_nodes_and_positions_persist(self):
        self.scan(network())
        w = self.w
        w.set_layout("hierarchique")
        self.assertIn("virt:internet", w.nodes)
        self.assertFalse(w.nodes["virt:internet"].flags() & gui.QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        key = gui.dkey(next(d for d in w.devices if d["hostname"] == "salon-tv"))
        n = w.nodes[key]; moved = (n.pos().x() + 123, n.pos().y() + 45)
        n._press = n.pos(); n.setPos(*moved); n.pos_cb(n)
        w.rebuild()
        self.assertAlmostEqual(w.nodes[key].pos().x(), moved[0]); self.assertAlmostEqual(w.nodes[key].pos().y(), moved[1])
        w.set_layout("etoile")
        self.assertNotAlmostEqual(w.nodes[key].pos().x(), moved[0])               # chaque disposition a ses positions
        w.set_layout("hierarchique"); w.reset_positions()
        self.assertNotAlmostEqual(w.nodes[key].pos().x(), moved[0])

    def test_theme_switch_does_not_break_rendering(self):
        self.scan(network())
        for name in ("light", "dark", "light"):
            self.w.apply_theme(name); self.app.processEvents()
            self.w.grab()
        gui.T.update(gui.THEMES["dark"])

    # --- sécurité
    def test_security_toggle_tab_and_exposure_column(self):
        w = self.w
        w.security_consent = True
        w.toggle_security(True)
        self.assertTrue(w.security_on)
        cam = dev("192.168.1.50", "cam", "camera", [23, 554])
        cam["security"] = security.analyze(cam, {554: "open"})
        self.scan([*network(), cam])
        self.assertIn("constat", w.sec_label.text())
        self.assertGreaterEqual(w.sec_table.rowCount(), 2)
        self.assertEqual(w.sec_table.item(0, 0).text(), "Élevé")
        row = next(r for r in range(w.table.rowCount()) if w.table.item(r, 0).text() == "cam")
        self.assertIn("Élevé", w.table.item(row, 10).text())
        w.toggle_security(False)
        self.assertIn("désactivée", w.sec_label.text())

    # --- comparaison, PDF
    def test_compare_dialog_reports_new_gone_and_changed(self):
        self.scan(network())
        changed = network(); changed[2]["ports"] = [8009, 8060]
        self.scan([*changed[:3], dev("192.168.1.70", "pc-compta", "desktop")])      # imprimante partie, TV modifiée, un nouveau
        scans = history.list_scans()
        self.assertEqual(len(scans), 2)
        dlg = gui.CompareDialog(scans, self.w)
        self.assertEqual(dlg.summary.text().split("  ·  ")[:3], ["1 nouveau", "1 disparu", "1 modifié"])
        kinds = [dlg.table.item(r, 0).text() for r in range(dlg.table.rowCount())]
        self.assertEqual(kinds, ["Nouveau", "Modifié", "Disparu"])
        dlg.a.setCurrentIndex(dlg.b.currentIndex())
        self.assertIn("deux scans différents", dlg.summary.text())

    def test_map_image_and_pdf_export(self):
        self.scan(network())
        w = self.w
        img = w.render_map_image(800)
        self.assertFalse(img.isNull())
        self.assertEqual(w.view.legend and gui.T["bg"], gui.THEMES["dark"]["bg"])  # le thème d'affichage n'a pas été modifié
        page = reportpdf.build_html(w.devices, [NET], time.time(), "map")
        path = os.path.join(self.tmp.name, "r.pdf")
        reportpdf.write_pdf(path, page, img)
        with open(path, "rb") as f:
            self.assertTrue(f.read(5) == b"%PDF-")

    def test_depth_policy_presence_needs_a_known_scan_and_auto_scans_alternate_with_full_scans(self):
        w = self.w
        w.depth.setCurrentIndex(w.depth.findData("normal"))
        self.assertEqual(w.choose_depth(auto=False)[0], "normal")                    # scan manuel : la profondeur choisie
        w.last_full_scan = time.time()
        self.assertEqual(w.choose_depth(auto=True)[0], "normal")                      # auto, mais aucun scan connu : pas de présence possible
        self.scan(network())                                                          # un scan complet existe maintenant
        w.last_full_scan = time.time()
        depth, known = w.choose_depth(auto=True)
        self.assertEqual(depth, "presence")
        self.assertEqual(len(known), 4)                                               # les 4 appareils du scan précédent
        w.last_full_scan = time.time() - 3 * 3600
        self.assertEqual(w.choose_depth(auto=True)[0], "normal")                      # plus d'une heure : scan complet
        w.depth.setCurrentIndex(w.depth.findData("presence"))
        self.assertEqual(w.choose_depth(auto=False)[0], "presence")                   # présence demandée à la main
        self.assertEqual(w.choose_depth(auto=True, now=time.time() + 10 * 3600)[0], "presence")

    def test_presence_scan_does_not_reset_the_full_scan_clock(self):
        w = self.w
        w.last_full_scan = 123.0
        self.scan(network(), depth="presence")
        self.assertEqual(w.last_full_scan, 123.0)
        self.assertIn("Scan de présence", w.status.text())
        self.scan(network(), depth="normal")
        self.assertGreater(w.last_full_scan, 123.0)

    # --- carte incrémentale
    def feed(self, devices, status="scanning"):
        """Simule l'état du scanner à un instant d'un scan en cours, puis laisse l'interface le lire."""
        sc = self.w.scanner
        sc.state.update(status=status, progress=40, network=self.w.network, networks=self.w.networks_info,
                        devices={d["ip"]: d for d in devices}, depth="normal")
        self.w.poll()
        self.app.processEvents()

    def test_devices_appear_during_a_scan_without_rebuilding_the_map(self):
        w = self.w
        net = network()
        rebuilds = []
        orig = w.rebuild
        w.rebuild = lambda: (rebuilds.append(1), orig())[1]
        self.feed(net[:2])                                                           # self + box : première apparition = reconstruction
        base = len(rebuilds)
        first = {k: n for k, n in w.nodes.items()}
        moved = next(iter(first.values()))
        moved.setPos(moved.pos().x() + 55, moved.pos().y() + 33); pos = (moved.pos().x(), moved.pos().y())
        self.feed(net[:3]); self.feed(net)
        self.assertEqual(len(rebuilds), base)                                         # aucune reconstruction pendant l'ajout
        self.assertEqual(len(w.nodes), 4)
        self.assertEqual(w.table.rowCount(), 4)
        for k, n in first.items():
            self.assertIs(w.nodes[k], n)                                              # mêmes objets : rien n'a été recréé
        self.assertEqual((moved.pos().x(), moved.pos().y()), pos)                     # le nœud déplacé n'a pas bougé
        self.assertEqual({k for k, _ in w.view.legend}, {"desktop", "router", "tv", "printer"})
        # chaque nouvel appareil est relié à cette machine
        me = next(n for n in w.nodes.values() if n.dev["is_self"])
        self.assertEqual(len(me.links), 3)

    def test_live_nodes_get_distinct_positions_and_wrap_into_rings(self):
        w = self.w
        base = network()[:2]
        many = [dev("192.168.1.%d" % (20 + i), "d%d" % i, "iot") for i in range(30)]
        self.feed(base)
        for i in range(0, 30, 6):
            self.feed(base + many[:i + 6])
        pts = {(round(n.pos().x()), round(n.pos().y())) for n in w.nodes.values()}
        self.assertEqual(len(pts), len(w.nodes))                                      # aucune superposition
        self.assertEqual(w.table.rowCount(), 32)

    def test_hierarchical_layout_and_other_networks_fall_back_to_throttled_rebuilds(self):
        w = self.w
        net = network()
        self.feed(net[:2])
        w.set_layout("hierarchique")
        calls = []
        orig = w.rebuild
        w.rebuild = lambda: (calls.append(1), orig())[1]
        w._last_rebuild = time.time()
        self.feed(net[:3])
        self.assertEqual(calls, [])                                                   # moins d'une seconde après la dernière : on attend
        w._last_rebuild = time.time() - 2
        self.feed(net)
        self.assertEqual(calls, [1])
        self.assertEqual(len(w.nodes) - len([k for k in w.nodes if k.startswith("virt:")]), 4)

    def test_the_previous_map_stays_visible_until_the_new_scan_finds_something(self):
        w = self.w
        self.feed(network())
        before = dict(w.nodes)
        self.feed([])                                                                 # le scan démarre : rien trouvé pour l'instant
        self.assertEqual(w.nodes, before)                                             # pas de carte vide qui clignote
        self.assertEqual(w.table.rowCount(), 4)

    def test_a_new_scan_replaces_the_previous_display(self):
        w = self.w
        self.feed(network())
        self.assertEqual(len(w.nodes), 4)
        self.feed(network()[:1])                                                      # le scan repart de zéro
        self.assertEqual(len(w.nodes), 1)

    # --- fusion de doublons
    def duplicate_scenario(self):
        old = dev("192.168.1.27", "iphone", "phone", mac="02:11:22:33:44:01", random_mac=True)
        self.scan([*network()[:2], old])
        trusted = self.w.devices[-1]
        history.set_trusted([trusted], True)
        new = dev("192.168.1.14", "iphone", "phone", mac="06:11:22:33:44:02", random_mac=True)
        for _ in range(2):
            self.scan([*network()[:2], new])                                       # l'ancienne MAC disparaît, une nouvelle apparaît
        return new

    def test_a_duplicate_is_suggested_after_the_scan_and_merging_keeps_history_and_trust(self):
        self.duplicate_scenario()
        w = self.w
        self.assertEqual(len(w.dup_suggestions), 1)
        self.assertIn("doublon", w.status.text())
        new, old, reasons = w.dup_suggestions[0]
        self.assertFalse(old["online"])
        self.assertTrue(w.merge_into(new, old))
        phones = [d for d in w.devices if d["hostname"] == "iphone"]
        self.assertEqual(len(phones), 1)
        self.assertTrue(phones[0]["trusted"])                                       # la confiance de l'ancienne identité est conservée
        self.assertEqual(w.dup_suggestions, [])
        self.assertEqual(history.alias_map(), {"02:11:22:33:44:01": "06:11:22:33:44:02"})
        self.assertIn("fusionné", w.status.text())
        kinds = [w.journal.item(r, 2).text() for r in range(w.journal.rowCount())]
        self.assertIn("Appareils fusionnés", kinds)

    def test_two_online_devices_cannot_be_merged(self):
        self.scan(network())
        w = self.w
        self.assertFalse(w.merge_into(w.devices[2], w.devices[3]))
        self.assertEqual(self.boxes[-1][0], "information")                           # l'utilisateur est prévenu

    def test_duplicates_dialog_merges_the_selected_row_and_empties_the_list(self):
        self.duplicate_scenario()
        w = self.w
        dlg = gui.DuplicatesDialog(w.dup_suggestions, w.merge_into, w)
        self.assertEqual(dlg.table.rowCount(), 1)
        dlg.merge_selected()
        self.assertEqual((dlg.table.rowCount(), dlg.merge_btn.isEnabled()), (0, False))

    def test_context_menu_offers_merge_only_when_there_is_something_to_merge(self):
        self.scan(network())
        w = self.w
        labels = []
        import panther.gui as g
        orig = g.QMenu.exec
        g.QMenu.exec = lambda self_, pos=None: labels.extend(a.text() for a in self_.actions())
        try:
            w.device_menu(w.devices[2], g.QPointF(0, 0).toPoint())
            self.assertFalse(any("Fusionner" in x for x in labels))                   # tous en ligne : rien à fusionner
            labels.clear()
            self.duplicate_scenario()
            new = next(d for d in w.devices if d["hostname"] == "iphone" and d["online"])
            w.device_menu(new, g.QPointF(0, 0).toPoint())
            self.assertTrue(any("Fusionner avec un appareil hors ligne" in x for x in labels))
        finally:
            g.QMenu.exec = orig

    # --- données et purge
    def test_data_dialog_shows_size_and_purges_old_history(self):
        w = self.w
        for i in range(6):                                                           # six scans, un par jour, il y a longtemps
            d = dev("192.168.1.2", "tv", "tv", ports=[i + 1])
            history.record_scan([d], now=time.time() - (40 - i) * 86400, networks=[NET])
        dlg = gui.DataDialog(history.KEEP_SCANS_DAYS, history.KEEP_EVENTS_DAYS, w)
        self.assertIn("Scans conservés : 6", dlg.info.text())
        self.assertIn("Appareils connus : 1", dlg.info.text())
        self.assertRegex(dlg.info.text(), r"Taille : [\d.,]+ (Ko|Mo)")
        dlg.sp_scans.setValue(37)                                                    # ne garde que ce qui a moins de 37 jours
        dlg.purge()
        self.assertIn("scans supprimés", dlg.result.text())
        self.assertIn("Scans conservés : 2", dlg.info.text())                         # restent les scans de 36 et 35 jours
        self.assertIn("4 scans supprimés", dlg.result.text())

    def test_retention_is_applied_and_remembered(self):
        w = self.w
        w.apply_retention(30, 400)
        self.assertEqual((history.KEEP_SCANS_DAYS, history.KEEP_EVENTS_DAYS), (30, 400))
        self.assertEqual(int(w.settings.value("keep_scans_days")), 30)
        history.KEEP_SCANS_DAYS, history.KEEP_EVENTS_DAYS = 90, 365                  # remet les valeurs par défaut pour les autres tests

    def test_human_size(self):
        self.assertEqual(gui.human_size(512), "512 o")
        self.assertEqual(gui.human_size(2048), "2.0 Ko")
        self.assertEqual(gui.human_size(5 * 1024 * 1024), "5.0 Mo")

    def test_scan_button_toggles_between_start_and_stop(self):
        w = self.w
        w.scanner.state["status"] = "scanning"                                    # scan en cours simulé
        called = []
        w.scanner.stop = lambda: called.append(1) or True
        w.on_scan_button()
        self.assertEqual(called, [1])
        self.assertFalse(w.btn.isEnabled())                                      # « arrêt en cours » : on évite le double clic


if __name__ == "__main__":
    unittest.main()
